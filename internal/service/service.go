// Package service wires the store, cache, signer and mailer into the
// application services: authentication (password, passwordless, refresh
// rotation, logout), RBAC permission checks and the OAuth2/OIDC
// authorization-server flows (authorize, token, revoke, introspect,
// userinfo, JWKS).
//
// The HTTP and gRPC layers are thin adapters over these services; all
// security-critical invariants live here.
package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/Sh4wnK/ApexAuth/internal/cache"
	"github.com/Sh4wnK/ApexAuth/internal/mailer"
	"github.com/Sh4wnK/ApexAuth/internal/passwd"
	"github.com/Sh4wnK/ApexAuth/internal/store"
	"github.com/Sh4wnK/ApexAuth/internal/tokens"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// OAuth / auth errors mapped onto RFC 6749 error codes.
var (
	ErrInvalidClient      = errors.New("invalid client")
	ErrInvalidGrant       = errors.New("invalid grant")
	ErrInvalidRequest     = errors.New("invalid request")
	ErrUnauthorizedClient = errors.New("unauthorized client")
	ErrAccessDenied       = errors.New("access denied")
	ErrRateLimited        = errors.New("rate limited")
	ErrInvalidCredentials = errors.New("invalid credentials")
)

// TokenResult is a successful authentication response.
type TokenResult struct {
	AccessToken  string
	RefreshToken string
	IDToken      string
	TokenType    string // "Bearer"
	ExpiresIn    int64
	Scope        string
	SessionID    string
	JTI          string
	User         store.User
}

// Tokens is the token service: sessions, JWT signing/verification, refresh
// rotation and RBAC lookups with the read-through cache.
type Tokens struct {
	store   *store.Store
	cache   *cache.Cache
	signer  *tokens.Signer
	issuer  string
	accTTL  time.Duration
	refTTL  time.Duration
	sessTTL time.Duration
	log     *slog.Logger
}

// NewTokens builds the token service.
func NewTokens(st *store.Store, ca *cache.Cache, signer *tokens.Signer, issuer string, accTTL, refTTL, sessTTL time.Duration, log *slog.Logger) *Tokens {
	if log == nil {
		log = slog.Default()
	}
	return &Tokens{store: st, cache: ca, signer: signer, issuer: issuer, accTTL: accTTL, refTTL: refTTL, sessTTL: sessTTL, log: log}
}

// AccessTTL / RefreshTTL / Issuer expose configuration.
func (t *Tokens) AccessTTL() time.Duration  { return t.accTTL }
func (t *Tokens) RefreshTTL() time.Duration { return t.refTTL }
func (t *Tokens) Issuer() string            { return t.issuer }
func (t *Tokens) SignerAlg() string         { return t.signer.ActiveAlg() }

// PasswordLogin authenticates email+password (argon2id) and opens a
// session, issuing access + refresh tokens.
func (t *Tokens) PasswordLogin(ctx context.Context, email, password string) (TokenResult, error) {
	u, err := t.store.GetUserByEmail(ctx, email)
	if err != nil {
		return TokenResult{}, ErrInvalidCredentials
	}
	if !u.Active {
		return TokenResult{}, store.ErrInactive
	}
	phc, perr := t.store.PasswordHash(ctx, u.ID)
	if errors.Is(perr, store.ErrNotFound) || (perr == nil && !verifyPassword(password, phc)) {
		// Constant-ish time when the user has no password hash so the two
		// failure paths are not distinguishable by timing.
		_ = verifyPassword(password, "$argon2id$v=19$m=65536,t=1,p=4$c2FsdHNhbHRzYWx0$RqmcYpVwPn3+9WjmlxPzP3X3O5KzH9QdUqYgA0nUQ7s")
		return TokenResult{}, ErrInvalidCredentials
	}
	if perr != nil {
		return TokenResult{}, perr
	}
	return t.IssueSession(ctx, u, "", nil, true, "")
}

// PasswordlessLogin logs in a user after a passwordless token was consumed.
func (t *Tokens) PasswordlessLogin(ctx context.Context, uid string, clientID string, scopes []string, nonce string) (TokenResult, error) {
	u, err := t.store.GetUserByID(ctx, uid)
	if err != nil {
		return TokenResult{}, err
	}
	if !u.Active {
		return TokenResult{}, store.ErrInactive
	}
	return t.IssueSession(ctx, u, clientID, scopes, true, nonce)
}

// IssueSession creates a session, access token and (optionally) refresh
// token for a user. clientID binds the refresh token to an OAuth client
// ("" for first-party sessions). nonce produces an id_token.
func (t *Tokens) IssueSession(ctx context.Context, u store.User, clientID string, scopes []string, withRefresh bool, nonce string) (TokenResult, error) {
	sess, err := t.store.CreateSession(ctx, u.ID, "", t.sessTTL)
	if err != nil {
		return TokenResult{}, err
	}
	jti, err := newJTI()
	if err != nil {
		return TokenResult{}, err
	}
	access, claims, err := t.signAccess(ctx, u, sess.ID, jti)
	if err != nil {
		return TokenResult{}, err
	}
	res := TokenResult{
		AccessToken: access,
		TokenType:   "Bearer",
		ExpiresIn:   int64(t.accTTL.Seconds()),
		SessionID:   sess.ID,
		JTI:         claims.ID,
		User:        u,
	}
	if len(scopes) > 0 {
		res.Scope = strings.Join(scopes, " ")
	}
	if withRefresh {
		rawRef := newRefreshRaw()
		if _, err := t.store.CreateRefreshToken(ctx, u.ID, clientID, rawRef, t.refTTL); err != nil {
			return TokenResult{}, err
		}
		res.RefreshToken = rawRef
	}
	if nonce != "" {
		idTok, err := t.signIDToken(u, nonce, sess.ID)
		if err != nil {
			return TokenResult{}, err
		}
		res.IDToken = idTok
	}
	go t.warmCache(context.Background(), u, sess)
	return res, nil
}

// VerifyAccess validates a JWT including session and activity checks
// (used by the gRPC interceptor and admin APIs).
func (t *Tokens) VerifyAccess(ctx context.Context, raw string) (*tokens.Claims, error) {
	claims, err := t.signer.Verify(raw, "access")
	if err != nil {
		return nil, err
	}
	denied, err := t.cache.TokenDenied(ctx, claims.ID)
	if err != nil {
		return nil, err
	}
	if denied {
		return nil, errors.New("token revoked")
	}
	if claims.SessionID != "" {
		sess, err := t.store.GetSession(ctx, claims.SessionID)
		if err != nil || !sess.ExpiresAt.After(time.Now()) {
			return nil, errors.New("token session ended")
		}
	}
	u, err := t.store.GetUserByID(ctx, claims.UserID)
	if err != nil || !u.Active {
		return nil, errors.New("token user inactive")
	}
	return claims, nil
}

// VerifyTokenOnly validates signature, expiry and denylist without DB
// session checks (used by introspection and /userinfo).
func (t *Tokens) VerifyTokenOnly(ctx context.Context, raw string) (*tokens.Claims, error) {
	claims, err := t.signer.Verify(raw, "access")
	if err != nil {
		return nil, err
	}
	denied, err := t.cache.TokenDenied(ctx, claims.ID)
	if err != nil {
		return nil, err
	}
	if denied {
		return nil, errors.New("token revoked")
	}
	return claims, nil
}

// Refresh rotates a refresh-token family. Reuse of an already-used token
// revokes the whole family and returns store.ErrReuseDetected.
func (t *Tokens) Refresh(ctx context.Context, refreshRaw, clientID string, scopes []string, nonce string) (TokenResult, error) {
	child, rawChild, err := t.store.RotateRefreshToken(ctx, refreshRaw, clientID, t.refTTL)
	if err != nil {
		if errors.Is(err, store.ErrReuseDetected) {
			if child.FamilyID != "" {
				_ = t.store.RevokeRefreshFamily(ctx, child.FamilyID)
				t.log.Warn("refresh token reuse detected; family revoked", "family_id", child.FamilyID)
			}
			return TokenResult{}, store.ErrReuseDetected
		}
		return TokenResult{}, err
	}
	u, err := t.store.GetUserByID(ctx, child.UserID)
	if err != nil {
		return TokenResult{}, err
	}
	if !u.Active {
		return TokenResult{}, store.ErrInactive
	}
	res, err := t.IssueSession(ctx, u, clientID, scopes, false, nonce)
	if err != nil {
		return TokenResult{}, err
	}
	res.RefreshToken = rawChild
	return res, nil
}

// Logout deletes the session, denylists the access jti and revokes the
// refresh token.
func (t *Tokens) Logout(ctx context.Context, sessionID, jti, refreshRaw string) error {
	if sessionID != "" {
		_ = t.store.DeleteSession(ctx, sessionID)
	}
	if jti != "" {
		_ = t.cache.DenyToken(ctx, jti, time.Now().Add(t.accTTL))
	}
	if refreshRaw != "" {
		_ = t.store.RevokeRefreshToken(ctx, refreshRaw)
	}
	return nil
}

// RevokeUser invalidates every session and token of a user.
func (t *Tokens) RevokeUser(ctx context.Context, userID string) error {
	if err := t.store.RevokeUserSessions(ctx, userID); err != nil {
		return err
	}
	if err := t.store.RevokeUserTokens(ctx, userID); err != nil {
		return err
	}
	_ = t.cache.InvalidateUser(ctx, userID)
	return nil
}

// DenyToken denylists a jti until the access TTL passes.
func (t *Tokens) DenyToken(ctx context.Context, jti string) error {
	return t.cache.DenyToken(ctx, jti, time.Now().Add(t.accTTL))
}

// PermissionsOf returns roles and permissions with a read-through cache.
// Cache entries carry the RBAC version; when a role's permissions change
// (BumpRBAC), stale per-user entries are detected and refetched.
func (t *Tokens) PermissionsOf(ctx context.Context, userID string) (roles, perms []string, err error) {
	if t.cache.Enabled() {
		ver, verr := t.cache.RBACVersion(ctx)
		if verr != nil {
			return t.loadPermissions(ctx, userID)
		}
		if r, ok, _ := t.cache.GetRoles(ctx, userID); ok {
			roles = r
		} else if r, err := t.store.ListRoles(ctx, userID); err == nil {
			roles = r
			_ = t.cache.PutRoles(ctx, userID, r, t.accTTL)
		}
		if p, pver, ok, _ := t.cache.GetPerms(ctx, userID); ok && pver == ver {
			perms = p
		} else {
			p, err := t.store.ListPermissions(ctx, userID)
			if err != nil {
				return nil, nil, err
			}
			perms = p
			_ = t.cache.PutPerms(ctx, userID, p, ver, t.accTTL)
		}
		return roles, perms, nil
	}
	return t.loadPermissions(ctx, userID)
}

func (t *Tokens) loadPermissions(ctx context.Context, userID string) ([]string, []string, error) {
	roles, err := t.store.ListRoles(ctx, userID)
	if err != nil {
		return nil, nil, err
	}
	perms, err := t.store.ListPermissions(ctx, userID)
	if err != nil {
		return nil, nil, err
	}
	return roles, perms, nil
}

// CheckPermission reports whether a user's effective permissions contain a
// match for the required permission (wildcards supported).
func (t *Tokens) CheckPermission(ctx context.Context, userID, required string) (bool, error) {
	if userID == "" {
		return false, nil
	}
	_, perms, err := t.PermissionsOf(ctx, userID)
	if err != nil {
		return false, err
	}
	return PermissionMatchAny(perms, required), nil
}

// PermissionMatchAny implements wildcard permission matching over a list.
func PermissionMatchAny(perms []string, req string) bool {
	for _, p := range perms {
		if permissionMatch(p, req) {
			return true
		}
	}
	return false
}

// permissionMatch implements pattern matching:
//   - "billing:*" matches "billing:read", "billing:write", ...
//   - "*:read" matches "billing:read", "users:read", ...
//   - "*" matches anything
//   - otherwise exact equality.
func permissionMatch(pattern, req string) bool {
	if pattern == "*" || pattern == req {
		return true
	}
	p := strings.SplitN(pattern, ":", 2)
	r := strings.SplitN(req, ":", 2)
	if len(p) != 2 || len(r) != 2 {
		return false
	}
	return (p[0] == "*" || p[0] == r[0]) && (p[1] == "*" || p[1] == r[1])
}

// VerifyClientSecret hashes a candidate and compares to the stored hash.
func VerifyClientSecret(stored []byte, cand string) bool {
	h := sha256.Sum256([]byte(cand))
	return subtle.ConstantTimeCompare(stored, h[:]) == 1
}

func (t *Tokens) signAccess(ctx context.Context, u store.User, sessID, jti string) (string, *tokens.Claims, error) {
	roles, perms, err := t.PermissionsOf(ctx, u.ID)
	if err != nil {
		return "", nil, err
	}
	claims := &tokens.Claims{
		UserID:           u.ID,
		Email:            u.Email,
		Name:             u.Name,
		Roles:            roles,
		Permissions:      perms,
		SessionID:        sessID,
		Type:             "access",
		RegisteredClaims: jwt.RegisteredClaims{ID: jti},
	}
	raw, err := t.signer.Sign(*claims, t.accTTL, t.issuer)
	return raw, claims, err
}

func (t *Tokens) signIDToken(u store.User, nonce, sessID string) (string, error) {
	claims := tokens.Claims{
		UserID: u.ID,
		Email:  u.Email,
		Name:   u.Name,
		Type:   "id_token",
		Nonce:  nonce,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:  u.ID,
			Audience: []string{t.issuer},
			ID:       mustJTI(),
		},
	}
	return t.signer.Sign(claims, t.accTTL, t.issuer)
}

func (t *Tokens) warmCache(ctx context.Context, u store.User, sess store.Session) {
	if !t.cache.Enabled() {
		return
	}
	cu := cache.User{ID: u.ID, Email: u.Email, Name: u.Name, EmailVerified: u.EmailVerified, Active: u.Active, CreatedAt: u.CreatedAt}
	_ = t.cache.PutUser(ctx, cu, t.accTTL)
	_ = t.cache.PutSession(ctx, cache.Session{ID: sess.ID, UserID: sess.UserID, JTI: sess.JTI, CreatedAt: sess.CreatedAt, ExpiresAt: sess.ExpiresAt})
}

// ---------------------------------------------------------------------------
// Passwordless

// Passwordless delivers magic links and OTPs.
type Passwordless struct {
	store *store.Store
	mail  mailer.Mailer
	from  string
	ttl   time.Duration
	log   *slog.Logger
}

// NewPasswordless wires the mailer.
func NewPasswordless(st *store.Store, mail mailer.Mailer, from string, ttl time.Duration, log *slog.Logger) *Passwordless {
	if log == nil {
		log = slog.Default()
	}
	return &Passwordless{store: st, mail: mail, from: from, ttl: ttl, log: log}
}

// TTL exposes the configured token lifetime.
func (p *Passwordless) TTL() time.Duration { return p.ttl }

// SendMagicLink emails a single-use magic link. linkPrefix is the URL the
// token is appended to (e.g. "https://auth.example.com/auth/magic?token=");
// stateParam is an opaque string appended as "&state=..." and must be
// echoed back by the client on the callback. Unknown emails are silently
// ignored (anti-enumeration).
func (p *Passwordless) SendMagicLink(ctx context.Context, email, linkPrefix, stateParam string) error {
	u, err := p.store.GetUserByEmail(ctx, email)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if !u.Active {
		return store.ErrInactive
	}
	tok, err := newMagicToken()
	if err != nil {
		return err
	}
	if err := p.store.CreatePasswordlessToken(ctx, u.ID, store.KindMagicLink, tok, p.ttl); err != nil {
		return err
	}
	link := linkPrefix + tok
	if stateParam != "" {
		link += "&state=" + urlQueryEscape(stateParam)
	}
	return p.mail.Send(ctx, mailer.Message{
		To:      u.Email,
		Subject: "Your ApexAuth magic sign-in link",
		Text:    "Click to sign in (valid " + p.ttl.String() + ", single use):\n\n" + link,
	})
}

// ConsumeMagicLink validates a magic-link token (single use) and returns
// the user.
func (p *Passwordless) ConsumeMagicLink(ctx context.Context, token string) (store.User, error) {
	uid, err := p.store.ConsumePasswordlessToken(ctx, store.KindMagicLink, token)
	if err != nil {
		return store.User{}, err
	}
	u, err := p.store.GetUserByID(ctx, uid)
	if err != nil {
		return store.User{}, err
	}
	if !u.Active {
		return store.User{}, store.ErrInactive
	}
	return u, nil
}

// SendOTP mails a 6-digit code; returns the code so tests can read it from
// a capturing mailer. Unknown emails are silently ignored.
func (p *Passwordless) SendOTP(ctx context.Context, email string) (string, error) {
	u, err := p.store.GetUserByEmail(ctx, email)
	if errors.Is(err, store.ErrNotFound) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if !u.Active {
		return "", store.ErrInactive
	}
	code, err := newOTP()
	if err != nil {
		return "", err
	}
	if err := p.store.CreatePasswordlessToken(ctx, u.ID, store.KindOTP, code, p.ttl); err != nil {
		return "", err
	}
	err = p.mail.Send(ctx, mailer.Message{
		To:      u.Email,
		Subject: "Your ApexAuth verification code",
		Text:    "Your code is " + code + ". It expires in " + p.ttl.String() + ".",
	})
	return code, err
}

// ConsumeOTP validates and consumes a code, returning the user.
func (p *Passwordless) ConsumeOTP(ctx context.Context, code string) (store.User, error) {
	uid, err := p.store.ConsumePasswordlessToken(ctx, store.KindOTP, code)
	if err != nil {
		return store.User{}, err
	}
	u, err := p.store.GetUserByID(ctx, uid)
	if err != nil {
		return store.User{}, err
	}
	if !u.Active {
		return store.User{}, store.ErrInactive
	}
	return u, nil
}

// ---------------------------------------------------------------------------
// OAuth2/OIDC authorization server

// Client is a registered third-party application.
type Client struct {
	ClientID       string
	Name           string
	RedirectURIs   []string
	AllowedGrants  []string
	AllowedScopes  []string
	IsConfidential bool
}

// AuthRequest is a validated /authorize input.
type AuthRequest struct {
	ClientID            string
	RedirectURI         string
	State               string
	Nonce               string
	Scopes              []string
	CodeChallenge       string
	CodeChallengeMethod string
	ResponseType        string
	Prompt              string
}

// OAuth implements the authorization-server endpoints.
type OAuth struct {
	store   *store.Store
	tokens  *Tokens
	codeTTL time.Duration
	issuer  string
	log     *slog.Logger
}

// NewOAuth wires the service.
func NewOAuth(st *store.Store, tk *Tokens, codeTTL time.Duration, issuer string, log *slog.Logger) *OAuth {
	if log == nil {
		log = slog.Default()
	}
	return &OAuth{store: st, tokens: tk, codeTTL: codeTTL, issuer: issuer, log: log}
}

// ValidateRedirectURI performs strict redirect matching: exact string
// equality against the registered list. No wildcards, no prefix matching,
// no userinfo, no fragments allowed (enforced at registration too).
func ValidateRedirectURI(registered []string, candidate string) bool {
	for _, r := range registered {
		if r == candidate {
			return true
		}
	}
	return false
}

// RedirectAllowed reports whether a candidate redirect URI is registered.
func (o *OAuth) RedirectAllowed(registered []string, candidate string) bool {
	return ValidateRedirectURI(registered, candidate)
}

// AuthenticateClient validates client_id and, for confidential clients,
// the client secret.
func (o *OAuth) AuthenticateClient(ctx context.Context, clientID, clientSecret string) (Client, error) {
	c, err := o.store.GetOAuthClient(ctx, clientID)
	if err != nil {
		return Client{}, ErrInvalidClient
	}
	if c.IsConfidential {
		if clientSecret == "" || !VerifyClientSecret(c.ClientSecret, clientSecret) {
			return Client{}, ErrInvalidClient
		}
	}
	return Client{
		ClientID:       c.ClientID,
		Name:           c.Name,
		RedirectURIs:   c.RedirectURIs,
		AllowedGrants:  c.AllowedGrants,
		AllowedScopes:  c.AllowedScopes,
		IsConfidential: c.IsConfidential,
	}, nil
}

// ValidateAuthorizeRequest checks response_type, client, redirect_uri and
// scope legality, and enforces PKCE for public clients.
func (o *OAuth) ValidateAuthorizeRequest(ctx context.Context, q AuthRequest) (Client, error) {
	if q.ResponseType != "code" {
		return Client{}, ErrInvalidRequest
	}
	c, err := o.store.GetOAuthClient(ctx, q.ClientID)
	if err != nil {
		return Client{}, ErrInvalidRequest
	}
	if !ValidateRedirectURI(c.RedirectURIs, q.RedirectURI) {
		return Client{}, ErrInvalidRequest
	}
	for _, s := range q.Scopes {
		if !containsStr(c.AllowedScopes, s) {
			return Client{}, ErrInvalidRequest
		}
	}
	if !c.IsConfidential {
		// RFC 7636: S256 required for public clients.
		if q.CodeChallenge == "" || q.CodeChallengeMethod != "S256" {
			return Client{}, ErrInvalidRequest
		}
	}
	return Client{
		ClientID:       c.ClientID,
		Name:           c.Name,
		RedirectURIs:   c.RedirectURIs,
		AllowedGrants:  c.AllowedGrants,
		AllowedScopes:  c.AllowedScopes,
		IsConfidential: c.IsConfidential,
	}, nil
}

// IssueCode creates a one-time authorization code (stored hashed) bound to
// the request parameters.
func (o *OAuth) IssueCode(ctx context.Context, u store.User, clientID, redirectURI, nonce, challenge, method string, scopes []string) (string, error) {
	raw, err := newCode()
	if err != nil {
		return "", err
	}
	if _, err := o.store.CreateOAuthCode(ctx, clientID, u.ID, raw, redirectURI, nonce, challenge, method, scopes, o.codeTTL); err != nil {
		return "", err
	}
	return raw, nil
}

// ExchangeCode trades an authorization code (+PKCE verifier) for tokens.
func (o *OAuth) ExchangeCode(ctx context.Context, clientID, clientSecret, code, verifier, redirectURI string) (TokenResult, error) {
	if _, err := o.AuthenticateClient(ctx, clientID, clientSecret); err != nil {
		return TokenResult{}, ErrInvalidClient
	}
	oc, err := o.store.ConsumeOAuthCode(ctx, code)
	if err != nil {
		return TokenResult{}, ErrInvalidGrant
	}
	if oc.ClientIDText != "" && oc.ClientIDText != clientID {
		return TokenResult{}, ErrInvalidGrant
	}
	if redirectURI != "" && oc.RedirectURI != redirectURI {
		return TokenResult{}, ErrInvalidGrant
	}
	if oc.PKCEChallenge != "" {
		if verifier == "" {
			return TokenResult{}, ErrInvalidGrant
		}
		sum := sha256.Sum256([]byte(verifier))
		if base64.RawURLEncoding.EncodeToString(sum[:]) != oc.PKCEChallenge {
			return TokenResult{}, ErrInvalidGrant
		}
	} else if oc.PKCEMethod != "" {
		return TokenResult{}, ErrInvalidGrant
	}
	u, err := o.store.GetUserByID(ctx, oc.UserID)
	if err != nil || !u.Active {
		return TokenResult{}, ErrInvalidGrant
	}
	res, err := o.tokens.IssueSession(ctx, u, clientID, oc.Scopes, true, oc.Nonce)
	if err != nil {
		return TokenResult{}, err
	}
	_ = o.store.DeleteOAuthCode(ctx, oc.ID)
	return res, nil
}

// ExchangeRefresh rotates a refresh token and issues fresh tokens.
func (o *OAuth) ExchangeRefresh(ctx context.Context, clientID, clientSecret, refreshToken string, scopes []string, nonce string) (TokenResult, error) {
	if _, err := o.AuthenticateClient(ctx, clientID, clientSecret); err != nil {
		return TokenResult{}, ErrInvalidClient
	}
	res, err := o.tokens.Refresh(ctx, refreshToken, clientID, scopes, nonce)
	if err != nil {
		if errors.Is(err, store.ErrReuseDetected) {
			return TokenResult{}, ErrInvalidGrant
		}
		return TokenResult{}, ErrInvalidGrant
	}
	return res, nil
}

// ExchangeClientCredentials issues an access token for a confidential
// client without a user (service-to-service).
func (o *OAuth) ExchangeClientCredentials(ctx context.Context, clientID, clientSecret string, scopes []string) (TokenResult, error) {
	c, err := o.AuthenticateClient(ctx, clientID, clientSecret)
	if err != nil {
		return TokenResult{}, ErrInvalidClient
	}
	if !grantAllowed(c.AllowedGrants, "client_credentials") {
		return TokenResult{}, ErrUnauthorizedClient
	}
	for _, s := range scopes {
		if !containsStr(c.AllowedScopes, s) {
			return TokenResult{}, ErrInvalidRequest
		}
	}
	jti, err := newJTI()
	if err != nil {
		return TokenResult{}, err
	}
	claims := tokens.Claims{
		Name:        c.Name,
		Roles:       []string{"client:" + c.ClientID},
		Permissions: scopes,
		Type:        "access",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: c.ClientID,
			ID:      jti,
		},
	}
	access, err := o.tokens.signer.Sign(claims, o.tokens.accTTL, o.issuer)
	if err != nil {
		return TokenResult{}, err
	}
	return TokenResult{
		AccessToken: access,
		TokenType:   "Bearer",
		ExpiresIn:   int64(o.tokens.accTTL.Seconds()),
		Scope:       strings.Join(scopes, " "),
		JTI:         jti,
	}, nil
}

// Revoke implements RFC 7009: access tokens (denylist by jti) and refresh
// tokens (family revocation). The client must authenticate first.
func (o *OAuth) Revoke(ctx context.Context, clientID, clientSecret, token string) error {
	if _, err := o.AuthenticateClient(ctx, clientID, clientSecret); err != nil {
		return ErrInvalidClient
	}
	if token == "" {
		return ErrInvalidRequest
	}
	if claims, err := o.tokens.signer.Verify(token, "access"); err == nil && claims != nil {
		_ = o.tokens.DenyToken(ctx, claims.ID)
		return nil
	}
	_ = o.store.RevokeRefreshToken(ctx, token)
	return nil
}

// Introspect implements RFC 7662 for access tokens (validated without DB
// session checks so resource servers can call it cheaply).
func (o *OAuth) Introspect(ctx context.Context, token string) map[string]any {
	claims, err := o.tokens.VerifyTokenOnly(ctx, token)
	if err != nil {
		return map[string]any{"active": false}
	}
	return map[string]any{
		"active":      true,
		"sub":         claims.UserID,
		"email":       claims.Email,
		"name":        claims.Name,
		"jti":         claims.ID,
		"sid":         claims.SessionID,
		"scope":       strings.Join(claims.Permissions, " "),
		"roles":       claims.Roles,
		"permissions": claims.Permissions,
		"token_type":  "Bearer",
		"exp":         claims.ExpiresAt.Unix(),
		"iat":         claims.IssuedAt.Unix(),
	}
}

// Userinfo returns the claims of a valid bearer token for /userinfo.
func (o *OAuth) Userinfo(ctx context.Context, raw string) (map[string]any, error) {
	claims, err := o.tokens.VerifyTokenOnly(ctx, raw)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"sub":            claims.UserID,
		"email":          claims.Email,
		"name":           claims.Name,
		"email_verified": true,
		"roles":          claims.Roles,
		"permissions":    claims.Permissions,
	}, nil
}

func grantAllowed(grants []string, g string) bool { return containsStr(grants, g) }

// ---------------------------------------------------------------------------
// helpers

func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func urlQueryEscape(s string) string { return url.QueryEscape(s) }

// ---------------------------------------------------------------------------
// generation helpers

var (
	newJTI        = func() (string, error) { return randomUUID(), nil }
	newRefreshRaw = func() string { return randomUUID() + randomUUID() }
	newMagicToken = func() (string, error) { return base64.RawURLEncoding.EncodeToString(mustRand(32)), nil }
	newOTP        = func() (string, error) {
		b := mustRand(4)
		return fmt.Sprintf("%06d", int(uint32(b[0])<<24|uint32(b[1])<<16|uint32(b[2])<<8|uint32(b[3]))%1000000), nil
	}
	newCode = func() (string, error) { return newMagicToken() }
)

func mustJTI() string {
	j, err := newJTI()
	if err != nil {
		return uuid.NewString()
	}
	return j
}

func randomUUID() string {
	b := mustRand(16)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	u, err := uuid.FromBytes(b)
	if err != nil {
		return uuid.NewString()
	}
	return u.String()
}

func mustRand(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return b
}

// verifyPassword checks an argon2id PHC string.
func verifyPassword(password, phc string) bool { return passwd.Verify(password, phc) }
