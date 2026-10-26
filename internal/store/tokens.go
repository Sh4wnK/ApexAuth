package store

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ---------------------------------------------------------------------------
// Sessions

// Session is an interactive login session (id, user, expiry).
type Session struct {
	ID        string
	UserID    string
	JTI       string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// CreateSession records a new session for access-token lifecycle tracking.
// When jti is empty a fresh one is generated (first-party logins bake the
// session's jti into their access token).
func (s *Store) CreateSession(ctx context.Context, userID, jti string, ttl time.Duration) (Session, error) {
	id := uuid.NewString()
	if jti == "" {
		jti = uuid.NewString()
	}
	sess := Session{ID: id, UserID: userID, JTI: jti, CreatedAt: s.now(), ExpiresAt: s.now().Add(ttl)}
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO sessions (id, user_id, created_at, expires_at, jti)
		VALUES ($1, $2, $3, $4, $5)`, id, userID, sess.CreatedAt, sess.ExpiresAt, jti); err != nil {
		return Session{}, fmt.Errorf("store: create session: %w", err)
	}
	return sess, nil
}

// GetSession returns a session by id.
func (s *Store) GetSession(ctx context.Context, id string) (Session, error) {
	var sess Session
	err := s.pool.QueryRow(ctx, `
		SELECT id, user_id, jti, created_at, expires_at FROM sessions WHERE id = $1`, id).
		Scan(&sess.ID, &sess.UserID, &sess.JTI, &sess.CreatedAt, &sess.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Session{}, ErrNotFound
	}
	if err != nil {
		return Session{}, fmt.Errorf("store: get session: %w", err)
	}
	return sess, nil
}

// DeleteSession removes a single session row.
func (s *Store) DeleteSession(ctx context.Context, sessionID string) error {
	if _, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE id = $1`, sessionID); err != nil {
		return fmt.Errorf("store: delete session: %w", err)
	}
	return nil
}

// RevokeUserSessions deletes every live session of a user (used by
// logout-all and password change).
func (s *Store) RevokeUserSessions(ctx context.Context, userID string) error {
	if _, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1`, userID); err != nil {
		return fmt.Errorf("store: revoke sessions: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Refresh tokens (rotation families)

// RefreshToken is a row of the rotation family.
type RefreshToken struct {
	ID        string
	FamilyID  string
	ParentID  string
	UserID    string
	ClientID  string
	TokenHash []byte
	Used      bool
	Revoked   bool
	ExpiresAt time.Time
}

// CreateRefreshToken inserts the family root (parentID == ""), optionally
// bound to an OAuth client (identified by its public client_id; "" for
// first-party sessions).
func (s *Store) CreateRefreshToken(ctx context.Context, userID, clientID, tokenRaw string, ttl time.Duration) (RefreshToken, error) {
	id := uuid.NewString()
	sh := sha256.Sum256([]byte(tokenRaw))
	t := RefreshToken{
		ID:        id,
		FamilyID:  id,
		UserID:    userID,
		TokenHash: sh[:],
		ExpiresAt: s.now().Add(ttl),
	}
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO refresh_tokens (id, family_id, user_id, client_id, token_hash, expires_at)
		SELECT $1, $2, $3, c.id, $4, $5
		FROM (SELECT NULL::uuid AS id) z
		LEFT JOIN oauth_clients c ON c.client_id = $6 AND NOT c.deleted`,
		t.ID, t.FamilyID, t.UserID, t.TokenHash, t.ExpiresAt, clientID); err != nil {
		return RefreshToken{}, fmt.Errorf("store: create refresh token: %w", err)
	}
	return t, nil
}

// RotateRefreshToken consumes a refresh token and produces its child.
// It returns the new token's row and the raw token string to hand to the
// client (the child hash is derived from that raw value).
//
// Returns ErrNotFound when the token does not exist or expired, and
// ErrReuseDetected when the token was already rotated (used) or revoked —
// the caller must revoke the whole family via RevokeRefreshFamily. The
// rotation is atomic: the parent is marked used and the child inserted in
// one transaction.
func (s *Store) RotateRefreshToken(ctx context.Context, tokenRaw string, clientID string, ttl time.Duration) (RefreshToken, string, error) {
	type parent struct {
		id, familyID, userID, clientID string
		used, revoked                  bool
		expiresAt                      time.Time
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return RefreshToken{}, "", fmt.Errorf("store: rotate: begin: %w", err)
	}
	defer tx.Rollback(ctx)

	var p parent
	h := sha256.Sum256([]byte(tokenRaw))
	err = tx.QueryRow(ctx, `
		SELECT id, family_id, user_id, COALESCE(client_id::text, ''), used, revoked, expires_at
		FROM refresh_tokens WHERE token_hash = $1 FOR UPDATE`, h[:]).
		Scan(&p.id, &p.familyID, &p.userID, &p.clientID, &p.used, &p.revoked, &p.expiresAt)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && !p.expiresAt.After(s.now())) {
		return RefreshToken{}, "", ErrNotFound
	}
	if err != nil {
		return RefreshToken{}, "", fmt.Errorf("store: rotate: lookup: %w", err)
	}
	if p.used || p.revoked {
		// Reuse of a rotated-out token: the rotating party may have leaked
		// the previous token. Signal (with the family id) so the caller can
		// revoke the whole family.
		return RefreshToken{ID: p.id, FamilyID: p.familyID, UserID: p.userID}, "", ErrReuseDetected
	}
	if clientID != "" && p.clientID != "" {
		// p.clientID is the internal UUID text; resolve the caller's public
		// client_id to its UUID and compare.
		var boundTo string
		_ = tx.QueryRow(ctx, `SELECT id FROM oauth_clients WHERE client_id = $1 AND NOT deleted`, clientID).Scan(&boundTo)
		if boundTo == "" || boundTo != p.clientID {
			return RefreshToken{}, "", ErrNotFound
		}
	}

	childRaw := genRawToken()
	childID := uuid.NewString()
	if _, err := tx.Exec(ctx, `UPDATE refresh_tokens SET used = TRUE WHERE id = $1`, p.id); err != nil {
		return RefreshToken{}, "", fmt.Errorf("store: rotate: mark used: %w", err)
	}
	var clientUUID *string
	if p.clientID != "" {
		clientUUID = &p.clientID
	}
	ch := sha256.Sum256([]byte(childRaw))
	if _, err := tx.Exec(ctx, `
		INSERT INTO refresh_tokens (id, family_id, parent_id, user_id, client_id, token_hash, expires_at)
		VALUES ($1, $2, $3, $4, $5::uuid, $6, $7)`,
		childID, p.familyID, p.id, p.userID, clientUUID, ch[:], s.now().Add(ttl)); err != nil {
		return RefreshToken{}, "", fmt.Errorf("store: rotate: insert child: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return RefreshToken{}, "", fmt.Errorf("store: rotate: commit: %w", err)
	}
	return RefreshToken{ID: childID, FamilyID: p.familyID, UserID: p.userID, ExpiresAt: s.now().Add(ttl)}, childRaw, nil
}

// LookupRefreshFamily returns the family id of a token (used to revoke
// families when reuse is detected and the token is already marked used).
func (s *Store) LookupRefreshFamily(ctx context.Context, tokenRaw string) (string, error) {
	hash := sha256.Sum256([]byte(tokenRaw))
	var family string
	err := s.pool.QueryRow(ctx, `SELECT family_id FROM refresh_tokens WHERE token_hash = $1`, hash[:]).Scan(&family)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("store: lookup family: %w", err)
	}
	return family, nil
}

// RevokeRefreshFamily marks every token in the family revoked.
func (s *Store) RevokeRefreshFamily(ctx context.Context, familyID string) error {
	if _, err := s.pool.Exec(ctx, `UPDATE refresh_tokens SET revoked = TRUE WHERE family_id = $1`, familyID); err != nil {
		return fmt.Errorf("store: revoke family: %w", err)
	}
	return nil
}

// RevokeRefreshToken revokes a single live refresh token by hash.
func (s *Store) RevokeRefreshToken(ctx context.Context, tokenRaw string) error {
	hash := sha256.Sum256([]byte(tokenRaw))
	if _, err := s.pool.Exec(ctx, `UPDATE refresh_tokens SET revoked = TRUE WHERE token_hash = $1`, hash[:]); err != nil {
		return fmt.Errorf("store: revoke refresh token: %w", err)
	}
	return nil
}

// RevokeUserTokens revokes every refresh token of a user.
func (s *Store) RevokeUserTokens(ctx context.Context, userID string) error {
	if _, err := s.pool.Exec(ctx, `UPDATE refresh_tokens SET revoked = TRUE WHERE user_id = $1 AND NOT revoked`, userID); err != nil {
		return fmt.Errorf("store: revoke user tokens: %w", err)
	}
	return nil
}

// CountLiveTokens returns the number of non-revoked, non-expired refresh
// tokens of a user (used by sessions listing).
func (s *Store) CountLiveTokens(ctx context.Context, userID string) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `
		SELECT count(*) FROM refresh_tokens
		WHERE user_id = $1 AND NOT revoked AND NOT used AND expires_at > now()`, userID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("store: count live tokens: %w", err)
	}
	return n, nil
}

// DropUsedRefreshTokens removes rotated-out and revoked tokens older than
// cutoff (janitor).
func (s *Store) DropUsedRefreshTokens(ctx context.Context, cutoff time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM refresh_tokens WHERE created_at < $1 AND (used OR revoked)`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("store: drop used tokens: %w", err)
	}
	return tag.RowsAffected(), nil
}

func genRawToken() string { return uuid.NewString() + uuid.NewString() }

// ---------------------------------------------------------------------------
// OAuth clients, codes, consents

// OAuthClient is a registered third-party application.
type OAuthClient struct {
	ID             string
	ClientID       string
	ClientSecret   []byte // SHA-256 hash of the secret; nil for public clients
	Name           string
	RedirectURIs   []string
	AllowedGrants  []string
	AllowedScopes  []string
	IsConfidential bool
	Deleted        bool
}

// CreateOAuthClient registers a new client. secretRaw is hashed before
// storage; pass "" for public clients.
func (s *Store) CreateOAuthClient(ctx context.Context, clientID, secretRaw, name string, redirectURIs, allowedScopes []string, confidential bool) (OAuthClient, error) {
	var secret []byte
	if secretRaw != "" {
		h := sha256.Sum256([]byte(secretRaw))
		secret = h[:]
	}
	grants := []string{"authorization_code", "refresh_token"}
	if !confidential {
		grants = []string{"authorization_code", "refresh_token"}
	}
	c := OAuthClient{
		ID:             uuid.NewString(),
		ClientID:       clientID,
		ClientSecret:   secret,
		Name:           name,
		RedirectURIs:   redirectURIs,
		AllowedGrants:  grants,
		AllowedScopes:  allowedScopes,
		IsConfidential: confidential,
	}
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO oauth_clients (id, client_id, client_secret, name, redirect_uris, allowed_grants, allowed_scopes, is_confidential)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		c.ID, c.ClientID, c.ClientSecret, c.Name, c.RedirectURIs, c.AllowedGrants, c.AllowedScopes, c.IsConfidential); err != nil {
		return OAuthClient{}, fmt.Errorf("store: create oauth client: %w", err)
	}
	return c, nil
}

// GetOAuthClient loads a client by public client_id.
func (s *Store) GetOAuthClient(ctx context.Context, clientID string) (OAuthClient, error) {
	var c OAuthClient
	err := s.pool.QueryRow(ctx, `
		SELECT id, client_id, client_secret, name, redirect_uris, allowed_grants, allowed_scopes, is_confidential, deleted
		FROM oauth_clients WHERE client_id = $1 AND NOT deleted`, clientID).
		Scan(&c.ID, &c.ClientID, &c.ClientSecret, &c.Name, &c.RedirectURIs, &c.AllowedGrants, &c.AllowedScopes, &c.IsConfidential, &c.Deleted)
	if errors.Is(err, pgx.ErrNoRows) {
		return OAuthClient{}, ErrNotFound
	}
	if err != nil {
		return OAuthClient{}, fmt.Errorf("store: get oauth client: %w", err)
	}
	return c, nil
}

// DeleteOAuthClient soft-deletes a client by public id.
func (s *Store) DeleteOAuthClient(ctx context.Context, clientID string) error {
	if _, err := s.pool.Exec(ctx, `UPDATE oauth_clients SET deleted = TRUE WHERE client_id = $1`, clientID); err != nil {
		return fmt.Errorf("store: delete oauth client: %w", err)
	}
	return nil
}

// ListOAuthClients returns all non-deleted clients (admin API).
func (s *Store) ListOAuthClients(ctx context.Context) ([]OAuthClient, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, client_id, client_secret, name, redirect_uris, allowed_grants, allowed_scopes, is_confidential, deleted
		FROM oauth_clients WHERE NOT deleted ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("store: list oauth clients: %w", err)
	}
	defer rows.Close()
	var out []OAuthClient
	for rows.Next() {
		var c OAuthClient
		if err := rows.Scan(&c.ID, &c.ClientID, &c.ClientSecret, &c.Name, &c.RedirectURIs, &c.AllowedGrants, &c.AllowedScopes, &c.IsConfidential, &c.Deleted); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// OAuthCode is a one-time authorization code row (PKCE challenge + nonce
// bound at issuance, code itself stored hashed).
type OAuthCode struct {
	ID            string
	ClientID      string // internal UUID
	ClientIDText  string // public client_id
	UserID        string
	CodeHash      []byte
	RedirectURI   string
	Scopes        []string
	Nonce         string
	PKCEChallenge string
	PKCEMethod    string
	Used          bool
	ExpiresAt     time.Time
}

// CreateOAuthCode stores a hashed authorization code. clientID is the
// public client_id; the internal UUID is resolved inside the insert.
func (s *Store) CreateOAuthCode(ctx context.Context, clientID, userID, codeRaw, redirectURI, nonce, pkceChallenge, pkceMethod string, scopes []string, ttl time.Duration) (OAuthCode, error) {
	id := uuid.NewString()
	sh := sha256.Sum256([]byte(codeRaw))
	c := OAuthCode{
		ID:            id,
		ClientIDText:  clientID,
		UserID:        userID,
		CodeHash:      sh[:],
		RedirectURI:   redirectURI,
		Scopes:        scopes,
		Nonce:         nonce,
		PKCEChallenge: pkceChallenge,
		PKCEMethod:    pkceMethod,
		ExpiresAt:     s.now().Add(ttl),
	}
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO authorization_codes (id, client_id, user_id, code_hash, redirect_uri, scopes, nonce, pkce_challenge, pkce_method, used, expires_at)
		SELECT $1, id, $3, $4, $5, $6, $7, $8, $9, FALSE, $10 FROM oauth_clients WHERE client_id = $2 AND NOT deleted`,
		c.ID, clientID, c.UserID, c.CodeHash, c.RedirectURI, c.Scopes, c.Nonce, c.PKCEChallenge, c.PKCEMethod, c.ExpiresAt); err != nil {
		return OAuthCode{}, fmt.Errorf("store: create oauth code: %w", err)
	}
	return c, nil
}

// ConsumeOAuthCode atomically reads and marks used an authorization code.
// Returns ErrNotFound when unknown/expired/already used.
func (s *Store) ConsumeOAuthCode(ctx context.Context, codeRaw string) (OAuthCode, error) {
	hash := func() []byte { h := sha256.Sum256([]byte(codeRaw)); return h[:] }()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return OAuthCode{}, fmt.Errorf("store: consume code: begin: %w", err)
	}
	defer tx.Rollback(ctx)
	var c OAuthCode
	err = tx.QueryRow(ctx, `
		SELECT id, client_id, user_id, redirect_uri, scopes, nonce, pkce_challenge, pkce_method, used, expires_at,
		       (SELECT client_id FROM oauth_clients WHERE id = authorization_codes.client_id)
		FROM authorization_codes WHERE code_hash = $1 FOR UPDATE`, hash).
		Scan(&c.ID, &c.ClientID, &c.UserID, &c.RedirectURI, &c.Scopes, &c.Nonce, &c.PKCEChallenge, &c.PKCEMethod, &c.Used, &c.ExpiresAt, &c.ClientIDText)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && (c.Used || !c.ExpiresAt.After(s.now()))) {
		return OAuthCode{}, ErrNotFound
	}
	if err != nil {
		return OAuthCode{}, fmt.Errorf("store: consume code: lookup: %w", err)
	}
	if c.Used {
		return OAuthCode{}, ErrNotFound
	}
	if _, err := tx.Exec(ctx, `UPDATE authorization_codes SET used = TRUE WHERE id = $1`, c.ID); err != nil {
		return OAuthCode{}, fmt.Errorf("store: consume code: mark used: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return OAuthCode{}, fmt.Errorf("store: consume code: commit: %w", err)
	}
	return c, nil
}

// DeleteOAuthCode removes a consumed code once the token exchange completes
// (defense in depth; consumed codes are already unusable).
func (s *Store) DeleteOAuthCode(ctx context.Context, codeID string) error {
	if _, err := s.pool.Exec(ctx, `DELETE FROM authorization_codes WHERE id = $1`, codeID); err != nil {
		return fmt.Errorf("store: delete oauth code: %w", err)
	}
	return nil
}

// RecordConsent upserts the client/user consent snapshot.
func (s *Store) RecordConsent(ctx context.Context, userID, clientID string, scopes []string) error {
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO consents (user_id, client_id, scopes, created_at)
		VALUES ($1, $2, $3, now())
		ON CONFLICT (user_id, client_id) DO UPDATE SET scopes = EXCLUDED.scopes, created_at = now()`,
		userID, clientID, scopes); err != nil {
		return fmt.Errorf("store: record consent: %w", err)
	}
	return nil
}

// HasConsent reports whether the user already consented to every requested
// scope for the client.
func (s *Store) HasConsent(ctx context.Context, userID, clientID string, scopes []string) (bool, error) {
	var stored []string
	err := s.pool.QueryRow(ctx, `SELECT scopes FROM consents WHERE user_id = $1 AND client_id = $2`, userID, clientID).Scan(&stored)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("store: has consent: %w", err)
	}
	have := map[string]bool{}
	for _, sc := range stored {
		have[sc] = true
	}
	for _, sc := range scopes {
		if !have[sc] {
			return false, nil
		}
	}
	return true, nil
}

// ---------------------------------------------------------------------------
// Passwordless tokens (magic links + OTPs)

// PasswordlessKind distinguishes magic links from one-time passcodes.
type PasswordlessKind string

const (
	KindMagicLink PasswordlessKind = "magic_link"
	KindOTP       PasswordlessKind = "otp"
)

// CreatePasswordlessToken stores a hashed single-use token.
func (s *Store) CreatePasswordlessToken(ctx context.Context, userID string, kind PasswordlessKind, tokenRaw string, ttl time.Duration) error {
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO passwordless_tokens (id, user_id, kind, token_hash, expires_at)
		VALUES ($1, $2, $3, $4, $5)`,
		uuid.NewString(), userID, string(kind), func() []byte { h := sha256.Sum256([]byte(tokenRaw)); return h[:] }(), s.now().Add(ttl)); err != nil {
		return fmt.Errorf("store: create passwordless token: %w", err)
	}
	return nil
}

// ConsumePasswordlessToken atomically validates and consumes a token.
// Returns ErrNotFound when unknown/expired/used or the kind does not match.
func (s *Store) ConsumePasswordlessToken(ctx context.Context, kind PasswordlessKind, tokenRaw string) (userID string, err error) {
	hash := func() []byte { h := sha256.Sum256([]byte(tokenRaw)); return h[:] }()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", fmt.Errorf("store: consume passwordless: begin: %w", err)
	}
	defer tx.Rollback(ctx)
	var (
		uid       string
		used      bool
		expiresAt time.Time
	)
	err = tx.QueryRow(ctx, `
		SELECT user_id, used, expires_at FROM passwordless_tokens
		WHERE kind = $1 AND token_hash = $2 FOR UPDATE`, string(kind), hash).
		Scan(&uid, &used, &expiresAt)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && (used || !expiresAt.After(s.now()))) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("store: consume passwordless: lookup: %w", err)
	}
	if used {
		return "", ErrNotFound
	}
	if _, err := tx.Exec(ctx, `UPDATE passwordless_tokens SET used = TRUE WHERE user_id = $1 AND kind = $2 AND token_hash = $3`, uid, string(kind), hash); err != nil {
		return "", fmt.Errorf("store: consume passwordless: mark used: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return "", fmt.Errorf("store: consume passwordless: commit: %w", err)
	}
	return uid, nil
}

// RevokePasswordlessTokens invalidates all outstanding tokens of a kind for
// a user (e.g. after a password change).
func (s *Store) RevokePasswordlessTokens(ctx context.Context, userID string, kind PasswordlessKind) error {
	if _, err := s.pool.Exec(ctx, `DELETE FROM passwordless_tokens WHERE user_id = $1 AND kind = $2`, userID, string(kind)); err != nil {
		return fmt.Errorf("store: revoke passwordless: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Audit log

// AuditEntry records a security-relevant event.
type AuditEntry struct {
	ActorID    string
	Action     string
	TargetType string
	TargetID   string
	IP         string
	UserAgent  string
	Metadata   map[string]any
	CreatedAt  time.Time
}

// Audit appends an entry to the append-only log.
func (s *Store) Audit(ctx context.Context, e AuditEntry) error {
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO audit_log (actor_id, action, target_type, target_id, ip, user_agent, metadata)
		VALUES (NULLIF($1, ''), $2, $3, $4, NULLIF($5, '')::inet, $6, $7)`,
		e.ActorID, e.Action, e.TargetType, e.TargetID, e.IP, e.UserAgent, e.Metadata); err != nil {
		return fmt.Errorf("store: audit: %w", err)
	}
	return nil
}

// RecentAudit returns the latest N entries, optionally filtered by actor.
func (s *Store) RecentAudit(ctx context.Context, actorID string, limit int) ([]AuditEntry, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT COALESCE(actor_id::text, ''), action, target_type, target_id, COALESCE(ip::text, ''), user_agent, metadata, created_at
		FROM audit_log WHERE ($1 = '' OR actor_id::text = $1)
		ORDER BY created_at DESC LIMIT $2`, actorID, limit)
	if err != nil {
		return nil, fmt.Errorf("store: recent audit: %w", err)
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ActorID, &e.Action, &e.TargetType, &e.TargetID, &e.IP, &e.UserAgent, &e.Metadata, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
