// Package httpapi exposes ApexAuth over HTTP: first-party auth endpoints,
// the OAuth2/OIDC authorization server, admin REST APIs and the minimal
// login/consent pages.
package httpapi

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Sh4wnK/ApexAuth/internal/cache"
	"github.com/Sh4wnK/ApexAuth/internal/passwd"
	"github.com/Sh4wnK/ApexAuth/internal/service"
	"github.com/Sh4wnK/ApexAuth/internal/store"
	"github.com/Sh4wnK/ApexAuth/internal/tokens"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

//go:embed static/*
var staticFS embed.FS

// Server is the HTTP front.
type Server struct {
	store       *store.Store
	cache       *cache.Cache
	tokens      *service.Tokens
	oauth       *service.OAuth
	pw          *service.Passwordless
	signer      *tokens.Signer
	issuer      string
	baseURL     string
	secret      []byte // HMAC secret for pending-auth state cookies
	rateLimit   *cache.Cache
	rateMax     int
	rateWindow  time.Duration
	attemptsMax int
	log         *slog.Logger
	mux         *http.ServeMux
	loginTmpl   *template.Template
	consentTmpl *template.Template
	doneTmpl    *template.Template
}

// Options configures the HTTP server.
type Options struct {
	Store        *store.Store
	Cache        *cache.Cache
	Tokens       *service.Tokens
	OAuth        *service.OAuth
	Passwordless *service.Passwordless
	Signer       *tokens.Signer
	Issuer       string
	BaseURL      string
	HMACSecret   []byte
	RateLimitMax int
	RateWindow   time.Duration
	AttemptsMax  int
	Log          *slog.Logger
}

// New builds the HTTP server and its routes.
func New(o Options) (*Server, error) {
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if len(o.HMACSecret) < 32 {
		return nil, errors.New("httpapi: HMAC secret must be at least 32 bytes")
	}
	s := &Server{
		store:       o.Store,
		cache:       o.Cache,
		tokens:      o.Tokens,
		oauth:       o.OAuth,
		pw:          o.Passwordless,
		signer:      o.Signer,
		issuer:      o.Issuer,
		baseURL:     o.BaseURL,
		secret:      o.HMACSecret,
		rateLimit:   o.Cache,
		rateMax:     o.RateLimitMax,
		rateWindow:  o.RateWindow,
		attemptsMax: o.AttemptsMax,
		log:         o.Log,
	}
	var err error
	if s.loginTmpl, err = template.ParseFS(staticFS, "static/login.html"); err != nil {
		return nil, fmt.Errorf("httpapi: login template: %w", err)
	}
	if s.consentTmpl, err = template.ParseFS(staticFS, "static/consent.html"); err != nil {
		return nil, fmt.Errorf("httpapi: consent template: %w", err)
	}
	if s.doneTmpl, err = template.ParseFS(staticFS, "static/done.html"); err != nil {
		return nil, fmt.Errorf("httpapi: done template: %w", err)
	}
	s.routes()
	return s, nil
}

// Handler returns the root handler.
func (s *Server) Handler() http.Handler { return s.mux }

func (s *Server) routes() {
	m := http.NewServeMux()

	// Health + discovery
	m.HandleFunc("GET /healthz", s.handleHealth)
	m.HandleFunc("GET /.well-known/openid-configuration", s.handleOpenIDConfig)
	m.HandleFunc("GET /.well-known/jwks.json", s.handleJWKS)

	// OAuth authorization server
	m.HandleFunc("GET /oauth2/authorize", s.handleAuthorize)
	m.HandleFunc("POST /oauth2/consent", s.handleConsent)
	m.HandleFunc("POST /oauth2/token", s.handleToken)
	m.HandleFunc("POST /oauth2/revoke", s.handleRevoke)
	m.HandleFunc("POST /oauth2/introspect", s.handleIntrospect)
	m.HandleFunc("GET /oauth2/userinfo", s.handleUserinfo)

	// First-party auth
	m.HandleFunc("GET /login", s.handleLoginPage)
	m.HandleFunc("POST /login", s.handleLogin)
	m.HandleFunc("POST /api/v1/login", s.handleLoginJSON)
	m.HandleFunc("POST /api/v1/logout", s.handleLogout)
	m.HandleFunc("GET /auth/magic", s.handleMagicGet)
	m.HandleFunc("POST /auth/magic", s.handleMagicSend)
	m.HandleFunc("GET /auth/otp", s.handleOTPPage)
	m.HandleFunc("POST /auth/otp", s.handleOTPVerify)
	m.HandleFunc("POST /api/v1/refresh", s.handleRefreshJSON)

	// Admin REST (RBAC-protected)
	m.Handle("GET /api/v1/admin/users", s.requirePerm("users:read", s.handleAdminUsers))
	m.Handle("GET /api/v1/admin/users/{id}", s.requirePerm("users:read", s.handleAdminUser))
	m.Handle("POST /api/v1/admin/users", s.requirePerm("users:write", s.handleAdminCreateUser))
	m.Handle("PATCH /api/v1/admin/users/{id}", s.requirePerm("users:write", s.handleAdminUpdateUser))
	m.Handle("POST /api/v1/admin/users/{id}/roles", s.requirePerm("roles:write", s.handleAdminAssignRole))
	m.Handle("DELETE /api/v1/admin/users/{id}/roles/{role}", s.requirePerm("roles:write", s.handleAdminRevokeRole))
	m.Handle("GET /api/v1/admin/users/{id}/roles", s.requirePerm("roles:read", s.handleAdminUserRoles))
	m.Handle("POST /api/v1/admin/users/{id}/revoke", s.requirePerm("sessions:write", s.handleAdminRevokeUser))
	m.Handle("GET /api/v1/admin/roles", s.requirePerm("roles:read", s.handleAdminRoles))
	m.Handle("POST /api/v1/admin/roles", s.requirePerm("roles:write", s.handleAdminCreateRole))
	m.Handle("POST /api/v1/admin/roles/{role}/permissions", s.requirePerm("roles:write", s.handleAdminGrantPerm))
	m.Handle("DELETE /api/v1/admin/roles/{role}/permissions", s.requirePerm("roles:write", s.handleAdminRevokePerm))
	m.Handle("GET /api/v1/admin/audit", s.requirePerm("audit:read", s.handleAdminAudit))
	m.Handle("GET /api/v1/admin/clients", s.requirePerm("clients:read", s.handleAdminClients))
	m.Handle("POST /api/v1/admin/clients", s.requirePerm("clients:write", s.handleAdminCreateClient))

	s.mux = m
}

// ---------------------------------------------------------------------------
// helpers

func (s *Server) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) writeErr(w http.ResponseWriter, status int, msg string) {
	s.writeJSON(w, status, map[string]string{"error": msg})
}

func (s *Server) oauthError(w http.ResponseWriter, err error, redirectURI, state string, logCtx string) {
	s.log.Warn("oauth error", "endpoint", logCtx, "error", err.Error())
	code := "invalid_request"
	switch {
	case errors.Is(err, service.ErrInvalidClient):
		code = "invalid_client"
	case errors.Is(err, service.ErrInvalidGrant):
		code = "invalid_grant"
	case errors.Is(err, service.ErrUnauthorizedClient):
		code = "unauthorized_client"
	case errors.Is(err, service.ErrAccessDenied):
		code = "access_denied"
	}
	if redirectURI == "" {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{"error": code, "error_description": err.Error()})
		return
	}
	u, uerr := url.Parse(redirectURI)
	if uerr != nil {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{"error": code})
		return
	}
	q := u.Query()
	q.Set("error", code)
	q.Set("error_description", err.Error())
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, redirectReq(), u.String(), http.StatusFound)
}

// redirectReq builds a minimal request object for http.Redirect.
func redirectReq() *http.Request {
	return httptest.NewRequest(http.MethodGet, "/", nil)
}

// ---------------------------------------------------------------------------
// health & discovery

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	dbOK := s.store.Ping(ctx) == nil
	cacheOK := true
	if s.cache.Enabled() {
		cacheOK = s.cache.Ping(ctx) == nil
	}
	status := http.StatusOK
	if !dbOK || !cacheOK {
		status = http.StatusServiceUnavailable
	}
	s.writeJSON(w, status, map[string]any{
		"status": map[bool]string{true: "ok", false: "degraded"}[dbOK && cacheOK],
		"db":     map[bool]string{true: "ok", false: "down"}[dbOK],
		"redis":  map[bool]string{true: "ok", false: "disabled/down"}[cacheOK],
	})
}

func (s *Server) handleOpenIDConfig(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                s.issuer,
		"authorization_endpoint":                s.issuer + "/oauth2/authorize",
		"token_endpoint":                        s.issuer + "/oauth2/token",
		"userinfo_endpoint":                     s.issuer + "/oauth2/userinfo",
		"jwks_uri":                              s.issuer + "/.well-known/jwks.json",
		"revocation_endpoint":                   s.issuer + "/oauth2/revoke",
		"introspection_endpoint":                s.issuer + "/oauth2/introspect",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token", "client_credentials"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{s.signer.ActiveAlg()},
		"code_challenge_methods_supported":      []string{"S256"},
		"scopes_supported":                      []string{"openid", "profile", "email", "billing:read", "billing:write", "users:read"},
		"claims_supported":                      []string{"sub", "email", "name", "roles", "permissions"},
	})
}

func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(s.signer.JWKS())
}

// ---------------------------------------------------------------------------
// rate limiting & login attempts

func (s *Server) rateLimitKey(r *http.Request, bucket string) string {
	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx >= 0 {
		ip = ip[:idx]
	}
	return bucket + ":" + ip + ":" + emailFrom(r)
}

func emailFrom(r *http.Request) string {
	if r.Method == http.MethodPost {
		if v := r.PostFormValue("email"); v != "" {
			return strings.ToLower(v)
		}
	}
	return "unknown"
}

// limited returns true when the request is over the login/otp budget.
func (s *Server) limited(w http.ResponseWriter, r *http.Request, bucket string) bool {
	allowed, _, err := s.cache.Allow(r.Context(), bucket, s.rateLimitKey(r, bucket), s.rateMax, s.rateWindow)
	if err != nil || !allowed {
		s.writeErr(w, http.StatusTooManyRequests, "rate limit exceeded; try again later")
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// first-party login (browser + JSON)

type loginFormData struct {
	ClientID            string
	RedirectURI         string
	ResponseType        string
	State               string
	Nonce               string
	Scope               string
	CodeChallenge       string
	CodeChallengeMethod string
	ClientName          string
	Error               string
	Query               string
}

func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	data := loginFormData{
		ClientID: r.URL.Query().Get("client_id"), RedirectURI: r.URL.Query().Get("redirect_uri"),
		ResponseType: r.URL.Query().Get("response_type"), State: r.URL.Query().Get("state"),
		Nonce: r.URL.Query().Get("nonce"), Scope: r.URL.Query().Get("scope"),
		CodeChallenge: r.URL.Query().Get("code_challenge"), CodeChallengeMethod: r.URL.Query().Get("code_challenge_method"),
		Query: r.URL.RawQuery,
	}
	if data.ClientID != "" {
		if c, err := s.store.GetOAuthClient(r.Context(), data.ClientID); err == nil {
			data.ClientName = c.Name
		} else {
			data.ClientName = data.ClientID
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = s.loginTmpl.Execute(w, data)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.writeErr(w, http.StatusBadRequest, "bad form")
		return
	}
	if s.limited(w, r, "login") {
		return
	}
	email := strings.TrimSpace(r.FormValue("email"))
	password := r.FormValue("password")
	oauthParams := r.FormValue("client_id") != ""

	if oauthParams {
		// Validate the authorize request first: failures redirect back with
		// an OAuth error, never a generic page.
		req := service.AuthRequest{
			ClientID: r.FormValue("client_id"), RedirectURI: r.FormValue("redirect_uri"),
			ResponseType: r.FormValue("response_type"), State: r.FormValue("state"),
			Nonce: r.FormValue("nonce"), Scopes: splitScopes(r.FormValue("scope")),
			CodeChallenge: r.FormValue("code_challenge"), CodeChallengeMethod: r.FormValue("code_challenge_method"),
		}
		if _, err := s.oauth.ValidateAuthorizeRequest(r.Context(), req); err != nil {
			s.oauthError(w, err, "", "", "authorize")
			return
		}
	}

	res, err := s.tokens.PasswordLogin(r.Context(), email, password)
	if err != nil {
		_ = s.store.Audit(r.Context(), store.AuditEntry{Action: "login_failed", TargetType: "user", TargetID: email, IP: r.RemoteAddr, Metadata: map[string]any{"method": "password"}})
		if oauthParams {
			s.oauthError(w, service.ErrAccessDenied, r.FormValue("redirect_uri"), r.FormValue("state"), "login")
			return
		}
		// browser form: re-render with error
		data := loginFormData{
			ClientID: r.FormValue("client_id"), RedirectURI: r.FormValue("redirect_uri"),
			ResponseType: r.FormValue("response_type"), State: r.FormValue("state"),
			Nonce: r.FormValue("nonce"), Scope: r.FormValue("scope"),
			CodeChallenge: r.FormValue("code_challenge"), CodeChallengeMethod: r.FormValue("code_challenge_method"),
			Error: "Invalid email or password.",
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		_ = s.loginTmpl.Execute(w, data)
		return
	}
	s.setBrowserUser(w, res.User.ID)
	s.finishLogin(w, r, res, r.FormValue("client_id"), r.FormValue("redirect_uri"), r.FormValue("state"), r.FormValue("nonce"), r.FormValue("scope"), r.FormValue("code_challenge"), r.FormValue("code_challenge_method"), false)
}

func (s *Server) handleLoginJSON(w http.ResponseWriter, r *http.Request) {
	if s.limited(w, r, "login") {
		return
	}
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	res, err := s.tokens.PasswordLogin(r.Context(), strings.TrimSpace(req.Email), req.Password)
	if err != nil {
		_ = s.store.Audit(r.Context(), store.AuditEntry{Action: "login_failed", TargetType: "user", TargetID: req.Email, IP: r.RemoteAddr, Metadata: map[string]any{"method": "password"}})
		s.writeErr(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	_ = s.store.Audit(r.Context(), store.AuditEntry{ActorID: res.User.ID, Action: "login", TargetType: "user", TargetID: res.User.ID, IP: r.RemoteAddr, UserAgent: r.UserAgent(), Metadata: map[string]any{"method": "password"}})
	s.writeJSON(w, http.StatusOK, tokenResponse(res))
}

func (s *Server) finishLogin(w http.ResponseWriter, r *http.Request, res service.TokenResult, clientID, redirectURI, state, nonce, scope, challenge, method string, fromConsent bool) {
	_ = s.store.Audit(r.Context(), store.AuditEntry{ActorID: res.User.ID, Action: "login", TargetType: "user", TargetID: res.User.ID, IP: r.RemoteAddr, UserAgent: r.UserAgent(), Metadata: map[string]any{"method": "password"}})

	if clientID == "" {
		// Console login: show the token (demo done page).
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_ = s.doneTmpl.Execute(w, map[string]string{"Email": res.User.Email, "Token": res.AccessToken})
		return
	}
	req := service.AuthRequest{
		ClientID: clientID, RedirectURI: redirectURI, ResponseType: "code", State: state, Nonce: nonce,
		Scopes: splitScopes(scope), CodeChallenge: challenge, CodeChallengeMethod: method,
	}
	if _, err := s.oauth.ValidateAuthorizeRequest(r.Context(), req); err != nil {
		s.oauthError(w, err, redirectURI, state, "finish-login")
		return
	}
	// If the user already consented to these scopes, skip the consent page.
	ok, err := s.store.HasConsent(r.Context(), res.User.ID, req.ClientID, req.Scopes)
	if err != nil || !ok {
		s.renderConsent(w, r, res.User.Email, req)
		return
	}
	s.issueCodeFor(w, r, res.User, req)
}

func (s *Server) renderConsent(w http.ResponseWriter, r *http.Request, email string, req service.AuthRequest) {
	data := map[string]any{
		"ClientID": req.ClientID, "RedirectURI": req.RedirectURI, "ResponseType": req.ResponseType,
		"State": req.State, "Nonce": req.Nonce, "Scope": strings.Join(req.Scopes, " "),
		"CodeChallenge": req.CodeChallenge, "CodeChallengeMethod": req.CodeChallengeMethod,
		"UserEmail": email, "Scopes": req.Scopes,
		"ClientName": req.ClientID,
	}
	if c, err := s.store.GetOAuthClient(r.Context(), req.ClientID); err == nil {
		data["ClientName"] = c.Name
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = s.consentTmpl.Execute(w, data)
}

func (s *Server) handleConsent(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.writeErr(w, http.StatusBadRequest, "bad form")
		return
	}
	decision := r.FormValue("decision")
	req := service.AuthRequest{
		ClientID: r.FormValue("client_id"), RedirectURI: r.FormValue("redirect_uri"),
		ResponseType: r.FormValue("response_type"), State: r.FormValue("state"),
		Nonce: r.FormValue("nonce"), Scopes: splitScopes(r.FormValue("scope")),
		CodeChallenge: r.FormValue("code_challenge"), CodeChallengeMethod: r.FormValue("code_challenge_method"),
	}
	if _, err := s.oauth.ValidateAuthorizeRequest(r.Context(), req); err != nil {
		s.oauthError(w, err, req.RedirectURI, req.State, "consent")
		return
	}
	// The consent page must come from a login; we re-validate with the
	// browser cookie that the login handler set.
	uid, ok := s.browserUser(r)
	if !ok {
		s.oauthError(w, service.ErrAccessDenied, req.RedirectURI, req.State, "consent")
		return
	}
	u, err := s.store.GetUserByID(r.Context(), uid)
	if err != nil {
		s.oauthError(w, service.ErrAccessDenied, req.RedirectURI, req.State, "consent")
		return
	}
	if decision != "allow" {
		s.oauthError(w, service.ErrAccessDenied, req.RedirectURI, req.State, "consent")
		return
	}
	_ = s.store.RecordConsent(r.Context(), u.ID, req.ClientID, req.Scopes)
	s.issueCodeFor(w, r, u, req)
}

// issueCodeFor issues the one-time authorization code and redirects.
func (s *Server) issueCodeFor(w http.ResponseWriter, r *http.Request, u store.User, req service.AuthRequest) {
	code, err := s.oauth.IssueCode(r.Context(), u, req.ClientID, req.RedirectURI, req.Nonce, req.CodeChallenge, req.CodeChallengeMethod, req.Scopes)
	if err != nil {
		s.oauthError(w, err, req.RedirectURI, req.State, "issue-code")
		return
	}
	_ = s.store.Audit(r.Context(), store.AuditEntry{ActorID: u.ID, Action: "oauth_code_issued", TargetType: "client", TargetID: req.ClientID, IP: r.RemoteAddr, Metadata: map[string]any{"scopes": req.Scopes}})
	loc, err := url.Parse(req.RedirectURI)
	if err != nil {
		s.oauthError(w, err, "", "", "issue-code")
		return
	}
	q := loc.Query()
	q.Set("code", code)
	if req.State != "" {
		q.Set("state", req.State)
	}
	loc.RawQuery = q.Encode()
	http.Redirect(w, r, loc.String(), http.StatusFound)
}

func (s *Server) browserUser(r *http.Request) (string, bool) {
	c, err := r.Cookie("apexauth_browser")
	if err != nil {
		return "", false
	}
	raw, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return "", false
	}
	if len(raw) < 33 {
		return "", false
	}
	mac, payload := raw[:32], raw[32:]
	expected := s.signBytes(payload)
	if hmac.Equal(expected, mac) {
		return string(payload), true
	}
	return "", false
}

func (s *Server) setBrowserUser(w http.ResponseWriter, uid string) {
	payload := []byte(uid)
	mac := s.signBytes(payload)
	v := base64.RawURLEncoding.EncodeToString(append(mac, payload...))
	http.SetCookie(w, &http.Cookie{
		Name: "apexauth_browser", Value: v, Path: "/", MaxAge: 900,
		HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: strings.HasPrefix(s.issuer, "https://"),
	})
}

func (s *Server) signBytes(b []byte) []byte {
	m := hmac.New(sha256.New, s.secret)
	m.Write(b)
	return m.Sum(nil)
}

func (s *Server) clearBrowserUser(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: "apexauth_browser", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode})
}

// ---------------------------------------------------------------------------
// passwordless

func (s *Server) handleMagicGet(w http.ResponseWriter, r *http.Request) {
	tok := r.URL.Query().Get("token")
	if tok == "" {
		// Show the email form (keeps OAuth params for the callback).
		data := loginFormData{Query: r.URL.RawQuery, ClientName: "ApexAuth"}
		data.ClientID = r.URL.Query().Get("client_id")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_ = s.loginTmpl.Execute(w, data)
		return
	}
	u, err := s.pw.ConsumeMagicLink(r.Context(), tok)
	if err != nil {
		s.oauthError(w, service.ErrAccessDenied, "", "", "magic")
		return
	}
	res, err := s.tokens.PasswordlessLogin(r.Context(), u.ID, "", nil, "")
	if err != nil {
		s.oauthError(w, service.ErrAccessDenied, "", "", "magic")
		return
	}
	// The magic link carries the originating OAuth params (encoded state).
	state := r.URL.Query().Get("state")
	if state != "" {
		if params, ok := decodeState(state); ok && params.Get("client_id") != "" {
			s.handleAuthorizeAfterLogin(w, r, res, params)
			return
		}
	}
	_ = s.store.Audit(r.Context(), store.AuditEntry{ActorID: u.ID, Action: "login", TargetType: "user", TargetID: u.ID, IP: r.RemoteAddr, UserAgent: r.UserAgent(), Metadata: map[string]any{"method": "magic_link"}})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = s.doneTmpl.Execute(w, map[string]string{"Email": res.User.Email, "Token": res.AccessToken})
}

// handleAuthorizeAfterLogin resumes an authorize flow once the user is
// authenticated via passwordless.
func (s *Server) handleAuthorizeAfterLogin(w http.ResponseWriter, r *http.Request, res service.TokenResult, params url.Values) {
	req := service.AuthRequest{
		ClientID: params.Get("client_id"), RedirectURI: params.Get("redirect_uri"),
		ResponseType: params.Get("response_type"), State: params.Get("state"),
		Nonce: params.Get("nonce"), Scopes: splitScopes(params.Get("scope")),
		CodeChallenge: params.Get("code_challenge"), CodeChallengeMethod: params.Get("code_challenge_method"),
	}
	if _, err := s.oauth.ValidateAuthorizeRequest(r.Context(), req); err != nil {
		s.oauthError(w, err, req.RedirectURI, req.State, "passwordless-resume")
		return
	}
	ok, err := s.store.HasConsent(r.Context(), res.User.ID, req.ClientID, req.Scopes)
	if err != nil || !ok {
		s.renderConsent(w, r, res.User.Email, req)
		return
	}
	s.issueCodeFor(w, r, res.User, req)
}

func (s *Server) handleMagicSend(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.writeErr(w, http.StatusBadRequest, "bad form")
		return
	}
	if s.limited(w, r, "magic") {
		return
	}
	email := strings.TrimSpace(r.FormValue("email"))
	if email == "" {
		s.writeErr(w, http.StatusBadRequest, "email required")
		return
	}
	// Preserve the OAuth authorize params so the emailed link can resume.
	var stateParam string
	if r.FormValue("client_id") != "" {
		v := url.Values{}
		for _, k := range []string{"client_id", "redirect_uri", "response_type", "state", "nonce", "scope", "code_challenge", "code_challenge_method"} {
			if val := r.FormValue(k); val != "" {
				v.Set(k, val)
			}
		}
		stateParam = encodeState(v)
	}
	link := s.issuer + "/auth/magic?token="
	_ = s.pw.SendMagicLink(r.Context(), email, link, stateParam)
	s.showPasswordlessSent(w, "If that email has an account, a magic link is on its way.")
}

func (s *Server) handleOTPPage(w http.ResponseWriter, r *http.Request) {
	data := loginFormData{Query: r.URL.RawQuery, ClientName: "ApexAuth"}
	data.ClientID = r.URL.Query().Get("client_id")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	data.Error = "enter your email to receive a code"
	_ = s.loginTmpl.Execute(w, data)
}

func (s *Server) handleOTPVerify(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.writeErr(w, http.StatusBadRequest, "bad form")
		return
	}
	if s.limited(w, r, "otp") {
		return
	}
	email := strings.TrimSpace(r.FormValue("email"))
	code := strings.TrimSpace(r.FormValue("code"))
	if code == "" {
		if _, err := s.pw.SendOTP(r.Context(), email); err != nil {
			s.writeErr(w, http.StatusInternalServerError, "could not send code")
			return
		}
		s.showPasswordlessSent(w, "If that email has an account, a code is on its way.")
		return
	}
	u, err := s.pw.ConsumeOTP(r.Context(), code)
	if err != nil {
		data := loginFormData{Query: r.URL.RawQuery, ClientName: "ApexAuth", Error: "Invalid or expired code."}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		_ = s.loginTmpl.Execute(w, data)
		return
	}
	res, err := s.tokens.PasswordlessLogin(r.Context(), u.ID, "", nil, "")
	if err != nil {
		s.writeErr(w, http.StatusUnauthorized, "login failed")
		return
	}
	if params, ok := s.pendingOAuthParams(r); ok {
		s.handleAuthorizeAfterLogin(w, r, res, params)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = s.doneTmpl.Execute(w, map[string]string{"Email": res.User.Email, "Token": res.AccessToken})
}

func (s *Server) pendingOAuthParams(r *http.Request) (url.Values, bool) {
	if raw := r.FormValue("state"); raw != "" {
		if v, ok := decodeState(raw); ok {
			return v, true
		}
	}
	return nil, false
}

func (s *Server) showPasswordlessSent(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, "<!DOCTYPE html><html><body style='font-family:sans-serif;background:#0f1115;color:#e6e8eb;display:flex;align-items:center;justify-content:center;height:100vh'><div style='max-width:420px;text-align:center'><h1>ApexAuth</h1><p>%s</p></div></body></html>", msg)
}

// ---------------------------------------------------------------------------
// OAuth token, revoke, introspect, userinfo

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	grant := r.FormValue("grant_type")
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")

	// Clients may authenticate via Basic auth; prefer form when present.
	if clientID == "" {
		if id, secret, ok := r.BasicAuth(); ok {
			clientID, clientSecret = id, secret
		}
	}
	if clientID == "" {
		s.writeErr(w, http.StatusUnauthorized, "client credentials required")
		return
	}

	switch grant {
	case "authorization_code":
		code := r.FormValue("code")
		verifier := r.FormValue("code_verifier")
		redirectURI := r.FormValue("redirect_uri")
		if code == "" {
			s.writeErr(w, http.StatusBadRequest, "invalid_grant: missing code")
			return
		}
		res, err := s.oauth.ExchangeCode(r.Context(), clientID, clientSecret, code, verifier, redirectURI)
		if err != nil {
			s.writeOAuthTokenError(w, err)
			return
		}
		s.writeJSON(w, http.StatusOK, tokenResponse(res))
	case "refresh_token":
		ref := r.FormValue("refresh_token")
		if ref == "" {
			s.writeErr(w, http.StatusBadRequest, "invalid_grant: missing refresh_token")
			return
		}
		scopes := splitScopes(r.FormValue("scope"))
		res, err := s.oauth.ExchangeRefresh(r.Context(), clientID, clientSecret, ref, scopes, "")
		if err != nil {
			s.writeOAuthTokenError(w, err)
			return
		}
		s.writeJSON(w, http.StatusOK, tokenResponse(res))
	case "client_credentials":
		scopes := splitScopes(r.FormValue("scope"))
		res, err := s.oauth.ExchangeClientCredentials(r.Context(), clientID, clientSecret, scopes)
		if err != nil {
			s.writeOAuthTokenError(w, err)
			return
		}
		s.writeJSON(w, http.StatusOK, tokenResponse(res))
	default:
		s.writeErr(w, http.StatusBadRequest, "unsupported_grant_type")
	}
}

func (s *Server) writeOAuthTokenError(w http.ResponseWriter, err error) {
	code := "invalid_request"
	status := http.StatusBadRequest
	switch {
	case errors.Is(err, service.ErrInvalidClient):
		code, status = "invalid_client", http.StatusUnauthorized
	case errors.Is(err, service.ErrInvalidGrant):
		code, status = "invalid_grant", http.StatusBadRequest
	case errors.Is(err, service.ErrUnauthorizedClient):
		code, status = "unauthorized_client", http.StatusForbidden
	}
	s.writeJSON(w, status, map[string]string{"error": code, "error_description": err.Error()})
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")
	if clientID == "" {
		if id, secret, ok := r.BasicAuth(); ok {
			clientID, clientSecret = id, secret
		}
	}
	if clientID == "" {
		s.writeErr(w, http.StatusUnauthorized, "client credentials required")
		return
	}
	tok := r.FormValue("token")
	if tok == "" {
		s.writeErr(w, http.StatusBadRequest, "invalid_request: missing token")
		return
	}
	if err := s.oauth.Revoke(r.Context(), clientID, clientSecret, tok); err != nil {
		s.writeOAuthTokenError(w, err)
		return
	}
	// RFC 7009: 200 with empty body.
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")
	if clientID == "" {
		if id, secret, ok := r.BasicAuth(); ok {
			clientID, clientSecret = id, secret
		}
	}
	if clientID == "" {
		s.writeErr(w, http.StatusUnauthorized, "client credentials required")
		return
	}
	if _, err := s.oauth.AuthenticateClient(r.Context(), clientID, clientSecret); err != nil {
		s.writeErr(w, http.StatusUnauthorized, "invalid client")
		return
	}
	tok := r.FormValue("token")
	if tok == "" {
		s.writeErr(w, http.StatusBadRequest, "invalid_request: missing token")
		return
	}
	s.writeJSON(w, http.StatusOK, s.oauth.Introspect(r.Context(), tok))
}

func (s *Server) handleUserinfo(w http.ResponseWriter, r *http.Request) {
	raw := bearerToken(r)
	if raw == "" {
		s.writeErr(w, http.StatusUnauthorized, "missing bearer token")
		return
	}
	claims, err := s.tokens.VerifyTokenOnly(r.Context(), raw)
	if err != nil {
		s.writeErr(w, http.StatusUnauthorized, "invalid token")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"sub":            claims.UserID,
		"email":          claims.Email,
		"name":           claims.Name,
		"email_verified": true,
		"roles":          claims.Roles,
		"permissions":    claims.Permissions,
	})
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "Bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

func tokenResponse(res service.TokenResult) map[string]any {
	out := map[string]any{
		"access_token": res.AccessToken,
		"token_type":   res.TokenType,
		"expires_in":   res.ExpiresIn,
	}
	if res.RefreshToken != "" {
		out["refresh_token"] = res.RefreshToken
	}
	if res.IDToken != "" {
		out["id_token"] = res.IDToken
	}
	if res.Scope != "" {
		out["scope"] = res.Scope
	}
	return out
}

// ---------------------------------------------------------------------------
// first-party refresh/logout JSON APIs

func (s *Server) handleRefreshJSON(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	res, err := s.tokens.Refresh(r.Context(), req.RefreshToken, "", nil, "")
	if err != nil {
		if errors.Is(err, store.ErrReuseDetected) {
			s.writeErr(w, http.StatusUnauthorized, "refresh token reused; family revoked")
			return
		}
		s.writeErr(w, http.StatusUnauthorized, "invalid refresh token")
		return
	}
	s.writeJSON(w, http.StatusOK, tokenResponse(res))
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	raw := bearerToken(r)
	var refresh string
	if r.Method == http.MethodPost {
		_ = r.ParseForm()
		refresh = r.FormValue("refresh_token")
		_ = json.NewDecoder(r.Body).Decode(&struct{ RefreshToken *string }{})
	}
	var jti, sid string
	if raw != "" {
		if claims, err := s.tokens.VerifyTokenOnly(r.Context(), raw); err == nil {
			jti, sid = claims.ID, claims.SessionID
		}
	}
	_ = s.tokens.Logout(r.Context(), sid, jti, refresh)
	s.clearBrowserUser(w)
	s.writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ---------------------------------------------------------------------------
// OAuth authorize entry

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	req := service.AuthRequest{
		ClientID: q.Get("client_id"), RedirectURI: q.Get("redirect_uri"),
		ResponseType: q.Get("response_type"), State: q.Get("state"),
		Nonce: q.Get("nonce"), Scopes: splitScopes(q.Get("scope")),
		CodeChallenge: q.Get("code_challenge"), CodeChallengeMethod: q.Get("code_challenge_method"),
		Prompt: q.Get("prompt"),
	}
	if req.ResponseType == "" {
		req.ResponseType = "code"
	}
	if _, err := s.oauth.ValidateAuthorizeRequest(r.Context(), req); err != nil {
		s.oauthError(w, err, req.RedirectURI, req.State, "authorize")
		return
	}
	// Not logged in (no browser cookie): show login with params embedded.
	uid, ok := s.browserUser(r)
	if !ok || req.Prompt == "login" {
		data := loginFormData{
			ClientID: req.ClientID, RedirectURI: req.RedirectURI, ResponseType: req.ResponseType,
			State: req.State, Nonce: req.Nonce, Scope: strings.Join(req.Scopes, " "),
			CodeChallenge: req.CodeChallenge, CodeChallengeMethod: req.CodeChallengeMethod,
			Query: r.URL.RawQuery,
		}
		if c, err := s.store.GetOAuthClient(r.Context(), req.ClientID); err == nil {
			data.ClientName = c.Name
		} else {
			data.ClientName = req.ClientID
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_ = s.loginTmpl.Execute(w, data)
		return
	}
	if req.Prompt == "none" && !ok {
		// silent auth request: redirect with login_required
		u2, _ := url.Parse(req.RedirectURI)
		qq := u2.Query()
		qq.Set("error", "login_required")
		if req.State != "" {
			qq.Set("state", req.State)
		}
		u2.RawQuery = qq.Encode()
		http.Redirect(w, r, u2.String(), http.StatusFound)
		return
	}
	u, err := s.store.GetUserByID(r.Context(), uid)
	if err != nil {
		s.oauthError(w, service.ErrAccessDenied, req.RedirectURI, req.State, "authorize")
		return
	}
	ok, err = s.store.HasConsent(r.Context(), u.ID, req.ClientID, req.Scopes)
	if err != nil || !ok {
		s.renderConsent(w, r, u.Email, req)
		return
	}
	s.issueCodeFor(w, r, u, req)
}

// ---------------------------------------------------------------------------
// encode/decode of pending OAuth state carried through magic links

func encodeState(v url.Values) string {
	return base64.RawURLEncoding.EncodeToString([]byte(v.Encode()))
}

func decodeState(s string) (url.Values, bool) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, false
	}
	v, err := url.ParseQuery(string(b))
	if err != nil {
		return nil, false
	}
	return v, true
}

func splitScopes(s string) []string {
	var out []string
	for _, p := range strings.Fields(s) {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// admin endpoints

type contextKey string

const principalKey contextKey = "principal"

const ctxUserKey contextKey = "principal"

func userIDfrom(r *http.Request) string {
	v, _ := r.Context().Value(ctxUserKey).(string)
	return v
}

// requirePerm guards a handler with bearer-token authentication and an
// RBAC permission check.
func (s *Server) requirePerm(perm string, h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := bearerToken(r)
		if raw == "" {
			s.writeErr(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		claims, err := s.tokens.VerifyAccess(r.Context(), raw)
		if err != nil {
			s.writeErr(w, http.StatusUnauthorized, "invalid token")
			return
		}
		if claims.UserID == "" {
			s.writeErr(w, http.StatusForbidden, "user tokens only")
			return
		}
		allowed, err := s.tokens.CheckPermission(r.Context(), claims.UserID, perm)
		if err != nil || !allowed {
			s.writeErr(w, http.StatusForbidden, "insufficient permissions")
			return
		}
		h(w, r.WithContext(context.WithValue(r.Context(), ctxUserKey, claims.UserID)))
	})
}

func (s *Server) handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	users, total, err := s.store.ListUsers(r.Context(), limit, offset)
	if err != nil {
		s.writeErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"users": users, "total": total, "limit": limit, "offset": offset})
}

func (s *Server) handleAdminUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	u, err := s.store.GetUserByID(r.Context(), id)
	if err != nil {
		s.writeErr(w, http.StatusNotFound, "user not found")
		return
	}
	roles, _ := s.store.ListRoles(r.Context(), u.ID)
	perms, _ := s.store.ListPermissions(r.Context(), u.ID)
	s.writeJSON(w, http.StatusOK, map[string]any{"user": u, "roles": roles, "permissions": perms})
}

func (s *Server) handleAdminCreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email         string   `json:"email"`
		Name          string   `json:"name"`
		Password      string   `json:"password"`
		EmailVerified bool     `json:"email_verified"`
		Roles         []string `json:"roles"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	u, err := s.store.CreateUser(r.Context(), strings.TrimSpace(req.Email), req.Name, req.EmailVerified)
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			s.writeErr(w, http.StatusConflict, "email already exists")
			return
		}
		s.writeErr(w, http.StatusInternalServerError, "create failed")
		return
	}
	if req.Password != "" {
		phc, err := hashPassword(req.Password)
		if err != nil {
			s.writeErr(w, http.StatusInternalServerError, "hash failed")
			return
		}
		_ = s.store.SetPassword(r.Context(), u.ID, phc)
	}
	for _, role := range req.Roles {
		_ = s.store.AssignRole(r.Context(), u.ID, role)
	}
	if len(req.Roles) > 0 {
		_ = s.cache.InvalidateUser(r.Context(), u.ID)
	}
	s.writeJSON(w, http.StatusCreated, u)
}

func (s *Server) handleAdminUpdateUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req struct {
		Active        *bool  `json:"active"`
		EmailVerified *bool  `json:"email_verified"`
		Name          string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	u, err := s.store.GetUserByID(r.Context(), id)
	if err != nil {
		s.writeErr(w, http.StatusNotFound, "user not found")
		return
	}
	if req.Name != "" {
		u.Name = req.Name
	}
	if req.Active != nil {
		u.Active = *req.Active
		if !u.Active {
			_ = s.tokens.RevokeUser(r.Context(), id)
		}
	}
	if req.EmailVerified != nil {
		u.EmailVerified = *req.EmailVerified
	}
	if err := s.store.UpdateUser(r.Context(), u); err != nil {
		s.writeErr(w, http.StatusInternalServerError, "update failed")
		return
	}
	_ = s.cache.InvalidateUser(r.Context(), id)
	s.writeJSON(w, http.StatusOK, u)
}

func (s *Server) handleAdminAssignRole(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req struct {
		Role string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if err := s.store.AssignRole(r.Context(), id, req.Role); err != nil {
		s.writeErr(w, http.StatusBadRequest, "assign failed")
		return
	}
	_ = s.cache.InvalidateUser(r.Context(), id)
	s.writeJSON(w, http.StatusOK, map[string]bool{"assigned": true})
}

func (s *Server) handleAdminRevokeRole(w http.ResponseWriter, r *http.Request) {
	if err := s.store.RevokeRole(r.Context(), r.PathValue("id"), r.PathValue("role")); err != nil {
		s.writeErr(w, http.StatusBadRequest, "revoke failed")
		return
	}
	_ = s.cache.InvalidateUser(r.Context(), r.PathValue("id"))
	s.writeJSON(w, http.StatusOK, map[string]bool{"revoked": true})
}

func (s *Server) handleAdminUserRoles(w http.ResponseWriter, r *http.Request) {
	roles, err := s.store.ListRoles(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeErr(w, http.StatusNotFound, "user not found")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"roles": roles})
}

func (s *Server) handleAdminRevokeUser(w http.ResponseWriter, r *http.Request) {
	if err := s.tokens.RevokeUser(r.Context(), r.PathValue("id")); err != nil {
		s.writeErr(w, http.StatusInternalServerError, "revoke failed")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleAdminRoles(w http.ResponseWriter, r *http.Request) {
	roles, err := s.store.AllRoles(r.Context())
	if err != nil {
		s.writeErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"roles": roles})
}

func (s *Server) handleAdminCreateRole(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Permissions []string `json:"permissions"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.Name == "" || strings.Contains(req.Name, " ") {
		s.writeErr(w, http.StatusBadRequest, "role name required (no spaces)")
		return
	}
	role, err := s.store.EnsureRole(r.Context(), req.Name, req.Description)
	if err != nil {
		s.writeErr(w, http.StatusInternalServerError, "create failed")
		return
	}
	for _, p := range req.Permissions {
		_ = s.store.GrantRolePermission(r.Context(), req.Name, p)
	}
	role.Permissions = req.Permissions
	// Invalidate all users carrying this role (they are cached per-user,
	// so sprinkle via warm cache eviction marker).
	_ = s.cache.TouchRoleVersion(r.Context(), req.Name)
	s.writeJSON(w, http.StatusCreated, role)
}

func (s *Server) handleAdminGrantPerm(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Permission string `json:"permission"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if err := s.store.GrantRolePermission(r.Context(), r.PathValue("role"), req.Permission); err != nil {
		s.writeErr(w, http.StatusBadRequest, "grant failed")
		return
	}
	_ = s.cache.TouchRoleVersion(r.Context(), r.PathValue("role"))
	s.writeJSON(w, http.StatusOK, map[string]bool{"granted": true})
}

func (s *Server) handleAdminRevokePerm(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Permission string `json:"permission"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if err := s.store.RevokeRolePermission(r.Context(), r.PathValue("role"), req.Permission); err != nil {
		s.writeErr(w, http.StatusBadRequest, "revoke failed")
		return
	}
	_ = s.cache.TouchRoleVersion(r.Context(), r.PathValue("role"))
	s.writeJSON(w, http.StatusOK, map[string]bool{"revoked": true})
}

func (s *Server) handleAdminAudit(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	entries, err := s.store.RecentAudit(r.Context(), "", limit)
	if err != nil {
		s.writeErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"audit": entries})
}

func (s *Server) handleAdminClients(w http.ResponseWriter, r *http.Request) {
	clients, err := s.store.ListOAuthClients(r.Context())
	if err != nil {
		s.writeErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"clients": clients})
}

func (s *Server) handleAdminCreateClient(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ClientID      string   `json:"client_id"`
		ClientSecret  string   `json:"client_secret"`
		Name          string   `json:"name"`
		RedirectURIs  []string `json:"redirect_uris"`
		AllowedScopes []string `json:"allowed_scopes"`
		Confidential  bool     `json:"confidential"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.ClientID == "" || req.Name == "" || len(req.RedirectURIs) == 0 {
		s.writeErr(w, http.StatusBadRequest, "client_id, name and redirect_uris required")
		return
	}
	c, err := s.store.CreateOAuthClient(r.Context(), req.ClientID, req.ClientSecret, req.Name, req.RedirectURIs, req.AllowedScopes, req.Confidential)
	if err != nil {
		s.writeErr(w, http.StatusConflict, "client_id already exists")
		return
	}
	s.writeJSON(w, http.StatusCreated, map[string]string{"id": c.ID, "client_id": c.ClientID, "name": c.Name})
}

// hashPassword is injectable for tests (kept here for the admin user create).
var hashPassword = func(p string) (string, error) { return passwd.Hash(p) }

// ---------------------------------------------------------------------------
// misc

var _ = uuid.NewString
var _ = pgx.ErrNoRows
var _ = sort.Strings

// sortScopes sorts and dedupes (used by response builders).
func sortScopes(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

var _ = subtle.ConstantTimeCompare
var _ = service.ErrRateLimited
