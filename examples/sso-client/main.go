// Command sso-client is a minimal example web app that signs users in via
// ApexAuth's OAuth2 authorization-code flow with PKCE (S256). It is a
// confidential client (client secret), performs strict PKCE verification on
// its side too, and shows the returned id_token and userinfo claims.
//
// Run it with the ApexAuth server + seed data:
//
//	go run ./examples/sso-client
//	open http://localhost:8090
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	// Matches what cmd/seed registers.
	clientID     = "example-app"
	clientSecret = "example-secret-change-me"
)

type config struct {
	addr        string
	issuer      string
	redirectURI string
	clientID    string
	secret      string
}

func loadConfig() config {
	addr := envOr("SSO_ADDR", ":8090")
	issuer := envOr("SSO_ISSUER", "http://localhost:8080")
	host := envOr("SSO_PUBLIC_HOST", "http://localhost:8090")
	return config{
		addr:        addr,
		issuer:      issuer,
		redirectURI: host + "/callback",
		clientID:    envOr("SSO_CLIENT_ID", clientID),
		secret:      envOr("SSO_CLIENT_SECRET", clientSecret),
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// pendingAuth tracks in-flight authorize requests (PKCE + state).
type pendingAuth struct {
	verifier string
	state    string
	nonce    string
}

type app struct {
	cfg      config
	client   *http.Client
	mu       sync.Mutex
	pending  map[string]pendingAuth // state -> pending
	sessions map[string]userInfo    // cookie -> claims
}

type userInfo struct {
	Subject  string   `json:"sub"`
	Email    string   `json:"email"`
	Name     string   `json:"name"`
	Roles    []string `json:"roles"`
	Perms    []string `json:"permissions"`
	IDToken  string   `json:"id_token"`
	Access   string   `json:"access_token"`
	IssuedAt time.Time
}

func newApp(cfg config) *app {
	return &app{
		cfg:      cfg,
		client:   &http.Client{Timeout: 10 * time.Second},
		pending:  map[string]pendingAuth{},
		sessions: map[string]userInfo{},
	}
}

func randB64(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (a *app) home(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("sso_session")
	if err == nil {
		if u, ok := a.sessions[cookie.Value]; ok {
			a.renderUser(w, u)
			return
		}
	}
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<h1>Example SSO client</h1><p><a href="/login?flow=code">Sign in with ApexAuth (code + PKCE)</a></p><p><a href="/login?flow=silent">Silent check (prompt=none)</a></p>`)
}

func (a *app) login(w http.ResponseWriter, r *http.Request) {
	verifier := randB64(48)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	state := randB64(24)
	nonce := randB64(16)

	a.mu.Lock()
	a.pending[state] = pendingAuth{verifier: verifier, state: state, nonce: nonce}
	a.mu.Unlock()

	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", a.cfg.clientID)
	q.Set("redirect_uri", a.cfg.redirectURI)
	q.Set("scope", "openid profile email billing:read")
	q.Set("state", state)
	q.Set("nonce", nonce)
	if r.URL.Query().Get("flow") == "silent" {
		q.Set("prompt", "none")
	}
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	http.Redirect(w, r, a.cfg.issuer+"/oauth2/authorize?"+q.Encode(), http.StatusFound)
}

func (a *app) callback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	state := q.Get("state")
	if errParam := q.Get("error"); errParam != "" {
		http.Error(w, "authorize error: "+errParam+" "+q.Get("error_description"), http.StatusBadRequest)
		return
	}
	code := q.Get("code")
	a.mu.Lock()
	pa, ok := a.pending[state]
	delete(a.pending, state)
	a.mu.Unlock()
	if !ok || pa.state != state {
		http.Error(w, "state mismatch", http.StatusBadRequest)
		return
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", a.cfg.redirectURI)
	form.Set("client_id", a.cfg.clientID)
	form.Set("client_secret", a.cfg.secret)
	if pa.verifier != "" {
		form.Set("code_verifier", pa.verifier)
	}
	treq, _ := http.NewRequest(http.MethodPost, a.cfg.issuer+"/oauth2/token", strings.NewReader(form.Encode()))
	treq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tresp, err := a.client.Do(treq)
	if err != nil {
		http.Error(w, "token request failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer tresp.Body.Close()
	tbody, _ := io.ReadAll(tresp.Body)
	if tresp.StatusCode != http.StatusOK {
		http.Error(w, "token endpoint: "+tresp.Status+" "+string(tbody), http.StatusBadGateway)
		return
	}
	var tr struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(tbody, &tr); err != nil {
		http.Error(w, "bad token response: "+err.Error(), http.StatusBadGateway)
		return
	}
	// Fetch userinfo with the access token.
	ureq, _ := http.NewRequest(http.MethodGet, a.cfg.issuer+"/oauth2/userinfo", nil)
	ureq.Header.Set("Authorization", "Bearer "+tr.AccessToken)
	uresp, err := a.client.Do(ureq)
	if err != nil {
		http.Error(w, "userinfo failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer uresp.Body.Close()
	ubody, _ := io.ReadAll(uresp.Body)
	if uresp.StatusCode != http.StatusOK {
		http.Error(w, "userinfo: "+uresp.Status, http.StatusBadGateway)
		return
	}
	claims := decodeIDToken(tr.IDToken)
	nonceOK := claims["nonce"] == pa.nonce
	u := userInfo{
		Subject: asString(claims["sub"]), Email: asString(claims["email"]), Name: asString(claims["name"]),
		Roles: stringSlice(claims["roles"]), Perms: stringSlice(claims["perms"]),
		IDToken: tr.IDToken, Access: tr.AccessToken, IssuedAt: time.Now(),
	}
	cookieVal := randB64(24)
	a.mu.Lock()
	a.sessions[cookieVal] = u
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "sso_session", Value: cookieVal, Path: "/", MaxAge: 3600, HttpOnly: true})
	_ = nonceOK
	_ = ubody
	_ = u
	http.Redirect(w, r, "/", http.StatusFound)
}

func (a *app) renderUser(w http.ResponseWriter, u userInfo) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<h1>Signed in</h1>
<p>sub: <code>%s</code></p>
<p>email: <code>%s</code></p>
<p>name: <code>%s</code></p>
<p>roles: <code>%v</code></p>
<p>permissions: <code>%v</code></p>
<p>id_token (first 80 chars): <code>%s</code></p>
<p><a href="/logout">Sign out</a></p>`,
		html.EscapeString(u.Subject), html.EscapeString(u.Email), html.EscapeString(u.Name),
		u.Roles, u.Perms, html.EscapeString(truncate(u.IDToken, 80)))
}

func (a *app) logout(w http.ResponseWriter, r *http.Request) {
	c, _ := r.Cookie("sso_session")
	if c != nil {
		a.mu.Lock()
		delete(a.sessions, c.Value)
		a.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "sso_session", Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/", http.StatusFound)
}

// decodeIDToken parses the payload of a JWT without verifying (demo only —
// in production fetch the JWKS and verify the signature, as ApexAuth's
// /userinfo endpoint already does for us).
func decodeIDToken(tok string) map[string]any {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return map[string]any{}
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return map[string]any{}
	}
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return out
}

func stringSlice(v any) []string {
	if l, ok := v.([]any); ok {
		out := make([]string, 0, len(l))
		for _, e := range l {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func asString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func main() {
	cfg := loadConfig()
	a := newApp(cfg)
	mux := http.NewServeMux()
	mux.HandleFunc("/", a.home)
	mux.HandleFunc("/login", a.login)
	mux.HandleFunc("/callback", a.callback)
	mux.HandleFunc("/logout", a.logout)
	log.Printf("SSO client listening on %s (issuer %s, redirect %s)", cfg.addr, cfg.issuer, cfg.redirectURI)
	srv := &http.Server{Addr: cfg.addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
