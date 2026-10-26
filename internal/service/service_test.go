package service

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/Sh4wnK/ApexAuth/internal/store"
)

// ---------------------------------------------------------------------------
// Redirect URI matching (strict)

func TestValidateRedirectURI(t *testing.T) {
	registered := []string{
		"https://app.example.com/callback",
		"http://localhost:8090/callback",
	}
	cases := []struct {
		candidate string
		want      bool
	}{
		{"https://app.example.com/callback", true},
		{"http://localhost:8090/callback", true},
		{"https://app.example.com/callback/", false},   // trailing slash differs
		{"https://app.example.com/callback?x=1", true}, // query allowed? no: must match exactly
		{"https://evil.example.com/callback", false},
		{"https://app.example.com.evil.com/callback", false},
		{"http://localhost:8090/other", false},
		{"https://app.example.com", false}, // no path
	}
	for _, c := range cases {
		got := ValidateRedirectURI(registered, c.candidate)
		// Query-string variant: the spec forbids adding query params to the
		// registered URI; our implementation compares full strings, so
		// "?x=1" fails.
		want := c.want
		if strings.Contains(c.candidate, "?x=1") {
			want = false
		}
		if got != want {
			t.Errorf("ValidateRedirectURI(%q) = %v, want %v", c.candidate, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// RBAC wildcard matching

func TestPermissionMatchAny(t *testing.T) {
	perms := []string{"billing:read", "billing:*", "roles:read"}
	cases := []struct {
		req  string
		want bool
	}{
		{"billing:read", true},
		{"billing:write", true}, // via wildcard
		{"billing:delete", true},
		{"roles:read", true},
		{"roles:write", false},
		{"users:read", false},
		{"*:read", false},
	}
	for _, c := range cases {
		if got := PermissionMatchAny(perms, c.req); got != c.want {
			t.Errorf("PermissionMatchAny(%q) = %v, want %v", c.req, got, c.want)
		}
	}
}

func TestPermissionWildcardResource(t *testing.T) {
	perms := []string{"*:read", "*:write"}
	for _, c := range []struct {
		req  string
		want bool
	}{
		{"billing:read", true}, {"users:read", true}, {"users:write", true},
		{"users:delete", false}, {"billing:delete", false},
	} {
		if got := PermissionMatchAny(perms, c.req); got != c.want {
			t.Errorf("PermissionMatchAny(%q) = %v, want %v", c.req, got, c.want)
		}
	}
}

// ---------------------------------------------------------------------------
// PKCE challenge/verifier verification via the code exchange

func pkcePair(t *testing.T) (verifier, challenge string) {
	t.Helper()
	verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" // RFC 7636 sample
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

func TestExchangeCodePKCE(t *testing.T) {
	e := newTestEnv(t)
	u := e.seedUser(t, "alice@test.dev", "pw", "member", "")
	e.seedClient(t, "pkce-client", "", []string{"https://app.example.com/cb"}, []string{"openid", "profile"}, false)

	verifier, challenge := pkcePair(t)
	code, err := e.oauth.IssueCode(context.Background(), u, "pkce-client", "https://app.example.com/cb", "nonce-1", challenge, "S256", []string{"openid"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := e.oauth.ExchangeCode(context.Background(), "pkce-client", "", code, verifier, "https://app.example.com/cb")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if res.AccessToken == "" || res.RefreshToken == "" {
		t.Fatal("expected access + refresh tokens")
	}
	if res.IDToken == "" {
		t.Fatal("expected id_token for openid scope with nonce")
	}
	if !strings.Contains(res.Scope, "openid") {
		t.Fatalf("scope missing openid: %q", res.Scope)
	}
}

func TestExchangeCodeRejectsWrongVerifier(t *testing.T) {
	e := newTestEnv(t)
	u := e.seedUser(t, "alice@test.dev", "pw", "member", "")
	e.seedClient(t, "pkce-client", "", []string{"https://app.example.com/cb"}, []string{"openid"}, false)

	_, challenge := pkcePair(t)
	code, err := e.oauth.IssueCode(context.Background(), u, "pkce-client", "https://app.example.com/cb", "", challenge, "S256", []string{"openid"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.oauth.ExchangeCode(context.Background(), "pkce-client", "", code, "wrong-verifier", "https://app.example.com/cb"); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("expected invalid grant, got %v", err)
	}
}

func TestExchangeCodeRejectsMissingVerifier(t *testing.T) {
	e := newTestEnv(t)
	u := e.seedUser(t, "alice@test.dev", "pw", "member", "")
	e.seedClient(t, "pkce-client", "", []string{"https://app.example.com/cb"}, []string{"openid"}, false)

	_, challenge := pkcePair(t)
	code, _ := e.oauth.IssueCode(context.Background(), u, "pkce-client", "https://app.example.com/cb", "", challenge, "S256", []string{"openid"})
	if _, err := e.oauth.ExchangeCode(context.Background(), "pkce-client", "", code, "", "https://app.example.com/cb"); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("expected invalid grant for missing verifier, got %v", err)
	}
}

func TestExchangeCodeSingleUse(t *testing.T) {
	e := newTestEnv(t)
	u := e.seedUser(t, "alice@test.dev", "pw", "member", "")
	// Confidential client: no PKCE needed.
	e.seedClient(t, "conf-client", "shh-secret", []string{"https://app.example.com/cb"}, []string{"openid"}, true)

	code, err := e.oauth.IssueCode(context.Background(), u, "conf-client", "https://app.example.com/cb", "", "", "", []string{"openid"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.oauth.ExchangeCode(context.Background(), "conf-client", "shh-secret", code, "", "https://app.example.com/cb"); err != nil {
		t.Fatalf("first exchange: %v", err)
	}
	if _, err := e.oauth.ExchangeCode(context.Background(), "conf-client", "shh-secret", code, "", "https://app.example.com/cb"); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("second exchange must fail, got %v", err)
	}
}

func TestExchangeCodeRejectsWrongRedirect(t *testing.T) {
	e := newTestEnv(t)
	u := e.seedUser(t, "alice@test.dev", "pw", "member", "")
	e.seedClient(t, "conf-client", "shh-secret", []string{"https://app.example.com/cb"}, []string{"openid"}, true)
	code, _ := e.oauth.IssueCode(context.Background(), u, "conf-client", "https://app.example.com/cb", "", "", "", []string{"openid"})
	if _, err := e.oauth.ExchangeCode(context.Background(), "conf-client", "shh-secret", code, "", "https://app.example.com/other"); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("expected invalid grant on redirect mismatch, got %v", err)
	}
}

func TestExchangeCodeWrongClient(t *testing.T) {
	e := newTestEnv(t)
	u := e.seedUser(t, "alice@test.dev", "pw", "member", "")
	e.seedClient(t, "client-a", "s1", []string{"https://app.example.com/cb"}, []string{"openid"}, true)
	e.seedClient(t, "client-b", "s2", []string{"https://app.example.com/cb"}, []string{"openid"}, true)
	code, _ := e.oauth.IssueCode(context.Background(), u, "client-a", "https://app.example.com/cb", "", "", "", []string{"openid"})
	if _, err := e.oauth.ExchangeCode(context.Background(), "client-b", "s2", code, "", "https://app.example.com/cb"); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("expected invalid grant for wrong client, got %v", err)
	}
}

func TestAuthorizeValidationForcesPKCEOnPublicClients(t *testing.T) {
	e := newTestEnv(t)
	e.seedClient(t, "pub-client", "", []string{"https://app.example.com/cb"}, []string{"openid"}, false)
	_, err := e.oauth.ValidateAuthorizeRequest(context.Background(), AuthRequest{
		ClientID:     "pub-client",
		RedirectURI:  "https://app.example.com/cb",
		ResponseType: "code",
		Scopes:       []string{"openid"},
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("public client without PKCE must be rejected, got %v", err)
	}
	// With PKCE S256 it passes.
	_, challenge := pkcePair(t)
	_, err = e.oauth.ValidateAuthorizeRequest(context.Background(), AuthRequest{
		ClientID: "pub-client", RedirectURI: "https://app.example.com/cb",
		ResponseType: "code", Scopes: []string{"openid"},
		CodeChallenge: challenge, CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatalf("public client with PKCE should pass: %v", err)
	}
}

func TestAuthorizeRejectsUnregisteredRedirect(t *testing.T) {
	e := newTestEnv(t)
	e.seedClient(t, "conf-client", "s", []string{"https://app.example.com/cb"}, []string{"openid"}, true)
	if _, err := e.oauth.ValidateAuthorizeRequest(context.Background(), AuthRequest{
		ClientID: "conf-client", RedirectURI: "https://evil.example.com/cb", ResponseType: "code",
	}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("expected rejection of unregistered redirect, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Refresh-token rotation with reuse detection

func TestRefreshRotationAndReuseDetection(t *testing.T) {
	e := newTestEnv(t)
	u := e.seedUser(t, "bob@test.dev", "pw", "member", "")
	e.seedClient(t, "ref-client", "s", []string{"https://app.example.com/cb"}, []string{"openid"}, true)

	res, err := e.tokens.PasswordlessLogin(context.Background(), u.ID, "ref-client", []string{"openid"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if res.RefreshToken == "" {
		t.Fatal("expected refresh token")
	}
	oldRef := res.RefreshToken

	// First rotation succeeds and issues a new refresh token.
	r2, err := e.oauth.ExchangeRefresh(context.Background(), "ref-client", "s", oldRef, nil, "")
	if err != nil {
		t.Fatalf("first refresh: %v", err)
	}
	if r2.RefreshToken == "" || r2.RefreshToken == oldRef {
		t.Fatal("rotation must issue a new refresh token")
	}

	// Second rotation with the SAME (already consumed) token must trigger
	// reuse detection and revoke the family.
	if _, err := e.oauth.ExchangeRefresh(context.Background(), "ref-client", "s", oldRef, nil, ""); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("reuse must be rejected, got %v", err)
	}

	// The family is dead: even the valid child cannot rotate anymore.
	if _, err := e.oauth.ExchangeRefresh(context.Background(), "ref-client", "s", r2.RefreshToken, nil, ""); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("family revocation must kill the child too, got %v", err)
	}
}

func TestRefreshRejectsWrongClient(t *testing.T) {
	e := newTestEnv(t)
	u := e.seedUser(t, "bob@test.dev", "pw", "member", "")
	e.seedClient(t, "ref-client", "s", []string{"https://app.example.com/cb"}, []string{"openid"}, true)
	res, _ := e.tokens.PasswordlessLogin(context.Background(), u.ID, "ref-client", []string{"openid"}, "")
	if _, err := e.oauth.ExchangeRefresh(context.Background(), "ref-client", "WRONG", res.RefreshToken, nil, ""); !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("wrong secret must fail auth, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Passwordless tokens

func TestMagicLinkLifecycle(t *testing.T) {
	e := newTestEnv(t)
	u := e.seedUser(t, "carol@test.dev", "pw", "member", "")

	if err := e.pw.SendMagicLink(context.Background(), u.Email, "https://auth.test/auth/magic?token=", ""); err != nil {
		t.Fatal(err)
	}
	if len(e.mail.texts) != 1 {
		t.Fatalf("expected 1 email, got %d", len(e.mail.texts))
	}
	tok := extractMagicToken(t, e.mail.texts[0])

	got, err := e.pw.ConsumeMagicLink(context.Background(), tok)
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if got.ID != u.ID {
		t.Fatal("consumed token must map to the right user")
	}
	// Single use: second consume fails.
	if _, err := e.pw.ConsumeMagicLink(context.Background(), tok); err == nil {
		t.Fatal("magic link must be single-use")
	}
}

func TestMagicLinkSkipsUnknownEmail(t *testing.T) {
	e := newTestEnv(t)
	if err := e.pw.SendMagicLink(context.Background(), "nobody@test.dev", "https://auth.test/auth/magic?token=", ""); err != nil {
		t.Fatal(err)
	}
	if len(e.mail.texts) != 0 {
		t.Fatal("must not email unknown accounts (enumeration)")
	}
}

func TestOTPLifecycle(t *testing.T) {
	e := newTestEnv(t)
	u := e.seedUser(t, "dave@test.dev", "pw", "member", "")

	code, err := e.pw.SendOTP(context.Background(), u.Email)
	if err != nil {
		t.Fatal(err)
	}
	if len(code) != 6 {
		t.Fatalf("code must be 6 digits, got %q", code)
	}
	got, err := e.pw.ConsumeOTP(context.Background(), code)
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if got.ID != u.ID {
		t.Fatal("wrong user")
	}
	if _, err := e.pw.ConsumeOTP(context.Background(), code); err == nil {
		t.Fatal("OTP must be single-use")
	}
}

func TestOTPWrongCode(t *testing.T) {
	e := newTestEnv(t)
	e.seedUser(t, "dave@test.dev", "pw", "member", "")
	if _, err := e.pw.ConsumeOTP(context.Background(), "000000"); err == nil {
		t.Fatal("wrong code must fail")
	}
}

func TestPasswordlessTokenHasher(t *testing.T) {
	// Confirm plaintext tokens are never stored: the DB row must hold a
	// SHA-256, never the code itself.
	e := newTestEnv(t)
	u := e.seedUser(t, "erin@test.dev", "pw", "member", "")
	code, _ := e.pw.SendOTP(context.Background(), u.Email)
	var stored string
	err := e.pgPool.QueryRow(context.Background(),
		"SELECT encode(token_hash, 'hex') FROM passwordless_tokens").Scan(&stored)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stored, code) || len(stored) != 64 {
		t.Fatalf("token must be stored as a SHA-256 hex hash, got %q", stored)
	}
}

func extractMagicToken(t *testing.T, text string) string {
	t.Helper()
	idx := strings.LastIndex(text, "=")
	if idx < 0 {
		t.Fatalf("no token in email: %q", text)
	}
	tok := strings.TrimSpace(text[idx+1:])
	if tok == "" {
		t.Fatalf("empty token in email %q", text)
	}
	return tok
}

// ---------------------------------------------------------------------------
// Password login + VerifyAccess

func TestPasswordLoginAndVerify(t *testing.T) {
	e := newTestEnv(t)
	u := e.seedUser(t, "frank@test.dev", "s3cret!", "member", "")
	// grant the member role a permission after user creation
	res, act := mustSplit("profile:read")
	if _, err := e.store.EnsurePermission(context.Background(), res, act, ""); err != nil {
		t.Fatal(err)
	}
	_ = e.store.GrantRolePermission(context.Background(), "member", "profile:read")

	res2, err := e.tokens.PasswordLogin(context.Background(), u.Email, "s3cret!")
	if err != nil {
		t.Fatal(err)
	}
	if res2.AccessToken == "" {
		t.Fatal("expected access token")
	}
	claims, err := e.tokens.VerifyAccess(context.Background(), res2.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if claims.UserID != u.ID {
		t.Fatal("claims subject mismatch")
	}
	containsPerm := func(p string) bool {
		for _, x := range claims.Permissions {
			if x == p {
				return true
			}
		}
		return false
	}
	if !containsPerm("profile:read") {
		t.Fatalf("permissions missing profile:read: %v", claims.Permissions)
	}
}

func TestPasswordLoginWrongPassword(t *testing.T) {
	e := newTestEnv(t)
	e.seedUser(t, "frank@test.dev", "s3cret!", "member", "")
	if _, err := e.tokens.PasswordLogin(context.Background(), "frank@test.dev", "wrong"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected invalid credentials, got %v", err)
	}
}

func TestCheckPermissionWildcard(t *testing.T) {
	e := newTestEnv(t)
	u := e.seedUser(t, "grace@test.dev", "pw", "billing", "")
	if _, err := e.store.EnsurePermission(context.Background(), "billing", "read", ""); err != nil {
		t.Fatal(err)
	}
	if err := e.store.GrantRolePermission(context.Background(), "billing", "billing:read"); err != nil {
		t.Fatal(err)
	}
	ok, err := e.tokens.CheckPermission(context.Background(), u.ID, "billing:read")
	if err != nil || !ok {
		t.Fatalf("billing:read should be allowed: ok=%v err=%v", ok, err)
	}
	// Wildcard at grant time: roles can carry "billing:*". The admin API
	// bumps the RBAC version after grants (see httpapi), invalidating cached
	// permission lists — mirror that here.
	if err := e.store.GrantRolePermission(context.Background(), "billing", "billing:*"); err != nil {
		t.Fatal(err)
	}
	_ = e.cache.TouchRoleVersion(context.Background(), "billing")
	ok, err = e.tokens.CheckPermission(context.Background(), u.ID, "billing:write")
	if err != nil || !ok {
		t.Fatalf("billing:write should match billing:*: ok=%v err=%v", ok, err)
	}
	ok, _ = e.tokens.CheckPermission(context.Background(), u.ID, "users:read")
	if ok {
		t.Fatal("users:read must not be allowed")
	}
}

func TestCheckPermissionUnknownUser(t *testing.T) {
	e := newTestEnv(t)
	ok, err := e.tokens.CheckPermission(context.Background(), "00000000-0000-0000-0000-000000000000", "anything:read")
	if err != nil || ok {
		t.Fatalf("unknown user must be denied without error: ok=%v err=%v", ok, err)
	}
}

func TestLogoutRevokesAccess(t *testing.T) {
	e := newTestEnv(t)
	u := e.seedUser(t, "heidi@test.dev", "pw", "member", "")
	res, _ := e.tokens.PasswordLogin(context.Background(), u.Email, "pw")
	claims, err := e.tokens.VerifyAccess(context.Background(), res.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.tokens.Logout(context.Background(), res.SessionID, claims.ID, res.RefreshToken); err != nil {
		t.Fatal(err)
	}
	if _, err := e.tokens.VerifyAccess(context.Background(), res.AccessToken); err == nil {
		t.Fatal("revoked access token must fail verification")
	}
	// Refresh also fails: the token is revoked.
	if _, err := e.oauth.ExchangeRefresh(context.Background(), "", "", res.RefreshToken, nil, ""); err == nil {
		t.Fatal("revoked refresh token must fail")
	}
}

var _ = fmt.Sprintf
var _ = store.ErrNotFound
