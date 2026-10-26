package service

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/Sh4wnK/ApexAuth/internal/cache"
	"github.com/Sh4wnK/ApexAuth/internal/mailer"
	"github.com/Sh4wnK/ApexAuth/internal/migrate"
	"github.com/Sh4wnK/ApexAuth/internal/passwd"
	"github.com/Sh4wnK/ApexAuth/internal/store"
	"github.com/Sh4wnK/ApexAuth/internal/tokens"
	"github.com/alicebob/miniredis/v2"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

const testPGPort = uint32(55432)

// testEnv bundles an embedded Postgres + miniredis + store + services.
type testEnv struct {
	pgConn *pgx.Conn
	pgPool *pgxpool.Pool
	mr     *miniredis.Miniredis
	store  *store.Store
	cache  *cache.Cache
	tokens *Tokens
	oauth  *OAuth
	pw     *Passwordless
	signer *tokens.Signer
	mail   *captureMailer
}

// captureMailer records outgoing messages so tests can assert on the code
// or link that was "emailed".
type captureMailer struct {
	texts []string
}

func (m *captureMailer) Send(_ context.Context, msg mailer.Message) error {
	m.texts = append(m.texts, msg.Text)
	return nil
}

// newTestEnv boots embedded postgres + miniredis and builds the services.
// Embedded postgres is started once per test binary (port 55432) and each
// test seals its schema in a transaction to keep runs independent and fast.
func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	ctx := context.Background()

	dsn := fmt.Sprintf("postgres://apexauth:apexauth@localhost:%d/apexauth_test?sslmode=disable", testPGPort)
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close(ctx) })
	if err := migrate.Up(ctx, conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	st := store.FromPool(pool)

	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	ca := cache.NewFromClient(rdb)
	t.Cleanup(func() { _ = rdb.Close() })

	signer, err := tokens.NewSigner(tokens.Options{Alg: "ed25519"})
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	t.Cleanup(signer.Close)

	log := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	tk := NewTokens(st, ca, signer, "https://auth.test", time.Minute, 24*time.Hour, 24*time.Hour, log)
	oauth := NewOAuth(st, tk, 5*time.Minute, "https://auth.test", log)
	ma := &captureMailer{}
	pw := NewPasswordless(st, ma, "noreply@auth.test", 10*time.Minute, log)

	// Wipe shared state so each test starts clean: drop all rows.
	for _, tbl := range []string{"audit_log", "passwordless_tokens", "authorization_codes", "consents", "sessions", "refresh_tokens", "user_roles", "role_permissions", "credentials", "oauth_clients", "permissions", "roles", "users"} {
		if _, err := pool.Exec(ctx, "TRUNCATE "+tbl+" CASCADE"); err != nil {
			t.Fatalf("truncate %s: %v", tbl, err)
		}
	}

	return &testEnv{
		pgConn: conn, pgPool: pool, mr: mr, store: st, cache: ca,
		tokens: tk, oauth: oauth, pw: pw, signer: signer, mail: ma,
	}
}

// seedUser creates a user with a role and grants the role a permission.
func (e *testEnv) seedUser(t *testing.T, email, password, role, perm string) store.User {
	t.Helper()
	u, err := e.store.CreateUser(context.Background(), email, "Test User", true)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if password != "" {
		phc, _ := passwd.Hash(password)
		if err := e.store.SetPassword(context.Background(), u.ID, phc); err != nil {
			t.Fatalf("set password: %v", err)
		}
	}
	if role != "" {
		if _, err := e.store.EnsureRole(context.Background(), role, ""); err != nil {
			t.Fatalf("ensure role: %v", err)
		}
		if err := e.store.AssignRole(context.Background(), u.ID, role); err != nil {
			t.Fatalf("assign role: %v", err)
		}
	}
	if perm != "" {
		res, act := mustSplit(perm)
		if _, err := e.store.EnsurePermission(context.Background(), res, act, ""); err != nil {
			t.Fatalf("ensure perm: %v", err)
		}
		if err := e.store.GrantRolePermission(context.Background(), role, perm); err != nil {
			t.Fatalf("grant perm: %v", err)
		}
	}
	return u
}

// seedClient registers an OAuth client.
func (e *testEnv) seedClient(t *testing.T, clientID, secret string, redirects []string, scopes []string, confidential bool) {
	t.Helper()
	if _, err := e.store.CreateOAuthClient(context.Background(), clientID, secret, "Test Client", redirects, scopes, confidential); err != nil {
		t.Fatalf("create client: %v", err)
	}
}

func mustSplit(p string) (string, string) {
	for i := 0; i < len(p); i++ {
		if p[i] == ':' {
			return p[:i], p[i+1:]
		}
	}
	return p, "*"
}
