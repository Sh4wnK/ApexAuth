// Command seed populates the database with test users (1000+ by default),
// the standard RBAC roles/permissions and an OAuth client for the SSO demo.
// It is idempotent: re-running inserts only missing rows.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/Sh4wnK/ApexAuth/internal/config"
	"github.com/Sh4wnK/ApexAuth/internal/migrate"
	"github.com/Sh4wnK/ApexAuth/internal/passwd"
	"github.com/Sh4wnK/ApexAuth/internal/store"
	"github.com/jackc/pgx/v5"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg, err := config.Load()
	if err != nil {
		log.Error("config", "error", err)
		os.Exit(1)
	}

	ctx := context.Background()
	conn, err := pgx.Connect(ctx, cfg.PGDSN)
	if err != nil {
		log.Error("connect", "error", err)
		os.Exit(1)
	}
	defer conn.Close(ctx)
	if err := migrate.Up(ctx, conn); err != nil {
		log.Error("migrate", "error", err)
		os.Exit(1)
	}

	st, err := store.New(ctx, cfg.PGDSN)
	if err != nil {
		log.Error("store", "error", err)
		os.Exit(1)
	}
	defer st.Close()

	// ------------------------------------------------------------------
	// RBAC baseline
	// ------------------------------------------------------------------
	roleAdmin, _ := st.EnsureRole(ctx, "admin", "Full access")
	_ = roleAdmin
	_, _ = st.EnsureRole(ctx, "member", "Standard member")
	_, _ = st.EnsureRole(ctx, "billing", "Billing operator")

	permissionSets := map[string][]string{
		"admin":   {"users:read", "users:write", "roles:read", "roles:write", "sessions:write", "audit:read", "clients:read", "clients:write", "billing:read", "billing:write", "users:impersonate"},
		"member":  {"profile:read", "profile:write"},
		"billing": {"billing:read", "billing:write"},
	}
	seen := map[string]bool{}
	for _, perms := range permissionSets {
		for _, p := range perms {
			if !seen[p] {
				res, act := splitPerm(p)
				_, _ = st.EnsurePermission(ctx, res, act, "")
				seen[p] = true
			}
		}
	}
	for role, perms := range permissionSets {
		for _, p := range perms {
			_ = st.GrantRolePermission(ctx, role, p)
		}
	}

	// ------------------------------------------------------------------
	// Demo users
	// ------------------------------------------------------------------
	adminPass, _ := passwd.Hash("admin-password")
	u1, err := st.CreateUser(ctx, "admin@apexauth.dev", "Admin User", true)
	if err != nil {
		log.Error("create admin user", "error", err)
		os.Exit(1)
	}
	if err := st.SetPassword(ctx, u1.ID, adminPass); err != nil {
		log.Error("set admin password", "error", err)
		os.Exit(1)
	}
	_ = st.AssignRole(ctx, u1.ID, "admin")
	fmt.Printf("seeded admin user: admin@apexauth.dev / admin-password\n")

	memberPass, _ := passwd.Hash("member-password")
	u2, err := st.CreateUser(ctx, "member@apexauth.dev", "Member User", true)
	if err != nil {
		log.Error("create member user", "error", err)
		os.Exit(1)
	}
	_ = st.SetPassword(ctx, u2.ID, memberPass)
	_ = st.AssignRole(ctx, u2.ID, "member")
	fmt.Printf("seeded member user: member@apexauth.dev / member-password\n")

	// ------------------------------------------------------------------
	// Bulk test users (1,000 by default; APEXAUTH_SEED_USERS=n to change)
	// ------------------------------------------------------------------
	start := time.Now()
	inserted := 0
	for i := 0; i < cfg.SeedUsers; i++ {
		email := fmt.Sprintf("user%04d@apexauth.dev", i)
		u, err := st.CreateUser(ctx, email, fmt.Sprintf("Test User %d", i), true)
		if err != nil {
			if err == store.ErrConflict {
				continue // already present from a previous run
			}
			log.Error("create bulk user", "error", err)
			os.Exit(1)
		}
		phc, _ := passwd.Hash("password123")
		_ = st.SetPassword(ctx, u.ID, phc)
		_ = st.AssignRole(ctx, u.ID, "member")
		inserted++
	}
	fmt.Printf("seeded %d test users (target %d) in %s\n", inserted, cfg.SeedUsers, time.Since(start).Round(time.Millisecond))

	// ------------------------------------------------------------------
	// OAuth clients
	// ------------------------------------------------------------------
	const (
		clientID     = "example-app"
		clientSecret = "example-secret-change-me"
		redirectURI  = "http://localhost:8090/callback"
		exampleScope = "openid profile email"
	)
	if _, err := st.GetOAuthClient(ctx, clientID); err == store.ErrNotFound {
		_, err := st.CreateOAuthClient(ctx, clientID, clientSecret, "Example SSO App",
			[]string{redirectURI}, []string{"openid", "profile", "email", "billing:read"}, true)
		if err != nil {
			log.Error("create oauth client", "error", err)
			os.Exit(1)
		}
		fmt.Printf("seeded oauth client: %s / %s -> %s\n", clientID, clientSecret, redirectURI)
	} else if err != nil {
		log.Error("load oauth client", "error", err)
		os.Exit(1)
	} else {
		fmt.Printf("oauth client %s already exists\n", clientID)
	}
	fmt.Println("seed complete")
}

func splitPerm(p string) (string, string) {
	for i := 0; i < len(p); i++ {
		if p[i] == ':' {
			return p[:i], p[i+1:]
		}
	}
	return p, "*"
}
