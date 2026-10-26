package grpcapi

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/Sh4wnK/ApexAuth/gen/apexauth/v1"
	"github.com/Sh4wnK/ApexAuth/internal/cache"
	"github.com/Sh4wnK/ApexAuth/internal/migrate"
	"github.com/Sh4wnK/ApexAuth/internal/passwd"
	"github.com/Sh4wnK/ApexAuth/internal/service"
	"github.com/Sh4wnK/ApexAuth/internal/store"
	"github.com/Sh4wnK/ApexAuth/internal/tokens"
	"github.com/alicebob/miniredis/v2"
	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"
)

func TestValidateTokenAndCheckPermission(t *testing.T) {
	// ---- shared test infra (PG once per binary) ----
	ctx := context.Background()
	pg := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Port(55434).Username("apexauth").Password("apexauth").Database("apexauth_test").
		RuntimePath(t.TempDir() + "/rt").DataPath(t.TempDir() + "/data").BinariesPath(t.TempDir() + "/bin"))
	if err := pg.Start(); err != nil {
		t.Fatal(err)
	}
	defer pg.Stop()
	dsn := "postgres://apexauth:apexauth@localhost:55434/apexauth_test?sslmode=disable"
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	if err := migrate.Up(ctx, conn); err != nil {
		t.Fatal(err)
	}
	conn.Close(ctx)
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	st := store.FromPool(pool)

	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()
	ca := cache.NewFromClient(rdb)

	signer, err := tokens.NewSigner(tokens.Options{Alg: "ed25519"})
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Close()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	tk := service.NewTokens(st, ca, signer, "https://grpc.test", 15*time.Minute, 24*time.Hour, 24*time.Hour, log)

	// ---- seed user with roles/permissions ----
	u, err := st.CreateUser(ctx, "grpc@test.dev", "gRPC User", true)
	if err != nil {
		t.Fatal(err)
	}
	phc, _ := passwd.Hash("pw")
	_ = st.SetPassword(ctx, u.ID, phc)
	_, _ = st.EnsureRole(ctx, "admin", "")
	_, _ = st.EnsurePermission(ctx, "users", "read", "")
	_, _ = st.EnsurePermission(ctx, "roles", "write", "")
	_ = st.GrantRolePermission(ctx, "admin", "users:read")
	_ = st.GrantRolePermission(ctx, "admin", "roles:write")
	_ = st.GrantRolePermission(ctx, "admin", "roles:read")
	_ = st.AssignRole(ctx, u.ID, "admin")

	res, err := tk.PasswordLogin(ctx, "grpc@test.dev", "pw")
	if err != nil {
		t.Fatal(err)
	}

	// ---- bufconn gRPC server ----
	lis := bufconn.Listen(1 << 20)
	gsrv := grpc.NewServer(grpc.UnaryInterceptor(Interceptor(tk)))
	impl := New(tk, st, ca)
	apexauthv1.RegisterAuthServiceServer(gsrv, impl)
	apexauthv1.RegisterAdminServiceServer(gsrv, impl)
	go gsrv.Serve(lis)
	defer gsrv.Stop()

	cc, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	ac := apexauthv1.NewAuthServiceClient(cc)

	authCtx := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+res.AccessToken)

	// ---- ValidateToken ----
	vr, err := ac.ValidateToken(authCtx, &apexauthv1.ValidateTokenRequest{Token: res.AccessToken})
	if err != nil {
		t.Fatal(err)
	}
	if !vr.Valid || vr.UserId != u.ID || vr.Email != "grpc@test.dev" {
		t.Fatalf("validate mismatch: %+v", vr)
	}

	// ---- CheckPermission (allowed + denied) ----
	cr, err := ac.CheckPermission(authCtx, &apexauthv1.CheckPermissionRequest{Permission: "users:read"})
	if err != nil || !cr.Allowed {
		t.Fatalf("users:read should be allowed: %v %+v", err, cr)
	}
	cr2, err := ac.CheckPermission(authCtx, &apexauthv1.CheckPermissionRequest{Permission: "billing:write"})
	if err != nil || cr2.Allowed {
		t.Fatalf("billing:write must be denied: %v %+v", err, cr2)
	}
	// wildcard granted in admin role
	_ = st.GrantRolePermission(ctx, "admin", "billing:*")
	_ = ca.TouchRoleVersion(ctx, "admin")
	cr3, err := ac.CheckPermission(authCtx, &apexauthv1.CheckPermissionRequest{Permission: "billing:read"})
	if err != nil || !cr3.Allowed {
		t.Fatalf("billing:read should match billing:*: %v %+v", err, cr3)
	}

	// ---- GetUser / ListUserRoles ----
	gu, err := ac.GetUser(authCtx, &apexauthv1.GetUserRequest{UserId: u.ID})
	if err != nil {
		t.Fatal(err)
	}
	if gu.Email != "grpc@test.dev" || len(gu.Roles) != 1 || gu.Roles[0] != "admin" {
		t.Fatalf("getuser mismatch: %+v", gu)
	}
	lr, err := ac.ListUserRoles(authCtx, &apexauthv1.ListUserRolesRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(lr.Roles) != 1 || lr.Roles[0].Name != "admin" {
		t.Fatalf("list roles mismatch: %+v", lr)
	}

	// ---- unauthenticated call is rejected ----
	if _, err := ac.CheckPermission(ctx, &apexauthv1.CheckPermissionRequest{Permission: "users:read"}); err == nil {
		t.Fatal("expected unauthenticated error")
	}

	// ---- admin RPC with admin token ----
	adm := apexauthv1.NewAdminServiceClient(cc)
	rr, err := adm.CreateRole(authCtx, &apexauthv1.CreateRoleRequest{Name: "ops", Permissions: []string{"audit:read"}})
	if err != nil {
		t.Fatal(err)
	}
	if rr.Name != "ops" {
		t.Fatalf("role name mismatch: %+v", rr)
	}
	rr2, err := adm.ListRoles(authCtx, &apexauthv1.ListRolesRequest{})
	if err != nil || len(rr2.Roles) < 2 {
		t.Fatalf("list roles: %v %+v", err, rr2)
	}

	// ---- revoked token fails ----
	_ = tk.Logout(ctx, res.SessionID, res.JTI, res.RefreshToken)
	if _, err := ac.ValidateToken(authCtx, &apexauthv1.ValidateTokenRequest{Token: res.AccessToken}); err == nil {
		t.Fatal("revoked token must fail validation")
	}
}
