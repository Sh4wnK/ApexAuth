// Package server wires everything together and runs the HTTP and gRPC
// listeners with graceful shutdown.
package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Sh4wnK/ApexAuth/gen/apexauth/v1"
	"github.com/Sh4wnK/ApexAuth/internal/cache"
	"github.com/Sh4wnK/ApexAuth/internal/config"
	"github.com/Sh4wnK/ApexAuth/internal/grpcapi"
	"github.com/Sh4wnK/ApexAuth/internal/httpapi"
	"github.com/Sh4wnK/ApexAuth/internal/mailer"
	"github.com/Sh4wnK/ApexAuth/internal/migrate"
	"github.com/Sh4wnK/ApexAuth/internal/service"
	"github.com/Sh4wnK/ApexAuth/internal/store"
	"github.com/Sh4wnK/ApexAuth/internal/tokens"
	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
)

// Dependencies holds the constructed services (tests build their own).
type Dependencies struct {
	Store    *store.Store
	Cache    *cache.Cache
	Tokens   *service.Tokens
	OAuth    *service.OAuth
	Password *service.Passwordless
	Signer   *tokens.Signer
	HTTP     *httpapi.Server
}

// Build constructs the full dependency graph from configuration. It applies
// migrations and connects to Postgres and Redis.
func Build(ctx context.Context, cfg *config.Config, log *slog.Logger) (*Dependencies, error) {
	connStr := cfg.PGDSN
	conn, err := pgx.Connect(ctx, connStr)
	if err != nil {
		return nil, fmt.Errorf("server: connect pg: %w", err)
	}
	defer conn.Close(ctx)
	if err := migrate.Up(ctx, conn); err != nil {
		return nil, fmt.Errorf("server: migrate: %w", err)
	}

	st, err := store.New(ctx, cfg.PGDSN)
	if err != nil {
		return nil, fmt.Errorf("server: store: %w", err)
	}
	ca, err := cache.New(cfg.RedisAddr, cfg.RedisPassword, cfg.RedisDB, cfg.CacheEnabled)
	if err != nil {
		st.Close()
		return nil, fmt.Errorf("server: cache: %w", err)
	}

	signer, err := tokens.NewSigner(tokens.Options{
		Alg:         cfg.SignAlg,
		KeyPath:     cfg.SigningKeyPath,
		RotateAfter: cfg.RotateAfter,
	})
	if err != nil {
		st.Close()
		return nil, fmt.Errorf("server: signer: %w", err)
	}

	tk := service.NewTokens(st, ca, signer, cfg.BaseURL, cfg.AccessTokenTTL, cfg.RefreshTokenTTL, cfg.SessionTTL, log)
	oauth := service.NewOAuth(st, tk, cfg.CodeTTL, cfg.BaseURL, log)

	var mail mailer.Mailer
	if m, err := mailer.NewSMTPMailer(mailer.SMTPConfig{
		Host:     envOr("APEXAUTH_SMTP_HOST", ""),
		Port:     envPortOr("APEXAUTH_SMTP_PORT", 587),
		Username: os.Getenv("APEXAUTH_SMTP_USERNAME"),
		Password: os.Getenv("APEXAUTH_SMTP_PASSWORD"),
		From:     cfg.EmailFrom,
	}, log); err == nil {
		mail = m
	} else {
		mail = mailer.NewLogMailer(log)
	}
	pw := service.NewPasswordless(st, mail, cfg.EmailFrom, cfg.PasswordlessTTL, log)

	secret := os.Getenv("APEXAUTH_HMAC_SECRET")
	if secret == "" {
		if cfg.EnvIsProd() {
			return nil, errors.New("server: APEXAUTH_HMAC_SECRET required in production")
		}
		b := make([]byte, 32)
		_, _ = rand.Read(b)
		secret = hex.EncodeToString(b)
		log.Warn("APEXAUTH_HMAC_SECRET not set; generated ephemeral secret (sessions will not survive restart)")
	}
	if len(secret) < 32 {
		return nil, errors.New("server: APEXAUTH_HMAC_SECRET must be at least 32 characters")
	}

	httpSrv, err := httpapi.New(httpapi.Options{
		Store:        st,
		Cache:        ca,
		Tokens:       tk,
		OAuth:        oauth,
		Passwordless: pw,
		Signer:       signer,
		Issuer:       cfg.BaseURL,
		BaseURL:      cfg.BaseURL,
		HMACSecret:   []byte(secret),
		RateLimitMax: cfg.RateLimitMax,
		RateWindow:   cfg.RateLimitWindow,
		AttemptsMax:  cfg.MaxLoginAttempts,
		Log:          log,
	})
	if err != nil {
		st.Close()
		return nil, fmt.Errorf("server: http: %w", err)
	}
	return &Dependencies{
		Store: st, Cache: ca, Tokens: tk, OAuth: oauth, Password: pw, Signer: signer, HTTP: httpSrv,
	}, nil
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envPortOr(k string, def int) int {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	var p int
	if _, err := fmt.Sscanf(v, "%d", &p); err == nil {
		return p
	}
	return def
}

// Run starts HTTP and gRPC servers and blocks until SIGINT/SIGTERM, then
// shuts down gracefully.
func Run(deps *Dependencies, cfg *config.Config, log *slog.Logger) error {
	httpLn, err := net.Listen("tcp", cfg.HTTPAddr)
	if err != nil {
		return fmt.Errorf("server: http listen: %w", err)
	}
	grpcLn, err := net.Listen("tcp", cfg.GRPCAddr)
	if err != nil {
		return fmt.Errorf("server: grpc listen: %w", err)
	}

	httpSrv := &http.Server{
		Handler:           deps.HTTP.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	grpcSrv := grpc.NewServer(
		grpc.UnaryInterceptor(grpcapi.Interceptor(deps.Tokens)),
	)
	gs := grpcapi.New(deps.Tokens, deps.Store, deps.Cache)
	apexauthv1.RegisterAuthServiceServer(grpcSrv, gs)
	apexauthv1.RegisterAdminServiceServer(grpcSrv, gs)
	hs := health.NewServer()
	hs.SetServingStatus("apexauth.v1.AuthService", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(grpcSrv, hs)
	reflection.Register(grpcSrv)

	errCh := make(chan error, 2)
	go func() {
		log.Info("http server listening", "addr", httpLn.Addr().String())
		if err := httpSrv.Serve(httpLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("http: %w", err)
		}
	}()
	go func() {
		log.Info("grpc server listening", "addr", grpcLn.Addr().String())
		if err := grpcSrv.Serve(grpcLn); err != nil {
			errCh <- fmt.Errorf("grpc: %w", err)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}

	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	grpcSrv.GracefulStop()
	_ = httpSrv.Shutdown(shutdownCtx)
	deps.Signer.Close()
	deps.Store.Close()
	deps.Cache.Close()
	return nil
}
