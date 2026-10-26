// Package config loads ApexAuth server configuration from environment
// variables. Every setting can be supplied via env; default values are
// tuned for local development and the Docker compose setup.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the full server configuration.
type Config struct {
	HTTPAddr      string
	GRPCAddr      string
	BaseURL       string
	LogLevel      string
	PGDSN         string
	RedisAddr     string
	RedisPassword string
	RedisDB       int
	// CacheEnabled toggles the Redis session/role cache. When disabled the
	// server falls back to direct (and still indexed) PostgreSQL lookups.
	// The bench command uses this to demonstrate the latency difference.
	CacheEnabled bool

	// JWT signing. Ed25519 is the default and recommended algorithm;
	// RSA (RS256) is supported for interop.
	SignAlg        string // "ed25519" | "rsa"
	SigningKeyPath string // private key PEM; generated at startup if empty
	// RotateAfter sets how long a signing key stays active before a new
	// key is generated and the old one is retired to the JWKS set.
	RotateAfter time.Duration

	AccessTokenTTL   time.Duration
	RefreshTokenTTL  time.Duration
	SessionTTL       time.Duration
	CodeTTL          time.Duration
	PasswordlessTTL  time.Duration
	RateLimitWindow  time.Duration
	RateLimitMax     int
	MaxLoginAttempts int

	EmailFrom string

	// SeedUsers is the number of test users the seed command creates.
	SeedUsers int
}

// Load reads the configuration from the environment.
func Load() (*Config, error) {
	c := &Config{
		HTTPAddr:         env("APEXAUTH_HTTP_ADDR", ":8080"),
		GRPCAddr:         env("APEXAUTH_GRPC_ADDR", ":9090"),
		BaseURL:          env("APEXAUTH_BASE_URL", "http://localhost:8080"),
		LogLevel:         env("APEXAUTH_LOG_LEVEL", "info"),
		PGDSN:            env("APEXAUTH_PG_DSN", "postgres://apexauth:apexauth@localhost:5432/apexauth?sslmode=disable"),
		RedisAddr:        env("APEXAUTH_REDIS_ADDR", "localhost:6379"),
		RedisPassword:    env("APEXAUTH_REDIS_PASSWORD", ""),
		SignAlg:          env("APEXAUTH_SIGN_ALG", "ed25519"),
		SigningKeyPath:   env("APEXAUTH_SIGNING_KEY", ""),
		EmailFrom:        env("APEXAUTH_EMAIL_FROM", "ApexAuth <no-reply@apexauth.local>"),
		AccessTokenTTL:   15 * time.Minute,
		RefreshTokenTTL:  30 * 24 * time.Hour,
		SessionTTL:       30 * 24 * time.Hour,
		CodeTTL:          5 * time.Minute,
		PasswordlessTTL:  10 * time.Minute,
		RateLimitWindow:  time.Minute,
		RateLimitMax:     10,
		MaxLoginAttempts: 5,
		RotateAfter:      24 * time.Hour,
		SeedUsers:        1000,
	}

	var err error
	if v, ok := os.LookupEnv("APEXAUTH_REDIS_DB"); ok {
		if c.RedisDB, err = strconv.Atoi(v); err != nil {
			return nil, fmt.Errorf("config: APEXAUTH_REDIS_DB: %w", err)
		}
	}
	for _, key := range []string{"APEXAUTH_ACCESS_TTL", "APEXAUTH_REFRESH_TTL", "APEXAUTH_SESSION_TTL", "APEXAUTH_CODE_TTL", "APEXAUTH_PASSWORDLESS_TTL", "APEXAUTH_RATE_WINDOW"} {
		if v, ok := os.LookupEnv(key); ok {
			d, derr := time.ParseDuration(v)
			if derr != nil {
				return nil, fmt.Errorf("config: %s: %w", key, derr)
			}
			switch key {
			case "APEXAUTH_ACCESS_TTL":
				c.AccessTokenTTL = d
			case "APEXAUTH_REFRESH_TTL":
				c.RefreshTokenTTL = d
			case "APEXAUTH_SESSION_TTL":
				c.SessionTTL = d
			case "APEXAUTH_CODE_TTL":
				c.CodeTTL = d
			case "APEXAUTH_PASSWORDLESS_TTL":
				c.PasswordlessTTL = d
			case "APEXAUTH_RATE_WINDOW":
				c.RateLimitWindow = d
			}
		}
	}
	if v, ok := os.LookupEnv("APEXAUTH_RATE_MAX"); ok {
		if c.RateLimitMax, err = strconv.Atoi(v); err != nil {
			return nil, fmt.Errorf("config: APEXAUTH_RATE_MAX: %w", err)
		}
	}
	if v, ok := os.LookupEnv("APEXAUTH_LOGIN_ATTEMPTS"); ok {
		if c.MaxLoginAttempts, err = strconv.Atoi(v); err != nil {
			return nil, fmt.Errorf("config: APEXAUTH_LOGIN_ATTEMPTS: %w", err)
		}
	}
	if v, ok := os.LookupEnv("APEXAUTH_SEED_USERS"); ok {
		if c.SeedUsers, err = strconv.Atoi(v); err != nil {
			return nil, fmt.Errorf("config: APEXAUTH_SEED_USERS: %w", err)
		}
	}
	c.CacheEnabled = strings.EqualFold(env("APEXAUTH_CACHE", "true"), "true")
	if !strings.EqualFold(c.SignAlg, "ed25519") && !strings.EqualFold(c.SignAlg, "rsa") {
		return nil, fmt.Errorf("config: APEXAUTH_SIGN_ALG must be ed25519 or rsa, got %q", c.SignAlg)
	}
	return c, nil
}

// EnvIsProd reports whether APEXAUTH_ENV is set to production.
func (c *Config) EnvIsProd() bool {
	return strings.EqualFold(os.Getenv("APEXAUTH_ENV"), "production")
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}
