# ApexAuth

Centralized authentication and authorization microservice built in Go: password and
passwordless (magic link / 6-digit OTP) login, JWT access tokens with Ed25519 key
rotation, refresh-token rotation families with reuse detection, Role-Based Access
Control (RBAC) with wildcard permissions, and a complete OAuth2.0 / OIDC provider
for third-party apps (SSO). Data lives in PostgreSQL; Redis powers the session and
permission caches, token denylist and rate limiting. The API is surfaced over both
HTTP and gRPC.

## Features

- **Password login** — argon2id hashes (PHC format), per-email attempt rate limiting.
- **Passwordless login** — email magic links and 6-digit OTPs: single-use, SHA-256
  hashed at rest, short TTLs, anti-enumeration (unknown emails get no response
  difference), pluggable `Mailer` interface (SMTP + log implementations).
- **Refresh-token rotation with reuse detection** — every refresh token belongs to a
  rotation family (family_id / parent_id). Replaying a rotated-out token revokes the
  whole family, killing even the legitimate session's tokens.
- **JWT access tokens** — Ed25519 (default) or RS256, `kid`-based key rotation with a
  JWKS endpoint, Redis denylist by `jti`.
- **RBAC** — roles and permissions (`resource:action`) with wildcard support
  (`billing:*`), permissions embedded in token claims, admin REST + gRPC endpoints
  protected by RBAC checks.
- **OAuth2.0 / OIDC provider** — `/oauth2/authorize` (authorization code; PKCE S256
  required for public clients), `/oauth2/token` (authorization_code, refresh_token,
  client_credentials), `/oauth2/revoke`, `/oauth2/introspect`, `/oauth2/userinfo`,
  `/.well-known/openid-configuration`, `/.well-known/jwks.json`, `id_token` issuance,
  minimal login/consent HTML pages. Strict redirect-URI matching, state + nonce
  handling.
- **gRPC API** — `AuthService` (ValidateToken, CheckPermission, GetUser, ListUserRoles)
  and `AdminService` (role/permission management), bearer-token auth interceptor,
  health service, reflection. Generated from `proto/apexauth/v1/auth.proto`.
- **Redis** — read-through session/user/roles/permission cache with invalidation on
  role change and revocation (RBAC version counter), token denylist, sliding-window
  rate limiting. Disable with `APEXAUTH_CACHE=false` (see Performance).
- **Audit log** — append-only `audit_log` table for security-relevant events.

## Architecture

```mermaid
flowchart LR
    U[User / Browser] -->|HTTPS login, SSO, passwordless| HTTP[ApexAuth HTTP :8080]
    A[Third-party app] -->|OAuth2/OIDC| HTTP
    S[Services / CLI] -->|gRPC :9090| GRPC[ApexAuth gRPC]
    HTTP --> SVC[service layer: authn, oauth, rbac]
    GRPC --> SVC
    SVC --> PG[(PostgreSQL)]
    SVC --> RD[(Redis cache / denylist / rate limits)]
    HTTP --> JWKS[JWKS endpoint]
    SVC --> MAIL[SMTP / log mailer]
```

### Login + refresh rotation

```mermaid
sequenceDiagram
    participant C as Client
    participant A as ApexAuth
    participant P as PostgreSQL
    participant R as Redis

    C->>A: POST /api/v1/login (email, password)
    A->>P: verify argon2id hash, create session
    A->>R: cache user roles/permissions
    A-->>C: access token (JWT) + refresh token

    C->>A: POST /api/v1/refresh (refresh_token)
    A->>P: rotation tx: mark parent used, insert child
    A-->>C: new access token + rotated refresh token

    rect rgb(255, 235, 235)
    Note over C,A: Attacker replays the old refresh token
    C->>A: POST /api/v1/refresh (stale token)
    A->>P: parent already used -> reuse detected
    A->>P: REVOKE whole family (family_id)
    A-->>C: unauthorized; family dead
    end
```

### OAuth2 authorization-code + PKCE flow

```mermaid
sequenceDiagram
    participant B as Browser
    participant App as Third-party app
    participant A as ApexAuth
    participant P as PostgreSQL

    B->>App: click "Sign in"
    App->>A: GET /oauth2/authorize (client_id, redirect_uri, state, nonce, code_challenge)
    A-->>B: login page
    B->>A: POST /login (email, password)
    A->>P: authenticate user, create session
    A-->>B: consent page (scopes)
    B->>A: POST /oauth2/consent (allow)
    A->>P: issue one-time code (hashed), record consent
    A-->>B: 302 redirect_uri?code=...&state=...
    App->>A: POST /oauth2/token (code + code_verifier)
    A->>P: consume code (single-use), verify S256(verifier)
    A-->>App: access_token + refresh_token + id_token
    App->>A: GET /oauth2/userinfo (Bearer)
    A-->>App: subject claims
```

## Quickstart

```bash
# Local (requires PostgreSQL + Redis, or use docker compose)
docker compose up -d postgres redis
go run ./cmd/apexauth &          # applies migrations on boot

# Seed 1000+ test users, RBAC roles and the SSO example client
go run ./cmd/seed

# Run the example SSO app (authorization code + PKCE)
go run ./examples/sso-client    # open http://localhost:8090
```

Or everything at once:

```bash
docker compose up --build       # postgres + redis + apexauth + seed + example-app
```

Demo accounts created by `seed`: `admin@apexauth.dev / admin-password` (admin role)
and `member@apexauth.dev / member-password`; bulk users `user0000@apexauth.dev` ..
`user0999@apexauth.dev` / `password123` (member role).

### Console login

```bash
curl -s -X POST localhost:8080/api/v1/login \
  -H 'content-type: application/json' \
  -d '{"email":"admin@apexauth.dev","password":"admin-password"}'
# {"access_token":"eyJ...","refresh_token":"...","expires_in":900, ...}

curl -s localhost:8080/.well-known/jwks.json     # public keys (kid rotation)
curl -s localhost:8080/healthz
```

### Admin REST (RBAC-protected)

```bash
TOKEN=$(curl -s -X POST localhost:8080/api/v1/login \
  -H 'content-type: application/json' \
  -d '{"email":"admin@apexauth.dev","password":"admin-password"}' | jq -r .access_token)

curl -s localhost:8080/api/v1/admin/users -H "authorization: Bearer $TOKEN"
curl -s -X POST localhost:8080/api/v1/admin/roles \
  -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"name":"support","permissions":["users:read","billing:*"]}'
curl -s -X POST localhost:8080/api/v1/admin/users/<user-id>/roles \
  -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"role":"support"}'
```

Wildcards: a role granted `billing:*` covers `billing:read`, `billing:write`, etc.

### gRPC

```bash
grpcurl -plaintext -H "authorization: Bearer $TOKEN" localhost:9090 \
  apexauth.v1.AuthService/ValidateToken -d '{"token":"'$TOKEN'"}'
grpcurl -plaintext localhost:9090 list                 # reflection is on
```

## Configuration

| Env var | Default | Purpose |
|---|---|---|
| `APEXAUTH_HTTP_ADDR` | `:8080` | HTTP listen address |
| `APEXAUTH_GRPC_ADDR` | `:9090` | gRPC listen address |
| `APEXAUTH_BASE_URL` | `http://localhost:8080` | issuer URL used in tokens and OIDC discovery |
| `APEXAUTH_PG_DSN` | `postgres://apexauth:apexauth@localhost:5432/apexauth?sslmode=disable` | PostgreSQL DSN |
| `APEXAUTH_REDIS_ADDR` | `localhost:6379` | Redis address |
| `APEXAUTH_REDIS_PASSWORD` / `APEXAUTH_REDIS_DB` | empty / `0` | Redis auth / db |
| `APEXAUTH_CACHE` | `true` | enable Redis caches (set `false` to compare) |
| `APEXAUTH_SIGN_ALG` | `ed25519` | `ed25519` or `rsa` |
| `APEXAUTH_SIGNING_KEY` | empty | path to an existing PEM private key |
| `APEXAUTH_ACCESS_TTL` | `15m` | access token lifetime |
| `APEXAUTH_REFRESH_TTL` | `720h` | refresh token lifetime |
| `APEXAUTH_SESSION_TTL` | `720h` | session lifetime |
| `APEXAUTH_CODE_TTL` | `5m` | authorization code lifetime |
| `APEXAUTH_PASSWORDLESS_TTL` | `10m` | magic link / OTP lifetime |
| `APEXAUTH_RATE_WINDOW` / `APEXAUTH_RATE_MAX` | `1m` / `10` | login/OTP rate limit |
| `APEXAUTH_LOGIN_ATTEMPTS` | `5` | max password attempts |
| `APEXAUTH_EMAIL_FROM` | `ApexAuth <no-reply@apexauth.local>` | mailer From |
| `APEXAUTH_SMTP_HOST` / `PORT` / `USERNAME` / `PASSWORD` | empty | SMTP mailer (falls back to log mailer) |
| `APEXAUTH_HMAC_SECRET` | generated | login-cookie HMAC key (>= 32 chars; required in production) |
| `APEXAUTH_SEED_USERS` | `1000` | number of test users created by `cmd/seed` |

## Schema & indexes

Migrations live in `migrations/` (embedded in the binary, applied on boot). The
index design is documented inline in `0001_schema.up.sql`; highlights:

- `users (lower(email))` unique — natural key for login, magic link, OTP lookups.
- `refresh_tokens (user_id, family_id)` — fast family-scoped revocation;
  partial index `(expires_at) WHERE NOT used` for the janitor sweep.
- `sessions (user_id, expires_at DESC)` — session listing / revocation.
- `oauth_clients (client_id) WHERE NOT deleted` — partial unique so client ids can
  be soft-deleted and reused.
- `audit_log (actor_id, created_at DESC)` — admin activity queries.

All secrets are stored hashed: passwords as argon2id PHC strings, OAuth client
secrets / authorization codes / magic links / OTPs as SHA-256 digests.

## Project layout

```
cmd/apexauth     HTTP + gRPC server entry point
cmd/seed         creates 1000+ users, RBAC roles, OAuth client
cmd/bench        load tester (login + token validation, cache on/off, p50/p95/p99)
examples/sso-client  minimal OAuth2 code+PKCE SSO web app
internal/store   PostgreSQL data layer (pgx/v5)
internal/cache   Redis caches, denylist, rate limiting
internal/service authn / RBAC / OAuth2 services (the security core)
internal/tokens  JWT signing, Ed25519/RS256 rotation, JWKS
internal/mailer  SMTP + log mailers (pluggable)
internal/migrate embedded migrations
internal/httpapi HTTP + OIDC endpoints + login/consent pages
internal/grpcapi gRPC services + auth interceptor
proto/apexauth/v1  .proto source
gen/apexauth/v1    generated gRPC/protobuf code (committed)
```

## Testing

```bash
go vet ./...
go build ./...
go test -race ./...   # unit + integration (embedded-postgres + miniredis, no external services)
```

- **Unit**: refresh-token rotation/reuse detection, PKCE verification, redirect
  matching, RBAC wildcard matching, passwordless lifecycle, JWT/JWKS rotation,
  argon2id hashing.
- **Integration**: full OAuth authorization-code + PKCE flow over `httptest`
  (authorize -> login -> consent -> code -> token -> userinfo -> refresh rotation
  -> replay detection), gRPC `ValidateToken` / `CheckPermission` / admin RPCs over
  `bufconn`, all against embedded-postgres + miniredis. Tests never require
  external services.

## Performance

Login and token-validation latency with the Redis cache on vs. off, measured by
the bundled in-process harness (`internal/benchtest`). It boots the full HTTP
server against embedded-postgres + miniredis, seeds 500 users, and runs a
15-second 50% login / 50% token-validation workload with 40 concurrent workers
for each mode:

```
$ APEXAUTH_BENCH=1 go test ./internal/benchtest -run TestDriverRun -count=1 -v
cache=on  requests=3536 ok=3536 p50=148.3ms p95=426.8ms p99=577.3ms
cache=off requests=1731 ok=1731 p50=324.5ms p95=460.8ms p99=596.9ms
```

Machine: Apple M3, macOS. argon2id hashing (64 MiB) dominates login latency;
the cache-off path also pays a Postgres round-trip per permission fetch. The
throughput gap (requests completed in the same window) is where the cache shows
most. Against a deployed instance (e.g. `docker compose up` + `go run ./cmd/seed`),
`cmd/bench` runs the same workload over the network:

```
$ go run ./cmd/bench -users 500 -concurrency 40 -duration 15s
```

## Security notes

- Refresh tokens are randomly generated 128-bit values, hashed (SHA-256) at rest,
  and rotate on every use; replay revokes the entire family.
- Authorization codes are single-use, hashed at rest, 5-minute TTL, and bound to
  the issuing client, redirect URI, nonce and PKCE challenge.
- PKCE (S256) is **required** for public clients.
- Passwords are argon2id (64 MiB, t=1, p=4) with per-user salts; login failure
  paths are constant-time against missing credentials.
- JWTs are Ed25519-signed by default with `kid` rotation and a published JWKS;
  the Redis denylist supports immediate revocation by `jti`.
- Rate limiting (login/OTP/magic) is enforced server side; audit events are logged
  for login, password changes, OAuth consents and admin actions.
- Everything is configurable via environment variables; never hard-code secrets
  (see `.env.example`).

## License

MIT — see [LICENSE](LICENSE).
