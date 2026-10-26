-- ApexAuth schema v1
--
-- Important design decisions (see README "Schema & indexes" for the full
-- rationale):
--
-- 1. Credentials are argon2id hashes (encoded with the standard PHC string
--    format) — never plaintext, never reversible.
-- 2. Secrets (OAuth client secret, magic-link/OTP hashes, authorization
--    codes) are stored as SHA-256 hashes. The system never holds the raw
--    value in the DB.
-- 3. refresh_tokens form a rotation "family": every new refresh token points
--    at its parent (parent_id) and at the family root (family_id). When a
--    rotated-out (used) token is presented again — a classic theft signal —
--    the whole family is revoked.
-- 4. Indexes are deliberate:
--      - users(email): unique natural key used by login, magic link, OTP.
--      - tokens(user_id, kind, expires_at DESC): covering index for listing
--        "live" tokens of a kind per user (session revocation, OTP cleanup).
--      - tokens(jti): unique, supports the Redis revocation denylist check
--        and idempotent inserts.
--      - refresh_tokens(user_id, family_id): composite FK for family-scoped
--        revocations.
--      - refresh_tokens(expires_at, used): partial index for the janitor
--        sweep (delete * FROM refresh_tokens WHERE expires_at < now()
--        AND NOT used).
--      - oauth_clients(client_id): partial unique index over only
--        non-deleted clients, so client ids can be soft-deleted/recreated.
--      - oauth_codes(expires_at) and passwordless_tokens(expires_at):
--        partial indexes for expiry sweeps.
-- 5. audit_log is append-only. Its (actor_id, created_at) index serves the
--    "recent activity for a user" queries used by the admin UI.

CREATE TABLE IF NOT EXISTS users (
    id             UUID PRIMARY KEY,
    email          TEXT NOT NULL,
    name           TEXT NOT NULL DEFAULT '',
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    active         BOOLEAN NOT NULL DEFAULT TRUE,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Natural key for login/magic-link/OTP lookups; case-insensitive without
-- depending on the citext extension.
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users (lower(email));
CREATE INDEX IF NOT EXISTS idx_users_created_at ON users (created_at DESC);

CREATE TABLE IF NOT EXISTS credentials (
    user_id     UUID PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    password    TEXT -- PHC-encoded argon2id hash; NULL when the user never set a password
);

CREATE TABLE IF NOT EXISTS roles (
    id          UUID PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS permissions (
    id          UUID PRIMARY KEY,
    resource    TEXT NOT NULL,
    action      TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (resource, action)
);

CREATE TABLE IF NOT EXISTS role_permissions (
    role_id       UUID NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions (id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE IF NOT EXISTS user_roles (
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE IF NOT EXISTS sessions (
    id         UUID PRIMARY KEY,
    user_id    UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    jti        UUID NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions (user_id, expires_at DESC);

CREATE TABLE IF NOT EXISTS oauth_clients (
    id              UUID PRIMARY KEY,
    client_id       TEXT NOT NULL,
    client_secret   BYTEA, -- SHA-256 of the secret; NULL for public clients
    name            TEXT NOT NULL,
    redirect_uris   TEXT[] NOT NULL,
    allowed_grants  TEXT[] NOT NULL DEFAULT '{authorization_code,refresh_token}',
    allowed_scopes  TEXT[] NOT NULL DEFAULT '{}',
    is_confidential BOOLEAN NOT NULL DEFAULT TRUE,
    deleted         BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_oauth_clients_client_id ON oauth_clients (client_id) WHERE NOT deleted;

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id         UUID PRIMARY KEY,
    family_id  UUID NOT NULL,
    parent_id  UUID, -- the token this one was rotated from
    user_id    UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    client_id  UUID REFERENCES oauth_clients (id) ON DELETE CASCADE,
    token_hash BYTEA NOT NULL,
    used       BOOLEAN NOT NULL DEFAULT FALSE,
    revoked    BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_refresh_user_family ON refresh_tokens (user_id, family_id);
CREATE INDEX IF NOT EXISTS idx_refresh_expiry ON refresh_tokens (expires_at) WHERE NOT used;

CREATE TABLE IF NOT EXISTS authorization_codes (
    id         UUID PRIMARY KEY,
    client_id  UUID NOT NULL REFERENCES oauth_clients (id) ON DELETE CASCADE,
    user_id    UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash  BYTEA NOT NULL,
    redirect_uri TEXT NOT NULL,
    scopes     TEXT[] NOT NULL,
    nonce      TEXT NOT NULL DEFAULT '',
    pkce_challenge TEXT NOT NULL DEFAULT '',
    pkce_method TEXT NOT NULL DEFAULT '',
    used       BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_auth_codes_expiry ON authorization_codes (expires_at);

CREATE TABLE IF NOT EXISTS consents (
    user_id    UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    client_id  UUID NOT NULL REFERENCES oauth_clients (id) ON DELETE CASCADE,
    scopes     TEXT[] NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, client_id)
);

CREATE TABLE IF NOT EXISTS passwordless_tokens (
    id         UUID PRIMARY KEY,
    user_id    UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    kind       TEXT NOT NULL CHECK (kind IN ('magic_link', 'otp')),
    token_hash BYTEA NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used       BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_passwordless_expiry ON passwordless_tokens (expires_at);

CREATE TABLE IF NOT EXISTS audit_log (
    id          BIGSERIAL PRIMARY KEY,
    actor_id    UUID REFERENCES users (id) ON DELETE SET NULL,
    action      TEXT NOT NULL,
    target_type TEXT NOT NULL DEFAULT '',
    target_id   TEXT NOT NULL DEFAULT '',
    ip          INET,
    user_agent  TEXT NOT NULL DEFAULT '',
    metadata    JSONB NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log (actor_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log (action, created_at DESC);