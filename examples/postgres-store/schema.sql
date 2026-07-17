-- Reference schema for an authery store over Postgres.
--
-- Nothing here is imposed by authery: table and column names, id types and
-- indexing strategy are all yours. This layout simply mirrors the entity
-- traits one-to-one. Applied idempotently at example startup.

CREATE TABLE IF NOT EXISTS users (
    id            uuid PRIMARY KEY,
    password_hash text
);

CREATE TABLE IF NOT EXISTS user_emails (
    user_id          uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    address          text NOT NULL UNIQUE,
    verified         boolean NOT NULL DEFAULT false,
    allow_link_login boolean NOT NULL DEFAULT false
);

CREATE TABLE IF NOT EXISTS user_phones (
    user_id     uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    number      text NOT NULL UNIQUE,
    verified    boolean NOT NULL DEFAULT false,
    allow_login boolean NOT NULL DEFAULT false
);

CREATE TABLE IF NOT EXISTS sessions (
    id      uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- LoginMethod is serde-serializable; persist it opaquely.
    method  jsonb NOT NULL,
    expires timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions (user_id);

-- Email and SMS challenges share this table; authery namespaces the codes.
CREATE TABLE IF NOT EXISTS challenges (
    code    text PRIMARY KEY,
    address text NOT NULL,
    next    text,
    expires timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS oauth_tokens (
    id               uuid PRIMARY KEY,
    user_id          uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    provider_name    text NOT NULL,
    provider_user_id text NOT NULL,
    access_token     text NOT NULL,
    refresh_token    text,
    expires          timestamptz,
    scopes           text[] NOT NULL DEFAULT '{}',
    UNIQUE (provider_name, provider_user_id)
);

CREATE TABLE IF NOT EXISTS passkeys (
    credential_id bytea PRIMARY KEY,
    user_id       uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- webauthn-rs Passkey blobs are serde-serializable; persist opaquely.
    passkey       jsonb NOT NULL
);

CREATE TABLE IF NOT EXISTS totp_credentials (
    user_id    uuid PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    credential jsonb NOT NULL
);

-- Single-use MFA recovery codes; only hashes are stored.
CREATE TABLE IF NOT EXISTS recovery_codes (
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    hash    text NOT NULL,
    PRIMARY KEY (user_id, hash)
);
