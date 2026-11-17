CREATE TABLE users (
    id            INTEGER PRIMARY KEY,
    password_hash TEXT NOT NULL DEFAULT '',
    created_at    INTEGER NOT NULL
);

-- Global, strictly increasing change counter used as the sync cursor.
CREATE TABLE counters (
    name  TEXT PRIMARY KEY,
    value INTEGER NOT NULL
);
INSERT INTO counters (name, value) VALUES ('seq', 0);

CREATE TABLE todos (
    user_id    INTEGER NOT NULL REFERENCES users (id),
    id         TEXT NOT NULL,
    title      TEXT NOT NULL,
    day        TEXT NOT NULL,
    minutes    INTEGER,
    done       INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL, -- unix milliseconds
    updated_at INTEGER NOT NULL, -- unix milliseconds
    deleted    INTEGER NOT NULL DEFAULT 0,
    seq        INTEGER NOT NULL,
    PRIMARY KEY (user_id, id)
);
CREATE UNIQUE INDEX todos_seq ON todos (user_id, seq);
CREATE INDEX todos_day ON todos (user_id, deleted, day);

CREATE TABLE devices (
    id           TEXT PRIMARY KEY,
    user_id      INTEGER NOT NULL REFERENCES users (id),
    name         TEXT NOT NULL,
    token_hash   TEXT NOT NULL UNIQUE,
    created_at   INTEGER NOT NULL,
    last_seen_at INTEGER,
    revoked_at   INTEGER
);

CREATE TABLE pair_requests (
    device_code_hash TEXT PRIMARY KEY,
    user_code        TEXT NOT NULL UNIQUE,
    device_name      TEXT NOT NULL,
    created_at       INTEGER NOT NULL,
    expires_at       INTEGER NOT NULL,
    last_poll_at     INTEGER,
    status           TEXT NOT NULL DEFAULT 'pending', -- pending, approved, denied, delivered
    user_id          INTEGER REFERENCES users (id)
);

CREATE TABLE oauth_clients (
    id               TEXT PRIMARY KEY,
    name             TEXT NOT NULL,
    redirect_uris    TEXT NOT NULL, -- JSON array
    secret_hash      TEXT,          -- NULL for public clients
    auth_method      TEXT NOT NULL, -- none, client_secret_post, client_secret_basic
    source           TEXT NOT NULL, -- dcr, cli
    created_at       INTEGER NOT NULL
);

CREATE TABLE oauth_grants (
    id           TEXT PRIMARY KEY,
    user_id      INTEGER NOT NULL REFERENCES users (id),
    client_id    TEXT NOT NULL REFERENCES oauth_clients (id) ON DELETE CASCADE,
    scope        TEXT NOT NULL,
    resource     TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    last_used_at INTEGER,
    revoked_at   INTEGER
);

CREATE TABLE oauth_codes (
    code_hash      TEXT PRIMARY KEY,
    grant_id       TEXT NOT NULL REFERENCES oauth_grants (id) ON DELETE CASCADE,
    redirect_uri   TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    expires_at     INTEGER NOT NULL,
    used           INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE oauth_tokens (
    token_hash TEXT PRIMARY KEY,
    grant_id   TEXT NOT NULL REFERENCES oauth_grants (id) ON DELETE CASCADE,
    kind       TEXT NOT NULL, -- access, refresh
    expires_at INTEGER NOT NULL,
    used       INTEGER NOT NULL DEFAULT 0 -- refresh tokens: rotated
);
CREATE INDEX oauth_tokens_grant ON oauth_tokens (grant_id);

CREATE TABLE web_sessions (
    id_hash    TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users (id),
    csrf       TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
