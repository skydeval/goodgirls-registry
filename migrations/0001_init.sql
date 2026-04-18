-- Initial schema (DESIGN §3).
--
-- No foreign keys between handles and secrets: their lifecycles are
-- intentionally independent, so the tables stay decoupled.

CREATE TABLE IF NOT EXISTS handles (
    subdomain   TEXT PRIMARY KEY,
    did         TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_handles_did ON handles(did);

CREATE TABLE IF NOT EXISTS secrets (
    did         TEXT PRIMARY KEY,
    secret_hash TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sessions (
    session_id  TEXT PRIMARY KEY,
    csrf_token  TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at  TEXT NOT NULL
);
