-- Purser schema — migration 001.
--
-- Two seams are baked in from the very first migration (cheap now, expensive to retrofit):
--   Seam 1: opaque ULID identity. `id` columns are permanent; paths/remotes are projections.
--   Seam 2: capabilities over generic resources (see `grants.resource_type`).
--
-- Value-blind invariant: secret VALUES never live in plaintext. `secrets` has no value
-- column; ciphertext lives only in `secret_versions`; `audit_events` never stores a value.

-- Projects registered for bootstrap. git_remote/branch are projections off `id`, not identity.
CREATE TABLE projects (
    id              TEXT PRIMARY KEY,   -- ULID (seam 1)
    name            TEXT NOT NULL,
    git_remote      TEXT,
    branch          TEXT,
    package_manager TEXT,               -- npm | pnpm | cargo | uv | ...
    profile_ref     TEXT,               -- which secret profile this project uses
    created_at      TEXT NOT NULL
);

-- Secret metadata only. NO value column by design.
CREATE TABLE secrets (
    id         TEXT PRIMARY KEY,        -- ULID (seam 1)
    name       TEXT NOT NULL,
    group_name TEXT,
    profile    TEXT NOT NULL,           -- local | test | staging
    configured INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

-- Encrypted values, versioned. Old versions are retained (safe recovery from a bad edit).
CREATE TABLE secret_versions (
    id         TEXT PRIMARY KEY,        -- ULID
    secret_id  TEXT NOT NULL REFERENCES secrets(id),
    version    INTEGER NOT NULL,
    ciphertext BLOB NOT NULL,           -- encrypted value ONLY — never plaintext
    created_at TEXT NOT NULL,
    UNIQUE (secret_id, version)
);

-- The owner's trusted devices (peer-to-peer). One holds is_self = 1 on each machine.
CREATE TABLE devices (
    id         TEXT PRIMARY KEY,        -- ULID
    label      TEXT NOT NULL,
    public_key BLOB NOT NULL,
    is_self    INTEGER NOT NULL DEFAULT 0,
    paired_at  TEXT NOT NULL
);

-- Seam 2: a capability over a GENERIC resource. v1 only writes resource_type = 'secret';
-- the shape already fits 'file' | 'commit' | 'branch' for the permissioned-git future.
CREATE TABLE grants (
    id            TEXT PRIMARY KEY,     -- ULID
    subject       TEXT NOT NULL,        -- device id / agent session / user
    capability    TEXT NOT NULL,        -- metadata | use | manage
    resource_type TEXT NOT NULL,        -- v1: 'secret'
    resource_id   TEXT NOT NULL,        -- ULID of the resource
    created_at    TEXT NOT NULL
);

-- A human or agent run, with its scope.
CREATE TABLE sessions (
    id         TEXT PRIMARY KEY,        -- ULID
    kind       TEXT NOT NULL,           -- human | agent
    scope      TEXT,                    -- JSON: profile, secret allowlist, use vs metadata-only
    started_at TEXT NOT NULL,
    ended_at   TEXT
);

-- Append-only audit. Every use / injection / denial. Values are NEVER recorded here.
-- prev_hash/hash form a checksum chain so tampering is detectable.
CREATE TABLE audit_events (
    id         TEXT PRIMARY KEY,        -- ULID
    session_id TEXT REFERENCES sessions(id),
    kind       TEXT NOT NULL,           -- used | injected | denied
    secret_ref TEXT,                    -- secret id or name — NOT the value
    decision   TEXT NOT NULL,
    prev_hash  TEXT,
    hash       TEXT NOT NULL,
    created_at TEXT NOT NULL
);

-- Per-peer replication cursor for p2p sync (seam 3 moves opaque encrypted records).
CREATE TABLE sync_state (
    peer_id    TEXT PRIMARY KEY,
    cursor     TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
