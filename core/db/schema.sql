PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;

-- =========================
-- ENTITIES (core objects)
-- =========================
CREATE TABLE IF NOT EXISTS entities (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,          -- domain, ip, url, email
    value TEXT NOT NULL,
    first_seen TEXT,
    last_seen TEXT,
    confidence REAL DEFAULT 1.0
);

CREATE INDEX IF NOT EXISTS idx_entities_value ON entities(value);
CREATE INDEX IF NOT EXISTS idx_entities_type ON entities(type);

-- =========================
-- RELATIONSHIPS (graph)
-- =========================
CREATE TABLE IF NOT EXISTS relationships (
    id TEXT PRIMARY KEY,
    src_id TEXT,
    dst_id TEXT,
    type TEXT,                   -- resolves_to, hosts, api_call
    confidence REAL DEFAULT 1.0,
    first_seen TEXT,
    last_seen TEXT
);

CREATE INDEX IF NOT EXISTS idx_rel_src ON relationships(src_id);
CREATE INDEX IF NOT EXISTS idx_rel_dst ON relationships(dst_id);

-- =========================
-- OBSERVATIONS (raw module data)
-- =========================
CREATE TABLE IF NOT EXISTS observations (
    id TEXT PRIMARY KEY,
    entity_id TEXT,
    module TEXT,
    data TEXT,                   -- JSON
    timestamp TEXT
);

CREATE INDEX IF NOT EXISTS idx_obs_entity ON observations(entity_id);

-- =========================
-- FINDINGS (intelligence output)
-- =========================
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    entity_id TEXT,
    type TEXT,                   -- takeover, exposed_api
    severity TEXT,               -- P1-P4
    confidence REAL,
    reason TEXT,
    first_seen TEXT,
    last_seen TEXT
);

-- =========================
-- DECISIONS (arbiter brain logs)
-- =========================
CREATE TABLE IF NOT EXISTS decisions (
    id TEXT PRIMARY KEY,
    entity_id TEXT,
    action TEXT,                 -- scan, ignore, prioritize
    reason TEXT,
    timestamp TEXT
);
