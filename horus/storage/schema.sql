-- Horus SQLite schema. Idempotent — safe to run on every startup.
PRAGMA foreign_keys = ON;

-- ─── Primary entities ────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS cve (
    id              TEXT PRIMARY KEY,
    description     TEXT,                       -- nullable: stub rows from JSON migration
    cvss_score      REAL,
    cvss_severity   TEXT,
    published_at    TEXT,
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS poc (
    url             TEXT PRIMARY KEY,
    source          TEXT NOT NULL,              -- github | gitlab | exploit-db
    stars           INTEGER,
    age_days        INTEGER,
    description     TEXT,
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS product (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    vendor          TEXT NOT NULL,
    product         TEXT NOT NULL,
    category        TEXT NOT NULL,              -- from PRODUCT_CATEGORIES
    UNIQUE (vendor, product)
);

CREATE TABLE IF NOT EXISTS attack_tag (
    name            TEXT PRIMARY KEY            -- from ATTACK_TAGS
);

CREATE TABLE IF NOT EXISTS cwe (
    id              TEXT PRIMARY KEY,
    attack_tag      TEXT REFERENCES attack_tag(name)
);

-- ─── Join tables (also the graph edges) ──────────────────────────────────

CREATE TABLE IF NOT EXISTS cve_attack_tag (
    cve_id          TEXT NOT NULL REFERENCES cve(id) ON DELETE CASCADE,
    tag             TEXT NOT NULL REFERENCES attack_tag(name),
    PRIMARY KEY (cve_id, tag)
);

CREATE TABLE IF NOT EXISTS cve_cwe (
    cve_id          TEXT NOT NULL REFERENCES cve(id) ON DELETE CASCADE,
    cwe_id          TEXT NOT NULL REFERENCES cwe(id),
    PRIMARY KEY (cve_id, cwe_id)
);

CREATE TABLE IF NOT EXISTS cve_product (
    cve_id          TEXT NOT NULL REFERENCES cve(id) ON DELETE CASCADE,
    product_id      INTEGER NOT NULL REFERENCES product(id),
    versions        TEXT,
    PRIMARY KEY (cve_id, product_id)
);

CREATE TABLE IF NOT EXISTS cve_source (
    cve_id          TEXT NOT NULL REFERENCES cve(id) ON DELETE CASCADE,
    source          TEXT NOT NULL,              -- nvd | github | ...
    PRIMARY KEY (cve_id, source)
);

CREATE TABLE IF NOT EXISTS poc_cve (
    poc_url         TEXT NOT NULL REFERENCES poc(url) ON DELETE CASCADE,
    cve_id          TEXT NOT NULL REFERENCES cve(id) ON DELETE CASCADE,
    PRIMARY KEY (poc_url, cve_id)
);

-- ─── Run metadata (replaces last_run.json) ───────────────────────────────

CREATE TABLE IF NOT EXISTS meta (
    key             TEXT PRIMARY KEY,
    value           TEXT NOT NULL
);

-- ─── Indexes ─────────────────────────────────────────────────────────────

CREATE INDEX IF NOT EXISTS idx_cve_published_at        ON cve(published_at);
CREATE INDEX IF NOT EXISTS idx_cve_cvss_score          ON cve(cvss_score);
CREATE INDEX IF NOT EXISTS idx_cve_product_product_id  ON cve_product(product_id);
CREATE INDEX IF NOT EXISTS idx_cve_attack_tag_tag      ON cve_attack_tag(tag);
CREATE INDEX IF NOT EXISTS idx_poc_cve_cve_id          ON poc_cve(cve_id);
CREATE INDEX IF NOT EXISTS idx_poc_source              ON poc(source);
