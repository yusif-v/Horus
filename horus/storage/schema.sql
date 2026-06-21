-- Horus SQLite schema. Idempotent — safe to run on every startup.
PRAGMA foreign_keys = ON;

-- ─── Primary entities ────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS cve (
    id              TEXT PRIMARY KEY,
    description     TEXT,                       -- nullable: stub rows from JSON migration
    cvss_score      REAL,
    cvss_severity   TEXT,
    published_at    TEXT,
    epss_score      REAL,                       -- EPSS probability (0-1)
    kev             INTEGER DEFAULT 0,          -- CISA Known Exploited (0/1)
    exploitability_score REAL,                  -- legacy: kept for backward compat
    social_mentions INTEGER DEFAULT 0,          -- how many X posts mention this CVE
    poc_source_count INTEGER DEFAULT 0,         -- how many distinct signal sources have PoCs
    reputation_score REAL,                      -- computed composite (0-10)
    confidence      TEXT DEFAULT 'high',        -- high | medium | low
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS poc (
    url             TEXT PRIMARY KEY,
    source          TEXT NOT NULL,              -- github | gitlab | exploit-db | pastebin | web | manual
    stars           INTEGER,
    age_days        INTEGER,                    -- Deprecated: computed dynamically from repo_created_at
    description     TEXT,
    fetched_date    TEXT,                       -- when PoC was fetched from external source
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL,
    repo_created_at TEXT                        -- ISO 8601: when the repo/resource was created at source
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
CREATE INDEX IF NOT EXISTS idx_cve_epss_score          ON cve(epss_score);
CREATE INDEX IF NOT EXISTS idx_cve_kev                ON cve(kev);
CREATE INDEX IF NOT EXISTS idx_cve_product_product_id  ON cve_product(product_id);
CREATE INDEX IF NOT EXISTS idx_cve_attack_tag_tag      ON cve_attack_tag(tag);
CREATE INDEX IF NOT EXISTS idx_poc_cve_cve_id          ON poc_cve(cve_id);
CREATE INDEX IF NOT EXISTS idx_poc_source              ON poc(source);

CREATE INDEX IF NOT EXISTS idx_cve_reputation_score     ON cve(reputation_score);
CREATE INDEX IF NOT EXISTS idx_cve_social_mentions      ON cve(social_mentions);
CREATE INDEX IF NOT EXISTS idx_cve_poc_source_count     ON cve(poc_source_count);
CREATE INDEX IF NOT EXISTS idx_cve_confidence           ON cve(confidence);

-- ─── Social posts (X tweets mentioning a CVE) ────────────────────────────

CREATE TABLE IF NOT EXISTS cve_social_post (
    cve_id          TEXT NOT NULL REFERENCES cve(id) ON DELETE CASCADE,
    url             TEXT NOT NULL,                 -- canonical post URL
    source          TEXT NOT NULL,                 -- x_twitter | (future: news, mastodon, ...)
    screen_name     TEXT,
    likes           INTEGER DEFAULT 0,
    retweets        INTEGER DEFAULT 0,
    replies         INTEGER DEFAULT 0,
    views           INTEGER DEFAULT 0,
    posted_at       TEXT,                          -- ISO-8601 if known
    first_seen      TEXT NOT NULL,
    PRIMARY KEY (cve_id, url)
);

CREATE INDEX IF NOT EXISTS idx_cve_social_post_cve_id ON cve_social_post(cve_id);

-- ─── Watchlist (signal-only CVEs not yet in NVD) ──────────────────────────

CREATE TABLE IF NOT EXISTS cve_watchlist (
    id              TEXT PRIMARY KEY,
    first_seen      TEXT NOT NULL,
    social_mentions INTEGER DEFAULT 0,
    source          TEXT NOT NULL,     -- which signal source found it
    confidence      TEXT DEFAULT 'low',
    resolved        INTEGER DEFAULT 0  -- 1 when NVD confirms it
);

-- ─── Triage state (per-CVE workflow) ─────────────────────────────────────
-- One row per CVE; rows are created lazily the first time an analyst
-- touches a CVE. Default-absent rows are treated as status='new'.

CREATE TABLE IF NOT EXISTS cve_triage (
    cve_id          TEXT PRIMARY KEY REFERENCES cve(id) ON DELETE CASCADE,
    status          TEXT NOT NULL DEFAULT 'new'
                    CHECK (status IN ('new', 'acknowledged', 'working',
                                      'dismissed', 'done')),
    assigned_to     INTEGER REFERENCES user(id) ON DELETE SET NULL,
    note            TEXT,
    updated_at      TEXT NOT NULL,
    updated_by      INTEGER REFERENCES user(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_cve_triage_status ON cve_triage(status);
CREATE INDEX IF NOT EXISTS idx_cve_triage_assignee ON cve_triage(assigned_to);

-- ─── Per-team watchlist (red/blue) ────────────────────────────────────────

CREATE TABLE IF NOT EXISTS team_watchlist (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    team            TEXT NOT NULL CHECK (team IN ('red', 'blue')),
    vendor          TEXT NOT NULL,
    product         TEXT NOT NULL DEFAULT '',   -- '' = any product from vendor
    note            TEXT,
    created_at      TEXT NOT NULL,
    created_by      INTEGER REFERENCES user(id) ON DELETE SET NULL,
    UNIQUE (team, vendor, product)
);

CREATE INDEX IF NOT EXISTS idx_team_watchlist_team   ON team_watchlist(team);
CREATE INDEX IF NOT EXISTS idx_team_watchlist_vendor ON team_watchlist(vendor);

-- ─── User management ─────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS role (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT NOT NULL UNIQUE,          -- admin | analyst | viewer
    description     TEXT
);

CREATE TABLE IF NOT EXISTS user (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT NOT NULL UNIQUE,
    email           TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,
    is_active       INTEGER DEFAULT 1,
    team            TEXT NOT NULL DEFAULT 'none'
                    CHECK (team IN ('red', 'blue', 'both', 'none')),
    created_at      TEXT NOT NULL,
    last_login      TEXT,
    -- v0.10: Telegram link state. NULL until the user completes deep-link.
    telegram_chat_id    INTEGER UNIQUE,
    telegram_username   TEXT,
    telegram_linked_at  TEXT
);

-- One-time deep-link tokens. Created when a user clicks "Connect Telegram";
-- consumed when the bot receives /start <token>. Single-use, time-limited.
CREATE TABLE IF NOT EXISTS telegram_link_token (
    token       TEXT PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES user(id) ON DELETE CASCADE,
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    used_at     TEXT
);

CREATE INDEX IF NOT EXISTS idx_telegram_link_token_user ON telegram_link_token(user_id);

-- Per-user notification category toggles. Default-absent kinds use the
-- DEFAULT_PREFS map in horus/web/notifications.py.
CREATE TABLE IF NOT EXISTS notification_pref (
    user_id     INTEGER NOT NULL REFERENCES user(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL,
    enabled     INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (user_id, kind)
);

CREATE TABLE IF NOT EXISTS user_role (
    user_id         INTEGER NOT NULL REFERENCES user(id) ON DELETE CASCADE,
    role_id         INTEGER NOT NULL REFERENCES role(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

-- ─── Audit log ────────────────────────────────────────────────────────────
-- Append-only record of security-relevant mutations. `actor_username` is
-- denormalized so events survive deletion of the acting user.

CREATE TABLE IF NOT EXISTS audit_event (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              TEXT NOT NULL,
    actor_id        INTEGER REFERENCES user(id) ON DELETE SET NULL,
    actor_username  TEXT,                           -- denormalized snapshot
    action          TEXT NOT NULL,                  -- e.g. user.create, watchlist.add
    target_type     TEXT NOT NULL,                  -- user | watchlist | …
    target_id       TEXT,                           -- stringified PK
    before_json     TEXT,                           -- JSON snapshot, nullable
    after_json      TEXT                            -- JSON snapshot, nullable
);

CREATE INDEX IF NOT EXISTS idx_audit_event_ts        ON audit_event(ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_event_actor     ON audit_event(actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_event_action    ON audit_event(action);

CREATE INDEX IF NOT EXISTS idx_user_username ON user(username);
CREATE INDEX IF NOT EXISTS idx_user_email ON user(email);
CREATE INDEX IF NOT EXISTS idx_user_role_user_id ON user_role(user_id);
CREATE INDEX IF NOT EXISTS idx_user_role_role_id ON user_role(role_id);

-- ─── Security resources (broad intelligence beyond CVE-linked PoCs) ──────

CREATE TABLE IF NOT EXISTS security_resource (
    url             TEXT PRIMARY KEY,
    resource_type   TEXT NOT NULL,  -- poc / exploit / tool / technique / advisory / bypass / disclosure
    title           TEXT,
    description     TEXT,
    source          TEXT NOT NULL,  -- x_twitter / github / gitlab / pastebin / web
    source_url      TEXT,           -- original tweet/post URL
    source_author   TEXT,           -- tweet author screen name
    engagement_score INTEGER DEFAULT 0,  -- likes + retweets*3 + replies
    tags            TEXT,           -- JSON array of tags
    cve_refs        TEXT,           -- JSON array of CVE IDs (if any)
    stars           INTEGER,        -- GitHub stars if applicable
    repo_created_at TEXT,           -- ISO 8601
    tweet_created_at TEXT,          -- ISO 8601: when the original tweet/post was published
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_security_resource_type ON security_resource(resource_type);
CREATE INDEX IF NOT EXISTS idx_security_resource_source ON security_resource(source);
CREATE INDEX IF NOT EXISTS idx_security_resource_engagement ON security_resource(engagement_score);
CREATE INDEX IF NOT EXISTS idx_security_resource_first_seen ON security_resource(first_seen);
CREATE INDEX IF NOT EXISTS idx_security_resource_tweet_created ON security_resource(tweet_created_at);

-- ─── News articles (RSS feed items) ───────────────────────────────────────

CREATE TABLE IF NOT EXISTS news_article (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    title           TEXT NOT NULL,
    url             TEXT NOT NULL UNIQUE,
    source          TEXT NOT NULL,              -- feed key (cisa, hacker_news, etc.)
    tier            INTEGER NOT NULL DEFAULT 3, -- 1 (critical) .. 5 (noise)
    summary         TEXT,
    published_at    TEXT,
    first_seen      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_news_article_source ON news_article(source);
CREATE INDEX IF NOT EXISTS idx_news_article_tier ON news_article(tier);
CREATE INDEX IF NOT EXISTS idx_news_article_published ON news_article(published_at);
CREATE INDEX IF NOT EXISTS idx_news_article_first_seen ON news_article(first_seen);
