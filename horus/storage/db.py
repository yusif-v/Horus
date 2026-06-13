"""SQLite storage layer: schema, vocab seeding, JSON migration, CRUD.

Single source of truth for persistent state. Replaces the JSON files that
used to live under state/ (seen_items.json, last_run.json) — those are
migrated once on first run and then renamed to .migrated.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..config import STATE_DIR
from ..core.model import CVE, PoC, Resource
from ..core.vocab import ATTACK_TAGS, CWE_TO_TAG

DB_PATH = STATE_DIR / "horus.db"
SCHEMA_PATH = Path(__file__).parent / "schema.sql"

# Legacy JSON file paths — kept here for migration only.
STATE_FILE = STATE_DIR / "seen_items.json"
LAST_RUN_FILE = STATE_DIR / "last_run.json"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@contextmanager
def connect() -> Iterator[sqlite3.Connection]:
    """Open the DB, commit on clean exit, always close."""
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


# ─── Schema + vocab seeding ──────────────────────────────────────────────


def _init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA_PATH.read_text())


def _seed_vocab(conn: sqlite3.Connection) -> None:
    conn.executemany(
        "INSERT OR IGNORE INTO attack_tag (name) VALUES (?)",
        [(t,) for t in sorted(ATTACK_TAGS)],
    )
    conn.executemany(
        "INSERT OR IGNORE INTO cwe (id, attack_tag) VALUES (?, ?)",
        list(CWE_TO_TAG.items()),
    )


# ─── One-shot JSON migration ─────────────────────────────────────────────


def _migrate_from_json(conn: sqlite3.Connection) -> tuple[int, int]:
    """Import legacy state/seen_items.json + last_run.json. Returns
    (cves_imported, pocs_imported). Renames source files to .migrated
    so we never re-import."""
    cve_count = 0
    poc_count = 0
    now = _now()

    if STATE_FILE.exists():
        try:
            keys = json.loads(STATE_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            keys = []
        for key in keys:
            if key.startswith("nvd:"):
                cve_id = key[4:]
                conn.execute(
                    "INSERT OR IGNORE INTO cve (id, first_seen, last_seen) VALUES (?, ?, ?)",
                    (cve_id, now, now),
                )
                conn.execute(
                    "INSERT OR IGNORE INTO cve_source (cve_id, source) VALUES (?, ?)",
                    (cve_id, "nvd"),
                )
                cve_count += 1
            elif key.startswith("github:"):
                slug = key[7:]
                url = f"https://github.com/{slug}"
                conn.execute(
                    "INSERT OR IGNORE INTO poc"
                    " (url, source, first_seen, last_seen)"
                    " VALUES (?, ?, ?, ?)",
                    (url, "github", now, now),
                )
                poc_count += 1
        STATE_FILE.rename(STATE_FILE.with_suffix(".json.migrated"))

    if LAST_RUN_FILE.exists():
        try:
            lr = json.loads(LAST_RUN_FILE.read_text())
            for k, v in lr.items():
                conn.execute(
                    "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
                    (f"last_run.{k}", v),
                )
        except (json.JSONDecodeError, OSError):
            pass
        LAST_RUN_FILE.rename(LAST_RUN_FILE.with_suffix(".json.migrated"))

    return cve_count, poc_count


def _migrate_indexes(conn: sqlite3.Connection) -> None:
    """Create any missing indexes (idempotent)."""
    indexes = [
        ("idx_cve_published_at", "cve(published_at)"),
        ("idx_cve_cvss_score", "cve(cvss_score)"),
        ("idx_cve_epss_score", "cve(epss_score)"),
        ("idx_cve_kev", "cve(kev)"),
        ("idx_cve_product_product_id", "cve_product(product_id)"),
        ("idx_cve_attack_tag_tag", "cve_attack_tag(tag)"),
        ("idx_poc_cve_cve_id", "poc_cve(cve_id)"),
        ("idx_poc_source", "poc(source)"),
    ]
    for name, cols in indexes:
        conn.execute(f"CREATE INDEX IF NOT EXISTS {name} ON {cols}")


def _migrate_columns(conn: sqlite3.Connection) -> None:
    """Add columns introduced after the initial schema (idempotent).

    SQLite's CREATE TABLE IF NOT EXISTS does not add columns to an
    existing table, so we manage post-v0.7 columns explicitly here.
    Must run BEFORE _init_schema because some indexes in schema.sql
    reference these columns.
    """
    # Skip if the cve table doesn't exist yet — schema init will create it
    # with these columns already in place.
    has_table = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='cve'"
    ).fetchone()
    if not has_table:
        return
    existing = {row[1] for row in conn.execute("PRAGMA table_info(cve)")}
    additions = [
        ("social_mentions", "INTEGER DEFAULT 0"),
        ("poc_source_count", "INTEGER DEFAULT 0"),
        ("reputation_score", "REAL"),
        ("confidence", "TEXT DEFAULT 'high'"),
    ]
    for col, decl in additions:
        if col not in existing:
            conn.execute(f"ALTER TABLE cve ADD COLUMN {col} {decl}")


def initialize() -> tuple[int, int]:
    """Idempotent setup: schema + vocab + index migration + one-shot migration. Returns
    (cves_migrated, pocs_migrated) — both 0 on subsequent runs."""
    with connect() as conn:
        _migrate_columns(conn)
        _init_schema(conn)
        _seed_vocab(conn)
        _migrate_indexes(conn)
        return _migrate_from_json(conn)


# ─── Read helpers ────────────────────────────────────────────────────────


def list_known_cve_ids(conn: sqlite3.Connection) -> set[str]:
    return {row[0] for row in conn.execute("SELECT id FROM cve")}


def list_known_poc_urls(conn: sqlite3.Connection) -> set[str]:
    return {row[0] for row in conn.execute("SELECT url FROM poc")}


def get_last_run(conn: sqlite3.Connection, source: str) -> str | None:
    row = conn.execute(
        "SELECT value FROM meta WHERE key = ?",
        (f"last_run.{source}",),
    ).fetchone()
    return row[0] if row else None


def mark_run(conn: sqlite3.Connection, source: str) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
        (f"last_run.{source}", _now()),
    )


# ─── Persistence ─────────────────────────────────────────────────────────


def _upsert_product(
    conn: sqlite3.Connection,
    vendor: str,
    product: str,
    category: str,
) -> int:
    row = conn.execute(
        "SELECT id FROM product WHERE vendor = ? AND product = ?",
        (vendor, product),
    ).fetchone()
    if row:
        return int(row[0])
    cur = conn.execute(
        "INSERT INTO product (vendor, product, category) VALUES (?, ?, ?)",
        (vendor, product, category),
    )
    pid = cur.lastrowid
    assert pid is not None
    return pid


def _compute_reputation(cve: CVE) -> float:
    """Compute a composite reputation score (0-10).

    Weighted formula:
      - CVSS base score (0-10): weight 0.35
      - EPSS probability (0-1) scaled to 0-10: weight 0.25
      - KEV bonus: +1.5 if in CISA KEV
      - Social mentions: min(social_mentions * 0.15, 1.0)
      - PoC source count: min(poc_source_count * 0.5, 1.5)
      - Ubiquity bonus: +1.0 if affects a widely-deployed product

    Returns 0.0 if no CVSS score is available.
    """
    from ..core.merge import cve_affects_ubiquitous

    if cve.cvss_score is None:
        return 0.0

    score = cve.cvss_score * 0.35

    if cve.epss_score is not None:
        score += cve.epss_score * 10 * 0.25

    if cve.kev:
        score += 1.5

    score += min(cve.social_mentions * 0.15, 1.0)
    score += min(cve.poc_source_count * 0.5, 1.5)

    if cve_affects_ubiquitous(cve):
        score += 1.0

    return min(score, 10.0)


def persist_cve(conn: sqlite3.Connection, cve: CVE) -> None:
    now = _now()

    # Compute reputation score before persisting
    reputation = _compute_reputation(cve)

    conn.execute(
        """INSERT INTO cve
              (id, description, cvss_score, cvss_severity, published_at,
               epss_score, kev, reputation_score, confidence,
               social_mentions, poc_source_count,
               first_seen, last_seen)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(id) DO UPDATE SET
             description           = COALESCE(excluded.description, cve.description),
             cvss_score            = COALESCE(excluded.cvss_score, cve.cvss_score),
             cvss_severity         = COALESCE(excluded.cvss_severity, cve.cvss_severity),
             published_at          = COALESCE(excluded.published_at, cve.published_at),
             epss_score            = COALESCE(excluded.epss_score, cve.epss_score),
             kev                   = MAX(excluded.kev, cve.kev),
             reputation_score      = COALESCE(excluded.reputation_score, cve.reputation_score),
             confidence            = COALESCE(excluded.confidence, cve.confidence),
             social_mentions       = COALESCE(excluded.social_mentions, cve.social_mentions),
             poc_source_count      = COALESCE(excluded.poc_source_count, cve.poc_source_count),
             last_seen             = excluded.last_seen
        """,
        (
            cve.id,
            cve.description,
            cve.cvss_score,
            cve.cvss_severity,
            cve.published_at.isoformat() if cve.published_at else None,
            cve.epss_score,
            cve.kev,
            reputation,
            cve.confidence,
            cve.social_mentions,
            cve.poc_source_count,
            now,
            now,
        ),
    )

    for tag in cve.attack_tags:
        conn.execute(
            "INSERT OR IGNORE INTO cve_attack_tag (cve_id, tag) VALUES (?, ?)",
            (cve.id, tag),
        )

    for cwe_id in cve.cwe_ids:
        conn.execute("INSERT OR IGNORE INTO cwe (id) VALUES (?)", (cwe_id,))
        conn.execute(
            "INSERT OR IGNORE INTO cve_cwe (cve_id, cwe_id) VALUES (?, ?)",
            (cve.id, cwe_id),
        )

    for ap in cve.affected:
        product_id = _upsert_product(conn, ap.vendor, ap.product, ap.category)
        versions = "; ".join(ap.versions) if ap.versions else None
        conn.execute(
            """INSERT INTO cve_product (cve_id, product_id, versions)
               VALUES (?, ?, ?)
               ON CONFLICT(cve_id, product_id) DO UPDATE
                 SET versions = excluded.versions
            """,
            (cve.id, product_id, versions),
        )

    for source in cve.sources:
        conn.execute(
            "INSERT OR IGNORE INTO cve_source (cve_id, source) VALUES (?, ?)",
            (cve.id, source),
        )


def persist_poc(conn: sqlite3.Connection, poc: PoC) -> None:
    now = _now()
    # Compute age_days dynamically from repo_created_at
    age_days = _compute_age_days(poc.repo_created_at)
    conn.execute(
        """INSERT INTO poc
              (url, source, stars, age_days, description, first_seen, last_seen, repo_created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(url) DO UPDATE SET
             stars           = excluded.stars,
             age_days        = excluded.age_days,
             description     = excluded.description,
             last_seen       = excluded.last_seen,
             repo_created_at = COALESCE(excluded.repo_created_at, poc.repo_created_at)
        """,
        (poc.url, poc.source, poc.stars, age_days, poc.description, now, now, poc.repo_created_at),
    )


def _compute_age_days(repo_created_at: str | None) -> int | None:
    """Compute age in days from an ISO 8601 timestamp."""
    if not repo_created_at:
        return None
    try:
        from datetime import datetime, timezone

        created = datetime.fromisoformat(repo_created_at.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - created).days
    except (ValueError, TypeError):
        return None


def link_poc_to_cve(conn: sqlite3.Connection, poc_url: str, cve_id: str) -> bool:
    """Strict link: only inserts when the CVE already exists in the table.

    Returns True if the link was created (or already existed), False if the
    CVE is unknown and the link was skipped.
    """
    if not conn.execute(
        "SELECT 1 FROM cve WHERE id = ?",
        (cve_id,),
    ).fetchone():
        return False
    conn.execute(
        "INSERT OR IGNORE INTO poc_cve (poc_url, cve_id) VALUES (?, ?)",
        (poc_url, cve_id),
    )
    return True


def persist_watchlist(
    conn: sqlite3.Connection, cve_id: str, source: str, social_mentions: int = 0
) -> None:
    """Insert or update a CVE watchlist entry for signal-only CVEs not yet in NVD."""
    now = _now()
    conn.execute(
        """INSERT INTO cve_watchlist (id, first_seen, social_mentions, source, confidence, resolved)
           VALUES (?, ?, ?, ?, 'low', 0)
           ON CONFLICT(id) DO UPDATE SET
             social_mentions = cve_watchlist.social_mentions + excluded.social_mentions,
             resolved = 0
        """,
        (cve_id.upper(), now, social_mentions, source),
    )


def persist_social_posts(
    conn: sqlite3.Connection,
    signals: list[dict[str, Any]],
    known_cve_ids: set[str],
) -> int:
    """Persist tweet metadata for signals whose cve_id matches a stored CVE.

    Watchlist-only signals are skipped — the CVE row doesn't exist yet, so
    the FK would fail. Returns the number of rows upserted.
    """
    if not signals:
        return 0
    now = _now()
    count = 0
    for sig in signals:
        cve_id = (sig.get("cve_id") or "").upper()
        url = sig.get("tweet_url") or ""
        if not cve_id or not url or cve_id not in known_cve_ids:
            continue
        conn.execute(
            """INSERT INTO cve_social_post
               (cve_id, url, source, screen_name, likes, retweets, replies, views, first_seen)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(cve_id, url) DO UPDATE SET
                 likes     = excluded.likes,
                 retweets  = excluded.retweets,
                 replies   = excluded.replies,
                 views     = excluded.views,
                 screen_name = COALESCE(excluded.screen_name, cve_social_post.screen_name)
            """,
            (
                cve_id,
                url,
                sig.get("source", "x_twitter"),
                sig.get("screen_name") or None,
                int(sig.get("likes") or 0),
                int(sig.get("retweets") or 0),
                int(sig.get("replies") or 0),
                int(sig.get("views") or 0),
                now,
            ),
        )
        count += 1
    return count


def resolve_watchlist(conn: sqlite3.Connection, cve_id: str) -> None:
    """Mark a watchlist entry as resolved (confirmed by NVD)."""
    conn.execute(
        "UPDATE cve_watchlist SET resolved = 1 WHERE id = ?",
        (cve_id.upper(),),
    )


def list_known_resource_urls(conn: sqlite3.Connection) -> set[str]:
    return {row[0] for row in conn.execute("SELECT url FROM security_resource")}


def persist_resource(conn: sqlite3.Connection, resource: Resource) -> None:
    now = _now()
    tags_json = json.dumps(resource.tags) if resource.tags else None
    cve_refs_json = json.dumps(resource.cve_refs) if resource.cve_refs else None
    conn.execute(
        """INSERT INTO security_resource
              (url, resource_type, title, description, source, source_url,
               source_author, engagement_score, tags, cve_refs, stars,
               repo_created_at, first_seen, last_seen)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(url) DO UPDATE SET
             resource_type   = excluded.resource_type,
             title           = COALESCE(excluded.title, security_resource.title),
             description     = COALESCE(excluded.description, security_resource.description),
             source_url      = COALESCE(excluded.source_url, security_resource.source_url),
            source_author   = COALESCE(excluded.source_author, security_resource.source_author),
             engagement_score = MAX(excluded.engagement_score, security_resource.engagement_score),
             tags            = COALESCE(excluded.tags, security_resource.tags),
             cve_refs        = COALESCE(excluded.cve_refs, security_resource.cve_refs),
             stars           = COALESCE(excluded.stars, security_resource.stars),
             repo_created_at = COALESCE(excluded.repo_created_at, security_resource.repo_created_at),
             last_seen       = excluded.last_seen
        """,
        (
            resource.url,
            resource.resource_type,
            resource.title,
            resource.description,
            resource.source,
            resource.source_url,
            resource.source_author,
            resource.engagement_score,
            tags_json,
            cve_refs_json,
            resource.stars,
            resource.repo_created_at,
            now,
            now,
        ),
    )


def fetch_resources(
    page: int = 1,
    per_page: int = 20,
    resource_type_filter: str | None = None,
    source_filter: str | None = None,
    tag_filter: str | None = None,
    sort: str = "newest",
) -> tuple[list[dict], int]:
    conditions: list[str] = []
    params: list = []
    if resource_type_filter:
        conditions.append("resource_type = ?")
        params.append(resource_type_filter)
    if source_filter:
        conditions.append("source = ?")
        params.append(source_filter)
    if tag_filter:
        conditions.append("tags LIKE ?")
        params.append(f'%"{tag_filter}"%')
    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    with connect() as conn:
        total = conn.execute(f"SELECT COUNT(*) FROM security_resource {where}", params).fetchone()[
            0
        ]
        offset = (page - 1) * per_page
        sort_map = {
            "newest": "first_seen DESC",
            "engagement": "engagement_score DESC, first_seen DESC",
            "stars": "stars DESC NULLS LAST, first_seen DESC",
        }
        order_by = sort_map.get(sort, sort_map["newest"])
        rows = conn.execute(
            f"""SELECT url, resource_type, title, description, source, source_url,
                       source_author, engagement_score, tags, cve_refs, stars,
                       repo_created_at, first_seen, last_seen
                FROM security_resource
                {where}
                ORDER BY {order_by} LIMIT ? OFFSET ?""",
            [*params, per_page, offset],
        ).fetchall()
        results = []
        for r in rows:
            d = dict(r)
            d["tags"] = json.loads(d["tags"]) if d.get("tags") else []
            d["cve_ids"] = json.loads(d["cve_refs"]) if d.get("cve_refs") else []
            results.append(d)
        return results, total
