"""SQLite storage layer: schema, vocab seeding, JSON migration, CRUD.

Single source of truth for persistent state. Replaces the JSON files that
used to live under state/ (seen_items.json, last_run.json) — those are
migrated once on first run and then renamed to .migrated.
"""

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from ..config import STATE_DIR
from ..core.model import CVE, PoC
from ..core.vocab import ATTACK_TAGS, CWE_TO_TAG

DB_PATH = STATE_DIR / 'horus.db'
SCHEMA_PATH = Path(__file__).parent / 'schema.sql'

# Legacy JSON file paths — kept here for migration only.
STATE_FILE = STATE_DIR / 'seen_items.json'
LAST_RUN_FILE = STATE_DIR / 'last_run.json'


def _now() -> str:
    return datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')


@contextmanager
def connect():
    """Open the DB, commit on clean exit, always close."""
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
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
        'INSERT OR IGNORE INTO attack_tag (name) VALUES (?)',
        [(t,) for t in sorted(ATTACK_TAGS)],
    )
    conn.executemany(
        'INSERT OR IGNORE INTO cwe (id, attack_tag) VALUES (?, ?)',
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
            if key.startswith('nvd:'):
                cve_id = key[4:]
                conn.execute(
                    'INSERT OR IGNORE INTO cve (id, first_seen, last_seen)'
                    ' VALUES (?, ?, ?)',
                    (cve_id, now, now),
                )
                conn.execute(
                    'INSERT OR IGNORE INTO cve_source (cve_id, source)'
                    ' VALUES (?, ?)',
                    (cve_id, 'nvd'),
                )
                cve_count += 1
            elif key.startswith('github:'):
                slug = key[7:]
                url = f'https://github.com/{slug}'
                conn.execute(
                    'INSERT OR IGNORE INTO poc'
                    ' (url, source, first_seen, last_seen)'
                    ' VALUES (?, ?, ?, ?)',
                    (url, 'github', now, now),
                )
                poc_count += 1
        STATE_FILE.rename(STATE_FILE.with_suffix('.json.migrated'))

    if LAST_RUN_FILE.exists():
        try:
            lr = json.loads(LAST_RUN_FILE.read_text())
            for k, v in lr.items():
                conn.execute(
                    'INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)',
                    (f'last_run.{k}', v),
                )
        except (json.JSONDecodeError, OSError):
            pass
        LAST_RUN_FILE.rename(LAST_RUN_FILE.with_suffix('.json.migrated'))

    return cve_count, poc_count


def initialize() -> tuple[int, int]:
    """Idempotent setup: schema + vocab + one-shot migration. Returns
    (cves_migrated, pocs_migrated) — both 0 on subsequent runs."""
    with connect() as conn:
        _init_schema(conn)
        _seed_vocab(conn)
        return _migrate_from_json(conn)


# ─── Read helpers ────────────────────────────────────────────────────────

def list_known_cve_ids(conn: sqlite3.Connection) -> set[str]:
    return {row[0] for row in conn.execute('SELECT id FROM cve')}


def list_known_poc_urls(conn: sqlite3.Connection) -> set[str]:
    return {row[0] for row in conn.execute('SELECT url FROM poc')}


def get_last_run(conn: sqlite3.Connection, source: str) -> str | None:
    row = conn.execute(
        'SELECT value FROM meta WHERE key = ?', (f'last_run.{source}',),
    ).fetchone()
    return row[0] if row else None


def mark_run(conn: sqlite3.Connection, source: str) -> None:
    conn.execute(
        'INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)',
        (f'last_run.{source}', _now()),
    )


# ─── Persistence ─────────────────────────────────────────────────────────

def _upsert_product(
    conn: sqlite3.Connection, vendor: str, product: str, category: str,
) -> int:
    row = conn.execute(
        'SELECT id FROM product WHERE vendor = ? AND product = ?',
        (vendor, product),
    ).fetchone()
    if row:
        return row[0]
    cur = conn.execute(
        'INSERT INTO product (vendor, product, category) VALUES (?, ?, ?)',
        (vendor, product, category),
    )
    return cur.lastrowid


def persist_cve(conn: sqlite3.Connection, cve: CVE) -> None:
    now = _now()
    conn.execute(
        '''INSERT INTO cve
              (id, description, cvss_score, cvss_severity, published_at,
               first_seen, last_seen)
           VALUES (?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(id) DO UPDATE SET
             description   = COALESCE(excluded.description,   cve.description),
             cvss_score    = COALESCE(excluded.cvss_score,    cve.cvss_score),
             cvss_severity = COALESCE(excluded.cvss_severity, cve.cvss_severity),
             published_at  = COALESCE(excluded.published_at,  cve.published_at),
             last_seen     = excluded.last_seen
        ''',
        (
            cve.id, cve.description, cve.cvss_score, cve.cvss_severity,
            cve.published_at.isoformat() if cve.published_at else None,
            now, now,
        ),
    )

    for tag in cve.attack_tags:
        conn.execute(
            'INSERT OR IGNORE INTO cve_attack_tag (cve_id, tag) VALUES (?, ?)',
            (cve.id, tag),
        )

    for cwe_id in cve.cwe_ids:
        conn.execute('INSERT OR IGNORE INTO cwe (id) VALUES (?)', (cwe_id,))
        conn.execute(
            'INSERT OR IGNORE INTO cve_cwe (cve_id, cwe_id) VALUES (?, ?)',
            (cve.id, cwe_id),
        )

    for ap in cve.affected:
        product_id = _upsert_product(conn, ap.vendor, ap.product, ap.category)
        versions = '; '.join(ap.versions) if ap.versions else None
        conn.execute(
            '''INSERT INTO cve_product (cve_id, product_id, versions)
               VALUES (?, ?, ?)
               ON CONFLICT(cve_id, product_id) DO UPDATE
                 SET versions = excluded.versions
            ''',
            (cve.id, product_id, versions),
        )

    for source in cve.sources:
        conn.execute(
            'INSERT OR IGNORE INTO cve_source (cve_id, source) VALUES (?, ?)',
            (cve.id, source),
        )


def persist_poc(conn: sqlite3.Connection, poc: PoC) -> None:
    now = _now()
    conn.execute(
        '''INSERT INTO poc
              (url, source, stars, age_days, description, first_seen, last_seen)
           VALUES (?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(url) DO UPDATE SET
             stars       = excluded.stars,
             age_days    = excluded.age_days,
             description = excluded.description,
             last_seen   = excluded.last_seen
        ''',
        (poc.url, poc.source, poc.stars, poc.age_days, poc.description, now, now),
    )


def link_poc_to_cve(conn: sqlite3.Connection, poc_url: str, cve_id: str) -> bool:
    """Strict link: only inserts when the CVE already exists in the table.

    Returns True if the link was created (or already existed), False if the
    CVE is unknown and the link was skipped.
    """
    if not conn.execute(
        'SELECT 1 FROM cve WHERE id = ?', (cve_id,),
    ).fetchone():
        return False
    conn.execute(
        'INSERT OR IGNORE INTO poc_cve (poc_url, cve_id) VALUES (?, ?)',
        (poc_url, cve_id),
    )
    return True
