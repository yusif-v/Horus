"""DB schema migration must be idempotent and additive for v0.7 → v0.8."""

from __future__ import annotations

import sqlite3

from horus.storage import db


def _columns(conn, table: str) -> set[str]:
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}


def test_initialize_creates_v08_columns_on_fresh_db(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "horus.db")
    db.initialize()
    with sqlite3.connect(db.DB_PATH) as conn:
        cols = _columns(conn, "cve")
    for required in ("social_mentions", "poc_source_count",
                     "reputation_score", "confidence"):
        assert required in cols, f"missing column: {required}"


def test_initialize_is_idempotent(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "horus.db")
    db.initialize()
    db.initialize()  # second pass must not raise


def test_migration_adds_columns_to_existing_v07_cve_table(tmp_path, monkeypatch):
    """Simulate a v0.7 DB (no new columns) → initialize() must add them."""
    db_path = tmp_path / "horus.db"
    monkeypatch.setattr(db, "DB_PATH", db_path)
    # Create a v0.7-shaped cve table directly, then run initialize().
    with sqlite3.connect(db_path) as conn:
        conn.execute("""
            CREATE TABLE cve (
                id TEXT PRIMARY KEY,
                description TEXT,
                cvss_score REAL,
                cvss_severity TEXT,
                published_at TEXT,
                epss_score REAL,
                kev INTEGER DEFAULT 0,
                exploitability_score REAL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL
            )
        """)
    db.initialize()
    with sqlite3.connect(db_path) as conn:
        cols = _columns(conn, "cve")
    for required in ("social_mentions", "poc_source_count",
                     "reputation_score", "confidence"):
        assert required in cols, f"migration missed: {required}"
