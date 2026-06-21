"""news_article table must be created by initialize() and survive re-init."""

from __future__ import annotations

import sqlite3

from horus.storage import db


def _columns(conn, table: str) -> set[str]:
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}


def test_initialize_creates_news_article_table(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "horus.db")
    db.initialize()
    with sqlite3.connect(db.DB_PATH) as conn:
        tables = {
            row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
    assert "news_article" in tables


def test_news_article_table_has_expected_columns(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "horus.db")
    db.initialize()
    with sqlite3.connect(db.DB_PATH) as conn:
        cols = _columns(conn, "news_article")
    for required in ("id", "title", "url", "source", "tier", "published_at", "first_seen"):
        assert required in cols, f"missing column: {required}"


def test_initialize_is_idempotent_with_news_article(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "horus.db")
    db.initialize()
    db.initialize()  # second pass must not raise
