"""news_feed DB layer: AI score columns, news_post table, helpers."""

from __future__ import annotations

from horus.storage import db


def test_news_article_score_columns_exist_after_init():
    db.initialize()
    with db.connect() as conn:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(news_article)")}
    for col in ("ai_score", "ai_rationale", "ai_headline", "ai_summary", "scored_at"):
        assert col in cols


def test_news_post_table_exists_after_init():
    db.initialize()
    with db.connect() as conn:
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='news_post'"
        ).fetchall()
    assert len(rows) == 1


def test_get_unscored_news_and_save_score(tmp_path):
    db.initialize()
    with db.connect() as conn:
        conn.execute(
            "INSERT INTO news_article (title, url, source, tier, summary, first_seen)"
            " VALUES ('A', 'http://a', 'hacker_news', 1, 's', '2026-08-01T00:00:00Z')"
        )
        conn.execute(
            "INSERT INTO news_article (title, url, source, tier, summary, first_seen)"
            " VALUES ('B', 'http://b', 'hacker_news', 3, 's', '2026-08-01T00:00:00Z')"
        )
        unscored = db.get_unscored_news(conn, limit=10)
        assert len(unscored) == 2
        first_id = unscored[0]["id"]
        db.save_news_score(
            conn,
            first_id,
            score=90,
            rationale="r",
            headline="h",
            summary="sm",
            scored_at="2026-08-15T00:00:00Z",
        )
        again = db.get_unscored_news(conn, limit=10)
        assert len(again) == 1  # scored article no longer returned
