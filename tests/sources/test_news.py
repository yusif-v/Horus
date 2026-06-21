"""News source plugin — RSS fetcher + tier classification."""

from __future__ import annotations

from horus.core.context import SourceContext
from horus.sources import news


def test_source_metadata():
    assert news.NAME == "News/RSS Feed"
    assert news.KIND == "news"
    assert news.DEFAULT_ENABLED is True


def test_classify_tier_critical():
    """CISA + KEV keywords → tier 1."""
    assert news._classify_tier("CISA Alert: KEV update for Apache RCE", "") == 1


def test_classify_tier_high():
    """CVE/RCE keywords → tier 2."""
    assert news._classify_tier("New CVE-2026-1234 RCE in Windows", "") == 2


def test_classify_tier_medium():
    """Security news keywords → tier 3."""
    assert news._classify_tier("Security patch Tuesday updates", "") == 3


def test_classify_tier_low():
    """No keywords match → tier 4 (default from feed config)."""
    assert news._classify_tier("Tech industry roundup", "Some article") == 4


def test_classify_tier_title_and_summary_combined():
    """Keywords in summary should also be checked."""
    assert news._classify_tier("Weekly digest", "CISA adds new KEV entries") == 1


def test_run_persists_articles(monkeypatch, tmp_path):
    """run() should persist articles directly to news_article table."""
    import horus.storage.db as db

    monkeypatch.setattr(db, "DB_PATH", tmp_path / "horus.db")
    db.initialize()

    # Mock feedparser.parse
    fake_entry = type(
        "Entry",
        (),
        {
            "title": "CISA Alert: Critical KEV Update",
            "link": "https://cisa.gov/alert/1",
            "summary": "CISA added new KEV entries",
            "published_parsed": None,
        },
    )()
    fake_feed = type(
        "Feed",
        (),
        {
            "entries": [fake_entry],
            "feed": type("FeedInfo", (), {"title": "CISA Alerts"})(),
        },
    )()
    monkeypatch.setattr("horus.sources.news.feedparser.parse", lambda url: fake_feed)

    ctx = SourceContext()
    result = news.run(ctx)

    assert result == {}
    with db.connect() as conn:
        rows = conn.execute("SELECT title, source, tier FROM news_article").fetchall()
    assert len(rows) == 1
    assert rows[0][0] == "CISA Alert: Critical KEV Update"
    assert rows[0][1] == "cisa"
    assert rows[0][2] == 1  # tier 1: CISA + KEV


def test_run_skips_duplicate_urls(monkeypatch, tmp_path):
    """run() should skip articles with URLs already in the DB."""
    import horus.storage.db as db

    monkeypatch.setattr(db, "DB_PATH", tmp_path / "horus.db")
    db.initialize()

    fake_entry = type(
        "Entry",
        (),
        {
            "title": "Same article",
            "link": "https://example.com/article-1",
            "summary": "Summary",
            "published_parsed": None,
        },
    )()
    fake_feed = type(
        "Feed",
        (),
        {
            "entries": [fake_entry],
            "feed": type("FeedInfo", (), {"title": "Test"})(),
        },
    )()
    monkeypatch.setattr("horus.sources.news.feedparser.parse", lambda url: fake_feed)

    # First run
    news.run(SourceContext())
    # Second run with same URL
    news.run(SourceContext())

    with db.connect() as conn:
        count = conn.execute("SELECT COUNT(*) FROM news_article").fetchone()[0]
    assert count == 1


def test_run_handles_feedparser_error(monkeypatch, tmp_path):
    """run() should handle feedparser errors gracefully."""
    import horus.storage.db as db

    monkeypatch.setattr(db, "DB_PATH", tmp_path / "horus.db")
    db.initialize()

    monkeypatch.setattr(
        "horus.sources.news.feedparser.parse", lambda url: (_ for _ in ()).throw(Exception("boom"))
    )

    result = news.run(SourceContext())
    assert result == {}
