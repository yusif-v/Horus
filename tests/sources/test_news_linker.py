"""CVE-news linker tests: extraction, snippet, context detection."""

from __future__ import annotations

import sqlite3

from horus.core.news_linker import (
    detect_context,
    extract_cves_from_text,
    extract_links_from_article,
    extract_snippet,
    link_cves_to_news,
)


def _make_conn():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript("""
        CREATE TABLE news_article (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            url TEXT NOT NULL UNIQUE,
            source TEXT NOT NULL,
            tier INTEGER DEFAULT 3,
            summary TEXT,
            published_at TEXT,
            first_seen TEXT NOT NULL
        );
        CREATE TABLE cve (
            id TEXT PRIMARY KEY,
            description TEXT,
            cvss_score REAL,
            cvss_severity TEXT,
            kev INTEGER DEFAULT 0,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL
        );
        CREATE TABLE news_article_cve (
            article_id INTEGER NOT NULL REFERENCES news_article(id) ON DELETE CASCADE,
            cve_id TEXT NOT NULL REFERENCES cve(id) ON DELETE CASCADE,
            snippet TEXT,
            context TEXT,
            linked_at TEXT NOT NULL,
            PRIMARY KEY (article_id, cve_id)
        );
    """)
    return conn


class TestLinkCvesToNews:
    def test_retroactive_match(self):
        conn = _make_conn()
        conn.execute(
            "INSERT INTO cve (id, first_seen, last_seen) VALUES (?, ?, ?)",
            ("CVE-2026-1234", "2026-08-01", "2026-08-01"),
        )
        conn.execute(
            "INSERT INTO news_article (title, url, source, summary, first_seen) VALUES (?, ?, ?, ?, ?)",
            (
                "CVE-2026-1234 exploited",
                "https://example.com/1",
                "cisa",
                "CVE-2026-1234 is actively exploited",
                "2026-08-05",
            ),
        )
        conn.commit()
        result = link_cves_to_news(conn, since_days=7)
        assert result["linked"] >= 1
        row = conn.execute("SELECT cve_id FROM news_article_cve").fetchone()
        assert row[0] == "CVE-2026-1234"

    def test_no_duplicates(self):
        conn = _make_conn()
        conn.execute(
            "INSERT INTO cve (id, first_seen, last_seen) VALUES (?, ?, ?)",
            ("CVE-2026-1234", "2026-08-01", "2026-08-01"),
        )
        conn.execute(
            "INSERT INTO news_article (title, url, source, summary, first_seen) VALUES (?, ?, ?, ?, ?)",
            ("CVE-2026-1234 news", "https://example.com/1", "cisa", "Summary", "2026-08-05"),
        )
        conn.commit()
        link_cves_to_news(conn, since_days=7)
        link_cves_to_news(conn, since_days=7)  # second run
        count = conn.execute("SELECT COUNT(*) FROM news_article_cve").fetchone()[0]
        assert count == 1  # still 1, no duplicate

    def test_skip_unknown_cve(self):
        conn = _make_conn()
        conn.execute(
            "INSERT INTO news_article (title, url, source, summary, first_seen) VALUES (?, ?, ?, ?, ?)",
            ("CVE-9999-9999 unknown", "https://example.com/1", "cisa", "Summary", "2026-08-05"),
        )
        conn.commit()
        result = link_cves_to_news(conn, since_days=7)
        assert result["linked"] == 0

    def test_active_search_critical_only(self):
        conn = _make_conn()
        conn.execute(
            "INSERT INTO cve (id, cvss_score, first_seen, last_seen) VALUES (?, ?, ?, ?)",
            ("CVE-2026-9999", 9.5, "2026-08-05", "2026-08-05"),
        )
        conn.execute(
            "INSERT INTO cve (id, cvss_score, first_seen, last_seen) VALUES (?, ?, ?, ?)",
            ("CVE-2026-0001", 5.0, "2026-08-05", "2026-08-05"),
        )
        conn.commit()
        # Active search should only query RSS for the critical CVE
        critical = conn.execute("SELECT id FROM cve WHERE cvss_score >= 9.0 OR kev = 1").fetchall()
        assert len(critical) == 1
        assert critical[0][0] == "CVE-2026-9999"


def test_extract_single_cve():
    assert extract_cves_from_text("CVE-2026-1234 was found") == ["CVE-2026-1234"]


def test_extract_multiple_cves():
    text = "CVE-2026-1234 and CVE-2026-5678 are critical"
    assert extract_cves_from_text(text) == ["CVE-2026-1234", "CVE-2026-5678"]


def test_extract_case_insensitive():
    assert extract_cves_from_text("cve-2026-1234") == ["CVE-2026-1234"]


def test_extract_no_cves():
    assert extract_cves_from_text("No CVEs here") == []


def test_extract_large_year():
    assert extract_cves_from_text("CVE-2026-123456") == ["CVE-2026-123456"]


def test_snippet_basic():
    text = "A" * 150 + "CVE-2026-1234" + "B" * 150
    snippet = extract_snippet(text, "CVE-2026-1234")
    assert "CVE-2026-1234" in snippet
    assert len(snippet) <= 313


def test_snippet_cve_at_start():
    text = "CVE-2026-1234 is bad" + "X" * 200
    snippet = extract_snippet(text, "CVE-2026-1234")
    assert "CVE-2026-1234" in snippet


def test_snippet_cve_not_found():
    assert extract_snippet("no match", "CVE-2026-1234") == ""


def test_detect_context_active_exploit():
    result = detect_context("CVE actively exploited in the wild")
    assert result["exploit_status"] == "active"


def test_detect_context_poc_available():
    result = detect_context("Proof of concept available for CVE")
    assert result["exploit_status"] == "poC"


def test_detect_context_patched():
    result = detect_context("Patch available for CVE-2026-1234")
    assert result["exploit_status"] == "patched"


def test_detect_context_unknown_status():
    result = detect_context("CVE-2026-1234 was discovered")
    assert result["exploit_status"] == "unknown"


def test_detect_context_severity_critical():
    result = detect_context("Critical vulnerability CVE-2026")
    assert result["severity_mention"] == "critical"


def test_detect_context_severity_high():
    result = detect_context("High severity issue found")
    assert result["severity_mention"] == "high"


def test_detect_context_severity_unknown():
    result = detect_context("Something happened")
    assert result["severity_mention"] == "unknown"


def test_extract_links_from_article_basic():
    article = {"title": "CVE-2026-1234 found", "summary": "actively exploited"}
    links = extract_links_from_article(article)
    assert len(links) == 1
    assert links[0]["cve_id"] == "CVE-2026-1234"
    assert links[0]["context"]["exploit_status"] == "active"


def test_extract_links_from_article_no_cves():
    article = {"title": "No CVEs", "summary": "nothing here"}
    assert extract_links_from_article(article) == []
