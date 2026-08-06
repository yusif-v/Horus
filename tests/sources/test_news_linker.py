"""CVE-news linker tests: extraction, snippet, context detection."""

from __future__ import annotations

from horus.sources.news_linker import (
    detect_context,
    extract_cves_from_text,
    extract_links_from_article,
    extract_snippet,
)


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
