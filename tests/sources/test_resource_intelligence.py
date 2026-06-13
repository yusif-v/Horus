"""Tests for the resource intelligence X source."""

from __future__ import annotations

from horus.core.model import Resource
from horus.core.url_extractor import UrlType
from horus.sources.resource_intelligence import (
    _classify_resource_type,
    _extract_tags,
    _source_for_url_type,
)


class TestClassifyResourceType:
    def test_exploit_keywords(self):
        text = "New exploit tool released for CVE-2026-1234 RCE"
        assert _classify_resource_type(text, UrlType.GITHUB_REPO) == "exploit"

    def test_tool_keywords(self):
        text = "Red team tool for lateral movement — check out this pentest framework"
        assert _classify_resource_type(text, UrlType.GITHUB_REPO) == "tool"

    def test_technique_keywords(self):
        text = "New attack technique for privilege escalation on Windows"
        result = _classify_resource_type(text, UrlType.GENERIC)
        assert result == "technique"

    def test_advisory_keywords(self):
        text = "Security advisory released — patch your systems now"
        assert _classify_resource_type(text, UrlType.GENERIC) == "advisory"

    def test_bypass_keywords(self):
        text = "EDR bypass technique using syscalls — full bypass here"
        result = _classify_resource_type(text, UrlType.GITHUB_REPO)
        assert result == "bypass"

    def test_poc_keywords(self):
        text = "Proof of concept for the latest vulnerability — reproducible test case"
        assert _classify_resource_type(text, UrlType.GITHUB_REPO) == "poc"

    def test_disclosure_keywords(self):
        text = "Full disclosure of a zero-day bug bounty report"
        assert _classify_resource_type(text, UrlType.GENERIC) == "disclosure"

    def test_fallback_github_repo(self):
        text = "Interesting project about coding"
        assert _classify_resource_type(text, UrlType.GITHUB_REPO) == "tool"

    def test_fallback_gist(self):
        text = "Some gist content"
        assert _classify_resource_type(text, UrlType.GITHUB_GIST) == "poc"

    def test_fallback_pastebin(self):
        text = "Some interesting content"
        assert _classify_resource_type(text, UrlType.PASTEBIN) == "poc"

    def test_fallback_generic(self):
        text = "Check this out"
        assert _classify_resource_type(text, UrlType.GENERIC) == "tool"

    def test_empty_text(self):
        assert _classify_resource_type("", UrlType.GITHUB_REPO) == "tool"


class TestExtractTags:
    def test_extracts_rce(self):
        text = "New RCE vulnerability in Apache server"
        tags = _extract_tags(text)
        assert "rce" in tags

    def test_extracts_multiple_tags(self):
        text = "Remote code execution via SQL injection in WordPress REST API"
        tags = _extract_tags(text)
        assert "sql injection" in tags

    def test_extracts_rce_tag(self):
        text = "CVE-2026-1234 RCE exploit released"
        tags = _extract_tags(text)
        assert "rce" in tags

    def test_no_tags(self):
        text = "Check out this cool tweet about nothing specific"
        tags = _extract_tags(text)
        assert len(tags) == 0

    def test_caps_at_10_tags(self):
        text = (
            "rce lpe xss sqli csrf ssrf xxe injection buffer overflow use after free race condition"
        )
        tags = _extract_tags(text)
        assert len(tags) <= 10

    def test_no_duplicates(self):
        text = "rce and more rce again"
        tags = _extract_tags(text)
        assert tags.count("rce") == 1


class TestSourceForUrlType:
    def test_github_repo(self):
        assert _source_for_url_type(UrlType.GITHUB_REPO) == "github"

    def test_github_gist(self):
        assert _source_for_url_type(UrlType.GITHUB_GIST) == "github"

    def test_gitlab(self):
        assert _source_for_url_type(UrlType.GITLAB_REPO) == "gitlab"

    def test_pastebin(self):
        assert _source_for_url_type(UrlType.PASTEBIN) == "pastebin"

    def test_generic(self):
        assert _source_for_url_type(UrlType.GENERIC) == "web"

    def test_hackerone(self):
        assert _source_for_url_type(UrlType.HACKERONE) == "hackerone"


class TestResourceDefaults:
    def test_resource_default_engagement(self):
        r = Resource(url="https://example.com", resource_type="tool", source="web")
        assert r.engagement_score == 0

    def test_resource_default_tags(self):
        r = Resource(url="https://example.com", resource_type="tool", source="web")
        assert r.tags == []

    def test_resource_default_cve_refs(self):
        r = Resource(url="https://example.com", resource_type="tool", source="web")
        assert r.cve_refs == []

    def test_resource_with_data(self):
        r = Resource(
            url="https://github.com/user/repo",
            resource_type="exploit",
            source="github",
            title="CVE-2026-1234 PoC",
            description="RCE exploit",
            engagement_score=42,
            tags=["rce", "kernel"],
            cve_refs=["CVE-2026-1234"],
        )
        assert r.url == "https://github.com/user/repo"
        assert r.resource_type == "exploit"
        assert r.engagement_score == 42
        assert r.tags == ["rce", "kernel"]
        assert r.cve_refs == ["CVE-2026-1234"]
