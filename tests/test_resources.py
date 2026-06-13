"""Tests for security resource intelligence system."""

from __future__ import annotations

from horus.core.model import Resource
from horus.core.url_extractor import UrlType


class TestResourceModel:
    def test_create_resource(self):
        r = Resource(
            url="https://github.com/user/repo",
            resource_type="tool",
            source="x_twitter",
            title="Test repo",
            tags=["rce", "kernel"],
            cve_refs=["CVE-2026-1234"],
        )
        assert r.url == "https://github.com/user/repo"
        assert r.resource_type == "tool"
        assert r.source == "x_twitter"
        assert r.tags == ["rce", "kernel"]
        assert r.cve_refs == ["CVE-2026-1234"]
        assert r.engagement_score == 0
        assert r.stars is None

    def test_resource_defaults(self):
        r = Resource(url="https://example.com", resource_type="poc", source="web")
        assert r.title is None
        assert r.description is None
        assert r.tags == []
        assert r.cve_refs == []
        assert r.engagement_score == 0


class TestResourceClassification:
    def test_classify_poc(self):
        from horus.sources.resource_intelligence import _classify_resource_type

        text = "New PoC released for CVE-2026-1234"
        assert _classify_resource_type(text, UrlType.GITHUB_REPO) == "poc"

    def test_classify_exploit(self):
        from horus.sources.resource_intelligence import _classify_resource_type

        text = "Exploit code for Windows kernel vulnerability"
        assert _classify_resource_type(text, UrlType.GITHUB_REPO) == "exploit"

    def test_classify_bypass(self):
        from horus.sources.resource_intelligence import _classify_resource_type

        text = "BitLocker bypass technique using physical access"
        assert _classify_resource_type(text, UrlType.GITHUB_REPO) == "bypass"

    def test_classify_tool(self):
        from horus.sources.resource_intelligence import _classify_resource_type

        text = "Red team tool for lateral movement"
        assert _classify_resource_type(text, UrlType.GITHUB_REPO) == "tool"

    def test_classify_advisory(self):
        from horus.sources.resource_intelligence import _classify_resource_type

        text = "Security advisory: 0day in popular library"
        assert _classify_resource_type(text, UrlType.GENERIC) == "advisory"

    def test_classify_gist_as_poc(self):
        from horus.sources.resource_intelligence import _classify_resource_type

        text = "Check this out"
        assert _classify_resource_type(text, UrlType.GITHUB_GIST) == "poc"

    def test_classify_pastebin_as_poc(self):
        from horus.sources.resource_intelligence import _classify_resource_type

        text = "Some code snippet"
        assert _classify_resource_type(text, UrlType.PASTEBIN) == "poc"

    def test_classify_hackerone_as_disclosure(self):
        from horus.sources.resource_intelligence import _classify_resource_type

        text = "Bug bounty report"
        assert _classify_resource_type(text, UrlType.HACKERONE) == "disclosure"


class TestTagExtraction:
    def test_extract_rce_tag(self):
        from horus.sources.resource_intelligence import _extract_tags

        text = "RCE exploit for CVE-2026-1234 in Windows kernel"
        tags = _extract_tags(text)
        assert "rce" in tags
        assert "kernel" in tags
        assert "windows" in tags

    def test_extract_bitlocker_tag(self):
        from horus.sources.resource_intelligence import _extract_tags

        text = "BitLocker bypass using TPM vulnerability"
        tags = _extract_tags(text)
        assert "bitlocker" in tags
        assert "tpm" in tags

    def test_extract_multiple_tags(self):
        from horus.sources.resource_intelligence import _extract_tags

        text = "LPE via SQL injection in Active Directory"
        tags = _extract_tags(text)
        assert "lpe" in tags
        assert "sql injection" in tags

    def test_max_10_tags(self):
        from horus.sources.resource_intelligence import _extract_tags

        text = "rce lpe xss sqli csrf ssrf xxe command injection file inclusion buffer overflow use-after-free"
        tags = _extract_tags(text)
        assert len(tags) == 10

    def test_case_insensitive(self):
        from horus.sources.resource_intelligence import _extract_tags

        text = "RCE Exploit for LINUX kernel"
        tags = _extract_tags(text)
        assert "rce" in tags
        assert "kernel" in tags


class TestPersistResource:
    def test_persist_and_fetch(self, tmp_path):

        from horus.storage import db as _db

        # Use temp DB
        db_path = tmp_path / "test.db"
        _db.DB_PATH = db_path
        _db.initialize()

        resource = Resource(
            url="https://github.com/test/repo",
            resource_type="tool",
            source="x_twitter",
            title="Test Resource",
            description="A test resource",
            source_url="https://x.com/user/status/123",
            source_author="testuser",
            engagement_score=42,
            tags=["rce", "kernel"],
            cve_refs=["CVE-2026-1234"],
            stars=100,
            repo_created_at="2026-01-01T00:00:00Z",
        )

        with _db.connect() as conn:
            _db.persist_resource(conn, resource)

        # Fetch back
        results, total = _db.fetch_resources(page=1, per_page=20)
        assert total == 1
        assert len(results) == 1
        r = results[0]
        assert r["url"] == "https://github.com/test/repo"
        assert r["resource_type"] == "tool"
        assert r["tags"] == ["rce", "kernel"]
        assert r["engagement_score"] == 42
        assert r["stars"] == 100

    def test_persist_dedup(self, tmp_path):
        from horus.storage import db as _db

        db_path = tmp_path / "test.db"
        _db.DB_PATH = db_path
        _db.initialize()

        r1 = Resource(url="https://example.com", resource_type="poc", source="web", title="First")
        r2 = Resource(
            url="https://example.com", resource_type="tool", source="web", title="Updated"
        )

        with _db.connect() as conn:
            _db.persist_resource(conn, r1)
            _db.persist_resource(conn, r2)

        _, total = _db.fetch_resources(page=1, per_page=20)
        assert total == 1  # Deduplicated by URL

    def test_fetch_with_filters(self, tmp_path):
        from horus.storage import db as _db

        db_path = tmp_path / "test.db"
        _db.DB_PATH = db_path
        _db.initialize()

        resources = [
            Resource(url="https://a.com", resource_type="poc", source="x_twitter"),
            Resource(url="https://b.com", resource_type="tool", source="github"),
            Resource(url="https://c.com", resource_type="poc", source="pastebin"),
        ]

        with _db.connect() as conn:
            for r in resources:
                _db.persist_resource(conn, r)

        # Filter by type
        _, total = _db.fetch_resources(page=1, per_page=20, resource_type_filter="poc")
        assert total == 2

        # Filter by source
        _, total = _db.fetch_resources(page=1, per_page=20, source_filter="github")
        assert total == 1

    def test_fetch_sort_engagement(self, tmp_path):
        from horus.storage import db as _db

        db_path = tmp_path / "test.db"
        _db.DB_PATH = db_path
        _db.initialize()

        resources = [
            Resource(url="https://a.com", resource_type="poc", source="web", engagement_score=10),
            Resource(url="https://b.com", resource_type="tool", source="web", engagement_score=100),
            Resource(
                url="https://c.com", resource_type="exploit", source="web", engagement_score=50
            ),
        ]

        with _db.connect() as conn:
            for r in resources:
                _db.persist_resource(conn, r)

        results, total = _db.fetch_resources(page=1, per_page=20, sort="engagement")
        assert total == 3
        assert results[0]["engagement_score"] == 100
        assert results[-1]["engagement_score"] == 10
