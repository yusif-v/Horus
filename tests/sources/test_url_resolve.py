"""URL classification logic — no network required."""

from __future__ import annotations

from horus.core import url_resolve


class TestClassifyDestinationDomain:
    def test_github_repo_is_poc(self):
        assert url_resolve.classify_destination_domain("https://github.com/u/exploit") == (
            "github",
            "poc",
        )

    def test_gitlab_is_poc(self):
        assert url_resolve.classify_destination_domain("https://gitlab.com/u/poc") == (
            "gitlab",
            "poc",
        )

    def test_exploit_db_is_poc(self):
        assert url_resolve.classify_destination_domain(
            "https://www.exploit-db.com/exploits/12345"
        ) == ("exploit-db", "poc")

    def test_pastebin_is_poc(self):
        assert url_resolve.classify_destination_domain("https://pastebin.com/abc123") == (
            "pastebin",
            "poc",
        )

    def test_nvd_is_advisory(self):
        assert url_resolve.classify_destination_domain(
            "https://nvd.nist.gov/vuln/detail/CVE-2026-1111"
        ) == ("web", "advisory")

    def test_news_site_is_advisory(self):
        assert url_resolve.classify_destination_domain(
            "https://thehackernews.com/2026/06/some-cve.html"
        ) == ("web", "advisory")

    def test_vendor_advisory_classified(self):
        assert url_resolve.classify_destination_domain(
            "https://msrc.microsoft.com/update-guide/vuln/CVE-2026-1111"
        ) == ("web", "advisory")

    def test_unknown_domain_defaults_to_advisory(self):
        assert url_resolve.classify_destination_domain(
            "https://random-unrelated-site.example/page"
        ) == ("web", "advisory")

    def test_empty_url_falls_through(self):
        assert url_resolve.classify_destination_domain("") == ("web", "advisory")


class TestResolveUrl:
    def test_resolve_failure_returns_none(self, monkeypatch):
        """Network errors collapse to None — caller treats unresolvable as opaque."""

        def boom(_req, timeout=0):
            raise RuntimeError("DNS failure")

        monkeypatch.setattr(url_resolve.urllib.request, "urlopen", boom)
        assert url_resolve.resolve_url("https://t.co/abc") is None

    def test_resolve_batch_handles_mixed_outcomes(self, monkeypatch):
        """One URL resolves, one fails — both keys present in result."""
        from contextlib import contextmanager

        class FakeResp:
            url = "https://github.com/real/repo"

        @contextmanager
        def fake_open(req, timeout=0):
            if "good" in req.full_url:
                yield FakeResp()
            else:
                raise RuntimeError("nope")

        monkeypatch.setattr(url_resolve.urllib.request, "urlopen", fake_open)

        result = url_resolve.resolve_urls_batch(
            ["https://good.example/x", "https://bad.example/y"], max_workers=2
        )

        assert result["https://good.example/x"] == "https://github.com/real/repo"
        assert result["https://bad.example/y"] is None
