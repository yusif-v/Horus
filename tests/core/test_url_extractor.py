"""Tests for URL extraction and categorization."""

from __future__ import annotations

from horus.core.url_extractor import (
    UrlType,
    canonicalize_url,
    extract_urls,
    extract_urls_by_type,
    normalize_url,
)


class TestNormalizeUrl:
    def test_strips_trailing_punctuation(self):
        assert normalize_url("https://example.com.") == "https://example.com"
        assert normalize_url("https://example.com,") == "https://example.com"
        assert normalize_url("https://example.com)") == "https://example.com"
        assert normalize_url('https://example.com"') == "https://example.com"

    def test_strips_fragment(self):
        assert normalize_url("https://example.com/page#section") == "https://example.com/page"

    def test_no_change_clean_url(self):
        assert normalize_url("https://example.com/page") == "https://example.com/page"


class TestCanonicalizeUrl:
    def test_github_repo(self):
        url = "https://github.com/user/repo/blob/main/README.md"
        assert canonicalize_url(url, UrlType.GITHUB_REPO) == "https://github.com/user/repo"

    def test_github_gist(self):
        url = "https://gist.github.com/abc123/def456"
        assert canonicalize_url(url, UrlType.GITHUB_GIST) == "https://gist.github.com/abc123/def456"

    def test_github_raw_maps_to_repo(self):
        url = "https://raw.githubusercontent.com/user/repo/main/poc.py"
        assert canonicalize_url(url, UrlType.GITHUB_RAW) == "https://github.com/user/repo"

    def test_gitlab_repo(self):
        url = "https://gitlab.com/user/repo/-/blob/main/README.md"
        assert canonicalize_url(url, UrlType.GITLAB_REPO) == "https://gitlab.com/user/repo"

    def test_pastebin(self):
        url = "https://pastebin.com/raw/AbCdEfGh"
        assert canonicalize_url(url, UrlType.PASTEBIN) == "https://pastebin.com/AbCdEfGh"

    def test_hackerone(self):
        url = "https://hackerone.com/reports/12345"
        assert canonicalize_url(url, UrlType.HACKERONE) == url


class TestExtractUrls:
    def test_github_repo(self):
        text = "Check this PoC: https://github.com/user/CVE-2026-1234"
        results = extract_urls(text)
        github = [r for r in results if r.url_type == UrlType.GITHUB_REPO]
        assert len(github) == 1
        assert github[0].canonical_url == "https://github.com/user/CVE-2026-1234"

    def test_gitlab_repo(self):
        text = "PoC here: https://gitlab.com/security/CVE-2026-poc"
        results = extract_urls(text)
        gitlab = [r for r in results if r.url_type == UrlType.GITLAB_REPO]
        assert len(gitlab) == 1

    def test_pastebin(self):
        text = "Exploit: https://pastebin.com/AbCdEfGh"
        results = extract_urls(text)
        pastebin = [r for r in results if r.url_type == UrlType.PASTEBIN]
        assert len(pastebin) == 1

    def test_hackerone(self):
        text = "Disclosure: https://hackerone.com/reports/12345"
        results = extract_urls(text)
        h1 = [r for r in results if r.url_type == UrlType.HACKERONE]
        assert len(h1) == 1

    def test_github_gist(self):
        text = "Gist: https://gist.github.com/user/abc123def456"
        results = extract_urls(text)
        gists = [r for r in results if r.url_type == UrlType.GITHUB_GIST]
        assert len(gists) == 1

    def test_raw_github(self):
        text = "Raw: https://raw.githubusercontent.com/user/repo/main/poc.py"
        results = extract_urls(text)
        raw = [r for r in results if r.url_type == UrlType.GITHUB_RAW]
        assert len(raw) == 1

    def test_generic_url(self):
        text = "See: https://example.com/poc/CVE-2026-1234"
        results = extract_urls(text)
        generic = [r for r in results if r.url_type == UrlType.GENERIC]
        assert len(generic) == 1

    def test_deduplicates_by_canonical_url(self):
        text = "Same repo: https://github.com/user/repo and https://github.com/user/repo/blob/main/README.md"
        results = extract_urls(text)
        github = [r for r in results if r.url_type == UrlType.GITHUB_REPO]
        assert len(github) == 1  # Deduplicated to single canonical URL

    def test_multiple_urls_same_text(self):
        text = "GitHub: https://github.com/user/repo Pastebin: https://pastebin.com/AbCd"
        results = extract_urls(text)
        types = {r.url_type for r in results}
        assert UrlType.GITHUB_REPO in types
        assert UrlType.PASTEBIN in types

    def test_no_urls(self):
        text = "This is just plain text with no links"
        results = extract_urls(text)
        assert len(results) == 0

    def test_excludes_github_non_repo_paths(self):
        text = "Issues: https://github.com/user/repo/issues/1"
        results = extract_urls(text)
        # Should not match as GITHUB_REPO since /issues/ is in the path
        github_repos = [r for r in results if r.url_type == UrlType.GITHUB_REPO]
        assert len(github_repos) == 0


class TestExtractUrlsByType:
    def test_filter_by_type(self):
        text = "GH: https://github.com/user/repo PB: https://pastebin.com/AbCd"
        urls = extract_urls_by_type(text, UrlType.PASTEBIN)
        assert len(urls) == 1
        assert "pastebin.com" in urls[0]
