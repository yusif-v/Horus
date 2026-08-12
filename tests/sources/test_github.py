"""GitHub PoC source — search + x-discovered URL enrichment."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from horus.core.context import SourceContext
from horus.plugins.sources.github import main as github


def _recent_iso(days_ago: int = 1) -> str:
    """GitHub format: 2026-06-12T10:30:45Z"""
    d = datetime.now(timezone.utc) - timedelta(days=days_ago)
    return d.strftime("%Y-%m-%dT%H:%M:%SZ")


def _repo(
    *,
    html_url: str,
    full_name: str,
    description: str,
    stars: int = 5,
    created_at: str | None = None,
) -> dict:
    return {
        "html_url": html_url,
        "full_name": full_name,
        "description": description,
        "stargazers_count": stars,
        "created_at": created_at or _recent_iso(),
    }


def _patch_search(monkeypatch, items: list[dict], *, repo_data: dict | None = None):
    calls: list[str] = []

    def fake_fetch(url, accept=None, headers=None):
        calls.append(url)
        if "/repos/" in url and repo_data is not None:
            return repo_data
        return {"items": items}

    monkeypatch.setattr(github, "fetch_json", fake_fetch)
    monkeypatch.setattr(github, "github_token", lambda: None)
    return calls


def test_parses_search_results(monkeypatch):
    _patch_search(
        monkeypatch,
        [
            _repo(
                html_url="https://github.com/u/cve-2026-1234-poc",
                full_name="u/cve-2026-1234-poc",
                description="PoC for CVE-2026-1234 RCE in nginx",
                stars=12,
            )
        ],
    )

    result = github.run(SourceContext(max_results=10))

    assert result["cves"] == []
    pocs = result["pocs"]
    assert len(pocs) >= 1
    p = pocs[0]
    assert p.url == "https://github.com/u/cve-2026-1234-poc"
    assert "CVE-2026-1234" in p.cve_refs
    assert p.stars == 12
    assert p.source == "github"


def test_skips_known_urls(monkeypatch):
    url = "https://github.com/u/known"
    _patch_search(
        monkeypatch,
        [_repo(html_url=url, full_name="u/known", description="exploit poc")],
    )
    result = github.run(SourceContext(known_poc_urls={url}))
    assert result["pocs"] == []


def test_skips_old_repos(monkeypatch):
    _patch_search(
        monkeypatch,
        [
            _repo(
                html_url="https://github.com/u/old",
                full_name="u/old",
                description="exploit poc",
                created_at=_recent_iso(days_ago=400),
            )
        ],
    )
    result = github.run(SourceContext())
    assert result["pocs"] == []


def test_enriches_x_discovered_urls(monkeypatch):
    """X-discovered GitHub URLs hit /repos/{owner}/{repo} for enrichment."""
    enriched = _repo(
        html_url="https://github.com/alice/cool-exploit",
        full_name="alice/cool-exploit",
        description="kernel exploit PoC",
        stars=50,
    )
    _patch_search(monkeypatch, items=[], repo_data=enriched)

    ctx = SourceContext()
    ctx.provided["x_discovered_urls"] = ["https://github.com/alice/cool-exploit"]

    result = github.run(ctx)

    assert len(result["pocs"]) == 1
    assert result["pocs"][0].url == "https://github.com/alice/cool-exploit"
    assert result["pocs"][0].stars == 50


def test_x_discovered_rejects_path_traversal(monkeypatch):
    """`..` segments must never get formed into an API URL."""
    fetched_urls: list[str] = []

    def fake_fetch(url, accept=None, headers=None):
        fetched_urls.append(url)
        return {"items": []}

    monkeypatch.setattr(github, "fetch_json", fake_fetch)
    monkeypatch.setattr(github, "github_token", lambda: None)

    ctx = SourceContext()
    ctx.provided["x_discovered_urls"] = ["https://github.com/../../etc/passwd"]
    github.run(ctx)

    # /repos/ should never have been queried for the traversal URL
    assert not any("/repos/.." in u for u in fetched_urls)


def test_search_failure_skips_query(monkeypatch):
    def boom(url, accept=None, headers=None):
        raise RuntimeError("rate limited")

    monkeypatch.setattr(github, "fetch_json", boom)
    monkeypatch.setattr(github, "github_token", lambda: None)
    result = github.run(SourceContext())
    assert result == {"cves": [], "pocs": []}


def test_confidence_mapping():
    assert github._confidence_for_stars(None) == "low"
    assert github._confidence_for_stars(0) == "low"
    assert github._confidence_for_stars(11) == "medium"
    assert github._confidence_for_stars(101) == "high"


def test_source_metadata():
    assert github.NAME == "GitHub PoC Repos"
    assert github.KIND == "poc"
    assert github.DEFAULT_ENABLED is True
    assert "x_discovered_urls" in github.CONSUMES
