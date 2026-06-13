"""GitLab PoC source — search results parsed against canned API JSON."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from horus.core.context import SourceContext
from horus.sources import gitlab


def _recent_iso(days_ago: int = 1) -> str:
    """GitLab format: 2026-06-12T10:30:45.123Z"""
    d = datetime.now(timezone.utc) - timedelta(days=days_ago)
    return d.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _project(
    *,
    web_url: str,
    name: str,
    description: str,
    stars: int = 5,
    full_path: str = "user",
    created_at: str | None = None,
) -> dict:
    return {
        "web_url": web_url,
        "name": name,
        "description": description,
        "star_count": stars,
        "created_at": created_at or _recent_iso(),
        "namespace": {"full_path": full_path},
    }


def _patch_search(monkeypatch, payload: list[dict]):
    calls: list[str] = []

    def fake_fetch(url):
        calls.append(url)
        return payload

    monkeypatch.setattr(gitlab, "fetch_json", fake_fetch)
    return calls


def test_parses_search_results(monkeypatch):
    payload = [
        _project(
            web_url="https://gitlab.com/u/cve-2026-1234-exploit",
            name="cve-2026-1234-exploit",
            description="PoC for CVE-2026-1234 RCE in Apache",
            stars=42,
        )
    ]
    _patch_search(monkeypatch, payload)
    ctx = SourceContext(max_results=5)

    result = gitlab.run(ctx)

    assert result["cves"] == []
    pocs = result["pocs"]
    assert len(pocs) >= 1
    p = pocs[0]
    assert p.url == "https://gitlab.com/u/cve-2026-1234-exploit"
    assert "CVE-2026-1234" in p.cve_refs
    assert p.stars == 42
    assert p.source == "gitlab"


def test_skips_known_urls(monkeypatch):
    url = "https://gitlab.com/u/poc-repo"
    _patch_search(
        monkeypatch,
        [_project(web_url=url, name="poc-repo", description="exploit poc")],
    )
    ctx = SourceContext(known_poc_urls={url})

    result = gitlab.run(ctx)

    assert result["pocs"] == []


def test_skips_repos_older_than_max_age(monkeypatch):
    old = _recent_iso(days_ago=400)
    _patch_search(
        monkeypatch,
        [
            _project(
                web_url="https://gitlab.com/u/old",
                name="old-exploit",
                description="exploit poc",
                created_at=old,
            )
        ],
    )
    result = gitlab.run(SourceContext())
    assert result["pocs"] == []


def test_skips_low_value_descriptions(monkeypatch):
    """`is_fresh_poc` rejects 'awesome' / 'list' style aggregators."""
    _patch_search(
        monkeypatch,
        [
            _project(
                web_url="https://gitlab.com/u/awesome-cves",
                name="awesome-cves",
                description="An awesome list of CVE databases",
            )
        ],
    )
    result = gitlab.run(SourceContext())
    assert result["pocs"] == []


def test_fetch_failure_skips_query(monkeypatch):
    def boom(_url):
        raise RuntimeError("503")

    monkeypatch.setattr(gitlab, "fetch_json", boom)
    result = gitlab.run(SourceContext())
    assert result == {"cves": [], "pocs": []}


def test_confidence_mapping():
    assert gitlab._confidence_for_stars(None) == "low"
    assert gitlab._confidence_for_stars(0) == "low"
    assert gitlab._confidence_for_stars(11) == "medium"
    assert gitlab._confidence_for_stars(101) == "high"


def test_source_metadata():
    assert gitlab.NAME == "GitLab PoC Repos"
    assert gitlab.KIND == "poc"
    assert gitlab.DEFAULT_ENABLED is True
