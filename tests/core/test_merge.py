"""Tests for horus/core/merge.py — CVE/PoC deduplication and merge logic."""

from __future__ import annotations

from horus.core.merge import (
    deduplicate_pocs,
    link_pocs_to_cves,
    merge_findings,
)
from horus.core.model import CVE, PoC


def _cve(cve_id: str, cvss_score: float | None = None, **kwargs) -> CVE:
    return CVE(id=cve_id, description=f"Desc {cve_id}", cvss_score=cvss_score, **kwargs)


def _poc(url: str, cve_refs: list[str] | None = None, **kwargs) -> PoC:
    return PoC(url=url, source="github", cve_refs=cve_refs or [], **kwargs)


# ── merge_findings ────────────────────────────────────────────────────────


def test_merge_findings_deduplicates_cves_by_id():
    cves = [
        _cve("CVE-2026-0001", cvss_score=7.0),
        _cve("CVE-2026-0001", cvss_score=5.0),  # duplicate
        _cve("CVE-2026-0002", cvss_score=9.0),
    ]
    result_cves, _, _ = merge_findings(cves, [])
    assert len(result_cves) == 2
    ids = {c.id for c in result_cves}
    assert ids == {"CVE-2026-0001", "CVE-2026-0002"}


def test_merge_findings_deduplicates_pocs_by_url():
    pocs = [
        _poc("https://github.com/a", cve_refs=["CVE-2026-0001"]),
        _poc("https://github.com/a", cve_refs=["CVE-2026-0002"]),  # same URL
    ]
    _, result_pocs, _ = merge_findings([], pocs)
    assert len(result_pocs) == 1


def test_merge_findings_merge_richer_poc_metadata():
    """When deduplicating, the richer description should win."""
    pocs = [
        _poc("https://github.com/a", description="short"),
        _poc("https://github.com/a", description="a much longer description"),
    ]
    _, result_pocs, _ = merge_findings([], pocs)
    assert len(result_pocs) == 1
    assert len(result_pocs[0].description or "") > 10


def test_merge_findings_aggregates_social_signals():
    cves = [_cve("CVE-2026-0001")]
    signals = [
        {"cve_id": "CVE-2026-0001", "tweet_url": "https://x.com/1", "source": "x_twitter"},
        {"cve_id": "CVE-2026-0001", "tweet_url": "https://x.com/2", "source": "x_twitter"},
    ]
    result_cves, _, _ = merge_findings(cves, [], social_signals=signals)
    assert result_cves[0].social_mentions == 2


def test_merge_findings_watchlist_for_unknown_cve_ids():
    signals = [
        {"cve_id": "CVE-2026-9999", "tweet_url": "https://x.com/1", "source": "x_twitter"},
    ]
    _, _, watchlist = merge_findings([], [], social_signals=signals)
    assert len(watchlist) == 1
    assert watchlist[0][0] == "CVE-2026-9999"


def test_merge_findings_computes_reputation_scores():
    cves = [_cve("CVE-2026-0001", cvss_score=8.0)]
    result_cves, _, _ = merge_findings(cves, [])
    assert result_cves[0].reputation_score > 0


def test_merge_findings_sets_confidence():
    cves = [_cve("CVE-2026-0001", cvss_score=5.0)]
    result_cves, _, _ = merge_findings(cves, [])
    assert result_cves[0].confidence == "high"


# ── link_pocs_to_cves ─────────────────────────────────────────────────────


def test_link_pocs_to_cves_basic():
    cves = [_cve("CVE-2026-0001")]
    pocs = [_poc("https://github.com/poc1", cve_refs=["CVE-2026-0001"])]
    links = link_pocs_to_cves(cves, pocs)
    assert "CVE-2026-0001" in links
    assert len(links["CVE-2026-0001"]) == 1


def test_link_pocs_to_cves_unmatched_ref():
    cves = [_cve("CVE-2026-0001")]
    pocs = [_poc("https://github.com/poc1", cve_refs=["CVE-2026-9999"])]
    links = link_pocs_to_cves(cves, pocs)
    assert links["CVE-2026-0001"] == []


def test_link_pocs_to_cves_no_pocs():
    cves = [_cve("CVE-2026-0001")]
    links = link_pocs_to_cves(cves, [])
    assert links["CVE-2026-0001"] == []


def test_link_pocs_to_cves_no_cves():
    pocs = [_poc("https://github.com/poc1", cve_refs=["CVE-2026-0001"])]
    links = link_pocs_to_cves([], pocs)
    assert links == {}


# ── deduplicate_pocs ──────────────────────────────────────────────────────


def test_deduplicate_pocs_merges_cve_refs():
    pocs = [
        _poc("https://github.com/a", cve_refs=["CVE-2026-0001"]),
        _poc("https://github.com/a", cve_refs=["CVE-2026-0002"]),
    ]
    result = deduplicate_pocs(pocs)
    assert len(result) == 1
    assert set(result[0].cve_refs) == {"CVE-2026-0001", "CVE-2026-0002"}


def test_deduplicate_pocs_keeps_higher_stars():
    pocs = [
        _poc("https://github.com/a", stars=10),
        _poc("https://github.com/a", stars=50),
    ]
    result = deduplicate_pocs(pocs)
    assert result[0].stars == 50
