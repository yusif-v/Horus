"""Reputation-score formula contract.

The score reflects the v0.8 design: CVSS-weighted, with explicit boosts
for KEV, EPSS, social heat, distinct PoC sources, and ubiquitous products.
These tests pin the weights so a change can't silently drift.
"""

from __future__ import annotations

from horus.core.merge import (
    UBIQUITOUS_PRODUCTS,
    compute_reputation_score,
    cve_affects_ubiquitous,
    merge_findings,
)
from horus.core.model import CVE, AffectedProduct, PoC


def _cve(**kw) -> CVE:
    defaults = {"id": "CVE-2026-0001", "description": "test"}
    defaults.update(kw)
    return CVE(**defaults)


def test_no_cvss_score_is_zero():
    assert compute_reputation_score(_cve(cvss_score=None)) == 0.0


def test_cvss_only_weighting():
    s = compute_reputation_score(_cve(cvss_score=9.8))
    assert round(s, 2) == round(9.8 * 0.35, 2)


def test_kev_bonus_is_one_point_five():
    base = compute_reputation_score(_cve(cvss_score=5.0))
    kev = compute_reputation_score(_cve(cvss_score=5.0, kev=1))
    assert round(kev - base, 2) == 1.5


def test_epss_max_is_capped_into_formula():
    s = compute_reputation_score(_cve(cvss_score=0.0, epss_score=1.0))
    assert round(s, 2) == 2.5


def test_social_mentions_capped_at_one():
    a = compute_reputation_score(_cve(cvss_score=5.0, social_mentions=100))
    b = compute_reputation_score(_cve(cvss_score=5.0, social_mentions=7))
    assert round(a - b, 2) == 0.0  # both saturated at +1.0


def test_poc_source_count_capped_at_one_point_five():
    a = compute_reputation_score(_cve(cvss_score=5.0, poc_source_count=100))
    b = compute_reputation_score(_cve(cvss_score=5.0, poc_source_count=3))
    assert round(a - b, 2) == 0.0


def test_score_caps_at_ten():
    s = compute_reputation_score(
        _cve(
            cvss_score=10.0,
            kev=1,
            epss_score=1.0,
            social_mentions=20,
            poc_source_count=10,
            affected=[AffectedProduct(vendor="nginx", product="nginx")],
        )
    )
    assert s == 10.0


def test_ubiquity_recognises_curated_products():
    cve = _cve(cvss_score=5.0, affected=[AffectedProduct(vendor="x", product="nginx")])
    assert cve_affects_ubiquitous(cve)


def test_ubiquity_unknown_product_is_false():
    cve = _cve(cvss_score=5.0, affected=[AffectedProduct(vendor="x", product="some-rare-thing")])
    assert not cve_affects_ubiquitous(cve)


def test_ubiquity_curated_set_includes_critical_products():
    # Sanity: items the user explicitly called out are present.
    for name in ("nginx", "php", "wordpress", "openssl", "kubernetes"):
        assert name in UBIQUITOUS_PRODUCTS


# ── merge_findings integration ──────────────────────────────────────────────


def test_merge_split_social_into_watchlist_when_not_in_nvd():
    cve = _cve(id="CVE-2026-0001", cvss_score=9.0)
    signals = [
        {"cve_id": "CVE-2026-0001"},
        {"cve_id": "CVE-9999-9999"},
        {"cve_id": "CVE-9999-9999"},
    ]
    cves, _pocs, watch = merge_findings([cve], [], social_signals=signals)
    assert cves[0].social_mentions == 1
    assert watch == [("CVE-9999-9999", "unknown", 2)]


def test_merge_counts_distinct_poc_sources():
    cve = _cve(id="CVE-2026-0001", cvss_score=9.0)
    pocs_in = [
        PoC(url="https://github.com/a/b", source="github", cve_refs=["CVE-2026-0001"]),
        PoC(url="https://exploit-db.com/1", source="exploit-db", cve_refs=["CVE-2026-0001"]),
        PoC(url="https://github.com/c/d", source="github", cve_refs=["CVE-2026-0001"]),
    ]
    cves, _pocs, _ = merge_findings([cve], pocs_in)
    assert cves[0].poc_source_count == 2  # distinct: github + exploit-db
