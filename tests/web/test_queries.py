"""Web query layer: stats, search, detail, PoC list, helpers."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from horus.core.model import CVE, AffectedProduct, PoC
from horus.storage import db
from horus.web import queries


@pytest.fixture()
def seeded(tmp_path, monkeypatch):
    """Fresh DB per test, with two CVEs and one PoC linked to one of them."""
    path = tmp_path / "horus.db"
    monkeypatch.setattr(db, "DB_PATH", path)
    monkeypatch.setattr(queries, "DB_PATH", path)
    db.initialize()
    with db.connect() as conn:
        db.persist_cve(
            conn,
            CVE(
                id="CVE-2026-2001",
                description="Critical RCE in nginx.",
                cvss_score=9.5,
                cvss_severity="CRITICAL",
                published_at=datetime(2026, 1, 5, tzinfo=timezone.utc),
                attack_tags=["rce"],
                cwe_ids=["CWE-94"],
                affected=[
                    AffectedProduct(vendor="nginx", product="nginx", versions=["1.0", "1.1"])
                ],
                sources=["nvd"],
                epss_score=0.8,
                kev=1,
                social_mentions=2,
            ),
        )
        db.persist_cve(
            conn,
            CVE(
                id="CVE-2026-2002",
                description="SQL injection in widget.",
                cvss_score=7.5,
                cvss_severity="HIGH",
                published_at=datetime(2026, 1, 10, tzinfo=timezone.utc),
                attack_tags=["sql-injection"],
                affected=[AffectedProduct(vendor="acme", product="widget", versions=["2.0"])],
                sources=["nvd"],
            ),
        )
        db.persist_poc(
            conn, PoC(url="https://gh/x/1", source="github", stars=10, description="poc")
        )
        db.link_poc_to_cve(conn, "https://gh/x/1", "CVE-2026-2001")
    return path


def test_rail_stats_counts(seeded):
    s = queries.rail_stats()
    assert s["cve_n"] == 2
    assert s["poc_n"] == 1


def test_get_stats_contract_and_counts(seeded):
    s = queries.get_stats()
    assert s["cve_count"] == 2
    assert s["poc_count"] == 1
    assert s["kev_count"] == 1
    assert s["social_heat"] == 1  # only one CVE has social_mentions > 0
    assert s["social_mentions_total"] == 2
    # actionable = KEV OR (EPSS>=0.5 AND has PoC) -- the nginx one qualifies on both
    assert s["actionable"] >= 1
    assert s["imminent"] >= 1  # epss>=0.5
    assert s["weaponized"] >= 1  # cvss>=9 ∧ linked PoC


def test_search_by_cve_id_prefix(seeded):
    results, total = queries.search_cves("CVE-2026-2001")
    assert total == 1
    assert results[0]["id"] == "CVE-2026-2001"


def test_search_by_keyword_in_description(seeded):
    results, total = queries.search_cves("nginx")
    assert total == 1
    assert results[0]["id"] == "CVE-2026-2001"


def test_search_pagination(seeded):
    # both CVEs contain "in" — page size 1 should return one each page.
    results, total = queries.search_cves("in", page=1, per_page=1)
    assert total >= 1
    assert len(results) <= 1


def test_get_cve_detail_returns_grouped_products(seeded):
    detail = queries.get_cve_detail("CVE-2026-2001")
    assert detail is not None
    assert detail["cve"]["id"] == "CVE-2026-2001"
    assert detail["products_grouped"]
    nginx_group = next(g for g in detail["products_grouped"] if g["vendor"] == "nginx")
    versions = nginx_group["products"][0]["versions"]
    # Semicolon-joined versions get split back into a list for the template.
    assert versions == ["1.0", "1.1"]
    assert detail["linked_pocs"]
    assert detail["linked_pocs"][0]["url"] == "https://gh/x/1"


def test_get_cve_detail_returns_none_for_unknown(seeded):
    assert queries.get_cve_detail("CVE-9999-99999") is None


def test_get_cve_detail_normalizes_naked_id(seeded):
    # "2026-2001" without the CVE- prefix should still resolve.
    detail = queries.get_cve_detail("2026-2001")
    assert detail is not None
    assert detail["cve"]["id"] == "CVE-2026-2001"


def test_fetch_pocs_lists_with_cve_ids(seeded):
    rows, total = queries.fetch_pocs()
    assert total == 1
    assert rows[0]["cve_ids"] == ["CVE-2026-2001"]


def test_fetch_pocs_source_filter(seeded):
    _, total = queries.fetch_pocs(source_filter="github")
    assert total == 1
    _, total = queries.fetch_pocs(source_filter="gitlab")
    assert total == 0


def test_group_products_by_vendor_splits_versions():
    grouped = queries.group_products_by_vendor(
        [
            {
                "vendor": "nginx",
                "product": "nginx",
                "versions": "1.0; 1.1; 2.0",
                "category": "web-server",
            },
        ]
    )
    assert grouped[0]["products"][0]["versions"] == ["1.0", "1.1", "2.0"]


def test_group_products_by_vendor_sorts_unknown_last():
    grouped = queries.group_products_by_vendor(
        [
            {"vendor": "unknown", "product": "x", "versions": "", "category": "unknown"},
            {"vendor": "apache", "product": "httpd", "versions": "", "category": "web-server"},
        ]
    )
    assert [g["vendor"] for g in grouped] == ["apache", "unknown"]


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("5", 5),
        ("0", 1),  # min_val clamp
        ("99999", 10000),  # max_val clamp
        ("abc", 1),  # default on garbage
        (None, 1),
    ],
)
def test_safe_int_clamps_and_defaults(raw, expected):
    assert queries.safe_int(raw) == expected
