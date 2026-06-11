"""End-to-end query rendering: text & markdown."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from horus.core.model import CVE, AffectedProduct, PoC
from horus.storage import db, query


@pytest.fixture()
def seeded(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "horus.db")
    monkeypatch.setattr(query, "DB_PATH", tmp_path / "horus.db")
    db.initialize()
    with db.connect() as conn:
        db.persist_cve(
            conn,
            CVE(
                id="CVE-2026-1111",
                description="A critical RCE in nginx via crafted request.",
                cvss_score=9.8,
                cvss_severity="CRITICAL",
                published_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
                attack_tags=["rce"],
                cwe_ids=["CWE-94"],
                affected=[AffectedProduct(vendor="nginx", product="nginx", versions=["1.0"])],
                sources=["nvd"],
                epss_score=0.7,
                kev=1,
            ),
        )
        db.persist_poc(conn, PoC(url="https://gh/x/1", source="github", stars=12))
        db.link_poc_to_cve(conn, "https://gh/x/1", "CVE-2026-1111")
    return tmp_path / "horus.db"


def test_query_cve_text_contains_core_fields(seeded):
    out = query.query_cve("CVE-2026-1111", fmt="text")
    assert "CVE-2026-1111" in out
    assert "nginx" in out
    assert "rce" in out


def test_query_cve_markdown_contains_headers(seeded):
    out = query.query_cve("CVE-2026-1111", fmt="md")
    assert "CVE-2026-1111" in out
    assert "#" in out  # Some markdown header rendered


def test_query_cve_unknown_id_falls_back_to_keyword_search(seeded):
    # No such CVE — but "nginx" matches via keyword search across descriptions.
    out = query.query_cve("CVE-2099-9999", fmt="text")
    assert "not found" in out.lower()


def test_query_cve_missing_database_returns_error_string(tmp_path, monkeypatch):
    monkeypatch.setattr(query, "DB_PATH", tmp_path / "missing.db")
    assert "database not found" in query.query_cve("CVE-2026-1111").lower()


def test_query_keyword_finds_match(seeded):
    out = query.query_keyword("nginx")
    assert "CVE-2026-1111" in out


def test_query_keyword_empty_result(seeded):
    out = query.query_keyword("nonexistent-product-name-xyz")
    assert "no cves found" in out.lower()
