"""CISA KEV enricher: mark CVEs that appear in the catalog."""

from __future__ import annotations

from datetime import datetime, timezone

from horus.core.context import EnricherContext
from horus.core.model import CVE
from horus.enrichers import kev


def _cve(cve_id: str, kev_flag: int = 0, kev_due_date: str | None = None) -> CVE:
    return CVE(
        id=cve_id,
        description="x",
        cvss_score=7.0,
        published_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        kev=kev_flag,
        kev_due_date=kev_due_date,
    )


def test_enrich_marks_matching_cves(monkeypatch):
    catalog = {
        "vulnerabilities": [
            {"cveID": "CVE-2026-7777"},
            {"cveID": "CVE-2026-8888"},
        ]
    }
    monkeypatch.setattr(kev, "fetch_json", lambda url: catalog)
    ctx = EnricherContext(
        cves=[_cve("CVE-2026-7777"), _cve("CVE-2026-9999")],
        pocs=[],
    )
    kev.enrich(ctx)
    assert ctx.cves[0].kev == 1
    assert ctx.cves[1].kev == 0


def test_enrich_captures_due_date(monkeypatch):
    """CVEs in KEV catalog should capture their dueDate field."""
    catalog = {
        "vulnerabilities": [
            {"cveID": "CVE-2026-7777", "dueDate": "2026-07-15"},
            {"cveID": "CVE-2026-8888", "dueDate": None},
        ]
    }
    monkeypatch.setattr(kev, "fetch_json", lambda url: catalog)
    ctx = EnricherContext(cves=[_cve("CVE-2026-7777")], pocs=[])
    kev.enrich(ctx)
    assert ctx.cves[0].kev == 1
    assert ctx.cves[0].kev_due_date == "2026-07-15"


def test_enrich_handles_fetch_failure(monkeypatch):
    def boom(url):
        raise RuntimeError("network down")

    monkeypatch.setattr(kev, "fetch_json", boom)
    ctx = EnricherContext(cves=[_cve("CVE-2026-7777")], pocs=[])
    kev.enrich(ctx)  # must not raise
    assert ctx.cves[0].kev == 0


def test_enrich_is_case_insensitive(monkeypatch):
    catalog = {"vulnerabilities": [{"cveID": "cve-2026-aaaa"}]}
    monkeypatch.setattr(kev, "fetch_json", lambda url: catalog)
    ctx = EnricherContext(cves=[_cve("CVE-2026-AAAA")], pocs=[])
    kev.enrich(ctx)
    assert ctx.cves[0].kev == 1
