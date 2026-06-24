"""Post-enrich scoring pass sets imminence on CVEs and persists it."""

from __future__ import annotations

from horus.core.model import CVE
from horus.pipeline import _score_imminence  # helper added in this task
from horus.storage import db


def test_score_imminence_sets_fields():
    db.initialize()
    # epss=0.9*3 + kev=2 + poc=min(2*0.75,1.5)=1.5 + cvss=0.98 + nginx_ubiquity=0.5 = 7.68 → imminent
    cves = [
        CVE(
            id="CVE-2026-5000",
            description="nginx flaw",
            cvss_score=9.8,
            epss_score=0.9,
            kev=1,
            poc_source_count=2,
        )
    ]
    with db.connect() as conn:
        _score_imminence(cves, conn)
    assert cves[0].imminence_bucket == "imminent"
    assert cves[0].imminence_score >= 7.5


def test_persist_cve_writes_imminence():
    """Round-trip: persist a CVE with imminence fields and read them back."""
    db.initialize()
    cve = CVE(
        id="CVE-2026-5001",
        description="test persist imminence",
        cvss_score=8.0,
        epss_score=0.6,
        kev=0,
        poc_source_count=1,
        imminence_score=6.5,
        imminence_bucket="weeks",
    )
    with db.connect() as conn:
        db.persist_cve(conn, cve)
        row = conn.execute(
            "SELECT imminence_score, imminence_bucket FROM cve WHERE id = ?",
            (cve.id,),
        ).fetchone()
    assert row is not None
    assert abs(row["imminence_score"] - 6.5) < 0.01
    assert row["imminence_bucket"] == "weeks"
