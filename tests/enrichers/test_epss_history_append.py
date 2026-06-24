"""EPSS enricher writes a history row when it scores a CVE."""

from __future__ import annotations

from horus.core.context import EnricherContext
from horus.core.model import CVE
from horus.enrichers import epss
from horus.storage import db


def test_enrich_appends_history(monkeypatch):
    db.initialize()
    with db.connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO cve (id, description, first_seen, last_seen)"
            " VALUES (?, ?, ?, ?)",
            ("CVE-2026-2000", "x", "2026-06-01", "2026-06-01"),
        )
        conn.commit()

    monkeypatch.setattr(epss, "_download_epss_scores", lambda: {"CVE-2026-2000": 0.42})
    ctx = EnricherContext(cves=[CVE(id="CVE-2026-2000", description="x")], pocs=[])
    epss.enrich(ctx)

    with db.connect() as conn:
        rows = conn.execute(
            "SELECT score FROM epss_history WHERE cve_id = ?", ("CVE-2026-2000",)
        ).fetchall()
    assert rows and abs(rows[0][0] - 0.42) < 1e-9
