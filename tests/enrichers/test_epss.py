"""EPSS enricher: CSV-derived score table application + DB backfill."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from horus.core.context import EnricherContext
from horus.core.model import CVE
from horus.enrichers import epss
from horus.storage import db


@pytest.fixture()
def fresh_db(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "horus.db")
    db.initialize()
    return tmp_path / "horus.db"


def _cve(cve_id: str, epss_score: float | None = None) -> CVE:
    return CVE(
        id=cve_id,
        description="x",
        cvss_score=7.0,
        published_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        epss_score=epss_score,
    )


def test_enrich_applies_scores_to_ctx_cves(monkeypatch, fresh_db):
    scores = {"CVE-2026-0001": 0.42, "CVE-2026-0002": 0.99}
    monkeypatch.setattr(epss, "_download_epss_scores", lambda: scores)

    ctx = EnricherContext(
        cves=[_cve("CVE-2026-0001"), _cve("CVE-2026-0002"), _cve("CVE-2026-0003")],
        pocs=[],
    )
    epss.enrich(ctx)
    assert ctx.cves[0].epss_score == 0.42
    assert ctx.cves[1].epss_score == 0.99
    assert ctx.cves[2].epss_score is None  # not in scores → untouched


def test_enrich_empty_scores_is_noop(monkeypatch, fresh_db):
    monkeypatch.setattr(epss, "_download_epss_scores", lambda: {})
    ctx = EnricherContext(cves=[_cve("CVE-2026-0001")], pocs=[])
    epss.enrich(ctx)  # must not raise
    assert ctx.cves[0].epss_score is None


def test_backfill_updates_only_unscored(fresh_db):
    with db.connect() as conn:
        db.persist_cve(conn, _cve("CVE-2026-A001"))  # no epss
        db.persist_cve(conn, _cve("CVE-2026-A002", epss_score=0.1))  # scored
        scores = {"CVE-2026-A001": 0.5, "CVE-2026-A002": 0.9}
        updated = epss._backfill_db(conn, scores)
        assert updated == 1
        row = conn.execute("SELECT epss_score FROM cve WHERE id = ?", ("CVE-2026-A001",)).fetchone()
        assert row[0] == 0.5
        # Pre-scored row must not be overwritten.
        row = conn.execute("SELECT epss_score FROM cve WHERE id = ?", ("CVE-2026-A002",)).fetchone()
        assert row[0] == 0.1
