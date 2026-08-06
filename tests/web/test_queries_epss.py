"""EPSS trend query functions: epss_trend, epss_movers, epss_threshold_alerts."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from horus.core.model import CVE
from horus.storage import db
from horus.web import queries


@pytest.fixture()
def seeded(tmp_path, monkeypatch):
    """Fresh DB with CVEs and EPSS history spanning multiple days."""
    path = tmp_path / "horus.db"
    monkeypatch.setattr(db, "DB_PATH", path)
    monkeypatch.setattr(queries, "DB_PATH", path)
    db.initialize()
    now = datetime.now(timezone.utc)
    with db.connect() as conn:
        db.persist_cve(
            conn,
            CVE(
                id="CVE-2026-2001",
                description="Critical RCE.",
                cvss_score=9.5,
                cvss_severity="CRITICAL",
                published_at=datetime(2026, 1, 5, tzinfo=timezone.utc),
                epss_score=0.85,
                kev=1,
            ),
        )
        db.persist_cve(
            conn,
            CVE(
                id="CVE-2026-2002",
                description="SQL injection.",
                cvss_score=7.5,
                cvss_severity="HIGH",
                published_at=datetime(2026, 1, 10, tzinfo=timezone.utc),
                epss_score=0.45,
            ),
        )
        db.persist_cve(
            conn,
            CVE(
                id="CVE-2026-2003",
                description="XSS.",
                cvss_score=6.0,
                cvss_severity="MEDIUM",
                published_at=datetime(2026, 1, 15, tzinfo=timezone.utc),
                epss_score=0.10,
            ),
        )
        db.persist_cve(
            conn,
            CVE(
                id="CVE-2026-2004",
                description="No history.",
                cvss_score=5.0,
                cvss_severity="MEDIUM",
                published_at=datetime(2026, 1, 20, tzinfo=timezone.utc),
            ),
        )
        # CVE-2026-2001: rising from 0.40 → 0.85 over 10 days
        for i in range(11):
            day = (now - timedelta(days=10 - i)).strftime("%Y-%m-%d")
            score = round(0.40 + (0.45 / 10) * i, 4)
            conn.execute(
                "INSERT OR REPLACE INTO epss_history (cve_id, score, recorded_at) VALUES (?, ?, ?)",
                ("CVE-2026-2001", score, day),
            )
        # CVE-2026-2002: falling from 0.70 → 0.45 over 10 days
        for i in range(11):
            day = (now - timedelta(days=10 - i)).strftime("%Y-%m-%d")
            score = round(0.70 - (0.25 / 10) * i, 4)
            conn.execute(
                "INSERT OR REPLACE INTO epss_history (cve_id, score, recorded_at) VALUES (?, ?, ?)",
                ("CVE-2026-2002", score, day),
            )
        # CVE-2026-2003: stable around 0.10
        for i in range(11):
            day = (now - timedelta(days=10 - i)).strftime("%Y-%m-%d")
            conn.execute(
                "INSERT OR REPLACE INTO epss_history (cve_id, score, recorded_at) VALUES (?, ?, ?)",
                ("CVE-2026-2003", 0.10, day),
            )
    return path


# ── epss_trend ──────────────────────────────────────────────────────────────


def test_epss_trend_returns_full_structure(seeded):
    result = queries.epss_trend("CVE-2026-2001")
    assert result["cve_id"] == "CVE-2026-2001"
    assert "current_score" in result
    assert "velocity" in result
    assert "trend" in result
    assert "days_above_50pct" in result
    assert "history" in result
    assert isinstance(result["history"], list)


def test_epss_trend_rising_classification(seeded):
    result = queries.epss_trend("CVE-2026-2001")
    assert result["trend"] == "rising"
    assert result["velocity"] > 0.005


def test_epss_trend_falling_classification(seeded):
    result = queries.epss_trend("CVE-2026-2002")
    assert result["trend"] == "falling"
    assert result["velocity"] < -0.005


def test_epss_trend_stable_classification(seeded):
    result = queries.epss_trend("CVE-2026-2003")
    assert result["trend"] == "stable"


def test_epss_trend_days_above_50pct(seeded):
    result = queries.epss_trend("CVE-2026-2001")
    # Scores go from 0.40 → 0.85 in steps of 0.045: days 0-2 are below 0.50,
    # days 3-10 are >= 0.50 — so 8 of 11 days qualify.
    assert result["days_above_50pct"] == 8


def test_epss_trend_no_history(seeded):
    result = queries.epss_trend("CVE-2026-2004")
    assert result["cve_id"] == "CVE-2026-2004"
    assert result["current_score"] is None
    assert result["velocity"] == 0.0
    assert result["trend"] == "stable"
    assert result["days_above_50pct"] == 0
    assert result["history"] == []


def test_epss_trend_unknown_cve(seeded):
    result = queries.epss_trend("CVE-9999-99999")
    assert result["cve_id"] == "CVE-9999-99999"
    assert result["current_score"] is None
    assert result["velocity"] == 0.0
    assert result["trend"] == "stable"


# ── epss_movers ─────────────────────────────────────────────────────────────


def test_epss_movers_returns_list_of_dicts(seeded):
    result = queries.epss_movers(days=30, limit=20)
    assert isinstance(result, list)
    for item in result:
        assert "cve_id" in item
        assert "current_score" in item
        assert "previous_score" in item
        assert "velocity" in item
        assert "trend" in item


def test_epss_movers_sorted_by_abs_velocity_desc(seeded):
    result = queries.epss_movers(days=30, limit=20)
    assert len(result) >= 2
    abs_velocities = [abs(item["velocity"]) for item in result]
    assert abs_velocities == sorted(abs_velocities, reverse=True)


def test_epss_movers_respects_limit(seeded):
    result = queries.epss_movers(days=30, limit=2)
    assert len(result) <= 2


def test_epss_movers_includes_cvss_and_kev(seeded):
    result = queries.epss_movers(days=30, limit=20)
    cve1 = next(item for item in result if item["cve_id"] == "CVE-2026-2001")
    assert cve1["cvss_score"] == 9.5
    assert cve1["kev"] == 1


def test_epss_movers_no_history_returns_empty(seeded):
    result = queries.epss_movers(days=30, limit=20)
    cve_ids = [item["cve_id"] for item in result]
    assert "CVE-2026-2004" not in cve_ids


def test_epss_movers_scoped_by_days(seeded):
    # With days=0, only today's data point exists — not enough for velocity (needs 2)
    result = queries.epss_movers(days=0, limit=20)
    assert result == []


# ── epss_threshold_alerts ───────────────────────────────────────────────────


def test_epss_threshold_alerts_detects_rising_crossing(seeded):
    result = queries.epss_threshold_alerts(days=30)
    cve_ids = [item["cve_id"] for item in result]
    assert "CVE-2026-2001" in cve_ids
    cve1 = next(item for item in result if item["cve_id"] == "CVE-2026-2001")
    assert cve1["direction"] == "above"


def test_epss_threshold_alerts_detects_falling_crossing(seeded):
    result = queries.epss_threshold_alerts(days=30)
    cve_ids = [item["cve_id"] for item in result]
    assert "CVE-2026-2002" in cve_ids
    cve2 = next(item for item in result if item["cve_id"] == "CVE-2026-2002")
    assert cve2["direction"] == "below"


def test_epss_threshold_alerts_no_crossing(seeded):
    result = queries.epss_threshold_alerts(days=30)
    cve_ids = [item["cve_id"] for item in result]
    assert "CVE-2026-2003" not in cve_ids


def test_epss_threshold_alerts_structure(seeded):
    result = queries.epss_threshold_alerts(days=30)
    for item in result:
        assert "cve_id" in item
        assert "crossed_at" in item
        assert "direction" in item
        assert item["direction"] in ("above", "below")


def test_epss_threshold_alerts_scoped_by_days(seeded):
    # days=1 — only today's point, can't have a crossing
    result = queries.epss_threshold_alerts(days=1)
    assert result == []
