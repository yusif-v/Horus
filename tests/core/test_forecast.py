"""EPSS velocity + imminence forecast."""

from __future__ import annotations

from horus.core import forecast
from horus.storage import db


def _seed_history(conn, cve_id, points):
    conn.execute(
        "INSERT OR REPLACE INTO cve (id, description, first_seen, last_seen) VALUES (?, ?, ?, ?)",
        (cve_id, "x", "2026-06-01", "2026-06-01"),
    )
    for score, date in points:
        conn.execute(
            "INSERT OR IGNORE INTO epss_history (cve_id, score, recorded_at) VALUES (?, ?, ?)",
            (cve_id, score, date),
        )


def test_velocity_zero_with_one_point():
    db.initialize()
    with db.connect() as conn:
        _seed_history(conn, "CVE-2026-3001", [(0.10, "2026-06-01")])
        conn.commit()
        assert forecast.epss_velocity("CVE-2026-3001", conn) == 0.0


def test_velocity_positive_when_rising():
    db.initialize()
    with db.connect() as conn:
        _seed_history(conn, "CVE-2026-3002", [(0.10, "2026-06-01"), (0.40, "2026-06-11")])
        conn.commit()
        # (0.40 - 0.10) / 10 days = 0.03 / day
        assert abs(forecast.epss_velocity("CVE-2026-3002", conn) - 0.03) < 1e-6
