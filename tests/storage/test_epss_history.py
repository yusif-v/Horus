"""epss_history table + append helper (one row per cve per day)."""

from __future__ import annotations

from horus.storage import db


def _seed_cve(conn, cve_id="CVE-2026-1000"):
    conn.execute(
        "INSERT OR REPLACE INTO cve (id, description, first_seen, last_seen) VALUES (?, ?, ?, ?)",
        (cve_id, "x", "2026-06-01", "2026-06-01"),
    )


def test_append_inserts_one_row_per_day():
    db.initialize()
    with db.connect() as conn:
        _seed_cve(conn)
        first = db.append_epss_history(conn, "CVE-2026-1000", 0.10)
        second = db.append_epss_history(conn, "CVE-2026-1000", 0.20)
        assert first is True
        assert second is False  # same day → no duplicate
        rows = conn.execute(
            "SELECT score FROM epss_history WHERE cve_id = ?", ("CVE-2026-1000",)
        ).fetchall()
        assert len(rows) == 1
