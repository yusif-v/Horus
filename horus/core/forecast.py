"""Exploitability forecasting — heuristic, ML-ready.

v0.11 ships a transparent heuristic. The epss_history + exploitation_outcome
tables accrue the data a v0.12 ML model will train on, behind this same
interface.
"""

from __future__ import annotations

from datetime import date

_DATE_FMT = "%Y-%m-%d"


def epss_velocity(cve_id: str, conn) -> float:
    """Δscore per day over the two most recent distinct history points.

    Returns 0.0 when fewer than two points exist.
    """
    rows = conn.execute(
        "SELECT score, recorded_at FROM epss_history"
        " WHERE cve_id = ? ORDER BY recorded_at DESC LIMIT 2",
        (cve_id,),
    ).fetchall()
    if len(rows) < 2:
        return 0.0
    (s_new, d_new), (s_old, d_old) = rows[0], rows[1]
    try:
        days = (date.fromisoformat(d_new) - date.fromisoformat(d_old)).days
    except ValueError:
        return 0.0
    if days <= 0:
        return 0.0
    return (s_new - s_old) / days
