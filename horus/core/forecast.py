"""Exploitability forecasting — heuristic, ML-ready.

v0.11 ships a transparent heuristic. The epss_history + exploitation_outcome
tables accrue the data a v0.12 ML model will train on, behind this same
interface.
"""

from __future__ import annotations

from datetime import date

from .model import CVE

_DATE_FMT = "%Y-%m-%d"

# Products whose ubiquity raises imminence (mirrors reputation's ubiquity set).
_UBIQUITY = (
    "nginx",
    "php",
    "wordpress",
    "openssl",
    "kubernetes",
    "openssh",
    "apache",
    "mysql",
    "chrome",
    "linux",
)


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


def compute_imminence(cve: CVE, *, epss_velocity: float) -> tuple[float, str]:
    """Heuristic 0-10 imminence score + coarse bucket.

    Weights are intentionally transparent; v0.12 replaces this body with a
    trained model behind the same signature.
    """
    epss = cve.epss_score or 0.0
    # Normalize velocity: 0.02/day (≈ 0→0.6 over a month) saturates to 1.0.
    velocity_norm = max(0.0, min(epss_velocity / 0.02, 1.0))
    poc_signal = min((cve.poc_source_count or 0) * 0.75, 1.5)
    cvss = (cve.cvss_score or 0.0) / 10.0
    desc = (cve.description or "").lower()
    ubiquity = 0.5 if any(p in desc for p in _UBIQUITY) else 0.0

    score = (
        epss * 3.0
        + velocity_norm * 2.0
        + (2.0 if cve.kev else 0.0)
        + poc_signal
        + cvss * 1.0
        + ubiquity
    )
    score = round(min(score, 10.0), 3)

    if score >= 7.5:
        bucket = "imminent"
    elif score >= 5.0:
        bucket = "weeks"
    elif score >= 2.5:
        bucket = "months"
    else:
        bucket = "unlikely"
    return score, bucket
