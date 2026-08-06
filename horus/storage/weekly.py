"""Weekly threat report data aggregation layer.

Queries the Horus database for week-over-week threat intelligence,
producing structured data for the weekly report renderer.

Usage:
    from horus.storage.weekly import gather_weekly_data
    data = gather_weekly_data(conn, weeks_back=1)
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any


def _utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _week_boundaries(weeks_back: int = 1) -> tuple[str, str, str, str]:
    """Return (this_week_start, this_week_end, last_week_start, last_week_end) as ISO strings.

    weeks_back=1 means "the most recently completed 7-day window."
    weeks_back=2 means "the week before that," etc.
    """
    now = _utc_now() - timedelta(days=weeks_back * 7)
    # Find the Monday of the target week
    days_since_monday = now.weekday()
    this_week_start = (now - timedelta(days=days_since_monday)).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    this_week_end = this_week_start + timedelta(days=7)
    last_week_start = this_week_start - timedelta(days=7)
    last_week_end = this_week_start
    return (
        this_week_start.strftime("%Y-%m-%dT%H:%M:%S"),
        this_week_end.strftime("%Y-%m-%dT%H:%M:%S"),
        last_week_start.strftime("%Y-%m-%dT%H:%M:%S"),
        last_week_end.strftime("%Y-%m-%dT%H:%M:%S"),
    )


@dataclass
class WeeklyData:
    """All data needed to render a weekly threat report."""

    period_start: str
    period_end: str
    previous_period_start: str
    previous_period_end: str
    generated_at: str

    # Executive summary counts
    total_cves_this_week: int = 0
    total_cves_last_week: int = 0
    total_pocs_this_week: int = 0
    total_pocs_last_week: int = 0
    kev_new_this_week: int = 0
    kev_total: int = 0
    kev_overdue: int = 0
    critical_cves: int = 0
    high_cves: int = 0
    avg_cvss_this_week: float = 0.0
    avg_epss_this_week: float = 0.0
    avg_reputation_this_week: float = 0.0

    # Detail sections
    top_cves: list[dict[str, Any]] = field(default_factory=list)
    kev_entries: list[dict[str, Any]] = field(default_factory=list)
    epss_movers: list[dict[str, Any]] = field(default_factory=list)
    top_vendors: list[dict[str, Any]] = field(default_factory=list)
    top_tags: list[dict[str, Any]] = field(default_factory=list)
    news_highlights: list[dict[str, Any]] = field(default_factory=list)
    threatfox_summary: dict[str, Any] = field(default_factory=dict)
    top_pocs: list[dict[str, Any]] = field(default_factory=list)
    severity_breakdown: dict[str, int] = field(default_factory=dict)
    weekly_trend: list[dict[str, Any]] = field(default_factory=list)
    vendor_risk: list[dict[str, Any]] = field(default_factory=list)
    triage_summary: dict[str, int] = field(default_factory=dict)
    source_health: list[dict[str, Any]] = field(default_factory=list)


def gather_weekly_data(conn: sqlite3.Connection, weeks_back: int = 1) -> WeeklyData:
    """Gather all weekly report data from the database.

    Args:
        conn: SQLite connection.
        weeks_back: Number of weeks to look back (1 = most recent complete week).

    Returns:
        WeeklyData dataclass with all aggregated data.
    """
    (
        this_start,
        this_end,
        prev_start,
        prev_end,
    ) = _week_boundaries(weeks_back)

    data = WeeklyData(
        period_start=this_start[:10],
        period_end=this_end[:10],
        previous_period_start=prev_start[:10],
        previous_period_end=prev_end[:10],
        generated_at=_utc_now().strftime("%Y-%m-%d %H:%M UTC"),
    )

    _gather_executive_summary(conn, data, this_start, this_end, prev_start, prev_end)
    _gather_top_cves(conn, data, this_start, this_end)
    _gather_kev_details(conn, data, this_start, this_end)
    _gather_epss_movers(conn, data, this_start, this_end)
    _gather_vendor_breakdown(conn, data, this_start, this_end)
    _gather_attack_tags(conn, data, this_start, this_end)
    _gather_news(conn, data, this_start, this_end)
    _gather_threatfox(conn, data, this_start, this_end)
    _gather_top_pocs(conn, data, this_start, this_end)
    _gather_severity_breakdown(conn, data, this_start, this_end)
    _gather_weekly_trend(conn, data)
    _gather_triage_summary(conn, data)
    _gather_source_health(conn, data)

    return data


def _gather_executive_summary(
    conn: sqlite3.Connection,
    data: WeeklyData,
    this_start: str,
    this_end: str,
    prev_start: str,
    prev_end: str,
) -> None:
    """Fill in executive summary KPIs."""
    # CVE counts for this week and last week
    row = conn.execute(
        "SELECT COUNT(*) FROM cve WHERE first_seen >= ? AND first_seen < ?",
        (this_start, this_end),
    ).fetchone()
    data.total_cves_this_week = row[0] if row else 0

    row = conn.execute(
        "SELECT COUNT(*) FROM cve WHERE first_seen >= ? AND first_seen < ?",
        (prev_start, prev_end),
    ).fetchone()
    data.total_cves_last_week = row[0] if row else 0

    # PoC counts
    row = conn.execute(
        "SELECT COUNT(*) FROM poc WHERE first_seen >= ? AND first_seen < ?",
        (this_start, this_end),
    ).fetchone()
    data.total_pocs_this_week = row[0] if row else 0

    row = conn.execute(
        "SELECT COUNT(*) FROM poc WHERE first_seen >= ? AND first_seen < ?",
        (prev_start, prev_end),
    ).fetchone()
    data.total_pocs_last_week = row[0] if row else 0

    # KEV counts
    row = conn.execute(
        "SELECT COUNT(*) FROM cve WHERE kev = 1 AND first_seen >= ? AND first_seen < ?",
        (this_start, this_end),
    ).fetchone()
    data.kev_new_this_week = row[0] if row else 0

    row = conn.execute("SELECT COUNT(*) FROM cve WHERE kev = 1").fetchone()
    data.kev_total = row[0] if row else 0

    # KEV overdue (past remediation deadline)
    now_str = _utc_now().strftime("%Y-%m-%d")
    row = conn.execute(
        "SELECT COUNT(*) FROM cve WHERE kev = 1 AND kev_due_date IS NOT NULL AND kev_due_date < ?",
        (now_str,),
    ).fetchone()
    data.kev_overdue = row[0] if row else 0

    # Critical/High counts this week
    row = conn.execute(
        "SELECT COUNT(*) FROM cve WHERE first_seen >= ? AND first_seen < ? AND cvss_score >= 9.0",
        (this_start, this_end),
    ).fetchone()
    data.critical_cves = row[0] if row else 0

    row = conn.execute(
        "SELECT COUNT(*) FROM cve WHERE first_seen >= ? AND first_seen < ? AND cvss_score >= 7.0 AND cvss_score < 9.0",
        (this_start, this_end),
    ).fetchone()
    data.high_cves = row[0] if row else 0

    # Averages this week
    row = conn.execute(
        "SELECT AVG(cvss_score), AVG(epss_score), AVG(reputation_score) FROM cve WHERE first_seen >= ? AND first_seen < ?",
        (this_start, this_end),
    ).fetchone()
    if row:
        data.avg_cvss_this_week = round(row[0], 1) if row[0] else 0.0
        data.avg_epss_this_week = round(row[1], 4) if row[1] else 0.0
        data.avg_reputation_this_week = round(row[2], 1) if row[2] else 0.0


def _gather_top_cves(
    conn: sqlite3.Connection,
    data: WeeklyData,
    this_start: str,
    this_end: str,
) -> None:
    """Top 15 CVEs by reputation score (multi-factor risk)."""
    rows = conn.execute(
        """
        SELECT id, description, cvss_score, cvss_severity, epss_score, kev,
               reputation_score, social_mentions, poc_source_count, published_at,
               trust_score, threatfox_ioc_count, stealer_hits, kev_due_date
        FROM cve
        WHERE first_seen >= ? AND first_seen < ?
        ORDER BY reputation_score DESC, cvss_score DESC
        LIMIT 15
        """,
        (this_start, this_end),
    ).fetchall()

    data.top_cves = [
        {
            "id": r[0],
            "description": r[1][:200] if r[1] else "",
            "cvss_score": r[2],
            "cvss_severity": r[3],
            "epss_score": r[4],
            "kev": bool(r[5]),
            "reputation_score": r[6],
            "social_mentions": r[7] or 0,
            "poc_source_count": r[8] or 0,
            "published_at": r[9][:10] if r[9] else "",
            "trust_score": r[10] or 0,
            "threatfox_ioc_count": r[11] or 0,
            "stealer_hits": r[12] or 0,
            "kev_due_date": r[13],
        }
        for r in rows
    ]


def _gather_kev_details(
    conn: sqlite3.Connection,
    data: WeeklyData,
    this_start: str,
    this_end: str,
) -> None:
    """CISA KEV entries with details."""
    rows = conn.execute(
        """
        SELECT id, description, cvss_score, epss_score, kev_due_date, published_at
        FROM cve
        WHERE kev = 1
        ORDER BY kev_due_date ASC
        """,
    ).fetchall()

    data.kev_entries = [
        {
            "id": r[0],
            "description": r[1][:200] if r[1] else "",
            "cvss_score": r[2],
            "epss_score": r[3],
            "kev_due_date": r[4],
            "published_at": r[5][:10] if r[5] else "",
            "is_new": r[5] is not None and r[5] >= this_start,
            "is_overdue": r[4] is not None and r[4] < _utc_now().strftime("%Y-%m-%d"),
        }
        for r in rows
    ]


def _gather_epss_movers(
    conn: sqlite3.Connection,
    data: WeeklyData,
    this_start: str,
    this_end: str,
) -> None:
    """CVEs with the highest EPSS scores (exploitability likelihood)."""
    rows = conn.execute(
        """
        SELECT id, cvss_score, epss_score, kev, reputation_score, description
        FROM cve
        WHERE epss_score IS NOT NULL AND first_seen >= ? AND first_seen < ?
        ORDER BY epss_score DESC
        LIMIT 10
        """,
        (this_start, this_end),
    ).fetchall()

    data.epss_movers = [
        {
            "id": r[0],
            "cvss_score": r[1],
            "epss_score": r[2],
            "kev": bool(r[3]),
            "reputation_score": r[4],
            "description": r[5][:150] if r[5] else "",
        }
        for r in rows
    ]


def _gather_vendor_breakdown(
    conn: sqlite3.Connection,
    data: WeeklyData,
    this_start: str,
    this_end: str,
) -> None:
    """Top vendors by CVE count this week."""
    rows = conn.execute(
        """
        SELECT p.vendor, COUNT(DISTINCT c.id) as cve_count,
               AVG(c.cvss_score) as avg_cvss,
               SUM(CASE WHEN c.kev = 1 THEN 1 ELSE 0 END) as kev_count
        FROM cve c
        JOIN cve_product cp ON cp.cve_id = c.id
        JOIN product p ON p.id = cp.product_id
        WHERE c.first_seen >= ? AND c.first_seen < ?
        GROUP BY p.vendor
        ORDER BY cve_count DESC, avg_cvss DESC
        LIMIT 15
        """,
        (this_start, this_end),
    ).fetchall()

    data.top_vendors = [
        {
            "vendor": r[0],
            "cve_count": r[1],
            "avg_cvss": round(r[2], 1) if r[2] else 0.0,
            "kev_count": r[3],
        }
        for r in rows
    ]


def _gather_attack_tags(
    conn: sqlite3.Connection,
    data: WeeklyData,
    this_start: str,
    this_end: str,
) -> None:
    """Top attack technique tags (MITRE ATT&CK mapping)."""
    rows = conn.execute(
        """
        SELECT cat.tag, COUNT(DISTINCT c.id) as cve_count,
               AVG(c.cvss_score) as avg_cvss
        FROM cve c
        JOIN cve_attack_tag cat ON cat.cve_id = c.id
        WHERE c.first_seen >= ? AND c.first_seen < ?
        GROUP BY cat.tag
        ORDER BY cve_count DESC, avg_cvss DESC
        LIMIT 12
        """,
        (this_start, this_end),
    ).fetchall()

    data.top_tags = [
        {
            "tag": r[0],
            "cve_count": r[1],
            "avg_cvss": round(r[2], 1) if r[2] else 0.0,
        }
        for r in rows
    ]


def _gather_news(
    conn: sqlite3.Connection,
    data: WeeklyData,
    this_start: str,
    this_end: str,
) -> None:
    """Top news articles by tier (severity)."""
    rows = conn.execute(
        """
        SELECT title, url, source, tier, summary, published_at
        FROM news_article
        WHERE first_seen >= ? AND first_seen < ?
        ORDER BY tier ASC, published_at DESC
        LIMIT 10
        """,
        (this_start, this_end),
    ).fetchall()

    data.news_highlights = [
        {
            "title": r[0],
            "url": r[1],
            "source": r[2],
            "tier": r[3],
            "summary": r[4][:200] if r[4] else "",
            "published_at": r[5][:10] if r[5] else "",
        }
        for r in rows
    ]


def _gather_threatfox(
    conn: sqlite3.Connection,
    data: WeeklyData,
    this_start: str,
    this_end: str,
) -> None:
    """ThreatFox IOC summary."""
    # IOC type breakdown
    type_counts: dict[str, int] = {}
    for row in conn.execute("SELECT ioc_type, COUNT(*) FROM cve_threatfox_ioc GROUP BY ioc_type"):
        type_counts[row[0]] = row[1]

    # Total IOCs linked to CVEs
    row = conn.execute("SELECT COUNT(DISTINCT ioc_value) FROM cve_threatfox_ioc").fetchone()
    total_iocs = row[0] if row else 0

    # CVEs with IOCs
    row = conn.execute("SELECT COUNT(DISTINCT cve_id) FROM cve_threatfox_ioc").fetchone()
    cves_with_iocs = row[0] if row else 0

    # Top threat types
    threat_types: list[dict[str, Any]] = []
    for row in conn.execute(
        """
        SELECT threat_type, COUNT(*) as cnt
        FROM cve_threatfox_ioc
        WHERE threat_type IS NOT NULL
        GROUP BY threat_type
        ORDER BY cnt DESC
        LIMIT 8
        """
    ):
        threat_types.append({"threat_type": row[0], "count": row[1]})

    data.threatfox_summary = {
        "total_iocs": total_iocs,
        "cves_with_iocs": cves_with_iocs,
        "type_counts": type_counts,
        "top_threat_types": threat_types,
    }


def _gather_top_pocs(
    conn: sqlite3.Connection,
    data: WeeklyData,
    this_start: str,
    this_end: str,
) -> None:
    """Top PoCs by stars (community validation) and engagement."""
    rows = conn.execute(
        """
        SELECT p.url, p.source, p.stars, p.description, p.exploit_type,
               COUNT(pc.cve_id) as linked_cve_count
        FROM poc p
        LEFT JOIN poc_cve pc ON pc.poc_url = p.url
        WHERE p.first_seen >= ? AND p.first_seen < ?
        GROUP BY p.url
        ORDER BY p.stars DESC
        LIMIT 10
        """,
        (this_start, this_end),
    ).fetchall()

    data.top_pocs = [
        {
            "url": r[0],
            "source": r[1],
            "stars": r[2] or 0,
            "description": r[3][:150] if r[3] else "",
            "exploit_type": r[4],
            "linked_cves": r[5],
        }
        for r in rows
    ]


def _gather_severity_breakdown(
    conn: sqlite3.Connection,
    data: WeeklyData,
    this_start: str,
    this_end: str,
) -> None:
    """CVSS severity distribution for the week."""
    breakdown: dict[str, int] = {}
    for row in conn.execute(
        """
        SELECT cvss_severity, COUNT(*)
        FROM cve
        WHERE first_seen >= ? AND first_seen < ? AND cvss_severity IS NOT NULL
        GROUP BY cvss_severity
        """,
        (this_start, this_end),
    ):
        breakdown[row[0]] = row[1]
    data.severity_breakdown = breakdown


def _gather_weekly_trend(conn: sqlite3.Connection, data: WeeklyData) -> None:
    """Last 8 weeks of CVE intake for trend chart data."""
    rows = conn.execute(
        """
        SELECT SUBSTR(first_seen, 1, 7) AS month,
               SUBSTR(first_seen, 9, 2) AS day,
               COUNT(*) as cnt
        FROM cve
        WHERE first_seen IS NOT NULL
        GROUP BY SUBSTR(first_seen, 1, 10)
        ORDER BY SUBSTR(first_seen, 1, 10) DESC
        LIMIT 56
        """
    ).fetchall()

    # Aggregate into weekly buckets
    from collections import Counter

    weekly: Counter[str] = Counter()
    for r in rows:
        # Get the ISO week
        try:
            dt = datetime.strptime(r[0] + "-" + r[1], "%Y-%m-%d")
            iso_week = dt.strftime("%Y-W%W")
            weekly[iso_week] += r[2]
        except ValueError:
            pass

    data.weekly_trend = [
        {"week": w, "count": c} for w, c in sorted(weekly.items(), reverse=True)[:8]
    ][::-1]


def _gather_triage_summary(conn: sqlite3.Connection, data: WeeklyData) -> None:
    """Triage workflow status breakdown."""
    summary: dict[str, int] = {}
    for row in conn.execute("SELECT status, COUNT(*) FROM cve_triage GROUP BY status"):
        summary[row[0]] = row[1]
    data.triage_summary = summary


def _gather_source_health(conn: sqlite3.Connection, data: WeeklyData) -> None:
    """Source health observability data."""
    rows = conn.execute(
        """
        SELECT source_name, last_run_at, last_status, last_error,
               cve_count, poc_count, consecutive_failures
        FROM source_health
        ORDER BY source_name
        """
    ).fetchall()

    data.source_health = [
        {
            "source": r[0],
            "last_run": r[1][:19] if r[1] else "never",
            "status": r[2],
            "error": r[3][:100] if r[3] else None,
            "cves": r[4],
            "pocs": r[5],
            "consecutive_failures": r[6],
        }
        for r in rows
    ]
