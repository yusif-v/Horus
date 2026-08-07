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


def _truncate(text: str, max_len: int) -> str:
    """Truncate text at a word boundary, adding ellipsis if cut."""
    if not text or len(text) <= max_len:
        return text or ""
    truncated = text[:max_len]
    last_space = truncated.rfind(" ")
    if last_space > max_len // 2:
        truncated = truncated[:last_space]
    return truncated + "..."


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

    # IOC sections
    network_iocs: list[dict[str, Any]] = field(default_factory=list)
    host_iocs: list[dict[str, Any]] = field(default_factory=list)
    ioc_summary: dict[str, Any] = field(default_factory=dict)

    # Affected packages (vendor/product/version)
    affected_packages: list[dict[str, Any]] = field(default_factory=list)

    # Source health
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
    _gather_iocs(conn, data, this_start, this_end)
    _gather_affected_packages(conn, data, this_start, this_end)
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
            "description": _truncate(r[1], 200),
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
    """CISA KEV entries with full details."""
    today = _utc_now().strftime("%Y-%m-%d")
    rows = conn.execute(
        """
        SELECT c.id, c.description, c.cvss_score, c.cvss_severity,
               c.epss_score, c.kev_due_date, c.published_at,
               GROUP_CONCAT(DISTINCT p.vendor || '/' || p.product) as affected
        FROM cve c
        LEFT JOIN cve_product cp ON cp.cve_id = c.id
        LEFT JOIN product p ON p.id = cp.product_id AND p.category != 'unknown'
        WHERE c.kev = 1
        GROUP BY c.id
        ORDER BY c.kev_due_date ASC
        """,
    ).fetchall()

    data.kev_entries = []
    for r in rows:
        due_str = r[5] or "Not Set"
        is_overdue = r[5] is not None and r[5] < today
        days_overdue = 0
        if is_overdue:
            try:
                due_date = datetime.strptime(r[5], "%Y-%m-%d").date()
                days_overdue = (_utc_now().date() - due_date).days
            except ValueError:
                pass
        data.kev_entries.append(
            {
                "id": r[0],
                "description": _truncate(r[1], 200),
                "cvss_score": r[2],
                "cvss_severity": r[3],
                "epss_score": r[4],
                "kev_due_date": due_str,
                "published_at": r[6][:10] if r[6] else "",
                "affected": r[7] or "Unknown",
                "is_new": r[6] is not None and r[6] >= this_start,
                "is_overdue": is_overdue,
                "days_overdue": days_overdue,
            }
        )


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
            "description": _truncate(r[5], 150),
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
          AND p.category != 'unknown'
          AND p.vendor != 'unknown'
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
    """Top news articles by tier (severity) from the last 7 days."""
    cutoff = (_utc_now() - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S")
    rows = conn.execute(
        """
        SELECT title, url, source, tier, summary, published_at
        FROM news_article
        WHERE published_at >= ?
        ORDER BY tier ASC, published_at DESC
        LIMIT 10
        """,
        (cutoff,),
    ).fetchall()

    data.news_highlights = [
        {
            "title": r[0],
            "url": r[1],
            "source": r[2],
            "tier": r[3],
            "summary": _truncate(r[4], 200),
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
            "description": _truncate(r[3], 150),
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


def _gather_affected_packages(
    conn: sqlite3.Connection,
    data: WeeklyData,
    this_start: str,
    this_end: str,
) -> None:
    """Affected vendor/product combinations with CVE counts."""
    rows = conn.execute(
        """
        SELECT p.vendor, p.product, COUNT(DISTINCT c.id) as cve_count,
               GROUP_CONCAT(DISTINCT c.id) as sample_cves
        FROM cve c
        JOIN cve_product cp ON cp.cve_id = c.id
        JOIN product p ON p.id = cp.product_id
        WHERE p.category != 'unknown'
          AND p.vendor != 'unknown'
        GROUP BY p.vendor, p.product
        HAVING cve_count > 0
        ORDER BY cve_count DESC
        LIMIT 20
        """,
    ).fetchall()

    data.affected_packages = [
        {
            "vendor": r[0],
            "product": r[1],
            "cve_count": r[2],
            "sample_cves": r[3].split(",")[:5] if r[3] else [],
        }
        for r in rows
    ]


def _gather_source_health(conn: sqlite3.Connection, data: WeeklyData) -> None:
    """Gather source health status."""
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
            "last_run_at": r[1] or "",
            "status": r[2],
            "error": r[3],
            "cve_count": r[4] or 0,
            "poc_count": r[5] or 0,
            "consecutive_failures": r[6] or 0,
        }
        for r in rows
    ]


def _gather_iocs(
    conn: sqlite3.Connection,
    data: WeeklyData,
    this_start: str,
    this_end: str,
) -> None:
    """Gather network and host IOCs from ioc_indicator and cve_threatfox_ioc tables."""
    # Network IOCs: IPs, domains, URLs — from both ioc_indicator and threatfox
    network: dict[str, dict[str, Any]] = {}

    # From ioc_indicator — recent network IOCs
    cutoff = (_utc_now() - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%S")
    for row in conn.execute(
        """
        SELECT ioc_value, ioc_type, source, source_ref, cve_id
        FROM ioc_indicator
        WHERE ioc_type IN ('ip', 'domain', 'url')
          AND ioc_value NOT LIKE '%t.co%'
          AND last_seen >= ?
        ORDER BY last_seen DESC
        LIMIT 200
        """,
        (cutoff,),
    ):
        val, typ, src, ref, cve = row
        key = f"{typ}:{val}"
        if key not in network:
            network[key] = {
                "value": val,
                "type": typ,
                "sources": set(),
                "refs": set(),
                "cves": set(),
            }
        network[key]["sources"].add(src)
        if ref:
            network[key]["refs"].add(ref)
        if cve:
            network[key]["cves"].add(cve)

    # From threatfox — only those NOT already in ioc_indicator (avoid duplicates)
    existing_keys = set(network.keys())
    for row in conn.execute(
        """
        SELECT ioc_value, ioc_type, cve_id, threat_type
        FROM cve_threatfox_ioc
        WHERE ioc_type IN ('ip', 'domain', 'url')
          AND cve_id IS NOT NULL
        ORDER BY last_seen DESC
        LIMIT 100
        """,
    ):
        val, typ, cve, threat = row
        key = f"{typ}:{val}"
        if key in existing_keys:
            # Add CVE link to existing entry
            if cve:
                network[key]["cves"].add(cve)
            continue
        network[key] = {
            "value": val,
            "type": typ,
            "sources": {"threatfox"},
            "refs": set(),
            "cves": {cve} if cve else set(),
            "threat_type": threat or "",
        }

    data.network_iocs = sorted(
        [
            {
                "value": v["value"],
                "type": v["type"],
                "sources": sorted(v["sources"]),
                "refs": sorted(v["refs"])[:3],
                "cves": sorted(v["cves"]),
                "cve_count": len(v["cves"]),
                "threat_type": v.get("threat_type", ""),
            }
            for v in network.values()
        ],
        key=lambda x: (-x["cve_count"], x["type"], x["value"]),
    )

    # Host IOCs: hashes, paths, registry keys
    host: dict[str, dict[str, Any]] = {}

    for row in conn.execute(
        """
        SELECT ioc_value, ioc_type, source, source_ref, cve_id
        FROM ioc_indicator
        WHERE ioc_type IN ('hash_md5', 'hash_sha1', 'hash_sha256', 'path', 'registry')
          AND last_seen >= ?
        ORDER BY CASE WHEN cve_id IS NOT NULL THEN 0 ELSE 1 END, last_seen DESC
        LIMIT 200
        """,
        (cutoff,),
    ):
        val, typ, src, ref, cve = row
        key = f"{typ}:{val}"
        if key not in host:
            host[key] = {
                "value": val,
                "type": typ,
                "sources": set(),
                "refs": set(),
                "cves": set(),
            }
        host[key]["sources"].add(src)
        if ref:
            host[key]["refs"].add(ref)
        if cve:
            host[key]["cves"].add(cve)

    # ThreatFox hashes
    for row in conn.execute(
        """
        SELECT ioc_value, ioc_type, cve_id
        FROM cve_threatfox_ioc
        WHERE ioc_type = 'hash'
        ORDER BY last_seen DESC
        LIMIT 100
        """,
    ):
        val, typ, cve = row
        key = f"hash:{val}"
        if key not in host:
            host[key] = {
                "value": val,
                "type": "hash_md5"
                if len(val) == 32
                else "hash_sha1"
                if len(val) == 40
                else "hash_sha256",
                "sources": set(),
                "refs": set(),
                "cves": set(),
            }
        host[key]["sources"].add("threatfox")
        if cve:
            host[key]["cves"].add(cve)

    data.host_iocs = sorted(
        [
            {
                "value": v["value"],
                "type": v["type"],
                "sources": sorted(v["sources"]),
                "refs": sorted(v["refs"])[:3],
                "cves": sorted(v["cves"]),
                "cve_count": len(v["cves"]),
            }
            for v in host.values()
        ],
        key=lambda x: (-x["cve_count"], x["type"], x["value"]),
    )

    # IOC summary counts
    type_counts: dict[str, int] = {}
    for ioc in data.network_iocs + data.host_iocs:
        t = ioc["type"]
        type_counts[t] = type_counts.get(t, 0) + 1

    total_iocs = len(data.network_iocs) + len(data.host_iocs)
    all_cves: set[str] = set()
    for ioc in data.network_iocs + data.host_iocs:
        all_cves.update(ioc["cves"])

    data.ioc_summary = {
        "total_iocs": total_iocs,
        "network_count": len(data.network_iocs),
        "host_count": len(data.host_iocs),
        "cves_with_iocs": len(all_cves),
        "type_counts": type_counts,
    }
