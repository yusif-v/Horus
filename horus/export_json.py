"""Static JSON export — dump Horus DB to CVE-Intel-compatible JSON files.

Usage:
    python3 -m horus --export-json ./export_dir

Creates:
    stats.json          — aggregate statistics
    YYYY.json           — CVEs grouped by year with linked PoCs
    nvd_intel_YYYY.json — compact NVD intel per year
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any


def export_all(db_path: str, output_dir: str) -> list[str]:
    """Export the Horus DB to CVE-Intel-compatible JSON files.

    Args:
        db_path: Path to the SQLite database.
        output_dir: Directory to write JSON files into (created if needed).

    Returns:
        List of file paths that were written.
    """
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    written: list[str] = []
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        written.append(_export_stats(conn, out))
        written.extend(_export_year_cves(conn, out))
        written.extend(_export_nvd_intel(conn, out))
    finally:
        conn.close()

    return written


def _export_stats(conn: sqlite3.Connection, output_dir: Path) -> str:
    """Write aggregate stats to stats.json."""
    cve_count = conn.execute("SELECT COUNT(*) FROM cve").fetchone()[0]
    poc_count = conn.execute("SELECT COUNT(*) FROM poc").fetchone()[0]
    kev_count = conn.execute("SELECT COUNT(*) FROM cve WHERE kev = 1").fetchone()[0]
    with_epss = conn.execute("SELECT COUNT(*) FROM cve WHERE epss_score IS NOT NULL").fetchone()[0]
    linked_pocs = conn.execute("SELECT COUNT(DISTINCT poc_url) FROM poc_cve").fetchone()[0]
    cves_with_pocs = conn.execute("SELECT COUNT(DISTINCT cve_id) FROM poc_cve").fetchone()[0]

    avg_row = conn.execute("SELECT AVG(epss_score), AVG(reputation_score) FROM cve").fetchone()
    avg_epss = round(avg_row[0], 6) if avg_row[0] is not None else None
    avg_reputation = round(avg_row[1], 2) if avg_row[1] is not None else None

    weaponized = conn.execute(
        "SELECT COUNT(*) FROM cve WHERE kev = 1 OR EXISTS (SELECT 1 FROM poc_cve WHERE cve_id = cve.id)"
    ).fetchone()[0]

    # "imminent" = KEV + EPSS > 0.5 or reputation > 7
    imminent = conn.execute(
        """
        SELECT COUNT(*) FROM cve
        WHERE kev = 1
           OR (epss_score IS NOT NULL AND epss_score > 0.5)
           OR (reputation_score IS NOT NULL AND reputation_score > 7)
        """
    ).fetchone()[0]

    # Severity breakdown
    severity_breakdown: dict[str, int] = {}
    for row in conn.execute(
        "SELECT cvss_severity, COUNT(*) FROM cve WHERE cvss_severity IS NOT NULL GROUP BY cvss_severity"
    ):
        severity_breakdown[row[0]] = row[1]

    # Monthly CVEs (by published_at month)
    monthly_cves: dict[str, int] = {}
    for row in conn.execute(
        """
        SELECT SUBSTR(published_at, 1, 7) AS month, COUNT(*)
        FROM cve
        WHERE published_at IS NOT NULL
        GROUP BY month
        ORDER BY month
        """
    ):
        monthly_cves[row[0]] = row[1]

    stats: dict[str, Any] = {
        "cve_count": cve_count,
        "poc_count": poc_count,
        "kev_count": kev_count,
        "with_epss": with_epss,
        "linked_pocs": linked_pocs,
        "cves_with_pocs": cves_with_pocs,
        "avg_epss": avg_epss,
        "avg_reputation": avg_reputation,
        "weaponized": weaponized,
        "imminent": imminent,
        "severity_breakdown": severity_breakdown,
        "monthly_cves": monthly_cves,
    }

    out_path = output_dir / "stats.json"
    out_path.write_text(json.dumps(stats, indent=2))
    return str(out_path)


def _export_year_cves(conn: sqlite3.Connection, output_dir: Path) -> list[str]:
    """Write CVEs grouped by discovery year to YYYY.json files."""
    # Find all years present in published_at
    years_rows = conn.execute(
        """
        SELECT DISTINCT SUBSTR(published_at, 1, 4) AS year
        FROM cve
        WHERE published_at IS NOT NULL
        ORDER BY year
        """
    ).fetchall()
    years = [row[0] for row in years_rows]

    written: list[str] = []
    for year in years:
        cves = _fetch_cves_for_year(conn, year)
        if not cves:
            continue
        payload = {"year": int(year), "cves": cves}
        out_path = output_dir / f"{year}.json"
        out_path.write_text(json.dumps(payload, indent=2))
        written.append(str(out_path))

    return written


def _fetch_cves_for_year(conn: sqlite3.Connection, year: str) -> list[dict[str, Any]]:
    """Fetch all CVEs for a given year with linked PoCs."""
    rows = conn.execute(
        """
        SELECT id, description, cvss_score, cvss_severity, epss_score, kev, published_at
        FROM cve
        WHERE SUBSTR(published_at, 1, 4) = ?
        ORDER BY cvss_score DESC NULLS LAST
        """,
        (year,),
    ).fetchall()

    cves: list[dict[str, Any]] = []
    for row in rows:
        cve_id = row[0]
        repositories = _fetch_linked_repos(conn, cve_id)
        cves.append(
            {
                "id": cve_id,
                "description": row[1],
                "cvss_score": row[2],
                "cvss_severity": row[3],
                "epss_score": row[4],
                "kev": bool(row[5]),
                "published_at": row[6],
                "repositories": repositories,
            }
        )
    return cves


def _fetch_linked_repos(conn: sqlite3.Connection, cve_id: str) -> list[dict[str, Any]]:
    """Fetch linked PoC repositories for a CVE."""
    return [
        {
            "url": r[0],
            "source": r[1],
            "stars": r[2],
            "description": r[3],
        }
        for r in conn.execute(
            """
            SELECT p.url, p.source, p.stars, p.description
            FROM poc_cve pc
            JOIN poc p ON p.url = pc.poc_url
            WHERE pc.cve_id = ?
            ORDER BY p.stars DESC NULLS LAST
            """,
            (cve_id,),
        )
    ]


def _export_nvd_intel(conn: sqlite3.Connection, output_dir: Path) -> list[str]:
    """Write compact NVD intel per year to nvd_intel_YYYY.json files."""
    years_rows = conn.execute(
        """
        SELECT DISTINCT SUBSTR(published_at, 1, 4) AS year
        FROM cve
        WHERE published_at IS NOT NULL
        ORDER BY year
        """
    ).fetchall()
    years = [row[0] for row in years_rows]

    written: list[str] = []
    for year in years:
        intel = _fetch_nvd_intel_for_year(conn, year)
        if not intel:
            continue
        out_path = output_dir / f"nvd_intel_{year}.json"
        out_path.write_text(json.dumps(intel, indent=2))
        written.append(str(out_path))

    return written


def _fetch_nvd_intel_for_year(conn: sqlite3.Connection, year: str) -> dict[str, dict[str, Any]]:
    """Fetch compact NVD intel for a given year.

    Format: {"CVE-ID": {"s": score, "d": description[:200], "e": epss, "k": kev}}
    """
    intel: dict[str, dict[str, Any]] = {}
    for row in conn.execute(
        """
        SELECT id, cvss_score, description, epss_score, kev
        FROM cve
        WHERE SUBSTR(published_at, 1, 4) = ?
        """,
        (year,),
    ):
        cve_id = row[0]
        entry: dict[str, Any] = {}
        if row[1] is not None:
            entry["s"] = row[1]
        if row[2] is not None:
            entry["d"] = row[2][:200]
        if row[3] is not None:
            entry["e"] = row[3]
        entry["k"] = bool(row[4])
        intel[cve_id] = entry

    return intel
