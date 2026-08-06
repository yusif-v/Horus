"""Telegram message formatter for notification events.

Matches the existing Markdown report style.
"""

from __future__ import annotations

from typing import Any


def format_event_message(
    kind: str, item: dict[str, Any], username: str | None = None
) -> str | None:
    """Format a single event into a Telegram Markdown message.

    Returns None if the event can't be formatted.
    """
    if kind == "kev_new":
        return _format_kev(item)
    elif kind == "kev_overdue":
        return _format_kev_overdue(item)
    elif kind == "kev_due_soon":
        return _format_kev_due_soon(item)
    elif kind == "epss_jump":
        return _format_epss(item)
    elif kind == "critical_cve":
        return _format_critical(item)
    elif kind == "watchlist_match":
        return _format_watchlist(item)
    elif kind == "poc_new":
        return _format_poc(item)
    return None


def _format_kev(item: dict[str, Any]) -> str:
    cve_id = item.get("cve_id", "Unknown")
    score = item.get("cvss_score")
    severity = item.get("cvss_severity", "")
    score_str = f"CVSS {score} {severity}" if score else "no CVSS"
    return (
        f"🔴 *NEW KEV ADDITION*\n"
        f"*{cve_id}* — {score_str}\n"
        f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    )


def _format_kev_overdue(item: dict[str, Any]) -> str:
    """Format a KEV CVE that has passed its remediation deadline."""
    cve_id = item.get("cve_id", "Unknown")
    due_date = item.get("due_date", "Unknown")
    score = item.get("cvss_score")
    severity = item.get("cvss_severity", "")
    score_str = f"CVSS {score} {severity}" if score else "no CVSS"
    return (
        f"🔴 *KEV OVERDUE*\n"
        f"*{cve_id}* — {score_str}\n"
        f"Deadline: {due_date} (passed)\n"
        f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    )


def _format_kev_due_soon(item: dict[str, Any]) -> str:
    """Format a KEV CVE with deadline within 30 days."""
    cve_id = item.get("cve_id", "Unknown")
    due_date = item.get("due_date", "Unknown")
    score = item.get("cvss_score")
    severity = item.get("cvss_severity", "")
    score_str = f"CVSS {score} {severity}" if score else "no CVSS"
    return (
        f"🟡 *KEV DUE SOON*\n"
        f"*{cve_id}* — {score_str}\n"
        f"Deadline: {due_date}\n"
        f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    )


def _format_epss(item: dict[str, Any]) -> str:
    cve_id = item.get("cve_id", "Unknown")
    score = item.get("epss_score", 0)
    pct = f"{score * 100:.1f}%" if score else "N/A"
    return f"📊 *EPSS JUMP*\n*{cve_id}* — EPSS now {pct}\nhttps://nvd.nist.gov/vuln/detail/{cve_id}"


def _format_critical(item: dict[str, Any]) -> str:
    cve_id = item.get("cve_id", "Unknown")
    score = item.get("cvss_score")
    severity = item.get("cvss_severity", "")
    poc_count = item.get("poc_count", 0)
    score_str = f"CVSS {score} {severity}" if score else "no CVSS"
    poc_str = f" · {poc_count} PoC{'s' if poc_count != 1 else ''}" if poc_count else ""
    return (
        f"🚨 *CRITICAL CVE + PoC*\n"
        f"*{cve_id}* — {score_str}{poc_str}\n"
        f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    )


def _format_watchlist(item: dict[str, Any]) -> str:
    cve_id = item.get("cve_id", "Unknown")
    vendor = item.get("vendor", "Unknown")
    product = item.get("product", "")
    team = item.get("team", "")
    prod_str = f"{vendor}/{product}" if product else vendor
    team_str = f" [{team} team]" if team else ""
    return (
        f"⭐ *WATCHLIST MATCH{team_str}*\n"
        f"*{cve_id}* — {prod_str}\n"
        f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    )


def _format_poc(item: dict[str, Any]) -> str:
    cve_id = item.get("cve_id", "Unknown")
    url = item.get("url", "")
    source = item.get("source", "")
    return (
        f"🔧 *NEW PoC*\n*{cve_id}* — [{source}]({url})\nhttps://nvd.nist.gov/vuln/detail/{cve_id}"
    )
