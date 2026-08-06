"""Weekly threat report renderer.

Produces professional weekly threat intelligence reports in text, markdown,
and HTML formats suitable for executive distribution and SOC handoffs.

Usage:
    from horus.render.weekly import render_weekly_report
    report_md = render_weekly_report(data, fmt="md")
"""

from __future__ import annotations

from io import StringIO

from ..storage.weekly import WeeklyData
from .charts import (
    cve_trend_line,
    cvss_badge,
    epss_bar,
    mitre_heatmap,
    severity_donut,
    vendor_bar_chart,
)


def render_weekly_report(data: WeeklyData, fmt: str = "md") -> str:
    """Render a weekly threat report in the requested format.

    Args:
        data: WeeklyData from gather_weekly_data().
        fmt: Output format - "text", "md", or "html".

    Returns:
        Rendered report string.
    """
    if fmt == "html":
        return _render_html(data)
    if fmt == "text":
        return _render_text(data)
    return _render_markdown(data)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _pct_change(this_week: int, last_week: int) -> str:
    """Format week-over-week change as a percentage string."""
    if last_week == 0:
        return "NEW" if this_week > 0 else "0%"
    change = ((this_week - last_week) / last_week) * 100
    if change > 0:
        return f"+{change:.0f}%"
    return f"{change:.0f}%"


def _trend_arrow(this_week: int, last_week: int) -> str:
    """Return a trend indicator arrow."""
    if this_week > last_week:
        return "▲"
    if this_week < last_week:
        return "▼"
    return "→"


def _severity_emoji(severity: str) -> str:
    """Map CVSS severity to emoji indicator."""
    return {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🟢",
    }.get(severity, "⚪")


def _tier_label(tier: int) -> str:
    """Map news tier to label."""
    return {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM", 4: "LOW", 5: "BACKGROUND"}.get(tier, "INFO")


# ---------------------------------------------------------------------------
# Markdown renderer
# ---------------------------------------------------------------------------


def _render_markdown(data: WeeklyData) -> str:
    out = StringIO()

    def w(s: str = "") -> None:
        out.write(s + "\n")

    # Header
    w("# Weekly Threat Intelligence Report")
    w(f"**Period:** {data.period_start} to {data.period_end}")
    w(f"**Generated:** {data.generated_at}")
    w()
    w("---")
    w()

    # Executive Summary
    w("## Executive Summary")
    w()
    w("| Metric | This Week | Last Week | Change |")
    w("|--------|-----------|-----------|--------|")
    w(
        f"| New CVEs | {data.total_cves_this_week} | {data.total_cves_last_week} | {_trend_arrow(data.total_cves_this_week, data.total_cves_last_week)} {_pct_change(data.total_cves_this_week, data.total_cves_last_week)} |"
    )
    w(
        f"| New PoCs | {data.total_pocs_this_week} | {data.total_pocs_last_week} | {_trend_arrow(data.total_pocs_this_week, data.total_pocs_last_week)} {_pct_change(data.total_pocs_this_week, data.total_pocs_last_week)} |"
    )
    w(f"| KEV Additions | {data.kev_new_this_week} | — | — |")
    w(f"| Critical (CVSS 9+) | {data.critical_cves} | — | — |")
    w(f"| High (CVSS 7-8.9) | {data.high_cves} | — | — |")
    w(f"| Avg CVSS | {data.avg_cvss_this_week} | — | — |")
    w(f"| Avg EPSS | {data.avg_epss_this_week:.4f} | — | — |")
    w(f"| Avg Reputation | {data.avg_reputation_this_week}/10 | — | — |")
    w()

    if data.kev_overdue > 0:
        w(
            f"> **WARNING:** {data.kev_overdue} KEV-listed CVEs are past their CISA remediation deadline."
        )
        w()

    # Severity Breakdown
    if data.severity_breakdown:
        w("### Severity Distribution")
        w()
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = data.severity_breakdown.get(sev, 0)
            if count > 0:
                bar = "█" * min(count, 40)
                w(f"- {_severity_emoji(sev)} **{sev}:** {count} {bar}")
        w()

    # Top CVEs
    if data.top_cves:
        w("## Top CVEs by Risk Score")
        w()
        w("| CVE | CVSS | Severity | EPSS | KEV | Reputation | PoCs | Description |")
        w("|-----|------|----------|------|-----|------------|------|-------------|")
        for cve in data.top_cves[:10]:
            kev_badge = " YES" if cve["kev"] else ""
            epss = f"{cve['epss_score']:.4f}" if cve["epss_score"] is not None else "N/A"
            w(
                f"| {cve['id']} | {cve['cvss_score'] or 'N/A'} | {cve['cvss_severity'] or 'N/A'} | {epss} |{kev_badge} | {cve['reputation_score'] or 0:.1f}/10 | {cve['poc_source_count']} | {cve['description'][:80]}... |"
            )
        w()

    # KEV Details
    if data.kev_entries:
        w("## CISA Known Exploited Vulnerabilities")
        w()
        new_kevs = [k for k in data.kev_entries if k["is_new"]]
        overdue_kevs = [k for k in data.kev_entries if k["is_overdue"]]

        if new_kevs:
            w(f"### New This Week ({len(new_kevs)})")
            w()
            for kev in new_kevs[:5]:
                due = f" | **Due: {kev['kev_due_date']}**" if kev["kev_due_date"] else ""
                w(f"- **{kev['id']}** | CVSS {kev['cvss_score'] or 'N/A'}{due}")
                w(f"  > {kev['description'][:150]}")
                w()

        if overdue_kevs:
            w(f"> **OVERDUE:** {len(overdue_kevs)} KEV entries past remediation deadline:")
            w()
            for kev in overdue_kevs[:5]:
                w(f"- **{kev['id']}** | Due: {kev['kev_due_date']} | {kev['description'][:100]}")
            w()

    # EPSS Top Exploitability
    if data.epss_movers:
        w("## Highest Exploitability (EPSS)")
        w()
        w("| CVE | CVSS | EPSS | KEV | Description |")
        w("|-----|------|------|-----|-------------|")
        for m in data.epss_movers[:8]:
            kev_badge = " YES" if m["kev"] else ""
            w(
                f"| {m['id']} | {m['cvss_score'] or 'N/A'} | **{m['epss_score']:.4f}** |{kev_badge} | {m['description'][:80]}... |"
            )
        w()

    # Vendor Breakdown
    if data.top_vendors:
        w("## Most Targeted Vendors")
        w()
        w("| Vendor | CVEs | Avg CVSS | KEVs |")
        w("|--------|------|----------|------|")
        for v in data.top_vendors[:10]:
            w(f"| {v['vendor']} | {v['cve_count']} | {v['avg_cvss']} | {v['kev_count']} |")
        w()

    # Attack Tags (MITRE ATT&CK mapping)
    if data.top_tags:
        w("## Attack Technique Distribution")
        w()
        w("| Technique | CVEs | Avg CVSS |")
        w("|-----------|------|----------|")
        for t in data.top_tags[:10]:
            w(f"| {t['tag']} | {t['cve_count']} | {t['avg_cvss']} |")
        w()

    # News Highlights
    if data.news_highlights:
        w("## Security News Highlights")
        w()
        for article in data.news_highlights[:8]:
            tier_badge = _tier_label(article["tier"])
            w(f"- [{article['title']}]({article['url']}) `[{tier_badge}]` *{article['source']}*")
            if article["summary"]:
                w(f"  > {article['summary'][:150]}")
            w()

    # ThreatFox IOC Summary
    if data.threatfox_summary.get("total_iocs", 0) > 0:
        w("## Threat Intelligence (ThreatFox IOCs)")
        w()
        w(f"- **Total IOCs:** {data.threatfox_summary['total_iocs']}")
        w(f"- **CVEs with IOCs:** {data.threatfox_summary['cves_with_iocs']}")
        type_counts = data.threatfox_summary.get("type_counts", {})
        if type_counts:
            types_str = ", ".join(f"{k}: {v}" for k, v in sorted(type_counts.items()))
            w(f"- **IOC Types:** {types_str}")
        threat_types = data.threatfox_summary.get("top_threat_types", [])
        if threat_types:
            top_types_str = ", ".join(
                f"{t['threat_type']} ({t['count']})" for t in threat_types[:5]
            )
            w(f"- **Top Threat Types:** {top_types_str}")
        w()

    # Top PoCs
    if data.top_pocs:
        w("## Notable Exploit Publications")
        w()
        w("| PoC | Source | Stars | Type | Linked CVEs |")
        w("|-----|--------|-------|------|-------------|")
        for poc in data.top_pocs[:8]:
            w(
                f"| [{poc['url'][:50]}...]({poc['url']}) | {poc['source']} | {poc['stars']}★ | {poc['exploit_type'] or 'N/A'} | {poc['linked_cves']} |"
            )
        w()

    # Triage Summary
    if data.triage_summary:
        w("## Triage Workflow Status")
        w()
        total_triaged = sum(data.triage_summary.values())
        w(f"Total triaged: **{total_triaged}**")
        w()
        for status in ["new", "acknowledged", "working", "done", "dismissed"]:
            count = data.triage_summary.get(status, 0)
            if count > 0:
                pct = (count / total_triaged * 100) if total_triaged > 0 else 0
                w(f"- {status.capitalize()}: **{count}** ({pct:.0f}%)")
        w()

    # Source Health
    if data.source_health:
        w("## Source Health")
        w()
        w("| Source | Status | Last Run | CVEs | PoCs | Failures |")
        w("|--------|--------|----------|------|------|----------|")
        for sh in data.source_health:
            status_emoji = (
                "OK" if sh["status"] == "ok" else "ERR" if sh["status"] == "error" else "SKIP"
            )
            w(
                f"| {sh['source']} | {status_emoji} | {sh['last_run'][:16]} | {sh['cves']} | {sh['pocs']} | {sh['consecutive_failures']} |"
            )
        w()

    # Footer
    w("---")
    w()
    w(f"*Report generated by Horus — {data.generated_at}*")

    return out.getvalue()


# ---------------------------------------------------------------------------
# Plain text renderer
# ---------------------------------------------------------------------------


def _render_text(data: WeeklyData) -> str:
    out = StringIO()

    def w(s: str = "") -> None:
        out.write(s + "\n")

    w("=" * 72)
    w("  WEEKLY THREAT INTELLIGENCE REPORT")
    w(f"  Period: {data.period_start} to {data.period_end}")
    w(f"  Generated: {data.generated_at}")
    w("=" * 72)
    w()

    w("EXECUTIVE SUMMARY")
    w("-" * 40)
    w(
        f"  New CVEs:        {data.total_cves_this_week:>4} (was {data.total_cves_last_week}, {_pct_change(data.total_cves_this_week, data.total_cves_last_week)})"
    )
    w(
        f"  New PoCs:         {data.total_pocs_this_week:>4} (was {data.total_pocs_last_week}, {_pct_change(data.total_pocs_this_week, data.total_pocs_last_week)})"
    )
    w(f"  KEV Additions:    {data.kev_new_this_week:>4}")
    w(f"  Critical (9+):    {data.critical_cves:>4}")
    w(f"  High (7-8.9):     {data.high_cves:>4}")
    w(f"  Avg CVSS:         {data.avg_cvss_this_week:>4}")
    w(f"  Avg EPSS:         {data.avg_epss_this_week:>8.4f}")
    w(f"  Avg Reputation:   {data.avg_reputation_this_week:>4}/10")
    w()

    if data.kev_overdue > 0:
        w(f"  *** WARNING: {data.kev_overdue} KEV CVEs past remediation deadline ***")
        w()

    if data.severity_breakdown:
        w("SEVERITY DISTRIBUTION")
        w("-" * 40)
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = data.severity_breakdown.get(sev, 0)
            if count > 0:
                bar = "#" * min(count, 40)
                w(f"  {sev:>8}: {count:>4} {bar}")
        w()

    if data.top_cves:
        w("TOP CVES BY RISK SCORE")
        w("-" * 40)
        for cve in data.top_cves[:10]:
            kev_str = " [KEV]" if cve["kev"] else ""
            epss_str = f" EPSS={cve['epss_score']:.4f}" if cve["epss_score"] is not None else ""
            w(
                f"  {cve['id']}  CVSS {cve['cvss_score'] or 'N/A'}  Rep {cve['reputation_score'] or 0:.1f}/10{kev_str}{epss_str}"
            )
            w(f"    {cve['description'][:80]}")
            w()

    if data.kev_entries:
        w("CISA KEV ENTRIES")
        w("-" * 40)
        new_kevs = [k for k in data.kev_entries if k["is_new"]]
        overdue_kevs = [k for k in data.kev_entries if k["is_overdue"]]
        if new_kevs:
            w(f"  New this week ({len(new_kevs)}):")
            for kev in new_kevs[:5]:
                due = f" | Due: {kev['kev_due_date']}" if kev["kev_due_date"] else ""
                w(f"    {kev['id']}  CVSS {kev['cvss_score'] or 'N/A'}{due}")
                w(f"      {kev['description'][:100]}")
        if overdue_kevs:
            w(f"  OVERDUE ({len(overdue_kevs)}):")
            for kev in overdue_kevs[:5]:
                w(f"    {kev['id']}  Due: {kev['kev_due_date']}")
        w()

    if data.epss_movers:
        w("HIGHEST EXPLOITABILITY (EPSS)")
        w("-" * 40)
        for m in data.epss_movers[:8]:
            kev_str = " [KEV]" if m["kev"] else ""
            w(f"  {m['id']}  EPSS {m['epss_score']:.4f}  CVSS {m['cvss_score'] or 'N/A'}{kev_str}")
            w(f"    {m['description'][:80]}")
        w()

    if data.top_vendors:
        w("MOST TARGETED VENDORS")
        w("-" * 40)
        for v in data.top_vendors[:10]:
            kev_str = f" ({v['kev_count']} KEV)" if v["kev_count"] else ""
            w(f"  {v['vendor']:<25} {v['cve_count']:>3} CVEs  avg CVSS {v['avg_cvss']}{kev_str}")
        w()

    if data.top_tags:
        w("ATTACK TECHNIQUE DISTRIBUTION")
        w("-" * 40)
        for t in data.top_tags[:10]:
            w(f"  {t['tag']:<30} {t['cve_count']:>3} CVEs  avg CVSS {t['avg_cvss']}")
        w()

    if data.news_highlights:
        w("SECURITY NEWS HIGHLIGHTS")
        w("-" * 40)
        for article in data.news_highlights[:8]:
            tier = _tier_label(article["tier"])
            w(f"  [{tier}] {article['title'][:70]}")
            w(f"    Source: {article['source']}  {article['url'][:70]}")
            w()

    if data.threatfox_summary.get("total_iocs", 0) > 0:
        w("THREATFOX IOC SUMMARY")
        w("-" * 40)
        w(f"  Total IOCs: {data.threatfox_summary['total_iocs']}")
        w(f"  CVEs with IOCs: {data.threatfox_summary['cves_with_iocs']}")
        type_counts = data.threatfox_summary.get("type_counts", {})
        if type_counts:
            for k, v in sorted(type_counts.items()):
                w(f"    {k}: {v}")
        w()

    if data.top_pocs:
        w("NOTABLE EXPLOIT PUBLICATIONS")
        w("-" * 40)
        for poc in data.top_pocs[:8]:
            w(f"  {poc['url'][:60]}")
            w(
                f"    Source: {poc['source']}  Stars: {poc['stars']}  Type: {poc['exploit_type'] or 'N/A'}"
            )
        w()

    if data.triage_summary:
        w("TRIAGE WORKFLOW STATUS")
        w("-" * 40)
        total_triaged = sum(data.triage_summary.values())
        w(f"  Total triaged: {total_triaged}")
        for status in ["new", "acknowledged", "working", "done", "dismissed"]:
            count = data.triage_summary.get(status, 0)
            if count > 0:
                w(f"    {status.capitalize():<15} {count:>4}")
        w()

    if data.source_health:
        w("SOURCE HEALTH")
        w("-" * 40)
        for sh in data.source_health:
            err_str = f" (ERROR: {sh['error'][:50]})" if sh["error"] else ""
            w(f"  {sh['source']:<20} {sh['status']:<6}  Last: {sh['last_run'][:16]}{err_str}")
        w()

    w("=" * 72)
    w(f"  Generated by Horus — {data.generated_at}")
    w("=" * 72)

    return out.getvalue()


# ---------------------------------------------------------------------------
# HTML renderer (self-contained, professional)
# ---------------------------------------------------------------------------


def _render_html(data: WeeklyData) -> str:
    """Render a publication-quality HTML report with SVG charts and print-ready CSS."""
    total_cves = data.total_cves_this_week
    total_pocs = data.total_pocs_this_week
    cve_trend = _trend_arrow(data.total_cves_this_week, data.total_cves_last_week)
    poc_trend = _trend_arrow(data.total_pocs_this_week, data.total_pocs_last_week)
    cve_pct = _pct_change(data.total_cves_this_week, data.total_cves_last_week)
    poc_pct = _pct_change(data.total_pocs_this_week, data.total_pocs_last_week)

    # Determine trend direction classes
    cve_dir = (
        "up"
        if data.total_cves_this_week > data.total_cves_last_week
        else "down"
        if data.total_cves_this_week < data.total_cves_last_week
        else "neutral"
    )
    poc_dir = (
        "up"
        if data.total_pocs_this_week > data.total_pocs_last_week
        else "down"
        if data.total_pocs_this_week < data.total_pocs_last_week
        else "neutral"
    )

    # Build donut chart
    donut_chart = severity_donut(
        critical=data.severity_breakdown.get("CRITICAL", 0),
        high=data.severity_breakdown.get("HIGH", 0),
        medium=data.severity_breakdown.get("MEDIUM", 0),
        low=data.severity_breakdown.get("LOW", 0),
    )

    # Build trend line chart
    trend_chart = cve_trend_line(data.weekly_trend) if data.weekly_trend else ""

    # Build vendor bar chart
    vendor_chart = vendor_bar_chart(data.top_vendors) if data.top_tags else ""

    # Build MITRE heatmap
    mitre_chart = mitre_heatmap(data.top_tags) if data.top_tags else ""

    # Build executive narrative
    narrative = _build_narrative(data)

    # Build key findings
    findings = _build_findings(data)

    # Build top CVE cards
    cve_cards = _build_cve_cards(data.top_cves[:5]) if data.top_cves else ""

    # Build CVE detail table
    cves_html = _build_cve_table(data.top_cves[:10]) if data.top_cves else ""

    # Build KEV section
    kev_html = _build_kev_section(data.kev_entries)

    # Build vendor table
    vendor_html = _build_vendor_table(data.top_vendors[:10]) if data.top_vendors else ""

    # Build news section
    news_html = _build_news_section(data.news_highlights[:8]) if data.news_highlights else ""

    # Build ThreatFox section
    threatfox_html = _build_threatfox_section(data.threatfox_summary)

    # Build PoCs section
    pocs_html = _build_pocs_section(data.top_pocs[:8]) if data.top_pocs else ""

    # Build EPSS section
    epss_html = _build_epss_section(data.epss_movers[:8]) if data.epss_movers else ""

    # Build triage section
    triage_html = _build_triage_section(data.triage_summary)

    # Build source health
    health_html = _build_source_health(data.source_health)

    # Stats overlay for cover
    stats_overlay = (
        f'<div class="cover-stats">'
        f'<div class="cover-stat"><span class="cover-stat-num">{total_cves}</span><span class="cover-stat-label">New CVEs</span></div>'
        f'<div class="cover-stat"><span class="cover-stat-num critical">{data.critical_cves}</span><span class="cover-stat-label">Critical</span></div>'
        f'<div class="cover-stat"><span class="cover-stat-num">{data.kev_new_this_week}</span><span class="cover-stat-label">KEV Additions</span></div>'
        f'<div class="cover-stat"><span class="cover-stat-num">{total_pocs}</span><span class="cover-stat-label">New PoCs</span></div>'
        f"</div>"
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Weekly Threat Report — {data.period_start} to {data.period_end}</title>
<style>
:root {{
    --bg: #0d1117; --card: #161b22; --card-alt: #1c2128; --border: #30363d;
    --border-bright: #484f58; --text: #c9d1d9; --text-dim: #8b949e;
    --accent: #58a6ff; --accent-dim: #1f6feb; --green: #3fb950; --orange: #f0883e;
    --red: #f85149; --yellow: #d29922; --purple: #bc8cff;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Noto Sans', Helvetica, Arial, sans-serif;
    background: var(--bg); color: var(--text); line-height: 1.6;
    padding: 0;
}}
.container {{ max-width: 1100px; margin: 0 auto; padding: 0 2rem; }}

/* ── Cover Page ─────────────────────────────────────── */
.cover-page {{
    background: linear-gradient(135deg, #0d1117 0%, #161b22 50%, #0d1117 100%);
    min-height: 100vh;
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: center;
    text-align: center;
    padding: 3rem 2rem;
    border-bottom: 3px solid var(--accent);
    page-break-after: always;
}}
.cover-brand {{ font-size: 1rem; color: var(--accent); letter-spacing: 4px; text-transform: uppercase; margin-bottom: 1rem; font-weight: 600; }}
.cover-title {{ font-size: 2.8rem; font-weight: 800; color: #ffffff; margin-bottom: 0.5rem; letter-spacing: -0.5px; }}
.cover-subtitle {{ font-size: 1.2rem; color: var(--text-dim); margin-bottom: 1.5rem; }}
.cover-period {{ font-size: 1.1rem; color: var(--accent); font-weight: 500; margin-bottom: 0.5rem; }}
.cover-generated {{ font-size: 0.85rem; color: var(--text-dim); margin-bottom: 2rem; }}
.classification-banner {{
    display: inline-block; padding: 0.4rem 1.5rem; border: 2px solid var(--yellow);
    color: var(--yellow); font-weight: 700; font-size: 0.9rem; letter-spacing: 2px;
    border-radius: 4px; margin-bottom: 2rem;
}}
.cover-stats {{ display: flex; gap: 2rem; flex-wrap: wrap; justify-content: center; margin-top: 1rem; }}
.cover-stat {{ text-align: center; }}
.cover-stat-num {{ display: block; font-size: 2.2rem; font-weight: 800; color: var(--text); }}
.cover-stat-num.critical {{ color: var(--red); }}
.cover-stat-label {{ font-size: 0.75rem; color: var(--text-dim); text-transform: uppercase; letter-spacing: 1px; }}

/* ── Section Dividers ───────────────────────────────── */
.section {{ padding: 2.5rem 0; }}
.section-divider {{ height: 2px; background: linear-gradient(90deg, var(--accent), transparent); margin: 2rem 0; border-radius: 1px; }}
.section h2 {{
    color: var(--accent); font-size: 1.4rem; font-weight: 700;
    margin-bottom: 1.2rem; padding-bottom: 0.5rem;
    border-bottom: 2px solid var(--border);
    page-break-after: avoid;
}}
h3 {{ color: var(--text); margin: 1.5rem 0 0.8rem; font-size: 1.05rem; font-weight: 600; page-break-after: avoid; }}

/* ── Executive Summary ──────────────────────────────── */
.executive-narrative {{ font-size: 0.95rem; line-height: 1.75; margin-bottom: 1.5rem; }}
.executive-narrative p {{ margin-bottom: 0.8rem; }}
.findings-list {{ list-style: none; padding: 0; margin: 1rem 0; }}
.findings-list li {{ padding: 0.5rem 0; border-bottom: 1px solid var(--border); font-size: 0.9rem; display: flex; align-items: flex-start; gap: 0.6rem; }}
.findings-list li:last-child {{ border-bottom: none; }}
.finding-icon {{ flex-shrink: 0; font-size: 1rem; }}
.trend-indicator {{ font-size: 0.75rem; padding: 0.15rem 0.4rem; border-radius: 3px; margin-left: 0.5rem; }}
.trend-up {{ background: rgba(248,81,73,0.15); color: var(--red); }}
.trend-down {{ background: rgba(63,185,80,0.15); color: var(--green); }}
.trend-neutral {{ background: rgba(139,148,158,0.15); color: var(--text-dim); }}

/* ── KPI Grid ───────────────────────────────────────── */
.kpi-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
.kpi-card {{
    background: var(--card); border: 1px solid var(--border); border-radius: 10px;
    padding: 1.3rem 1rem; text-align: center; transition: border-color 0.2s;
}}
.kpi-card:hover {{ border-color: var(--accent); }}
.kpi-num {{ font-size: 2.2rem; font-weight: 800; display: block; line-height: 1.2; }}
.kpi-label {{ font-size: 0.75rem; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.8px; margin-top: 0.3rem; }}
.kpi-change {{ font-size: 0.75rem; margin-top: 0.4rem; display: block; }}
.up {{ color: var(--red); }} .down {{ color: var(--green); }} .neutral {{ color: var(--text-dim); }}
.critical {{ color: var(--red); }} .high {{ color: var(--orange); }}

/* ── Charts Grid ────────────────────────────────────── */
.charts-grid {{
    display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem;
    margin: 1.5rem 0;
}}
.chart-panel {{
    background: var(--card); border: 1px solid var(--border); border-radius: 10px;
    padding: 1.5rem; page-break-inside: avoid;
}}
.chart-panel h3 {{ color: var(--accent); font-size: 0.95rem; margin-bottom: 1rem; font-weight: 600; text-align: center; }}
.chart-panel.full-width {{ grid-column: 1 / -1; }}

/* ── CVE Cards ──────────────────────────────────────── */
.cve-cards {{ display: grid; grid-template-columns: 1fr; gap: 1rem; margin: 1rem 0; }}
.cve-card {{
    background: var(--card); border: 1px solid var(--border); border-radius: 10px;
    padding: 1.3rem 1.5rem; page-break-inside: avoid;
    transition: border-color 0.2s;
}}
.cve-card:hover {{ border-color: var(--border-bright); }}
.cve-card.kev-highlight {{ border-left: 4px solid var(--red); }}
.cve-card-header {{ display: flex; align-items: center; gap: 0.8rem; margin-bottom: 0.6rem; flex-wrap: wrap; }}
.cve-id {{ font-weight: 700; font-size: 1.05rem; color: var(--accent); }}
.cve-card-body {{ font-size: 0.85rem; color: var(--text-dim); line-height: 1.6; }}
.cve-card-meta {{ display: flex; gap: 1rem; margin-top: 0.6rem; flex-wrap: wrap; align-items: center; }}
.cve-meta-item {{ font-size: 0.78rem; color: var(--text-dim); }}
.cve-meta-item strong {{ color: var(--text); }}
.tag-list {{ display: flex; flex-wrap: wrap; gap: 0.3rem; margin-top: 0.5rem; }}
.attack-tag {{ background: rgba(140,100,255,0.15); color: var(--purple); padding: 0.1rem 0.5rem; border-radius: 10px; font-size: 0.7rem; font-weight: 500; }}

/* ── Badges & Pills ─────────────────────────────────── */
.badge {{ display: inline-block; padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.7rem; font-weight: 700; letter-spacing: 0.3px; }}
.badge.kev {{ background: rgba(248,81,73,0.2); color: var(--red); }}
.badge.kev-sm {{ background: rgba(248,81,73,0.15); color: var(--red); font-size: 0.65rem; }}
.sev-pill {{ padding: 0.15rem 0.6rem; border-radius: 12px; font-size: 0.7rem; font-weight: 700; display: inline-block; }}
.sev-pill.critical {{ background: rgba(248,81,73,0.2); color: var(--red); }}
.sev-pill.high {{ background: rgba(240,136,62,0.2); color: var(--orange); }}
.sev-pill.medium {{ background: rgba(210,153,34,0.2); color: var(--yellow); }}
.sev-pill.low {{ background: rgba(63,185,80,0.2); color: var(--green); }}

/* ── Data Tables ────────────────────────────────────── */
.data-table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; font-size: 0.85rem; }}
.data-table thead th {{
    background: var(--card-alt); padding: 0.7rem 0.9rem; text-align: left;
    border-bottom: 2px solid var(--border-bright); color: var(--text-dim);
    font-weight: 600; font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.4px;
}}
.data-table tbody td {{ padding: 0.6rem 0.9rem; border-bottom: 1px solid var(--border); }}
.data-table tbody tr:nth-child(even) {{ background: rgba(255,255,255,0.02); }}
.data-table tbody tr:hover {{ background: rgba(88,166,255,0.06); }}
.data-table .desc-cell {{ color: var(--text-dim); font-size: 0.8rem; max-width: 300px; }}
.kev-row {{ background: rgba(248,81,73,0.06) !important; }}

/* ── Alerts ─────────────────────────────────────────── */
.alert {{ padding: 0.8rem 1.2rem; border-radius: 6px; margin: 1rem 0; font-size: 0.9rem; page-break-inside: avoid; }}
.alert-danger {{ background: rgba(248,81,73,0.08); border: 1px solid rgba(248,81,73,0.3); color: var(--red); }}

/* ── News & PoCs ────────────────────────────────────── */
.news-list {{ margin: 1rem 0; }}
.news-item {{
    background: var(--card); border: 1px solid var(--border); border-radius: 8px;
    padding: 1rem 1.2rem; margin-bottom: 0.6rem; page-break-inside: avoid;
}}
.news-item a {{ color: var(--accent); text-decoration: none; font-weight: 600; font-size: 0.9rem; }}
.news-item a:hover {{ text-decoration: underline; }}
.news-source {{ color: var(--text-dim); font-size: 0.8rem; margin-left: 0.6rem; }}
.news-summary {{ color: var(--text-dim); font-size: 0.82rem; margin-top: 0.4rem; line-height: 1.5; }}
.tier-badge {{ display: inline-block; padding: 0.1rem 0.4rem; border-radius: 3px; font-size: 0.65rem; color: #fff; font-weight: 700; margin-right: 0.5rem; text-transform: uppercase; letter-spacing: 0.5px; }}

.poc-list {{ margin: 1rem 0; }}
.poc-item {{ padding: 0.7rem 0; border-bottom: 1px solid var(--border); }}
.poc-item a {{ color: var(--accent); text-decoration: none; font-size: 0.85rem; }}
.poc-meta {{ display: block; color: var(--text-dim); font-size: 0.75rem; margin-top: 0.2rem; }}

/* ── ThreatFox ──────────────────────────────────────── */
.tf-grid {{ display: flex; gap: 1.2rem; margin: 1rem 0; flex-wrap: wrap; }}
.tf-stat {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1.2rem 1.8rem; text-align: center; }}
.tf-num {{ display: block; font-size: 1.6rem; font-weight: 800; color: var(--accent); }}
.tf-label {{ font-size: 0.75rem; color: var(--text-dim); margin-top: 0.2rem; }}
.ioc-types {{ list-style: none; display: flex; flex-wrap: wrap; gap: 0.5rem; margin: 0.5rem 0; padding: 0; }}
.ioc-types li {{ background: var(--card); padding: 0.3rem 0.7rem; border-radius: 4px; font-size: 0.8rem; border: 1px solid var(--border); }}

/* ── Triage & Health ────────────────────────────────── */
.triage-list {{ list-style: none; display: flex; gap: 1rem; flex-wrap: wrap; margin: 0.5rem 0; padding: 0; }}
.triage-list li {{ background: var(--card); padding: 0.5rem 0.9rem; border-radius: 6px; font-size: 0.85rem; border: 1px solid var(--border); }}
.status-ok {{ color: var(--green); font-weight: 600; }}
.status-error {{ color: var(--red); font-weight: 600; }}
.status-skipped {{ color: var(--text-dim); }}

/* ── Footer ─────────────────────────────────────────── */
.footer {{ text-align: center; padding: 2rem 0; color: var(--text-dim); font-size: 0.8rem; border-top: 1px solid var(--border); margin-top: 2rem; }}

/* ── Print Styles ───────────────────────────────────── */
@media print {{
    body {{ background: #fff; color: #1a1a1a; font-size: 11pt; }}
    .container {{ max-width: 100%; padding: 0; }}
    .cover-page {{ background: #fff; min-height: auto; padding: 4cm 2cm; border-bottom: 3px solid #1f6feb; page-break-after: always; }}
    .cover-title {{ color: #1a1a1a; }}
    .cover-stat-num {{ color: #1a1a1a; }}
    .classification-banner {{ border-color: #d29922; color: #d29922; }}
    .section h2 {{ color: #1f6feb; border-bottom-color: #d0d7de; }}
    .kpi-card, .chart-panel, .cve-card, .news-item, .tf-stat {{
        background: #f6f8fa; border-color: #d0d7de; break-inside: avoid;
    }}
    .data-table thead th {{ background: #f6f8fa; color: #57606a; border-bottom-color: #d0d7de; }}
    .data-table tbody td {{ border-bottom-color: #d0d7de; }}
    .data-table tbody tr:nth-child(even) {{ background: #f6f8fa; }}
    .sev-pill {{ border: 1px solid currentColor; }}
    .cve-id, .news-item a, .poc-item a {{ color: #1f6feb; }}
    @page {{ margin: 2cm 1.5cm; size: A4; }}
    @page :first {{ margin: 0; }}
}}

/* ── Responsive ─────────────────────────────────────── */
@media screen and (max-width: 768px) {{
    .charts-grid {{ grid-template-columns: 1fr; }}
    .kpi-grid {{ grid-template-columns: repeat(2, 1fr); }}
    .cover-stats {{ gap: 1rem; }}
    .cover-title {{ font-size: 2rem; }}
}}
</style>
</head>
<body>

<!-- ═══════════ COVER PAGE ═══════════ -->
<div class="cover-page">
    <div class="cover-brand">HORUS</div>
    <h1 class="cover-title">Weekly Threat Intelligence Report</h1>
    <div class="cover-subtitle">CVE &amp; Exploit Analysis</div>
    <div class="cover-period">{data.period_start} to {data.period_end}</div>
    <div class="cover-generated">Generated: {data.generated_at}</div>
    <div class="classification-banner">TLP:WHITE</div>
    {stats_overlay}
</div>

<!-- ═══════════ EXECUTIVE SUMMARY ═══════════ -->
<div class="container">
<div class="section">
    <h2>Executive Summary</h2>
    <div class="executive-narrative">
        {narrative}
    </div>
    <ul class="findings-list">
        {findings}
    </ul>
</div>

<div class="section-divider"></div>

<!-- ═══════════ KPI CARDS ═══════════ -->
<div class="section">
    <h2>Key Metrics</h2>
    <div class="kpi-grid">
        <div class="kpi-card">
            <span class="kpi-num{" critical" if total_cves > 50 else ""}">{total_cves}</span>
            <span class="kpi-label">New CVEs</span>
            <span class="kpi-change {cve_dir}">{cve_trend} {cve_pct} WoW</span>
        </div>
        <div class="kpi-card">
            <span class="kpi-num">{total_pocs}</span>
            <span class="kpi-label">New PoCs</span>
            <span class="kpi-change {poc_dir}">{poc_trend} {poc_pct} WoW</span>
        </div>
        <div class="kpi-card">
            <span class="kpi-num{" critical" if data.kev_new_this_week > 0 else ""}">{data.kev_new_this_week}</span>
            <span class="kpi-label">KEV Added</span>
            <span class="kpi-change neutral">of {data.kev_total} total</span>
        </div>
        <div class="kpi-card">
            <span class="kpi-num critical">{data.critical_cves}</span>
            <span class="kpi-label">Critical (9+)</span>
            <span class="kpi-change neutral">{data.high_cves} High</span>
        </div>
        <div class="kpi-card">
            <span class="kpi-num">{data.avg_cvss_this_week}</span>
            <span class="kpi-label">Avg CVSS</span>
            <span class="kpi-change neutral">EPSS: {data.avg_epss_this_week:.3f}</span>
        </div>
        <div class="kpi-card">
            <span class="kpi-num">{data.kev_overdue}</span>
            <span class="kpi-label">KEV Overdue</span>
            <span class="kpi-change {"up" if data.kev_overdue > 0 else "neutral"}">Past deadline</span>
        </div>
    </div>
</div>

<div class="section-divider"></div>

<!-- ═══════════ CHARTS ═══════════ -->
<div class="section">
    <h2>Threat Landscape Visualization</h2>
    <div class="charts-grid">
        <div class="chart-panel">
            <h3>Severity Distribution</h3>
            {donut_chart}
        </div>
        <div class="chart-panel">
            <h3>MITRE ATT&CK Techniques</h3>
            {mitre_chart}
        </div>
        <div class="chart-panel full-width">
            <h3>CVE Intake Trend (8 Weeks)</h3>
            {trend_chart}
        </div>
        <div class="chart-panel full-width">
            <h3>Top Vendors by CVE Count</h3>
            {vendor_chart}
        </div>
    </div>
</div>

<div class="section-divider"></div>

<!-- ═══════════ TOP CVE CARDS ═══════════ -->
<div class="section">
    <h2>Top CVEs by Risk Score</h2>
    {cve_cards}
</div>

<div class="section-divider"></div>

<!-- ═══════════ DETAILED TABLES ═══════════ -->
<div class="section">
    <h2>CVE Detail Table</h2>
    {cves_html}
</div>

{kev_html}
{epss_html}
{threatfox_html}
{vendor_html}
{news_html}
{pocs_html}
{triage_html}
{health_html}

<div class="footer">
    <p>Generated by Horus Threat Intelligence Platform &mdash; {data.generated_at}</p>
    <p style="margin-top:0.3rem;font-size:0.7rem;">Classification: TLP:WHITE | For authorized distribution only</p>
</div>
</div>
</body>
</html>"""


def _build_narrative(data: WeeklyData) -> str:
    """Build executive summary narrative from actual data."""
    total = data.total_cves_this_week
    prev = data.total_cves_last_week
    crit = data.critical_cves
    high = data.high_cves
    kev = data.kev_new_this_week

    # Paragraph 1: Volume overview
    if total == 0:
        p1 = f"No new CVEs were observed during the reporting period of {data.period_start} to {data.period_end}. This may indicate reduced vulnerability disclosure activity or a gap in collection coverage."
    else:
        direction = (
            "increase"
            if total > prev
            else "decrease"
            if total < prev
            else "consistent volume compared"
        )
        p1 = (
            f"During the week of {data.period_start} to {data.period_end}, Horus tracked "
            f"<strong>{total} new CVEs</strong> — a {_pct_change(total, prev)} {direction} "
            f"from the previous week ({prev}). "
            f"The average CVSS severity was {data.avg_cvss_this_week}, with "
            f"{crit} critical-rated and {high} high-rated vulnerabilities requiring immediate attention."
        )

    # Paragraph 2: KEV & threat context
    if kev > 0:
        p2 = (
            f"CISA added <strong>{kev} new entries</strong> to the Known Exploited Vulnerabilities catalog this week, "
            f"bringing the total tracked KEVs to {data.kev_total}. "
        )
    elif data.kev_total > 0:
        p2 = f"No new KEV additions this week. {data.kev_total} total KEVs are currently tracked. "
    else:
        p2 = "No KEV entries are currently tracked. "

    if data.kev_overdue > 0:
        p2 += f"<strong style='color:var(--red);'>{data.kev_overdue} KEVs are past their CISA remediation deadline and require urgent action.</strong>"

    # Paragraph 3: EPSS & exploitability
    if data.avg_epss_this_week > 0.1:
        p3 = (
            f"The average EPSS (Exploit Prediction Scoring System) score for new CVEs was "
            f"<strong>{data.avg_epss_this_week:.3f}</strong>, indicating a "
            f"{'high' if data.avg_epss_this_week > 0.2 else 'moderate' if data.avg_epss_this_week > 0.05 else 'low'} "
            f"likelihood of exploitation within 30 days. "
            f"{data.total_pocs_this_week} new proof-of-concept exploits were published this week."
        )
    else:
        p3 = (
            f"{data.total_pocs_this_week} new proof-of-concept exploits were published this week. "
            f"The average EPSS score was {data.avg_epss_this_week:.3f}, suggesting "
            f"lower near-term exploitation likelihood."
        )

    return f"<p>{p1}</p><p>{p2}</p><p>{p3}</p>"


def _build_findings(data: WeeklyData) -> str:
    """Build key findings bullet list with emoji indicators."""
    findings = []

    # Critical CVEs
    if data.critical_cves > 0:
        findings.append(
            f'<li><span class="finding-icon">🔴</span><span><strong>{data.critical_cves} critical-rated CVEs (CVSS 9+)</strong> identified requiring immediate remediation priority.</span>'
            f'<span class="trend-indicator trend-up">ACTION</span></li>'
        )

    # KEV additions
    if data.kev_new_this_week > 0:
        findings.append(
            f'<li><span class="finding-icon">⚠️</span><span><strong>{data.kev_new_this_week} new KEV entries</strong> added by CISA — known actively exploited vulnerabilities.</span></li>'
        )

    # Top CVE
    if data.top_cves:
        top = data.top_cves[0]
        kev_tag = " [KEV]" if top["kev"] else ""
        findings.append(
            f'<li><span class="finding-icon">🎯</span><span>Highest-risk CVE: <strong>{top["id"]}{kev_tag}</strong> (CVSS {top["cvss_score"] or "N/A"}, EPSS {top["epss_score"]:.3f}) — {top["description"][:80]}</span></li>'
        )

    # Top vendor
    if data.top_vendors:
        v = data.top_vendors[0]
        findings.append(
            f'<li><span class="finding-icon">🏢</span><span>Most targeted vendor: <strong>{v["vendor"]}</strong> with {v["cve_count"]} CVEs (avg CVSS {v["avg_cvss"]})</span></li>'
        )

    # EPSS movers
    if data.epss_movers:
        m = data.epss_movers[0]
        if m["epss_score"] and m["epss_score"] > 0.5:
            findings.append(
                f'<li><span class="finding-icon">💥</span><span>Highest exploitability: <strong>{m["id"]}</strong> with EPSS {m["epss_score"]:.3f} ({m["epss_score"] * 100:.0f}% exploitation probability)</span></li>'
            )

    # WoW trend
    cve_change = _pct_change(data.total_cves_this_week, data.total_cves_last_week)
    if data.total_cves_this_week > data.total_cves_last_week:
        findings.append(
            f'<li><span class="finding-icon">📈</span><span>CVE volume increased <strong>{cve_change}</strong> week-over-week ({data.total_cves_last_week} → {data.total_cves_this_week})</span></li>'
        )
    elif data.total_cves_this_week < data.total_cves_last_week:
        findings.append(
            f'<li><span class="finding-icon">📉</span><span>CVE volume decreased <strong>{cve_change}</strong> week-over-week ({data.total_cves_last_week} → {data.total_cves_this_week})</span></li>'
        )

    # Overdue
    if data.kev_overdue > 0:
        findings.append(
            f'<li><span class="finding-icon">🚨</span><span><strong>{data.kev_overdue} KEVs overdue</strong> — past CISA remediation deadline</span>'
            f'<span class="trend-indicator trend-up">URGENT</span></li>'
        )

    return "\n".join(findings)


def _build_cve_cards(top_cves: list[dict]) -> str:
    """Build top CVE detail cards."""
    cards = []
    for cve in top_cves:
        kev_class = " kev-highlight" if cve["kev"] else ""
        kev_badge = ' <span class="badge kev">KEV</span>' if cve["kev"] else ""
        sev_class = (cve["cvss_severity"] or "N/A").lower()
        cvss = cvss_badge(cve["cvss_score"], cve["cvss_severity"])
        epss = epss_bar(cve["id"], cve["epss_score"]) if cve["epss_score"] is not None else "N/A"

        # ATT&CK tags
        tags_html = ""
        if cve.get("attack_tags"):
            tags = cve["attack_tags"][:4]
            tags_html = (
                '<div class="tag-list">'
                + "".join(f'<span class="attack-tag">{t}</span>' for t in tags)
                + "</div>"
            )

        due = (
            f'<span class="cve-meta-item"> | <strong>Due:</strong> {cve["kev_due_date"]}</span>'
            if cve.get("kev_due_date")
            else ""
        )

        cards.append(f"""<div class="cve-card{kev_class}">
    <div class="cve-card-header">
        <span class="cve-id">{cve["id"]}</span>{kev_badge} {cvss}
        <span class="sev-pill {sev_class}">{cve["cvss_severity"] or "N/A"}</span>
    </div>
    <div class="cve-card-body">{cve["description"]}</div>
    <div class="cve-card-meta">
        <span class="cve-meta-item"><strong>EPSS:</strong> {epss}</span>
        <span class="cve-meta-item"><strong>Reputation:</strong> {cve["reputation_score"] or 0:.1f}/10</span>
        <span class="cve-meta-item"><strong>PoCs:</strong> {cve["poc_source_count"]}</span>{due}
    </div>
    {tags_html}
</div>""")
    return '<div class="cve-cards">' + "\n".join(cards) + "</div>"


def _build_cve_table(top_cves: list[dict]) -> str:
    """Build refined CVE data table."""
    rows = ""
    for cve in top_cves:
        kev_class = ' class="kev-row"' if cve["kev"] else ""
        kev_badge = ' <span class="badge kev">KEV</span>' if cve["kev"] else ""
        sev_class = (cve["cvss_severity"] or "N/A").lower()
        epss_bar_html = (
            epss_bar(cve["id"], cve["epss_score"]) if cve["epss_score"] is not None else "N/A"
        )
        cvss = cvss_badge(cve["cvss_score"], cve["cvss_severity"])
        rows += f"""<tr{kev_class}>
            <td><strong>{cve["id"]}</strong>{kev_badge}</td>
            <td>{cvss}</td>
            <td><span class="sev-pill {sev_class}">{cve["cvss_severity"] or "N/A"}</span></td>
            <td>{epss_bar_html}</td>
            <td>{cve["reputation_score"] or 0:.1f}</td>
            <td>{cve["poc_source_count"]}</td>
            <td class="desc-cell">{cve["description"][:120]}</td>
        </tr>"""
    return f"""
    <table class="data-table">
        <thead><tr><th>CVE</th><th>CVSS</th><th>Severity</th><th>EPSS</th><th>Rep</th><th>PoCs</th><th>Description</th></tr></thead>
        <tbody>{rows}</tbody>
    </table>"""


def _build_kev_section(kev_entries: list[dict]) -> str:
    """Build KEV section with alerts."""
    if not kev_entries:
        return ""
    new_kevs = [k for k in kev_entries if k["is_new"]]
    overdue_kevs = [k for k in kev_entries if k["is_overdue"]]

    html = '<div class="section-divider"></div><div class="section"><h2>CISA Known Exploited Vulnerabilities</h2>'
    if overdue_kevs:
        html += f'<div class="alert alert-danger"><strong>OVERDUE:</strong> {len(overdue_kevs)} KEV entries past CISA remediation deadline — immediate action required</div>'
    if new_kevs:
        html += f"<h3>New This Week ({len(new_kevs)})</h3>"
        for kev in new_kevs[:5]:
            due = f" | <strong>Due: {kev['kev_due_date']}</strong>" if kev["kev_due_date"] else ""
            cvss = cvss_badge(kev["cvss_score"], None)
            html += f"""<div class="news-item">
                <strong>{kev["id"]}</strong> {cvss}{due}
                <p class="news-summary">{kev["description"]}</p>
            </div>"""
    html += "</div>"
    return html


def _build_vendor_table(vendors: list[dict]) -> str:
    """Build refined vendor table."""
    rows = ""
    for v in vendors:
        kev_str = (
            f' <span class="badge kev-sm">{v["kev_count"]} KEV</span>' if v["kev_count"] else ""
        )
        rows += f"<tr><td>{v['vendor']}</td><td>{v['cve_count']}</td><td>{v['avg_cvss']}</td><td>{kev_str}</td></tr>"
    return f"""
    <div class="section-divider"></div>
    <div class="section">
        <h2>Most Targeted Vendors</h2>
        <table class="data-table">
            <thead><tr><th>Vendor</th><th>CVEs</th><th>Avg CVSS</th><th>KEVs</th></tr></thead>
            <tbody>{rows}</tbody>
        </table>
    </div>"""


def _build_news_section(articles: list[dict]) -> str:
    """Build news highlights section."""
    tier_colors = {1: "#dc3545", 2: "#fd7e14", 3: "#ffc107", 4: "#28a745", 5: "#6c757d"}
    html = '<div class="section-divider"></div><div class="section"><h2>Security News Highlights</h2><div class="news-list">'
    for article in articles:
        tc = tier_colors.get(article["tier"], "#6c757d")
        html += f'''<div class="news-item">
            <span class="tier-badge" style="background:{tc}">{_tier_label(article["tier"])}</span>
            <a href="{article["url"]}">{article["title"]}</a>
            <span class="news-source">{article["source"]}</span>
            <p class="news-summary">{article["summary"][:200] if article["summary"] else ""}</p>
        </div>'''
    html += "</div></div>"
    return html


def _build_threatfox_section(summary: dict) -> str:
    """Build ThreatFox IOC section."""
    if summary.get("total_iocs", 0) == 0:
        return ""
    type_counts = summary.get("type_counts", {})
    type_items = "".join(
        f"<li><strong>{k}:</strong> {v}</li>" for k, v in sorted(type_counts.items())
    )
    threat_types = summary.get("top_threat_types", [])
    type_str = "".join(f"<li>{t['threat_type']} ({t['count']})</li>" for t in threat_types[:5])
    return f"""
    <div class="section-divider"></div>
    <div class="section">
        <h2>Threat Intelligence (ThreatFox)</h2>
        <div class="tf-grid">
            <div class="tf-stat"><span class="tf-num">{summary["total_iocs"]}</span><span class="tf-label">Total IOCs</span></div>
            <div class="tf-stat"><span class="tf-num">{summary["cves_with_iocs"]}</span><span class="tf-label">CVEs with IOCs</span></div>
        </div>
        <h3>IOC Types</h3><ul class="ioc-types">{type_items}</ul>
        {f'<h3>Top Threat Types</h3><ul class="ioc-types">{type_str}</ul>' if type_str else ""}
    </div>"""


def _build_pocs_section(pocs: list[dict]) -> str:
    """Build notable PoC publications section."""
    html = '<div class="section-divider"></div><div class="section"><h2>Notable Exploit Publications</h2><div class="poc-list">'
    for poc in pocs:
        html += f'''<div class="poc-item">
            <a href="{poc["url"]}">{poc["url"][:70]}...</a>
            <span class="poc-meta">{poc["source"]} | {poc["stars"]} stars | {poc["exploit_type"] or "N/A"} | {poc["linked_cves"]} CVEs</span>
        </div>'''
    html += "</div></div>"
    return html


def _build_epss_section(movers: list[dict]) -> str:
    """Build EPSS top exploitability section."""
    rows = ""
    for m in movers:
        kev_badge = ' <span class="badge kev">KEV</span>' if m["kev"] else ""
        epss_bar_html = epss_bar(m["id"], m["epss_score"]) if m["epss_score"] is not None else "N/A"
        cvss = cvss_badge(m["cvss_score"], None)
        rows += f"""<tr>
            <td><strong>{m["id"]}</strong>{kev_badge}</td>
            <td>{cvss}</td>
            <td>{epss_bar_html}</td>
            <td>{m["reputation_score"] or 0:.1f}</td>
            <td class="desc-cell">{m["description"][:100]}</td>
        </tr>"""
    return f"""
    <div class="section-divider"></div>
    <div class="section">
        <h2>Highest Exploitability (EPSS)</h2>
        <table class="data-table">
            <thead><tr><th>CVE</th><th>CVSS</th><th>EPSS</th><th>Rep</th><th>Description</th></tr></thead>
            <tbody>{rows}</tbody>
        </table>
    </div>"""


def _build_triage_section(summary: dict) -> str:
    """Build triage workflow section."""
    if not summary:
        return ""
    total = sum(summary.values())
    items = "".join(
        f"<li>{s.capitalize()}: <strong>{summary.get(s, 0)}</strong></li>"
        for s in ["new", "acknowledged", "working", "done", "dismissed"]
    )
    return f"""
    <div class="section-divider"></div>
    <div class="section">
        <h2>Triage Workflow</h2>
        <p>Total triaged: <strong>{total}</strong></p>
        <ul class="triage-list">{items}</ul>
    </div>"""


def _build_source_health(sources: list[dict]) -> str:
    """Build source health section."""
    if not sources:
        return ""
    rows = ""
    for sh in sources:
        status_class = (
            "ok" if sh["status"] == "ok" else "error" if sh["status"] == "error" else "skipped"
        )
        err_tip = f' title="{sh["error"][:100]}"' if sh["error"] else ""
        rows += f'<tr><td>{sh["source"]}</td><td class="status-{status_class}"{err_tip}>{sh["status"]}</td><td>{sh["last_run"][:16]}</td><td>{sh["cves"]}</td><td>{sh["pocs"]}</td><td>{sh["consecutive_failures"]}</td></tr>'
    return f"""
    <div class="section-divider"></div>
    <div class="section">
        <h2>Source Health</h2>
        <table class="data-table health-table">
            <thead><tr><th>Source</th><th>Status</th><th>Last Run</th><th>CVEs</th><th>PoCs</th><th>Fails</th></tr></thead>
            <tbody>{rows}</tbody>
        </table>
    </div>"""


def epss_section(data: WeeklyData) -> str:
    """Build EPSS top exploitability section (legacy wrapper)."""
    if not data.epss_movers:
        return ""
    rows = ""
    for m in data.epss_movers[:8]:
        kev_badge = '<span class="badge kev">KEV</span>' if m["kev"] else ""
        epss_bar_html = epss_bar(m["id"], m["epss_score"]) if m["epss_score"] is not None else "N/A"
        rows += f"""<tr>
            <td>{m["id"]} {kev_badge}</td>
            <td>{m["cvss_score"] or "N/A"}</td>
            <td>{epss_bar_html}</td>
            <td>{m["reputation_score"] or 0:.1f}</td>
            <td class="desc-cell">{m["description"][:100]}</td>
        </tr>"""
    return f"""
    <h2>Highest Exploitability (EPSS)</h2>
    <table class="data-table">
        <thead><tr><th>CVE</th><th>CVSS</th><th>EPSS</th><th>Rep</th><th>Description</th></tr></thead>
        <tbody>{rows}</tbody>
    </table>"""
