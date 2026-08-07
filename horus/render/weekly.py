"""Weekly threat report renderer.

Produces professional weekly threat intelligence reports in text, markdown,
and HTML formats suitable for executive distribution and SOC handoffs.
The HTML renderer generates a 15-20 page PDF-ready report with:
- SVG charts (donut, trend line, bar, heatmap, histogram)
- Full IOC sections (network + host indicators)
- Embedded AI analysis sections
- Print-ready CSS with page breaks and A4 margins

Usage:
    from horus.render.weekly import render_weekly_report
    report_html = render_weekly_report(data, fmt="html")
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
        data: WeeklyData from gather_weekly_report().
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


def _epss_histogram(data: list[dict], width: int = 500, height: int = 180) -> str:
    """Generate EPSS distribution histogram."""
    if not data:
        return f'<svg viewBox="0 0 {width} {height}" width="{width}" height="{height}"><text x="{width // 2}" y="{height // 2}" text-anchor="middle" fill="#8b949e" font-size="14">No EPSS data</text></svg>'

    # Bucket EPSS into 10 bins
    bins = [0] * 10
    for d in data:
        score = d.get("epss_score") or 0
        idx = min(int(score * 10), 9)
        bins[idx] += 1

    max_count = max(bins) if bins else 1
    padding = {"top": 15, "right": 15, "bottom": 35, "left": 35}
    chart_w = width - padding["left"] - padding["right"]
    chart_h = height - padding["top"] - padding["bottom"]
    bar_w = chart_w / 10

    bars = []
    for i, count in enumerate(bins):
        if count == 0:
            continue
        x = padding["left"] + i * bar_w
        bar_h = (count / max_count) * chart_h
        y = padding["top"] + chart_h - bar_h
        # Color by EPSS range
        intensity = i / 9
        r = int(88 + (248 - 88) * intensity)
        g = int(166 + (81 - 166) * intensity)
        b = int(255 + (73 - 255) * intensity)
        bars.append(
            f'<rect x="{x + 2:.1f}" y="{y:.1f}" width="{bar_w - 4:.1f}" height="{bar_h:.1f}" rx="2" '
            f'fill="rgb({r},{g},{b})" opacity="0.85"/>'
            f'<text x="{x + bar_w / 2:.1f}" y="{y - 3:.1f}" text-anchor="middle" fill="#c9d1d9" font-size="9">{count}</text>'
        )

    # X-axis labels
    x_labels = []
    bottom_pad = padding["bottom"]
    for i in range(10):
        x = padding["left"] + i * bar_w + bar_w / 2
        label = f"{i * 10}-{(i + 1) * 10}%"
        y_pos = height - bottom_pad + 15
        x_labels.append(
            f'<text x="{x:.1f}" y="{y_pos}" text-anchor="middle" fill="#8b949e" font-size="9" '
            f'transform="rotate(-25 {x:.1f} {y_pos})">{label}</text>'
        )

    # Y-axis grid
    grid = []
    left_pad = padding["left"]
    for i in range(5):
        y_val = padding["top"] + (i / 4) * chart_h
        val = int(max_count - (i / 4) * max_count)
        grid.append(
            f'<line x1="{left_pad}" y1="{y_val:.1f}" x2="{left_pad + chart_w}" y2="{y_val:.1f}" '
            f'stroke="#30363d" stroke-width="0.5" stroke-dasharray="2,2"/>'
            f'<text x="{left_pad - 5}" y="{y_val + 3:.1f}" text-anchor="end" fill="#8b949e" font-size="9">{val}</text>'
        )

    return (
        f'<svg viewBox="0 0 {width} {height}" width="{width}" height="{height}" style="max-width:100%;">'
        f"{''.join(grid)}{''.join(x_labels)}{''.join(bars)}"
        f'<text x="{width // 2}" y="{height - 3}" text-anchor="middle" fill="#8b949e" font-size="10">EPSS Score Range</text>'
        f"</svg>"
    )


def _ioc_type_donut(type_counts: dict[str, int], size: int = 200) -> str:
    """Generate IOC type breakdown donut chart."""
    if not type_counts:
        return f'<svg viewBox="0 0 {size} {size}" width="{size}" height="{size}"><text x="{size // 2}" y="{size // 2}" text-anchor="middle" fill="#8b949e" font-size="12">No IOC data</text></svg>'

    items = [
        ("IP", type_counts.get("ip", 0), "#58a6ff"),
        ("Domain", type_counts.get("domain", 0), "#3fb950"),
        ("URL", type_counts.get("url", 0), "#bc8cff"),
        (
            "Hash",
            (
                type_counts.get("hash_md5", 0)
                + type_counts.get("hash_sha1", 0)
                + type_counts.get("hash_sha256", 0)
            ),
            "#f0883e",
        ),
        ("Email", type_counts.get("email", 0), "#d29922"),
        ("Path", type_counts.get("path", 0), "#8b949e"),
        ("Registry", type_counts.get("registry", 0), "#f85149"),
    ]
    items = [(name, c, col) for name, c, col in items if c > 0]
    total = sum(c for _, c, _ in items)

    import math

    cx, cy = size // 2, size // 2
    outer_r = size // 2 - 8
    inner_r = int(outer_r * 0.6)

    arcs = []
    start = -90
    for _label, count, color in items:
        sweep = (count / total) * 360
        end = start + sweep
        x0 = cx + outer_r * math.cos(math.radians(start))
        y0 = cy + outer_r * math.sin(math.radians(start))
        x1 = cx + outer_r * math.cos(math.radians(end))
        y1 = cy + outer_r * math.sin(math.radians(end))
        xi0 = cx + inner_r * math.cos(math.radians(end))
        yi0 = cy + inner_r * math.sin(math.radians(end))
        xi1 = cx + inner_r * math.cos(math.radians(start))
        yi1 = cy + inner_r * math.sin(math.radians(start))
        large = 1 if sweep > 180 else 0
        d = (
            f"M {x0:.1f} {y0:.1f} A {outer_r} {outer_r} 0 {large} 1 {x1:.1f} {y1:.1f} "
            f"L {xi0:.1f} {yi0:.1f} A {inner_r} {inner_r} 0 {large} 0 {xi1:.1f} {yi1:.1f} Z"
        )
        arcs.append(f'<path d="{d}" fill="{color}" stroke="#0d1117" stroke-width="1"/>')
        start = end

    legend = "".join(
        f'<div style="display:flex;align-items:center;gap:4px;margin:1px 4px;">'
        f'<span style="width:8px;height:8px;background:{col};border-radius:1px;"></span>'
        f'<span style="color:#8b949e;font-size:10px;">{name}: {c}</span></div>'
        for name, c, col in items
    )

    return (
        f'<div style="text-align:center;">'
        f'<svg viewBox="0 0 {size} {size}" width="{size}" height="{size}" style="max-width:100%;">'
        f"{''.join(arcs)}"
        f'<text x="{cx}" y="{cy - 4}" text-anchor="middle" fill="#c9d1d9" font-size="16" font-weight="700">{total}</text>'
        f'<text x="{cx}" y="{cy + 12}" text-anchor="middle" fill="#8b949e" font-size="9">IOCs</text>'
        f"</svg>"
        f'<div style="display:flex;flex-wrap:wrap;justify-content:center;margin-top:4px;">{legend}</div>'
        f"</div>"
    )


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

    # Table of Contents
    w("## Table of Contents")
    w()
    w("1. [Executive Summary](#executive-summary)")
    w("2. [Threat Landscape Overview](#threat-landscape-overview)")
    if data.top_cves:
        w("3. [Critical & High CVE Analysis](#critical--high-cve-analysis)")
    if data.kev_entries:
        w("4. [CISA Known Exploited Vulnerabilities](#cisa-known-exploited-vulnerabilities)")
    if data.epss_movers:
        w("5. [EPSS Exploitability Trends](#epss-exploitability-trends)")
    if data.top_tags:
        w("6. [MITRE ATT&CK Technique Mapping](#mitre-attck-technique-mapping)")
    if data.network_iocs or data.ioc_summary.get("total_iocs", 0) > 0:
        w("7. [Network-based Indicators (IOCs)](#network-based-indicators-iocs)")
    if data.host_iocs:
        w("8. [Host-based Indicators (IOCs)](#host-based-indicators-iocs)")
    if data.news_highlights:
        w("9. [Vulnerability News & Intelligence](#vulnerability-news--intelligence)")
    if data.top_vendors:
        w("10. [Affected Vendors & Products](#vendors--products)")
    w("11. [Recommendations](#recommendations)")
    w("12. [Appendix](#appendix)")
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
    ioc_total = data.ioc_summary.get("total_iocs", 0)
    if ioc_total > 0:
        w(f"| Extracted IOCs | {ioc_total} | — | — |")
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

    # Threat Landscape
    w("## Threat Landscape Overview")
    w()
    w(
        f"This week saw {data.total_cves_this_week} new CVEs with an average CVSS of {data.avg_cvss_this_week}."
    )
    w(
        f"Critical: {data.critical_cves} | High: {data.high_cves} | KEV additions: {data.kev_new_this_week}"
    )
    w()

    # Top CVEs
    if data.top_cves:
        w("## Critical & High CVE Analysis")
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

        from datetime import date as _date_mod

        overdue_kevs = [k for k in data.kev_entries if k["is_overdue"]]
        due_soon = []
        no_due_date = []
        for k in data.kev_entries:
            if k["kev_due_date"] == "Not Set":
                no_due_date.append(k)
            elif not k["is_overdue"]:
                try:
                    due_d = _date_mod.fromisoformat(k["kev_due_date"])
                    if (due_d - _date_mod.today()).days <= 30:
                        due_soon.append(k)
                except ValueError:
                    pass

        w(
            f"**Total KEVs:** {len(data.kev_entries)} | **Overdue:** {len(overdue_kevs)} | **Due Soon:** {len(due_soon)} | **No Due Date:** {len(no_due_date)}"
        )
        w()

        if overdue_kevs:
            w(
                f"> **WARNING:** {len(overdue_kevs)} KEV-listed CVEs are past their CISA remediation deadline."
            )
            w()

        w("| CVE | CVSS | Severity | Due Date | Days Overdue | Affected Products | EPSS |")
        w("|-----|------|----------|----------|--------------|-------------------|------|")
        for kev in data.kev_entries:
            days_col = str(kev["days_overdue"]) if kev["is_overdue"] else "—"
            due_display = kev["kev_due_date"] if kev["kev_due_date"] != "Not Set" else "NOT SET"
            if kev["is_overdue"]:
                due_display = f"**{due_display}** ⚠️"
            sev = kev.get("cvss_severity") or "N/A"
            epss = f"{kev['epss_score']:.4f}" if kev.get("epss_score") is not None else "N/A"
            affected = (kev.get("affected") or "Unknown")[:60]
            w(
                f"| {kev['id']} | {kev['cvss_score'] or 'N/A'} | {sev} | {due_display} | {days_col} | {affected} | {epss} |"
            )
        w()

    # EPSS Top Exploitability
    if data.epss_movers:
        w("## EPSS Exploitability Trends")
        w()
        w("| CVE | CVSS | EPSS | KEV | Description |")
        w("|-----|------|------|-----|-------------|")
        for m in data.epss_movers[:8]:
            kev_badge = " YES" if m["kev"] else ""
            w(
                f"| {m['id']} | {m['cvss_score'] or 'N/A'} | **{m['epss_score']:.4f}** |{kev_badge} | {m['description'][:80]}... |"
            )
        w()

    # MITRE ATT&CK Tags
    if data.top_tags:
        w("## MITRE ATT&CK Technique Mapping")
        w()
        w("| Technique | CVEs | Avg CVSS |")
        w("|-----------|------|----------|")
        for t in data.top_tags[:10]:
            w(f"| {t['tag']} | {t['cve_count']} | {t['avg_cvss']} |")
        w()

    # Network IOCs
    if data.network_iocs or data.ioc_summary.get("network_count", 0) > 0:
        w("## Network-based Indicators (IOCs)")
        w()
        w("| Type | Value | Source | Linked CVEs |")
        w("|------|-------|--------|-------------|")
        for ioc in data.network_iocs[:20]:
            cves = ", ".join(ioc.get("cves", [])[:5])
            sources = ", ".join(ioc.get("sources", []))
            w(f"| {ioc['type']} | `{ioc['value'][:60]}` | {sources} | {cves or '—'} |")
        w()

    # Host IOCs
    if data.host_iocs:
        w("## Host-based Indicators (IOCs)")
        w()
        w("| Type | Value | Source | Linked CVEs |")
        w("|------|-------|--------|-------------|")
        for ioc in data.host_iocs[:20]:
            cves = ", ".join(ioc.get("cves", [])[:5])
            sources = ", ".join(ioc.get("sources", []))
            val = ioc["value"]
            if len(val) > 60:
                val = f"{val[:30]}...{val[-20:]}"
            w(f"| {ioc['type']} | `{val}` | {sources} | {cves or '—'} |")
        w()

    # News
    if data.news_highlights:
        w("## Vulnerability News & Intelligence")
        w()
        for article in data.news_highlights[:10]:
            tier_badge = _tier_label(article["tier"])
            w(
                f"- **[{tier_badge}]** [{article['title']}]({article['url']}) — *{article['source']}*"
            )
            if article["summary"]:
                w(f"  > {article['summary'][:200]}")
            w()

    # Vendors
    if data.top_vendors:
        w("## Affected Vendors & Products")
        w()
        w("| Vendor | CVEs | Avg CVSS | KEVs |")
        w("|--------|------|----------|------|")
        for v in data.top_vendors[:10]:
            w(f"| {v['vendor']} | {v['cve_count']} | {v['avg_cvss']} | {v['kev_count']} |")
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

    # Recommendations
    w("## Recommendations")
    w()
    w("1. **Patch Overdue KEVs:** Prioritize remediation of KEV-listed CVEs past deadline.")
    w("2. **Monitor Critical CVEs:** Focus on CVEs with CVSS 9+ and EPSS > 0.5.")
    if data.ioc_summary.get("network_count", 0) > 0:
        w("3. **Deploy Network IOCs:** Block identified IPs, domains, URLs at perimeter.")
    if data.ioc_summary.get("host_count", 0) > 0:
        w("4. **Deploy Host IOCs:** Add file hashes to EDR blocklists.")
    w("5. **Review Correlated CVEs:** CVEs sharing ATT&CK techniques may indicate campaigns.")
    w()

    # Appendix
    w("## Appendix")
    w()
    w("### Methodology")
    w("Data collected from NVD, GitHub, Exploit-DB, CISA KEV, ThreatFox, and security news feeds.")
    w(
        "Reputation scores calculated using CVSS, EPSS, social mentions, PoC availability, and vendor ubiquity."
    )
    w()
    w("### Data Sources")
    w("- NVD (National Vulnerability Database)")
    w("- CISA Known Exploited Vulnerabilities")
    w("- Exploit-DB / GitHub PoCs")
    w("- ThreatFox IOC Feed")
    w("- Security news RSS feeds")
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
        overdue_kevs = [k for k in data.kev_entries if k["is_overdue"]]
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

    w("=" * 72)
    w(f"  Generated by Horus — {data.generated_at}")
    w("=" * 72)

    return out.getvalue()


# ---------------------------------------------------------------------------
# HTML renderer (professional, PDF-ready, 15-20 pages)
# ---------------------------------------------------------------------------


def _render_html(data: WeeklyData) -> str:
    """Render a publication-quality HTML report with SVG charts and print-ready CSS."""

    # Pre-compute all charts and sections
    charts = _build_all_charts(data)
    cover_html = _build_cover(data)
    toc_html = _build_toc(data)
    executive_html = _build_executive_section(data)
    introduction_html = _build_introduction_section(data)
    landscape_html = _build_landscape_section(data, charts)
    cve_analysis_html = _build_cve_analysis(data)
    kev_html = _build_kev_section(data.kev_entries)
    epss_html = _build_epss_section(data, charts)
    mitre_html = _build_mitre_section(data, charts)
    network_ioc_html = _build_network_ioc_section(data)
    host_ioc_html = _build_host_ioc_section(data)
    affected_pkg_html = _build_affected_packages_section(data)
    news_html = _build_news_section(data.news_highlights[:10])
    correlation_html = _build_correlation_section(data)
    recommendations_html = _build_recommendations_section(data)
    appendix_html = _build_appendix(data)

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
    display: flex; flex-direction: column; justify-content: center;
    align-items: center; text-align: center; padding: 3rem 2rem;
    border-bottom: 3px solid var(--accent); page-break-after: always;
}}
.cover-brand {{ font-size: 1rem; color: var(--accent); letter-spacing: 4px; text-transform: uppercase; margin-bottom: 1rem; font-weight: 600; }}
.cover-title {{ font-size: 2.8rem; font-weight: 800; color: #ffffff; margin-bottom: 0.5rem; letter-spacing: -0.5px; }}
.cover-subtitle {{ font-size: 1.2rem; color: var(--text-dim); margin-bottom: 1.5rem; }}
.cover-period {{ font-size: 1.1rem; color: var(--accent); font-weight: 500; margin-bottom: 0.5rem; }}
.cover-generated {{ font-size: 0.85rem; color: var(--text-dim); margin-bottom: 2rem; }}
.classification-banner {{ display: inline-block; padding: 0.4rem 1.5rem; border: 2px solid var(--yellow); color: var(--yellow); font-weight: 700; font-size: 0.9rem; letter-spacing: 2px; border-radius: 4px; margin-bottom: 2rem; }}
.cover-stats {{ display: flex; gap: 2rem; flex-wrap: wrap; justify-content: center; margin-top: 1rem; }}
.cover-stat {{ text-align: center; }}
.cover-stat-num {{ display: block; font-size: 2.2rem; font-weight: 800; color: var(--text); }}
.cover-stat-num.critical {{ color: var(--red); }}
.cover-stat-label {{ font-size: 0.75rem; color: var(--text-dim); text-transform: uppercase; letter-spacing: 1px; }}

/* ── Table of Contents ──────────────────────────────── */
.toc-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 0.4rem 2rem; margin: 1rem 0; }}
.toc-item {{ padding: 0.5rem 0; border-bottom: 1px solid var(--border); display: flex; align-items: center; gap: 0.6rem; }}
.toc-num {{ color: var(--accent); font-weight: 700; font-size: 0.85rem; min-width: 1.5rem; }}
.toc-item a {{ color: var(--text); text-decoration: none; font-size: 0.9rem; }}
.toc-item a:hover {{ color: var(--accent); }}

/* ── Section Styles ─────────────────────────────────── */
.section {{ padding: 2.5rem 0; page-break-inside: avoid; }}
.section-divider {{ height: 2px; background: linear-gradient(90deg, var(--accent), transparent); margin: 2rem 0; border-radius: 1px; }}
.section h2 {{ color: var(--accent); font-size: 1.4rem; font-weight: 700; margin-bottom: 1.2rem; padding-bottom: 0.5rem; border-bottom: 2px solid var(--border); page-break-after: avoid; }}
h3 {{ color: var(--text); margin: 1.5rem 0 0.8rem; font-size: 1.05rem; font-weight: 600; page-break-after: avoid; }}

/* ── Executive Summary ──────────────────────────────── */
.executive-narrative {{ font-size: 0.95rem; line-height: 1.75; margin-bottom: 1.5rem; }}
.executive-narrative p {{ margin-bottom: 0.8rem; }}
.findings-list {{ list-style: none; padding: 0; margin: 1rem 0; }}
.findings-list li {{ padding: 0.5rem 0; border-bottom: 1px solid var(--border); font-size: 0.9rem; display: flex; align-items: flex-start; gap: 0.6rem; }}
.finding-icon {{ flex-shrink: 0; font-size: 1rem; }}
.trend-indicator {{ font-size: 0.75rem; padding: 0.15rem 0.4rem; border-radius: 3px; margin-left: auto; flex-shrink: 0; }}
.trend-up {{ background: rgba(248,81,73,0.15); color: var(--red); }}
.trend-down {{ background: rgba(63,185,80,0.15); color: var(--green); }}
.trend-neutral {{ background: rgba(139,148,158,0.15); color: var(--text-dim); }}

/* ── KPI Grid ───────────────────────────────────────── */
.kpi-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
.kpi-card {{ background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 1.3rem 1rem; text-align: center; }}
.kpi-num {{ font-size: 2.2rem; font-weight: 800; display: block; line-height: 1.2; }}
.kpi-label {{ font-size: 0.75rem; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.8px; margin-top: 0.3rem; }}
.kpi-change {{ font-size: 0.75rem; margin-top: 0.4rem; display: block; }}
.up {{ color: var(--red); }} .down {{ color: var(--green); }} .neutral {{ color: var(--text-dim); }}
.critical {{ color: var(--red); }} .high {{ color: var(--orange); }}

/* ── Charts Grid ────────────────────────────────────── */
.charts-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; margin: 1.5rem 0; }}
.chart-panel {{ background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 1.5rem; page-break-inside: avoid; }}
.chart-panel h3 {{ color: var(--accent); font-size: 0.95rem; margin-bottom: 1rem; font-weight: 600; text-align: center; }}
.chart-panel.full-width {{ grid-column: 1 / -1; }}

/* ── CVE Cards ──────────────────────────────────────── */
.cve-cards {{ display: grid; grid-template-columns: 1fr; gap: 1rem; margin: 1rem 0; }}
.cve-card {{ background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 1.3rem 1.5rem; page-break-inside: avoid; }}
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
.data-table thead th {{ background: var(--card-alt); padding: 0.7rem 0.9rem; text-align: left; border-bottom: 2px solid var(--border-bright); color: var(--text-dim); font-weight: 600; font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.4px; }}
.data-table tbody td {{ padding: 0.6rem 0.9rem; border-bottom: 1px solid var(--border); }}
.data-table tbody tr:nth-child(even) {{ background: rgba(255,255,255,0.02); }}
.data-table tbody tr:hover {{ background: rgba(88,166,255,0.06); }}
.data-table .desc-cell {{ color: var(--text-dim); font-size: 0.8rem; max-width: 300px; }}
.kev-row {{ background: rgba(248,81,73,0.06) !important; }}
.tf-num.warning {{ color: var(--orange); }}
.empty-cell {{ text-align: center; color: var(--text-dim); padding: 1.5rem !important; font-style: italic; }}

/* ── Alerts ─────────────────────────────────────────── */
.alert {{ padding: 0.8rem 1.2rem; border-radius: 6px; margin: 1rem 0; font-size: 0.9rem; page-break-inside: avoid; }}
.alert-danger {{ background: rgba(248,81,73,0.08); border: 1px solid rgba(248,81,73,0.3); color: var(--red); }}

/* ── News Section ───────────────────────────────────── */
.news-list {{ margin: 1rem 0; }}
.news-item {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1.2rem; margin-bottom: 0.6rem; page-break-inside: avoid; }}
.news-item a {{ color: var(--accent); text-decoration: none; font-weight: 600; font-size: 0.9rem; }}
.news-source {{ color: var(--text-dim); font-size: 0.8rem; margin-left: 0.6rem; }}
.news-summary {{ color: var(--text-dim); font-size: 0.82rem; margin-top: 0.4rem; line-height: 1.5; }}
.tier-badge {{ display: inline-block; padding: 0.1rem 0.4rem; border-radius: 3px; font-size: 0.65rem; color: #fff; font-weight: 700; margin-right: 0.5rem; text-transform: uppercase; letter-spacing: 0.5px; }}

/* ── IOC Tables ─────────────────────────────────────── */
.ioc-table {{ font-size: 0.8rem; }}
.ioc-table td {{ font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menospace, monospace; }}
.ioc-type-badge {{ background: var(--card-alt); padding: 0.15rem 0.4rem; border-radius: 3px; font-size: 0.7rem; font-weight: 600; }}

/* ── Recommendations ────────────────────────────────── */
.rec-list {{ list-style: none; padding: 0; margin: 1rem 0; }}
.rec-list li {{ padding: 0.7rem 0; border-bottom: 1px solid var(--border); display: flex; align-items: flex-start; gap: 0.7rem; }}
.rec-priority {{ font-weight: 700; font-size: 0.75rem; padding: 0.2rem 0.5rem; border-radius: 4px; flex-shrink: 0; }}
.rec-p1 {{ background: rgba(248,81,73,0.15); color: var(--red); }}
.rec-p2 {{ background: rgba(240,136,62,0.15); color: var(--orange); }}
.rec-p3 {{ background: rgba(210,153,34,0.15); color: var(--yellow); }}

/* ── Appendix ───────────────────────────────────────── */
.appendix {{ font-size: 0.85rem; color: var(--text-dim); }}
.appendix dt {{ color: var(--text); font-weight: 600; margin-top: 0.8rem; }}
.appendix dd {{ margin-left: 1rem; }}

/* ── Footer ─────────────────────────────────────────── */
.footer {{ text-align: center; padding: 2rem 0; color: var(--text-dim); font-size: 0.8rem; border-top: 1px solid var(--border); margin-top: 2rem; page-break-inside: avoid; }}

/* ── Print Styles ───────────────────────────────────── */
@media print {{
    body {{ background: #fff; color: #1a1a1a; font-size: 10.5pt; line-height: 1.45; }}
    .container {{ max-width: 100%; padding: 0; }}
    .cover-page {{ background: #fff; min-height: auto; padding: 5cm 2cm; border-bottom: 3px solid #1f6feb; page-break-after: always; }}
    .cover-title {{ color: #1a1a1a; }}
    .cover-stat-num {{ color: #1a1a1a; }}
    .classification-banner {{ border-color: #d29922; color: #8a6d00; }}
    .section {{ padding: 1.2rem 0; }}
    .section h2 {{ color: #1f6feb; border-bottom-color: #d0d7de; font-size: 1.1rem; }}
    .kpi-card, .chart-panel, .cve-card, .news-item {{ background: #f6f8fa; border-color: #d0d7de; break-inside: avoid; }}
    .data-table thead th {{ background: #f6f8fa; color: #57606a; border-bottom-color: #d0d7de; }}
    .data-table tbody td {{ border-bottom-color: #eaeef2; }}
    .data-table tbody tr:nth-child(even) {{ background: #f6f8fa; }}
    .cve-id, .news-item a {{ color: #1f6feb; }}
    @page {{ margin: 1.8cm 1.5cm; size: A4; }}
    @page :first {{ margin: 0; }}
    h2, h3 {{ page-break-after: avoid; }}
    .section {{ page-break-inside: avoid; }}
}}

/* ── Responsive ─────────────────────────────────────── */
@media screen and (max-width: 768px) {{
    .charts-grid {{ grid-template-columns: 1fr; }}
    .kpi-grid {{ grid-template-columns: repeat(2, 1fr); }}
    .toc-grid {{ grid-template-columns: 1fr; }}
    .cover-stats {{ gap: 1rem; }}
    .cover-title {{ font-size: 2rem; }}
}}
</style>
</head>
<body>

{cover_html}

<div class="container">
{toc_html}
{executive_html}
{introduction_html}
{landscape_html}
{cve_analysis_html}
{kev_html}
{epss_html}
{mitre_html}
{network_ioc_html}
{host_ioc_html}
{affected_pkg_html}
{news_html}
{correlation_html}
{recommendations_html}
{appendix_html}

<div class="footer">
    <p>Generated by Horus Threat Intelligence Platform &mdash; {data.generated_at}</p>
    <p style="margin-top:0.3rem;font-size:0.7rem;">Classification: TLP:WHITE | For authorized distribution only</p>
</div>
</div>
</body>
</html>"""


# ---------------------------------------------------------------------------
# HTML Section Builders
# ---------------------------------------------------------------------------


def _build_cover(data: WeeklyData) -> str:
    """Build cover page."""
    total_cves = data.total_cves_this_week
    return f"""<!-- ═══════════ COVER PAGE ═══════════ -->
<div class="cover-page" id="cover">
    <div class="cover-brand">HORUS</div>
    <h1 class="cover-title">Weekly Threat Intelligence Report</h1>
    <div class="cover-subtitle">CVE &amp; Exploit Analysis</div>
    <div class="cover-period">{data.period_start} to {data.period_end}</div>
    <div class="cover-generated">Generated: {data.generated_at}</div>
    <div class="classification-banner">TLP:WHITE</div>
    <div class="cover-stats">
        <div class="cover-stat"><span class="cover-stat-num">{total_cves}</span><span class="cover-stat-label">New CVEs</span></div>
        <div class="cover-stat"><span class="cover-stat-num critical">{data.critical_cves}</span><span class="cover-stat-label">Critical</span></div>
        <div class="cover-stat"><span class="cover-stat-num">{data.kev_new_this_week}</span><span class="cover-stat-label">KEV Added</span></div>
        <div class="cover-stat"><span class="cover-stat-num">{data.total_pocs_this_week}</span><span class="cover-stat-label">New PoCs</span></div>
        <div class="cover-stat"><span class="cover-stat-num">{data.ioc_summary.get("total_iocs", 0)}</span><span class="cover-stat-label">Extracted IOCs</span></div>
    </div>
</div>"""


def _build_toc(data: WeeklyData) -> str:
    """Build table of contents — all sections always present."""
    items = [
        ("1.", "executive-summary", "Executive Summary"),
        ("2.", "introduction", "Introduction"),
        ("3.", "landscape", "Threat Overview"),
        ("4.", "cve-analysis", "Critical & High CVE Analysis"),
        ("5.", "kev-section", "CISA Known Exploited Vulnerabilities"),
        ("6.", "epss-section", "EPSS Exploitability Trends"),
        ("7.", "mitre-section", "MITRE ATT&CK Technique Mapping"),
        ("8.", "network-iocs", "Network-based Indicators (IOCs)"),
        ("9.", "host-iocs", "Host-based Indicators (IOCs)"),
        ("10.", "affected-packages", "Affected Packages & Products"),
        ("11.", "news-section", "Vulnerability News & Intelligence"),
        ("12.", "correlation-section", "CVE Correlation Analysis"),
        ("13.", "recommendations", "Recommendations"),
        ("14.", "appendix", "Appendix"),
    ]

    items_html = "".join(
        f'<div class="toc-item"><span class="toc-num">{num}</span><a href="#{anchor}">{label}</a></div>'
        for num, anchor, label in items
    )
    return f"""<!-- ═══════════ TABLE OF CONTENTS ═══════════ -->
<div class="section" id="toc">
    <h2>Table of Contents</h2>
    <div class="toc-grid">{items_html}</div>
</div>"""


def _build_all_charts(data: WeeklyData) -> dict[str, str]:
    """Build all SVG charts."""
    return {
        "donut": severity_donut(
            critical=data.severity_breakdown.get("CRITICAL", 0),
            high=data.severity_breakdown.get("HIGH", 0),
            medium=data.severity_breakdown.get("MEDIUM", 0),
            low=data.severity_breakdown.get("LOW", 0),
        ),
        "trend": cve_trend_line(data.weekly_trend) if data.weekly_trend else "",
        "vendor": vendor_bar_chart(data.top_vendors) if data.top_vendors else "",
        "mitre": mitre_heatmap(data.top_tags) if data.top_tags else "",
        "epss_hist": _epss_histogram(data.epss_movers) if data.epss_movers else "",
        "ioc_donut": _ioc_type_donut(data.ioc_summary.get("type_counts", {})),
    }


def _build_executive_section(data: WeeklyData) -> str:
    """Build executive summary section."""
    total = data.total_cves_this_week
    prev = data.total_cves_last_week
    crit = data.critical_cves
    high = data.high_cves
    kev = data.kev_new_this_week

    # Narrative paragraphs
    if total == 0:
        p1 = f"No new CVEs were observed during the reporting period of {data.period_start} to {data.period_end}. This may indicate reduced vulnerability disclosure activity."
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

    if kev > 0:
        p2 = f"CISA added <strong>{kev} new entries</strong> to the Known Exploited Vulnerabilities catalog, bringing the total tracked KEVs to {data.kev_total}. "
    elif data.kev_total > 0:
        p2 = f"No new KEV additions this week. {data.kev_total} total KEVs are currently tracked. "
    else:
        p2 = "No KEV entries are currently tracked. "

    if data.kev_overdue > 0:
        p2 += f"<strong style='color:var(--red);'>{data.kev_overdue} KEVs are past their CISA remediation deadline and require urgent action.</strong>"

    p3 = (
        f"The average EPSS score for new CVEs was <strong>{data.avg_epss_this_week:.3f}</strong>, "
        f"indicating a {'high' if data.avg_epss_this_week > 0.2 else 'moderate' if data.avg_epss_this_week > 0.05 else 'low'} "
        f"likelihood of exploitation within 30 days. {data.total_pocs_this_week} new proof-of-concept exploits were published."
    )

    ioc_total = data.ioc_summary.get("total_iocs", 0)
    p4 = ""
    if ioc_total > 0:
        p4 = (
            f"<p>Threat intelligence processing extracted <strong>{ioc_total} indicators of compromise</strong> "
            f"({data.ioc_summary.get('network_count', 0)} network, {data.ioc_summary.get('host_count', 0)} host-based) "
            f"from security news, resources, and threat feeds. These indicators should be deployed to "
            f"perimeter defenses and endpoint detection systems.</p>"
        )

    # Findings
    findings = []
    if crit > 0:
        findings.append(
            f'<li><span class="finding-icon">🔴</span><span><strong>{crit} critical-rated CVEs (CVSS 9+)</strong> identified requiring immediate remediation priority.</span><span class="trend-indicator trend-up">ACTION</span></li>'
        )
    if kev > 0:
        findings.append(
            f'<li><span class="finding-icon">⚠️</span><span><strong>{kev} new KEV entries</strong> added by CISA — known actively exploited vulnerabilities.</span></li>'
        )
    if data.top_cves:
        top = data.top_cves[0]
        kev_tag = " [KEV]" if top["kev"] else ""
        findings.append(
            f'<li><span class="finding-icon">🎯</span><span>Highest-risk CVE: <strong>{top["id"]}{kev_tag}</strong> (CVSS {top["cvss_score"] or "N/A"}, EPSS {top["epss_score"]:.3f}) — {top["description"][:80]}</span></li>'
        )
    if data.top_vendors:
        v = data.top_vendors[0]
        findings.append(
            f'<li><span class="finding-icon">🏢</span><span>Most targeted vendor: <strong>{v["vendor"]}</strong> with {v["cve_count"]} CVEs (avg CVSS {v["avg_cvss"]})</span></li>'
        )
    if data.epss_movers and data.epss_movers[0].get("epss_score", 0) > 0.5:
        m = data.epss_movers[0]
        findings.append(
            f'<li><span class="finding-icon">💥</span><span>Highest exploitability: <strong>{m["id"]}</strong> with EPSS {m["epss_score"]:.3f} ({m["epss_score"] * 100:.0f}% exploitation probability)</span></li>'
        )
    if data.kev_overdue > 0:
        findings.append(
            f'<li><span class="finding-icon">🚨</span><span><strong>{data.kev_overdue} KEVs overdue</strong> — past CISA remediation deadline</span><span class="trend-indicator trend-up">URGENT</span></li>'
        )

    findings_html = (
        "\n        ".join(findings) if findings else "<li>No significant findings this period.</li>"
    )

    return f"""<!-- ═══════════ EXECUTIVE SUMMARY ═══════════ -->
<div class="section" id="executive-summary">
    <h2>1. Executive Summary</h2>
    <div class="executive-narrative">
        <p>{p1}</p>
        <p>{p2}</p>
        <p>{p3}</p>
        {p4}
    </div>
    <h3>Key Findings</h3>
    <ul class="findings-list">
        {findings_html}
    </ul>
</div>"""


def _build_introduction_section(data: WeeklyData) -> str:
    """Build introduction / scope section."""
    ioc_total = data.ioc_summary.get("total_iocs", 0)
    return f"""<!-- ═══════════ INTRODUCTION ═══════════ -->
<div class="section-divider"></div>
<div class="section" id="introduction">
    <h2>2. Introduction</h2>
    <div class="executive-narrative">
        <p>This report provides threat intelligence analysis for the period {data.period_start} to {data.period_end}.
        Data sources include NVD (authoritative CVE data), CISA KEV, EPSS, AlienVault OTX,
        and ThreatFox. Analysis covers {data.total_cves_this_week} new CVEs, {data.total_pocs_this_week} new exploit
        publications, and {ioc_total} indicators of compromise.</p>
        <p>The report follows a structured analytical methodology: initial data aggregation from authoritative sources,
        followed by multi-factor risk scoring (CVSS, EPSS, KEV status, PoC availability), IOC extraction and correlation,
        and finally prioritized recommendations. Each section builds on the previous to provide a comprehensive
        threat landscape assessment suitable for security operations teams, vulnerability management, and executive briefing.</p>
    </div>
</div>"""


def _build_landscape_section(data: WeeklyData, charts: dict[str, str]) -> str:
    """Build threat overview section with narrative analysis and charts."""
    tc = data.total_cves_this_week
    tn = (
        "up"
        if tc > data.total_cves_last_week
        else "down"
        if tc < data.total_cves_last_week
        else "neutral"
    )
    cve_pct = _pct_change(tc, data.total_cves_last_week)
    poc_pct = _pct_change(data.total_pocs_this_week, data.total_pocs_last_week)

    # ── Narrative analysis paragraphs ──
    # Paragraph 1: CVE volume trend interpretation
    if tc == 0:
        p1 = f"No new CVEs were observed during the reporting period ({data.period_start} to {data.period_end}). This may reflect reduced disclosure activity, a lull between major vulnerability cycles, or underreporting during holiday periods."
    elif tc > data.total_cves_last_week:
        p1 = f"<strong>CVE volume increased {cve_pct} week-over-week</strong> ({tc} vs {data.total_cves_last_week}), suggesting accelerated vulnerability disclosure. This may correlate with vendor patch cycles (e.g., Microsoft Patch Tuesday), coordinated disclosure following security conferences, or increased scanning activity by security researchers. Defenders should expect elevated patching workload in the coming days."
    elif tc < data.total_cves_last_week:
        p1 = f"<strong>CVE volume decreased {cve_pct} week-over-week</strong> ({tc} vs {data.total_cves_last_week}), indicating a slower disclosure period. While this reduces immediate patching pressure, it may precede a surge as deferred disclosures accumulate. Teams should use this window to address existing backlog."
    else:
        p1 = f"CVE volume remained stable at {tc} new entries this week, consistent with the previous week's {data.total_cves_last_week}. This steady-state suggests normal vulnerability disclosure cadence."

    # Paragraph 2: Severity and KEV analysis
    sev_parts = []
    if data.critical_cves > 0:
        sev_parts.append(f"<strong>{data.critical_cves} critical-rated (CVSS 9+)</strong>")
    if data.high_cves > 0:
        sev_parts.append(f"<strong>{data.high_cves} high-rated (CVSS 7-8.9)</strong>")
    sev_text = ", ".join(sev_parts) if sev_parts else "no critical or high-severity CVEs"
    p2 = f"This week's disclosures include {sev_text}. "
    if data.kev_new_this_week > 0:
        p2 += f"<strong>CISA added {data.kev_new_this_week} new KEV entries</strong>, confirming active exploitation in the wild. "
    if data.kev_overdue > 0:
        p2 += f"<strong style='color:var(--red);'>{data.kev_overdue} KEVs are past their remediation deadline — these represent known-exploited vulnerabilities with no excuse for delay.</strong> "
    p2 += f"The average EPSS of {data.avg_epss_this_week:.3f} suggests a {'high' if data.avg_epss_this_week > 0.2 else 'moderate' if data.avg_epss_this_week > 0.05 else 'low'} near-term exploitation likelihood across the new CVE set."

    # Paragraph 3: ATT&CK technique trends
    if data.top_tags:
        top3 = data.top_tags[:3]
        tech_detail = ", ".join(
            f"<strong>{t['tag']}</strong> ({t['cve_count']} CVEs, avg CVSS {t['avg_cvss']})"
            for t in top3
        )
        p3 = f"Attack technique analysis shows <strong>{top3[0]['tag']}</strong> as the most prevalent technique this week. The top 3 techniques — {tech_detail} — suggest "
        # Context-aware interpretation
        techniques = [t["tag"].lower() for t in top3]
        if any(t in ("rce", "command-execution", "code-execution") for t in techniques):
            p3 += "a focus on remote exploitation capabilities that enable initial access and lateral movement. "
        elif any(t in ("privilege-escalation", "elevation") for t in techniques):
            p3 += "adversaries prioritizing post-compromise privilege escalation. "
        elif any(t in ("xss", "csrf", "injection") for t in techniques):
            p3 += "continued targeting of web application attack surfaces. "
        else:
            p3 += "diverse adversary tooling and techniques. "
        p3 += "Defenders should ensure detections cover these techniques in EDR and SIEM platforms."
    else:
        p3 = "Insufficient attack technique data for trend analysis this period. Enriching CVE records with ATT&CK mappings would improve detection gap analysis."

    # Paragraph 4: Vendor targeting patterns
    if data.top_vendors:
        top_vendor = data.top_vendors[0]
        vendor_count = len(data.top_vendors)
        p4 = f"<strong>{vendor_count} vendors</strong> were affected by new CVEs this week. <strong>{top_vendor['vendor'].title()}</strong> was most targeted with {top_vendor['cve_count']} CVEs (avg CVSS {top_vendor['avg_cvss']}), "
        if top_vendor["kev_count"] > 0:
            p4 += f"including {top_vendor['kev_count']} KEV-listed vulnerability. "
        else:
            p4 += "none currently on the KEV catalog. "
        if vendor_count > 1:
            second = data.top_vendors[1]
            p4 += f"{second['vendor'].title()} followed with {second['cve_count']} CVEs. "
        p4 += "Organizations with significant exposure to these vendors should prioritize patching and verify compensating controls."
    else:
        p4 = "No vendor targeting data available for this period."

    narrative_html = f"""
    <div class="executive-narrative">
        <p>{p1}</p>
        <p>{p2}</p>
        <p>{p3}</p>
        <p>{p4}</p>
    </div>"""

    return f"""<!-- ═══════════ THREAT OVERVIEW ═══════════ -->
<div class="section-divider"></div>
<div class="section" id="landscape">
    <h2>3. Threat Overview</h2>
    {narrative_html}

    <div class="kpi-grid">
        <div class="kpi-card">
            <span class="kpi-num{" critical" if tc > 50 else ""}">{tc}</span>
            <span class="kpi-label">New CVEs</span>
            <span class="kpi-change {tn}">{_trend_arrow(tc, data.total_cves_last_week)} {cve_pct} WoW</span>
        </div>
        <div class="kpi-card">
            <span class="kpi-num">{data.total_pocs_this_week}</span>
            <span class="kpi-label">New PoCs</span>
            <span class="kpi-change neutral">{_trend_arrow(data.total_pocs_this_week, data.total_pocs_last_week)} {poc_pct} WoW</span>
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

    <div class="charts-grid">
        <div class="chart-panel">
            <h3>Severity Distribution</h3>
            {charts["donut"]}
        </div>
        <div class="chart-panel">
            <h3>MITRE ATT&CK Techniques</h3>
            {charts["mitre"]}
        </div>
        <div class="chart-panel full-width">
            <h3>CVE Intake Trend (8 Weeks)</h3>
            {charts["trend"]}
        </div>
    </div>
</div>"""


def _build_cve_analysis(data: WeeklyData) -> str:
    """Build critical & high CVE analysis section."""
    if not data.top_cves:
        return ""

    cards = []
    for cve in data.top_cves[:10]:
        kev_class = " kev-highlight" if cve["kev"] else ""
        kev_badge = ' <span class="badge kev">KEV</span>' if cve["kev"] else ""
        sev_class = (cve["cvss_severity"] or "N/A").lower()
        cvss = cvss_badge(cve["cvss_score"], cve["cvss_severity"])
        epss = epss_bar(cve["id"], cve["epss_score"]) if cve["epss_score"] is not None else "N/A"
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
</div>""")

    return f"""<!-- ═══════════ CVE ANALYSIS ═══════════ -->
<div class="section-divider"></div>
<div class="section" id="cve-analysis">
    <h2>4. Critical &amp; High CVE Analysis</h2>
    <div class="cve-cards">
        {"".join(cards)}
    </div>
</div>"""


def _build_kev_section(kev_entries: list[dict]) -> str:
    """Build CISA KEV section."""
    if not kev_entries:
        return ""

    from datetime import date as _date_mod

    overdue_kevs = [k for k in kev_entries if k["is_overdue"]]
    no_due_date = [k for k in kev_entries if k["kev_due_date"] == "Not Set"]
    due_soon = []
    for k in kev_entries:
        if k["kev_due_date"] != "Not Set" and not k["is_overdue"]:
            try:
                due_d = _date_mod.fromisoformat(k["kev_due_date"])
                if (due_d - _date_mod.today()).days <= 30:
                    due_soon.append(k)
            except ValueError:
                pass

    rows = ""
    for kev in kev_entries:
        row_class = ' class="kev-row"' if kev["is_overdue"] else ""
        sev_class = (kev.get("cvss_severity") or "N/A").lower()
        cvss = cvss_badge(kev["cvss_score"], None)
        due_display = kev["kev_due_date"] if kev["kev_due_date"] != "Not Set" else "NOT SET"
        days_display = str(kev["days_overdue"]) if kev["is_overdue"] else "—"
        epss = f"{kev['epss_score']:.4f}" if kev.get("epss_score") is not None else "N/A"
        affected = (kev.get("affected") or "Unknown")[:60]

        rows += f"""<tr{row_class}>
            <td><strong>{kev["id"]}</strong></td>
            <td>{cvss}</td>
            <td><span class="sev-pill {sev_class}">{kev.get("cvss_severity") or "N/A"}</span></td>
            <td>{due_display}</td>
            <td>{days_display}</td>
            <td class="desc-cell">{affected}</td>
            <td>{epss}</td>
        </tr>"""

    alert_html = ""
    if overdue_kevs:
        alert_html = f'<div class="alert alert-danger"><strong>OVERDUE:</strong> {len(overdue_kevs)} KEV entries past CISA remediation deadline — immediate action required</div>'

    return f"""<!-- ═══════════ KEV ═══════════ -->
<div class="section-divider"></div>
<div class="section" id="kev-section">
    <h2>5. CISA Known Exploited Vulnerabilities</h2>
    <div class="tf-grid">
        <div class="tf-stat"><span class="tf-num">{len(kev_entries)}</span><span class="tf-label">Total KEVs</span></div>
        <div class="tf-stat"><span class="tf-num critical">{len(overdue_kevs)}</span><span class="tf-label">Overdue</span></div>
        <div class="tf-stat"><span class="tf-num warning">{len(due_soon)}</span><span class="tf-label">Due Soon (≤30d)</span></div>
        <div class="tf-stat"><span class="tf-num">{len(no_due_date)}</span><span class="tf-label">No Due Date</span></div>
    </div>
    {alert_html}
    <table class="data-table">
        <thead><tr><th>CVE</th><th>CVSS</th><th>Severity</th><th>Due Date</th><th>Days Overdue</th><th>Affected Products</th><th>EPSS</th></tr></thead>
        <tbody>{rows}</tbody>
    </table>
</div>"""


def _build_epss_section(data: WeeklyData, charts: dict[str, str]) -> str:
    """Build EPSS exploitability section."""
    if not data.epss_movers:
        return ""

    rows = ""
    for m in data.epss_movers[:10]:
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

    return f"""<!-- ═══════════ EPSS ═══════════ -->
<div class="section-divider"></div>
<div class="section" id="epss-section">
    <h2>6. EPSS Exploitability Trends</h2>
    <div class="chart-panel">
        <h3>EPSS Score Distribution</h3>
        {charts["epss_hist"]}
    </div>
    <h3>Top 10 Highest EPSS CVEs</h3>
    <table class="data-table">
        <thead><tr><th>CVE</th><th>CVSS</th><th>EPSS</th><th>Rep</th><th>Description</th></tr></thead>
        <tbody>{rows}</tbody>
    </table>
</div>"""


def _build_mitre_section(data: WeeklyData, charts: dict[str, str]) -> str:
    """Build MITRE ATT&CK technique mapping section."""
    if not data.top_tags:
        return ""

    rows = ""
    for t in data.top_tags[:10]:
        rows += f"""<tr>
            <td>{t["tag"]}</td>
            <td>{t["cve_count"]}</td>
            <td>{t["avg_cvss"]}</td>
        </tr>"""

    return f"""<!-- ═══════════ MITRE ATT&CK ═══════════ -->
<div class="section-divider"></div>
<div class="section" id="mitre-section">
    <h2>7. MITRE ATT&amp;CK Technique Mapping</h2>
    <div class="charts-grid">
        <div class="chart-panel">
            <h3>Technique Heatmap</h3>
            {charts["mitre"]}
        </div>
        <div class="chart-panel">
            <h3>Technique Counts</h3>
            <table class="data-table">
                <thead><tr><th>Technique</th><th>CVEs</th><th>Avg CVSS</th></tr></thead>
                <tbody>{rows}</tbody>
            </table>
        </div>
    </div>
</div>"""


def _build_network_ioc_section(data: WeeklyData) -> str:
    """Build network-based IOCs section."""
    rows = ""
    for ioc in data.network_iocs[:50]:
        cves = ", ".join(ioc.get("cves", [])[:3])
        threat = ioc.get("threat_type", "")
        # Show CVE if available, otherwise threat type
        link_col = cves if cves else (threat if threat else "—")
        sources = ", ".join(ioc.get("sources", []))
        rows += f"""<tr>
            <td><span class="ioc-type-badge">{ioc["type"]}</span></td>
            <td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"><code>{ioc["value"][:60]}</code></td>
            <td>{sources}</td>
            <td>{link_col}</td>
        </tr>"""

    if not rows:
        rows = '<tr><td colspan="4" class="empty-cell">No network indicators identified in this reporting period.</td></tr>'

    return f"""<!-- ═══════════ NETWORK IOCs ═══════════ -->
<div class="section-divider"></div>
<div class="section" id="network-iocs">
    <h2>7. Network-based Indicators (IOCs)</h2>
    <p>Network indicators from threat intelligence sources. Linked CVEs indicate known exploitation targets; threat type indicates malware/C2 classification from ThreatFox.</p>
    <table class="data-table ioc-table">
        <thead><tr><th>Type</th><th>Value</th><th>Source</th><th>CVE / Threat</th></tr></thead>
        <tbody>{rows}</tbody>
    </table>
</div>"""


def _build_host_ioc_section(data: WeeklyData) -> str:
    """Build host-based IOCs section."""
    rows = ""
    for ioc in data.host_iocs[:50]:
        cves = ", ".join(ioc.get("cves", [])[:3])
        threat = ioc.get("threat_type", "")
        link_col = cves if cves else (threat if threat else "—")
        sources = ", ".join(ioc.get("sources", []))
        val = ioc["value"]
        # For hashes: show first 16 chars + ellipsis (standard IOC display)
        if ioc["type"].startswith("hash_") and len(val) > 20:
            val = f"{val[:16]}…"
        rows += f"""<tr>
            <td><span class="ioc-type-badge">{ioc["type"]}</span></td>
            <td><code>{val}</code></td>
            <td>{sources}</td>
            <td>{link_col}</td>
        </tr>"""

    if not rows:
        rows = '<tr><td colspan="4" class="empty-cell">No host indicators identified in this reporting period.</td></tr>'

    return f"""<!-- ═══════════ HOST IOCs ═══════════ -->
<div class="section-divider"></div>
<div class="section" id="host-iocs">
    <h2>8. Host-based Indicators (IOCs)</h2>
    <p>Host-based indicators including file hashes, file paths, and registry keys. Linked CVEs indicate known exploitation targets; threat type indicates malware classification.</p>
    <table class="data-table ioc-table">
        <thead><tr><th>Type</th><th>Value</th><th>Source</th><th>CVE / Threat</th></tr></thead>
        <tbody>{rows}</tbody>
    </table>
</div>"""


def _build_affected_packages_section(data: WeeklyData) -> str:
    """Build affected packages & products section."""
    rows = ""
    for pkg in data.affected_packages[:20]:
        cves = ", ".join(pkg["sample_cves"][:5])
        rows += f"""<tr>
            <td>{pkg["vendor"]}</td>
            <td>{pkg["product"]}</td>
            <td>{pkg["cve_count"]}</td>
            <td class="desc-cell">{cves}</td>
        </tr>"""
    if not rows:
        rows = '<tr><td colspan="4" class="empty-cell">No vendor/product data available for this reporting period.</td></tr>'

    return f"""<!-- ═══════════ AFFECTED PACKAGES ═══════════ -->
<div class="section-divider"></div>
<div class="section" id="affected-packages">
    <h2>10. Affected Packages &amp; Products</h2>
    <p style="color:var(--text-dim);font-size:0.85rem;margin-bottom:1rem;">Specific vendor/product combinations with CVE counts during this period.</p>
    <table class="data-table">
        <thead><tr><th>Vendor</th><th>Product</th><th>CVEs</th><th>Sample CVEs</th></tr></thead>
        <tbody>{rows}</tbody>
    </table></div>"""


def _build_news_section(articles: list[dict]) -> str:
    """Build news & intelligence section."""
    tier_colors = {1: "#dc3545", 2: "#fd7e14", 3: "#ffc107", 4: "#28a745", 5: "#6c757d"}
    html = '<div class="section-divider"></div><div class="section" id="news-section"><h2>11. Vulnerability News &amp; Intelligence</h2><p style="color:var(--text-dim);font-size:0.85rem;margin-bottom:1rem;">Recent security news and advisories relevant to this period\'s threat landscape (last 7 days).</p><div class="news-list">'
    if not articles:
        html += '<p class="empty-cell">No news articles linked in this reporting period.</p>'
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


def _build_vendor_section(data: WeeklyData, charts: dict[str, str]) -> str:
    """Build vendors section."""
    rows = ""
    for v in data.top_vendors[:15]:
        kev_str = (
            f' <span class="badge kev-sm">{v["kev_count"]} KEV</span>' if v["kev_count"] else ""
        )
        rows += f"""<tr>
            <td>{v["vendor"]}</td>
            <td>{v["cve_count"]}</td>
            <td>{v["avg_cvss"]}</td>
            <td>{kev_str}</td>
        </tr>"""
    if not rows:
        rows = '<tr><td colspan="4" class="empty-cell">No vendor data available for this reporting period.</td></tr>'

    return f"""<!-- ═══════════ VENDORS ═══════════ -->
<div class="section-divider"></div>
<div class="section" id="vendor-section">
    <h2>10. Affected Vendors &amp; Products</h2>
    <div class="charts-grid">
        <div class="chart-panel">
            <h3>Vendor Bar Chart</h3>
            {charts["vendor"]}
        </div>
        <div class="chart-panel">
            <h3>Vendor Table</h3>
            <table class="data-table">
                <thead><tr><th>Vendor</th><th>CVEs</th><th>Avg CVSS</th><th>KEVs</th></tr></thead>
                <tbody>{rows}</tbody>
            </table>
        </div>
    </div>
</div>"""


def _build_correlation_section(data: WeeklyData) -> str:
    """Build CVE correlation analysis section."""
    # Simple clustering: group CVEs with shared tags
    if not data.top_cves or len(data.top_cves) < 2:
        return ""

    # Build clusters from top tags
    clusters = []
    seen_cves: set[str] = set()
    for tag in data.top_tags[:5]:
        cluster_cves = [
            c["id"] for c in data.top_cves if tag["tag"] in c.get("description", "").lower()
        ]
        new_cves = [c for c in cluster_cves if c not in seen_cves]
        if new_cves:
            clusters.append(
                {"label": f"{tag['tag']} cluster", "cves": new_cves, "count": tag["cve_count"]}
            )
            seen_cves.update(new_cves)

    if not clusters:
        # Fallback: group by severity
        sev_groups: dict[str, list[str]] = {}
        for c in data.top_cves:
            sev = c.get("cvss_severity", "UNKNOWN")
            sev_groups.setdefault(sev, []).append(c["id"])
        clusters = [
            {"label": f"{sev} CVEs", "cves": cves, "count": len(cves)}
            for sev, cves in sev_groups.items()
            if len(cves) > 1
        ]

    if not clusters:
        return ""

    html = '<div class="section-divider"></div><div class="section" id="correlation-section"><h2>12. CVE Correlation Analysis</h2><p>CVEs grouped by shared characteristics (ATT&CK techniques, severity, or common PoC sources) that may indicate coordinated campaigns.</p>'
    for cluster in clusters[:5]:
        cve_list = ", ".join(cluster["cves"][:10])
        html += f"""<div class="news-item">
            <strong>{cluster["label"]}</strong> ({cluster["count"]} CVEs)
            <p class="news-summary">{cve_list}</p>
        </div>"""
    html += "</div>"
    return html


def _build_recommendations_section(data: WeeklyData) -> str:
    """Build data-driven, specific recommendations section."""
    recs = []

    # P1: Overdue KEVs with specific CVEs
    if data.kev_overdue > 0:
        overdue_ids = [k["id"] for k in data.kev_entries if k["is_overdue"]][:5]
        overdue_detail = ", ".join(overdue_ids) if overdue_ids else f"{data.kev_overdue} CVEs"
        recs.append(
            f'<li><span class="rec-priority rec-p1">P1</span><span><strong>Patch {data.kev_overdue} overdue KEVs:</strong> {overdue_detail} — past CISA remediation deadline. Immediate patching or vendor mitigation required.</span></li>'
        )

    # P1: Critical CVEs with EPSS > 50%
    critical_high_epss = [
        c
        for c in data.top_cves
        if c.get("cvss_score", 0) >= 9.0 and (c.get("epss_score") or 0) > 0.5
    ]
    if critical_high_epss:
        cve_list = ", ".join(c["id"] for c in critical_high_epss[:5])
        recs.append(
            f'<li><span class="rec-priority rec-p1">P1</span><span><strong>Address {len(critical_high_epss)} critical CVEs with high exploitability:</strong> {cve_list} — CVSS 9+ with EPSS &gt; 50%. Prioritize for emergency patching.</span></li>'
        )

    # P2: CVEs with EPSS > 90%
    high_epss = [c for c in data.top_cves if (c.get("epss_score") or 0) > 0.9]
    if high_epss:
        cve_list = ", ".join(f"{c['id']} ({c['epss_score']:.0%})" for c in high_epss[:6])
        recs.append(
            f'<li><span class="rec-priority rec-p2">P2</span><span><strong>Monitor {len(high_epss)} CVEs with EPSS &gt; 90%:</strong> {cve_list} — near-term exploitation likely. Apply patches or compensating controls.</span></li>'
        )

    # P2: Network IOCs
    if data.ioc_summary.get("network_count", 0) > 0:
        recs.append(
            f'<li><span class="rec-priority rec-p2">P2</span><span><strong>Deploy {data.ioc_summary["network_count"]} network IOCs:</strong> Block identified IPs, domains, and URLs at perimeter defenses (firewall, proxy, DNS).</span></li>'
        )

    # P2: Host IOCs
    if data.ioc_summary.get("host_count", 0) > 0:
        recs.append(
            f'<li><span class="rec-priority rec-p2">P2</span><span><strong>Deploy {data.ioc_summary["host_count"]} host IOCs:</strong> Add file hashes to EDR blocklists and monitor for registry modifications and suspicious file paths.</span></li>'
        )

    # P3: Vendor risk review
    if data.top_vendors:
        top3 = data.top_vendors[:3]
        vendor_detail = ", ".join(
            f"{v['vendor']} ({v['cve_count']} CVEs, avg CVSS {v['avg_cvss']})" for v in top3
        )
        recs.append(
            f'<li><span class="rec-priority rec-p3">P3</span><span><strong>Review exposure to top-targeted vendors:</strong> {vendor_detail} — assess organizational exposure and prioritize patching.</span></li>'
        )

    # P3: Correlated CVEs
    if data.top_tags and len(data.top_tags) > 1:
        top_tags = ", ".join(f"{t['tag']} ({t['cve_count']} CVEs)" for t in data.top_tags[:3])
        recs.append(
            f'<li><span class="rec-priority rec-p3">P3</span><span><strong>Review correlated attack techniques:</strong> {top_tags} — CVEs sharing ATT&CK techniques may indicate campaign-level targeting.</span></li>'
        )

    recs_html = (
        "\n        ".join(recs) if recs else "<li>No urgent recommendations this period.</li>"
    )

    return f"""<!-- ═══════════ RECOMMENDATIONS ═══════════ -->
<div class="section-divider"></div>
<div class="section" id="recommendations">
    <h2>13. Recommendations</h2>
    <p style="color:var(--text-dim);font-size:0.85rem;margin-bottom:1rem;">Prioritized, actionable recommendations based on this period's data. P1 = immediate action, P2 = near-term, P3 = planned review.</p>
    <ul class="rec-list">
        {recs_html}
    </ul>
</div>"""


def _build_appendix(data: WeeklyData) -> str:
    """Build appendix section."""
    return """<!-- ═══════════ APPENDIX ═══════════ -->
<div class="section-divider"></div>
<div class="section" id="appendix">
    <h2>14. Appendix</h2>
    <h3>Methodology</h3>
    <p class="appendix">Horus aggregates vulnerability data from NVD, CISA KEV, Exploit-DB, GitHub, and ThreatFox. Reputation scores (0-10) are calculated using: CVSS (35%), EPSS (25%), KEV status, social mentions, PoC availability, and vendor ubiquity. IOCs are extracted from news articles and security resources using regex pattern matching, with private IP ranges and common CDNs excluded.</p>
    <h3>Data Sources</h3>
    <dl class="appendix">
        <dt>NVD</dt><dd>National Vulnerability Database — authoritative CVE source</dd>
        <dt>CISA KEV</dt><dd>Known Exploited Vulnerabilities catalog</dd>
        <dt>Exploit-DB / GitHub</dt><dd>Proof-of-concept exploit publications</dd>
        <dt>ThreatFox</dt><dd>Abuse.ch threat intelligence IOC feed</dd>
        <dt>Security News</dt><dd>RSS feeds from security vendors and researchers</dd>
    </dl>
    <h3>Glossary</h3>
    <dl class="appendix">
        <dt>CVSS</dt><dd>Common Vulnerability Scoring System (0-10)</dd>
        <dt>EPSS</dt><dd>Exploit Prediction Scoring System (0-1 probability)</dd>
        <dt>KEV</dt><dd>Known Exploited Vulnerability (CISA catalog)</dd>
        <dt>IOC</dt><dd>Indicator of Compromise</dd>
        <dt>PoC</dt><dd>Proof of Concept exploit</dd>
        <dt>TLP:WHITE</dt><dd>Traffic Light Protocol — unlimited distribution</dd>
    </dl>
</div>"""


# ── Legacy wrappers and helpers ──


class tf_grid:
    """Placeholder for backward compatibility."""

    pass


def epss_section(data: WeeklyData) -> str:
    """Build EPSS top exploitability section (legacy wrapper)."""
    if not data.epss_movers:
        return ""
    charts = {"epss_hist": _epss_histogram(data.epss_movers)}
    return _build_epss_section(data, charts)


# Add CSS class for tf-grid (used by KEV section)
tf_grid_style = """
.tf-grid { display: flex; gap: 1.2rem; margin: 1rem 0; flex-wrap: wrap; }
.tf-stat { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1.2rem 1.8rem; text-align: center; }
.tf-num { display: block; font-size: 1.6rem; font-weight: 800; color: var(--accent); }
.tf-label { font-size: 0.75rem; color: var(--text-dim); margin-top: 0.2rem; }
"""
