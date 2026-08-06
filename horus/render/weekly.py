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
    """Render a self-contained HTML report with inline CSS."""
    total_cves = data.total_cves_this_week
    total_pocs = data.total_pocs_this_week

    # Build severity bars
    severity_html = ""
    if data.severity_breakdown:
        max_sev = max(data.severity_breakdown.values()) if data.severity_breakdown else 1
        severity_html = '<div class="severity-bars">'
        for sev, color in [
            ("CRITICAL", "#dc3545"),
            ("HIGH", "#fd7e14"),
            ("MEDIUM", "#ffc107"),
            ("LOW", "#28a745"),
        ]:
            count = data.severity_breakdown.get(sev, 0)
            pct = (count / max_sev * 100) if max_sev > 0 else 0
            severity_html += f"""
                <div class="sev-bar-row">
                    <span class="sev-label">{sev}</span>
                    <div class="sev-bar-bg"><div class="sev-bar" style="width:{pct:.0f}%;background:{color}"></div></div>
                    <span class="sev-count">{count}</span>
                </div>"""
        severity_html += "</div>"

    # Build top CVEs table
    cves_html = ""
    if data.top_cves:
        rows = ""
        for cve in data.top_cves[:10]:
            kev_badge = '<span class="badge kev">KEV</span>' if cve["kev"] else ""
            sev_class = (cve["cvss_severity"] or "N/A").lower()
            epss = f"{cve['epss_score']:.4f}" if cve["epss_score"] is not None else "N/A"
            rows += f"""<tr>
                <td><strong>{cve["id"]}</strong> {kev_badge}</td>
                <td>{cve["cvss_score"] or "N/A"}</td>
                <td><span class="sev-pill {sev_class}">{cve["cvss_severity"] or "N/A"}</span></td>
                <td>{epss}</td>
                <td>{cve["reputation_score"] or 0:.1f}</td>
                <td>{cve["poc_source_count"]}</td>
                <td class="desc-cell">{cve["description"][:100]}...</td>
            </tr>"""
        cves_html = f"""
        <h2>Top CVEs by Risk Score</h2>
        <table class="data-table">
            <thead><tr><th>CVE</th><th>CVSS</th><th>Severity</th><th>EPSS</th><th>Rep</th><th>PoCs</th><th>Description</th></tr></thead>
            <tbody>{rows}</tbody>
        </table>"""

    # Build KEV section
    kev_html = ""
    new_kevs = [k for k in data.kev_entries if k["is_new"]]
    overdue_kevs = [k for k in data.kev_entries if k["is_overdue"]]
    if new_kevs or overdue_kevs:
        kev_html = "<h2>CISA Known Exploited Vulnerabilities</h2>"
        if overdue_kevs:
            kev_html += f'<div class="alert alert-danger"><strong>OVERDUE:</strong> {len(overdue_kevs)} KEV entries past CISA remediation deadline</div>'
        if new_kevs:
            kev_html += f'<h3>New This Week ({len(new_kevs)})</h3><ul class="kev-list">'
            for kev in new_kevs[:5]:
                due = (
                    f" | <strong>Due: {kev['kev_due_date']}</strong>" if kev["kev_due_date"] else ""
                )
                kev_html += f'<li><strong>{kev["id"]}</strong> | CVSS {kev["cvss_score"] or "N/A"}{due}<br><span class="kev-desc">{kev["description"][:200]}</span></li>'
            kev_html += "</ul>"

    # Build vendor table
    vendor_html = ""
    if data.top_vendors:
        rows = ""
        for v in data.top_vendors[:10]:
            kev_str = (
                f' <span class="badge kev-sm">{v["kev_count"]} KEV</span>' if v["kev_count"] else ""
            )
            rows += f"<tr><td>{v['vendor']}</td><td>{v['cve_count']}</td><td>{v['avg_cvss']}</td><td>{kev_str}</td></tr>"
        vendor_html = f"""
        <h2>Most Targeted Vendors</h2>
        <table class="data-table">
            <thead><tr><th>Vendor</th><th>CVEs</th><th>Avg CVSS</th><th>KEVs</th></tr></thead>
            <tbody>{rows}</tbody>
        </table>"""

    # Build tags section
    tags_html = ""
    if data.top_tags:
        tags_html = '<h2>Attack Technique Distribution</h2><div class="tag-cloud">'
        for t in data.top_tags[:12]:
            tags_html += (
                f'<span class="tag-pill">{t["tag"]} <strong>{t["cve_count"]}</strong></span>'
            )
        tags_html += "</div>"

    # Build news section
    news_html = ""
    if data.news_highlights:
        news_html = '<h2>Security News Highlights</h2><div class="news-list">'
        for article in data.news_highlights[:8]:
            tier_colors = {1: "#dc3545", 2: "#fd7e14", 3: "#ffc107", 4: "#28a745", 5: "#6c757d"}
            tc = tier_colors.get(article["tier"], "#6c757d")
            news_html += f'''<div class="news-item">
                <span class="tier-badge" style="background:{tc}">{_tier_label(article["tier"])}</span>
                <a href="{article["url"]}">{article["title"]}</a>
                <span class="news-source">{article["source"]}</span>
                <p class="news-summary">{article["summary"][:200] if article["summary"] else ""}</p>
            </div>'''
        news_html += "</div>"

    # Build ThreatFox section
    threatfox_html = ""
    if data.threatfox_summary.get("total_iocs", 0) > 0:
        type_counts = data.threatfox_summary.get("type_counts", {})
        type_items = "".join(
            f"<li><strong>{k}:</strong> {v}</li>" for k, v in sorted(type_counts.items())
        )
        threat_types = data.threatfox_summary.get("top_threat_types", [])
        type_str = "".join(f"<li>{t['threat_type']} ({t['count']})</li>" for t in threat_types[:5])
        threatfox_html = f"""
        <h2>Threat Intelligence (ThreatFox)</h2>
        <div class="tf-grid">
            <div class="tf-stat"><span class="tf-num">{data.threatfox_summary["total_iocs"]}</span><span class="tf-label">Total IOCs</span></div>
            <div class="tf-stat"><span class="tf-num">{data.threatfox_summary["cves_with_iocs"]}</span><span class="tf-label">CVEs with IOCs</span></div>
        </div>
        <h3>IOC Types</h3><ul class="ioc-types">{type_items}</ul>
        {f'<h3>Top Threat Types</h3><ul class="ioc-types">{type_str}</ul>' if type_str else ""}"""

    # Build PoCs section
    pocs_html = ""
    if data.top_pocs:
        pocs_html = '<h2>Notable Exploit Publications</h2><div class="poc-list">'
        for poc in data.top_pocs[:8]:
            pocs_html += f'''<div class="poc-item">
                <a href="{poc["url"]}">{poc["url"][:70]}...</a>
                <span class="poc-meta">{poc["source"]} | {poc["stars"]} stars | {poc["exploit_type"] or "N/A"} | {poc["linked_cves"]} CVEs</span>
            </div>'''
        pocs_html += "</div>"

    # Build triage section
    triage_html = ""
    if data.triage_summary:
        total_t = sum(data.triage_summary.values())
        items = "".join(
            f"<li>{s.capitalize()}: <strong>{data.triage_summary.get(s, 0)}</strong></li>"
            for s in ["new", "acknowledged", "working", "done", "dismissed"]
        )
        triage_html = f'<h2>Triage Workflow</h2><p>Total triaged: <strong>{total_t}</strong></p><ul class="triage-list">{items}</ul>'

    # Build source health
    health_html = ""
    if data.source_health:
        rows = ""
        for sh in data.source_health:
            status_class = (
                "ok" if sh["status"] == "ok" else "error" if sh["status"] == "error" else "skipped"
            )
            err_tip = f' title="{sh["error"][:100]}"' if sh["error"] else ""
            rows += f'<tr><td>{sh["source"]}</td><td class="status-{status_class}"{err_tip}>{sh["status"]}</td><td>{sh["last_run"][:16]}</td><td>{sh["cves"]}</td><td>{sh["pocs"]}</td><td>{sh["consecutive_failures"]}</td></tr>'
        health_html = f"""
        <h2>Source Health</h2>
        <table class="data-table health-table">
            <thead><tr><th>Source</th><th>Status</th><th>Last Run</th><th>CVEs</th><th>PoCs</th><th>Fails</th></tr></thead>
            <tbody>{rows}</tbody>
        </table>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Weekly Threat Report — {data.period_start} to {data.period_end}</title>
<style>
:root {{
    --bg: #0d1117; --card: #161b22; --border: #30363d; --text: #c9d1d9;
    --text-dim: #8b949e; --accent: #58a6ff; --green: #3fb950; --orange: #f0883e;
    --red: #f85149; --yellow: #d29922; --purple: #bc8cff;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; padding: 2rem; }}
.container {{ max-width: 1000px; margin: 0 auto; }}
.header {{ text-align: center; padding: 2rem 0; border-bottom: 1px solid var(--border); margin-bottom: 2rem; }}
.header h1 {{ font-size: 1.8rem; color: var(--text); margin-bottom: 0.5rem; }}
.header .period {{ color: var(--accent); font-size: 1.1rem; }}
.header .generated {{ color: var(--text-dim); font-size: 0.9rem; margin-top: 0.5rem; }}
.kpi-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
.kpi-card {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1.2rem; text-align: center; }}
.kpi-num {{ font-size: 2rem; font-weight: 700; display: block; }}
.kpi-label {{ font-size: 0.8rem; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.5px; }}
.kpi-change {{ font-size: 0.75rem; margin-top: 0.3rem; }}
.up {{ color: var(--red); }} .down {{ color: var(--green); }} .neutral {{ color: var(--text-dim); }}
.critical {{ color: var(--red); }} .high {{ color: var(--orange); }}
h2 {{ color: var(--accent); margin: 2rem 0 1rem; padding-bottom: 0.5rem; border-bottom: 1px solid var(--border); }}
h3 {{ color: var(--text); margin: 1rem 0 0.5rem; font-size: 1rem; }}
.data-table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; font-size: 0.85rem; }}
.data-table th {{ background: var(--card); padding: 0.6rem 0.8rem; text-align: left; border-bottom: 2px solid var(--border); color: var(--text-dim); font-weight: 600; }}
.data-table td {{ padding: 0.5rem 0.8rem; border-bottom: 1px solid var(--border); }}
.data-table tr:hover {{ background: rgba(88,166,255,0.05); }}
.desc-cell {{ color: var(--text-dim); font-size: 0.8rem; }}
.badge {{ display: inline-block; padding: 0.15rem 0.4rem; border-radius: 4px; font-size: 0.7rem; font-weight: 600; }}
.badge.kev {{ background: rgba(248,81,73,0.2); color: var(--red); }}
.badge.kev-sm {{ background: rgba(248,81,73,0.15); color: var(--red); font-size: 0.65rem; }}
.sev-pill {{ padding: 0.15rem 0.5rem; border-radius: 12px; font-size: 0.7rem; font-weight: 600; }}
.sev-pill.critical {{ background: rgba(248,81,73,0.2); color: var(--red); }}
.sev-pill.high {{ background: rgba(240,136,62,0.2); color: var(--orange); }}
.sev-pill.medium {{ background: rgba(210,153,34,0.2); color: var(--yellow); }}
.sev-pill.low {{ background: rgba(63,185,80,0.2); color: var(--green); }}
.alert {{ padding: 0.8rem 1rem; border-radius: 6px; margin: 1rem 0; font-size: 0.9rem; }}
.alert-danger {{ background: rgba(248,81,73,0.1); border: 1px solid rgba(248,81,73,0.3); color: var(--red); }}
.severity-bars {{ margin: 1rem 0; }}
.sev-bar-row {{ display: flex; align-items: center; margin: 0.4rem 0; }}
.sev-label {{ width: 80px; font-size: 0.8rem; color: var(--text-dim); }}
.sev-bar-bg {{ flex: 1; height: 20px; background: var(--card); border-radius: 4px; overflow: hidden; }}
.sev-bar {{ height: 100%; border-radius: 4px; transition: width 0.3s; }}
.sev-count {{ width: 40px; text-align: right; font-weight: 600; font-size: 0.85rem; }}
.tag-cloud {{ display: flex; flex-wrap: wrap; gap: 0.5rem; margin: 1rem 0; }}
.tag-pill {{ background: var(--card); border: 1px solid var(--border); padding: 0.3rem 0.7rem; border-radius: 16px; font-size: 0.8rem; }}
.tag-pill strong {{ color: var(--accent); }}
.news-list {{ margin: 1rem 0; }}
.news-item {{ background: var(--card); border: 1px solid var(--border); border-radius: 6px; padding: 0.8rem 1rem; margin-bottom: 0.5rem; }}
.news-item a {{ color: var(--accent); text-decoration: none; font-weight: 500; }}
.news-item a:hover {{ text-decoration: underline; }}
.news-source {{ color: var(--text-dim); font-size: 0.8rem; margin-left: 0.5rem; }}
.news-summary {{ color: var(--text-dim); font-size: 0.8rem; margin-top: 0.3rem; }}
.tier-badge {{ display: inline-block; padding: 0.1rem 0.4rem; border-radius: 3px; font-size: 0.65rem; color: #fff; font-weight: 600; margin-right: 0.5rem; }}
.tf-grid {{ display: flex; gap: 1rem; margin: 1rem 0; }}
.tf-stat {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1.5rem; text-align: center; }}
.tf-num {{ display: block; font-size: 1.5rem; font-weight: 700; color: var(--accent); }}
.tf-label {{ font-size: 0.75rem; color: var(--text-dim); }}
.ioc-types {{ list-style: none; display: flex; flex-wrap: wrap; gap: 0.5rem; margin: 0.5rem 0; }}
.ioc-types li {{ background: var(--card); padding: 0.3rem 0.6rem; border-radius: 4px; font-size: 0.8rem; }}
.poc-list {{ margin: 1rem 0; }}
.poc-item {{ padding: 0.5rem 0; border-bottom: 1px solid var(--border); }}
.poc-item a {{ color: var(--accent); text-decoration: none; font-size: 0.85rem; }}
.poc-meta {{ display: block; color: var(--text-dim); font-size: 0.75rem; margin-top: 0.2rem; }}
.triage-list {{ list-style: none; display: flex; gap: 1rem; flex-wrap: wrap; margin: 0.5rem 0; }}
.triage-list li {{ background: var(--card); padding: 0.4rem 0.8rem; border-radius: 6px; font-size: 0.85rem; }}
.kev-list {{ list-style: none; margin: 0.5rem 0; }}
.kev-list li {{ padding: 0.5rem 0; border-bottom: 1px solid var(--border); }}
.kev-desc {{ color: var(--text-dim); font-size: 0.85rem; }}
.status-ok {{ color: var(--green); }} .status-error {{ color: var(--red); }} .status-skipped {{ color: var(--text-dim); }}
.footer {{ text-align: center; padding: 2rem 0; color: var(--text-dim); font-size: 0.8rem; border-top: 1px solid var(--border); margin-top: 2rem; }}
ul {{ padding-left: 1.2rem; }}
li {{ margin: 0.3rem 0; }}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>Weekly Threat Intelligence Report</h1>
        <div class="period">{data.period_start} to {data.period_end}</div>
        <div class="generated">Generated: {data.generated_at}</div>
    </div>

    <h2>Executive Summary</h2>
    <div class="kpi-grid">
        <div class="kpi-card">
            <span class="kpi-num{" critical" if total_cves > 50 else ""}">{total_cves}</span>
            <span class="kpi-label">New CVEs</span>
            <span class="kpi-change {"up" if data.total_cves_this_week > data.total_cves_last_week else "down" if data.total_cves_this_week < data.total_cves_last_week else "neutral"}">{_pct_change(data.total_cves_this_week, data.total_cves_last_week)} WoW</span>
        </div>
        <div class="kpi-card">
            <span class="kpi-num">{total_pocs}</span>
            <span class="kpi-label">New PoCs</span>
            <span class="kpi-change {"up" if data.total_pocs_this_week > data.total_pocs_last_week else "down" if data.total_pocs_this_week < data.total_pocs_last_week else "neutral"}">{_pct_change(data.total_pocs_this_week, data.total_pocs_last_week)} WoW</span>
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
    </div>

    {severity_html}
    {kev_html}
    {cves_html}
    {threatfox_html}
    {vendor_html}
    {tags_html}
    {epss_section(data)}
    {news_html}
    {pocs_html}
    {triage_html}
    {health_html}

    <div class="footer">
        <p>Generated by Horus — {data.generated_at}</p>
    </div>
</div>
</body>
</html>"""


def epss_section(data: WeeklyData) -> str:
    """Build EPSS top exploitability section."""
    if not data.epss_movers:
        return ""
    rows = ""
    for m in data.epss_movers[:8]:
        kev_badge = '<span class="badge kev">KEV</span>' if m["kev"] else ""
        rows += f"""<tr>
            <td>{m["id"]} {kev_badge}</td>
            <td>{m["cvss_score"] or "N/A"}</td>
            <td><strong>{m["epss_score"]:.4f}</strong></td>
            <td>{m["reputation_score"] or 0:.1f}</td>
            <td class="desc-cell">{m["description"][:100]}...</td>
        </tr>"""
    return f"""
    <h2>Highest Exploitability (EPSS)</h2>
    <table class="data-table">
        <thead><tr><th>CVE</th><th>CVSS</th><th>EPSS</th><th>Rep</th><th>Description</th></tr></thead>
        <tbody>{rows}</tbody>
    </table>"""
