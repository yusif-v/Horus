"""Pure SVG chart generators for Horus weekly threat reports.

Generates self-contained SVG charts with no external dependencies:
- Severity donut chart
- CVE trend line chart
- Vendor horizontal bar chart
- MITRE ATT&CK technique heatmap
"""

from __future__ import annotations

import math
from collections.abc import Sequence


def severity_donut(
    critical: int = 0,
    high: int = 0,
    medium: int = 0,
    low: int = 0,
    size: int = 220,
) -> str:
    """Generate an SVG donut chart showing severity distribution.

    Args:
        critical: Count of critical CVEs.
        high: Count of high CVEs.
        medium: Count of medium CVEs.
        low: Count of low CVEs.
        size: SVG width/height in pixels.

    Returns:
        SVG markup string.
    """
    segments = [
        ("Critical", critical, "#dc3545"),
        ("High", high, "#fd7e14"),
        ("Medium", medium, "#ffc107"),
        ("Low", low, "#28a745"),
    ]
    total = sum(s[1] for s in segments)
    if total == 0:
        return f'<svg viewBox="0 0 {size} {size}" width="{size}" height="{size}"><circle cx="{size // 2}" cy="{size // 2}" r="{size // 2 - 10}" fill="none" stroke="#30363d" stroke-width="20"/><text x="{size // 2}" y="{size // 2}" text-anchor="middle" fill="#8b949e" font-size="14">No data</text></svg>'

    cx, cy = size // 2, size // 2
    outer_r = size // 2 - 10
    inner_r = int(outer_r * 0.62)
    gap = 2.0  # gap in degrees

    # Calculate arc segments
    arcs: list[tuple[float, float, str, str]] = []  # start_angle, end_angle, color, label
    start = -90  # start at top
    for label, count, color in segments:
        if count == 0:
            continue
        sweep = (count / total) * 360 - gap
        if sweep < 0:
            sweep = 0
        arcs.append((start, start + sweep, color, label))
        start += (count / total) * 360

    paths = []
    for a0, a1, color, _ in arcs:
        x0 = cx + outer_r * _cos(_rad(a0))
        y0 = cy + outer_r * _sin(_rad(a0))
        x1 = cx + outer_r * _cos(_rad(a1))
        y1 = cy + outer_r * _sin(_rad(a1))
        xi0 = cx + inner_r * _cos(_rad(a1))
        yi0 = cy + inner_r * _sin(_rad(a1))
        xi1 = cx + inner_r * _cos(_rad(a0))
        yi1 = cy + inner_r * _sin(_rad(a0))
        large = 1 if (a1 - a0) > 180 else 0
        d = (
            f"M {x0:.1f} {y0:.1f} "
            f"A {outer_r} {outer_r} 0 {large} 1 {x1:.1f} {y1:.1f} "
            f"L {xi0:.1f} {yi0:.1f} "
            f"A {inner_r} {inner_r} 0 {large} 0 {xi1:.1f} {yi1:.1f} Z"
        )
        paths.append(
            f'<path d="{d}" fill="{color}" stroke="#0d1117" stroke-width="1.5"><title>{_label_for_arc(a0, a1, segments, total)}</title></path>'
        )

    # Build legend
    legend_items = []
    for label, count, color in segments:
        pct = (count / total * 100) if total > 0 else 0
        legend_items.append(
            f'<div style="display:flex;align-items:center;gap:6px;margin:2px 8px;">'
            f'<span style="width:10px;height:10px;border-radius:2px;background:{color};display:inline-block;"></span>'
            f'<span style="color:#8b949e;font-size:12px;">{label}: {count} ({pct:.0f}%)</span></div>'
        )

    return f'''<div style="text-align:center;">
<svg viewBox="0 0 {size} {size}" width="{size}" height="{size}" style="max-width:100%;">
{"".join(paths)}
<text x="{cx}" y="{cy - 6}" text-anchor="middle" fill="#c9d1d9" font-size="22" font-weight="700">{total}</text>
<text x="{cx}" y="{cy + 14}" text-anchor="middle" fill="#8b949e" font-size="11">Total CVEs</text>
</svg>
<div style="display:flex;flex-wrap:wrap;justify-content:center;margin-top:8px;">
{"".join(legend_items)}
</div>
</div>'''


def cve_trend_line(
    data: Sequence[dict],
    width: int = 600,
    height: int = 220,
) -> str:
    """Generate an SVG line chart showing CVE intake over weeks.

    Args:
        data: List of dicts with 'week' and 'count' keys.
        width: SVG width in pixels.
        height: SVG height in pixels.

    Returns:
        SVG markup string.
    """
    if not data:
        return f'<svg viewBox="0 0 {width} {height}" width="{width}" height="{height}"><text x="{width // 2}" y="{height // 2}" text-anchor="middle" fill="#8b949e" font-size="14">No trend data</text></svg>'

    padding = {"top": 20, "right": 20, "bottom": 50, "left": 50}
    chart_w = width - padding["left"] - padding["right"]
    chart_h = height - padding["top"] - padding["bottom"]

    counts = [d["count"] for d in data]
    max_count = max(counts) if counts else 1
    if max_count == 0:
        max_count = 1
    min_count = 0

    n = len(data)
    points: list[tuple[float, float]] = []
    for i, count in enumerate(counts):
        x = padding["left"] + (i / max(n - 1, 1)) * chart_w
        y = padding["top"] + chart_h - ((count - min_count) / (max_count - min_count)) * chart_h
        points.append((x, y))

    # Gradient fill area
    area_path = f"M {points[0][0]:.1f} {padding['top'] + chart_h:.1f} "
    for x, y in points:
        area_path += f"L {x:.1f} {y:.1f} "
    area_path += f"L {points[-1][0]:.1f} {padding['top'] + chart_h:.1f} Z"

    # Line path
    line_path = ""
    for i, (x, y) in enumerate(points):
        if i == 0:
            line_path += f"M {x:.1f} {y:.1f} "
        else:
            line_path += f"L {x:.1f} {y:.1f} "

    # Grid lines
    grid_lines = []
    for i in range(5):
        y_val = padding["top"] + (i / 4) * chart_h
        val = max_count - (i / 4) * (max_count - min_count)
        grid_lines.append(
            f'<line x1="{padding["left"]}" y1="{y_val:.1f}" x2="{padding["left"] + chart_w}" y2="{y_val:.1f}" stroke="#30363d" stroke-width="1" stroke-dasharray="3,3"/>'
            f'<text x="{padding["left"] - 8}" y="{y_val + 4}" text-anchor="end" fill="#8b949e" font-size="10">{val:.0f}</text>'
        )

    # X-axis labels
    x_labels = []
    for i, d in enumerate(data):
        x = padding["left"] + (i / max(n - 1, 1)) * chart_w
        y_pos = height - padding["bottom"] + 18
        week_label = d["week"].replace("2026-", "").replace("W", "Wk ")
        x_labels.append(
            f'<text x="{x:.1f}" y="{y_pos}" text-anchor="middle" fill="#8b949e" font-size="10" '
            f'transform="rotate(-30 {x:.1f} {y_pos})">{week_label}</text>'
        )

    # Data point markers
    markers = []
    for x, y in points:
        markers.append(
            f'<circle cx="{x:.1f}" cy="{y:.1f}" r="4" fill="#58a6ff" stroke="#0d1117" stroke-width="2"/>'
        )

    return f'''<svg viewBox="0 0 {width} {height}" width="{width}" height="{height}" style="max-width:100%;">
<defs>
<linearGradient id="trendGrad" x1="0" y1="0" x2="0" y2="1">
<stop offset="0%" stop-color="#58a6ff" stop-opacity="0.3"/>
<stop offset="100%" stop-color="#58a6ff" stop-opacity="0.02"/>
</linearGradient>
</defs>
{"".join(grid_lines)}
{"".join(x_labels)}
<path d="{area_path}" fill="url(#trendGrad)"/>
<path d="{line_path}" fill="none" stroke="#58a6ff" stroke-width="2.5" stroke-linejoin="round" stroke-linecap="round"/>
{"".join(markers)}
</svg>'''


def vendor_bar_chart(
    data: Sequence[dict],
    width: int = 600,
    height: int = 320,
    max_bars: int = 10,
) -> str:
    """Generate an SVG horizontal bar chart for top vendors by CVE count.

    Args:
        data: List of dicts with 'vendor' and 'cve_count' keys.
        width: SVG width in pixels.
        height: SVG height in pixels.
        max_bars: Maximum number of bars to show.

    Returns:
        SVG markup string.
    """
    if not data:
        return f'<svg viewBox="0 0 {width} {height}" width="{width}" height="{height}"><text x="{width // 2}" y="{height // 2}" text-anchor="middle" fill="#8b949e" font-size="14">No vendor data</text></svg>'

    display_data = list(data)[:max_bars]
    max_count = max(d["cve_count"] for d in display_data) if display_data else 1

    padding = {"top": 10, "right": 50, "bottom": 10, "left": 100}
    chart_w = width - padding["left"] - padding["right"]
    chart_h = height - padding["top"] - padding["bottom"]

    bar_height = min(24, chart_h / len(display_data) - 4)
    gap = (chart_h - bar_height * len(display_data)) / max(len(display_data) + 1, 1)

    bars = []
    for i, d in enumerate(display_data):
        y = padding["top"] + gap + i * (bar_height + gap)
        bar_w = (d["cve_count"] / max_count) * chart_w if max_count > 0 else 0
        intensity = 0.4 + 0.6 * (d["cve_count"] / max_count)
        bars.append(
            f'<text x="{padding["left"] - 8}" y="{y + bar_height / 2 + 4}" text-anchor="end" fill="#c9d1d9" font-size="11">{_escape_xml(d["vendor"][:16])}</text>'
            f'<rect x="{padding["left"]}" y="{y}" width="{bar_w:.1f}" height="{bar_height}" rx="3" fill="#58a6ff" opacity="{intensity:.2f}"/>'
            f'<text x="{padding["left"] + bar_w + 6}" y="{y + bar_height / 2 + 4}" fill="#c9d1d9" font-size="11" font-weight="600">{d["cve_count"]}</text>'
        )

    actual_height = int(padding["top"] + padding["bottom"] + len(display_data) * (bar_height + gap))
    return f'<svg viewBox="0 0 {width} {actual_height}" width="{width}" height="{actual_height}" style="max-width:100%;">{"".join(bars)}</svg>'


def mitre_heatmap(
    data: Sequence[dict],
    width: int = 600,
    height: int = 320,
    max_cells: int = 12,
) -> str:
    """Generate an SVG heatmap grid for MITRE ATT&CK techniques.

    Args:
        data: List of dicts with 'tag' and 'cve_count' keys.
        width: SVG width in pixels.
        height: SVG height in pixels.
        max_cells: Maximum number of technique cells.

    Returns:
        SVG markup string.
    """
    if not data:
        return f'<svg viewBox="0 0 {width} {height}" width="{width}" height="{height}"><text x="{width // 2}" y="{height // 2}" text-anchor="middle" fill="#8b949e" font-size="14">No technique data</text></svg>'

    display_data = list(data)[:max_cells]
    max_count = max(d["cve_count"] for d in display_data) if display_data else 1

    cols = 3
    rows = (len(display_data) + cols - 1) // cols
    cell_w = (width - 20) // cols
    cell_h = min(60, (height - 20) // max(rows, 1))
    gap = 6

    cells = []
    for i, d in enumerate(display_data):
        col = i % cols
        row = i // cols
        x = 10 + col * cell_w
        y = 10 + row * cell_h
        intensity = d["cve_count"] / max_count if max_count > 0 else 0
        # Color from dark blue to bright red based on intensity
        r = int(88 + (248 - 88) * intensity)
        g = int(166 + (81 - 166) * intensity)
        b = int(255 + (73 - 255) * intensity)
        bg_opacity = 0.15 + 0.55 * intensity
        cells.append(
            f'<rect x="{x + gap / 2}" y="{y + gap / 2}" width="{cell_w - gap}" height="{cell_h - gap}" rx="6" '
            f'fill="rgb({r},{g},{b})" fill-opacity="{bg_opacity:.2f}" stroke="rgb({r},{g},{b})" stroke-opacity="0.4" stroke-width="1"/>'
            f'<text x="{x + cell_w / 2}" y="{y + cell_h / 2 - 6}" text-anchor="middle" fill="#c9d1d9" font-size="11" font-weight="600">{_escape_xml(d["tag"][:18])}</text>'
            f'<text x="{x + cell_w / 2}" y="{y + cell_h / 2 + 12}" text-anchor="middle" fill="#8b949e" font-size="14" font-weight="700">{d["cve_count"]}</text>'
        )

    actual_height = int(20 + rows * cell_h)
    return f'<svg viewBox="0 0 {width} {actual_height}" width="{width}" height="{actual_height}" style="max-width:100%;">{"".join(cells)}</svg>'


def epss_bar(cve_id: str, epss: float, max_width: int = 120) -> str:
    """Generate a mini horizontal bar for EPSS score visualization.

    Args:
        cve_id: CVE identifier (for title).
        epss: EPSS score (0.0 to 1.0).
        max_width: Maximum bar width in pixels.

    Returns:
        SVG markup string.
    """
    pct = epss * 100
    bar_w = epss * max_width
    if pct >= 70:
        color = "#dc3545"
    elif pct >= 40:
        color = "#fd7e14"
    elif pct >= 15:
        color = "#ffc107"
    else:
        color = "#28a745"

    return (
        f'<svg width="{max_width + 40}" height="16" style="vertical-align:middle;">'
        f'<rect x="0" y="4" width="{max_width}" height="8" rx="4" fill="#30363d"/>'
        f'<rect x="0" y="4" width="{bar_w:.1f}" height="8" rx="4" fill="{color}"/>'
        f'<text x="{max_width + 6}" y="12" fill="#c9d1d9" font-size="10" font-weight="600">{pct:.0f}%</text>'
        f"</svg>"
    )


def cvss_badge(score: float | None, severity: str | None) -> str:
    """Generate a CVSS score badge with color coding.

    Args:
        score: CVSS score (0-10).
        severity: Severity label.

    Returns:
        HTML span element with badge styling.
    """
    if score is None:
        return '<span class="badge cvss-badge" style="background:#30363d;color:#8b949e;">N/A</span>'

    if score >= 9.0:
        bg = "#dc3545"
    elif score >= 7.0:
        bg = "#fd7e14"
    elif score >= 4.0:
        bg = "#ffc107"
    else:
        bg = "#28a745"

    return f'<span class="badge cvss-badge" style="background:{bg};color:#fff;font-weight:700;">{score:.1f}</span>'


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _rad(deg: float) -> float:
    return math.radians(deg)


def _cos(angle: float) -> float:
    return math.cos(angle)


def _sin(angle: float) -> float:
    return math.sin(angle)


def _label_for_arc(a0: float, a1: float, segments: list, total: int) -> str:
    """Determine which segment an arc belongs to based on midpoint angle."""
    mid = (a0 + a1) / 2
    # Convert back to fraction
    frac = (mid + 90) / 360
    cumulative = 0.0
    for label, count, _ in segments:
        cumulative += count / total
        if frac <= cumulative:
            return f"{label}: {count}"
    return ""


def _escape_xml(text: str) -> str:
    """Escape special XML characters."""
    return (
        text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
    )
