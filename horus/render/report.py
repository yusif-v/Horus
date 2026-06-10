"""Render CVEs and PoCs (text or markdown).

Renderers return strings; the caller decides whether to print, save, or both.
"""

from collections import defaultdict
from datetime import datetime
from io import StringIO

from ..core.model import CVE, PoC

# ---------------------------------------------------------------------------
# Grouping helpers
# ---------------------------------------------------------------------------


def _primary_category(cve: CVE) -> str:
    for ap in cve.affected:
        if ap.category != "unknown":
            return ap.category
    return "unknown"


def _group_cves(cves: list[CVE]) -> dict[str, list[CVE]]:
    groups: dict[str, list[CVE]] = defaultdict(list)
    for cve in cves:
        groups[_primary_category(cve)].append(cve)
    for items in groups.values():
        items.sort(key=lambda c: c.cvss_score or 0, reverse=True)
    return dict(sorted(groups.items(), key=lambda kv: (kv[0] == "unknown", kv[0])))


def _standalone_pocs(pocs: list[PoC], cves: list[CVE]) -> list[PoC]:
    known = {c.id.upper() for c in cves}
    return [p for p in pocs if not any(ref.upper() in known for ref in p.cve_refs)]


def _poc_label(poc: PoC) -> str:
    """Return a display label for a PoC, including X/Twitter attribution."""
    if poc.source in ("twitter", "x"):
        return f"{poc.url} [tweet]"
    return poc.url


def _poc_detail(poc: PoC) -> str:
    """Return detail line for a standalone PoC."""
    parts = [f"{poc.stars or 0}", f"{poc.age_days or 0}d"]
    if poc.source in ("twitter", "x"):
        parts.append("tweet")
    label = f"({' '.join(parts)})"
    return label


# ---------------------------------------------------------------------------
# Plain text
# ---------------------------------------------------------------------------


def _render_text(cves: list[CVE], pocs: list[PoC], links: dict[str, list[PoC]]) -> str:
    out = StringIO()

    def w(s: str = "") -> None:
        out.write(s + "\n")

    today = datetime.now().strftime("%Y-%m-%d")
    w(f"=== Daily PoC Research Report - {today} ===")
    standalone = _standalone_pocs(pocs, cves)
    w()
    w("=" * 60)
    w(f"CVEs: {len(cves)} | Standalone PoCs: {len(standalone)}")
    w("=" * 60)

    if not cves and not standalone:
        w()
        w("No new findings today.")
        return out.getvalue()

    for category, group in _group_cves(cves).items():
        w(f"\n--- {category} ({len(group)} CVE{'s' if len(group) != 1 else ''}) ---")
        for cve in group:
            score = cve.cvss_score
            score_str = f" [CVSS {score} {cve.cvss_severity or ''}]" if score else ""
            kev_str = " [KEV]" if cve.kev else ""
            epss_str = f" [EPSS {cve.epss_score:.1%}]" if cve.epss_score is not None else ""
            w(f"\n  {cve.id}{score_str}{kev_str}{epss_str}")
            w(f"    {cve.description[:200]}")
            if cve.attack_tags:
                w(f"    tags: {', '.join(cve.attack_tags)}")
            for ap in cve.affected[:3]:
                ver = f" ({', '.join(ap.versions[:2])})" if ap.versions else ""
                w(f"    affects: {ap.vendor}/{ap.product}{ver}")
            for poc in links.get(cve.id.upper(), []):
                w(f"    PoC: {_poc_label(poc)} ({poc.stars or 0}* [{poc.source}])")

    if standalone:
        w(f"\n--- Standalone PoCs ({len(standalone)}) ---")
        for poc in sorted(standalone, key=lambda p: p.stars or 0, reverse=True):
            refs = f" (refs: {', '.join(poc.cve_refs)})" if poc.cve_refs else ""
            w(f"\n  {_poc_label(poc)} {_poc_detail(poc)}{refs}")
            if poc.description:
                w(f"    {poc.description[:200]}")

    return out.getvalue()


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------


def _render_markdown(cves: list[CVE], pocs: list[PoC], links: dict[str, list[PoC]]) -> str:
    out = StringIO()

    def w(s: str = "") -> None:
        out.write(s + "\n")

    today = datetime.now().strftime("%Y-%m-%d")
    standalone = _standalone_pocs(pocs, cves)
    w(f"# Daily PoC Research Report - {today}\n")
    w(f"**CVEs:** {len(cves)} **Standalone PoCs:** {len(standalone)}")

    if not cves and not standalone:
        w("\n_No new findings today._")
        return out.getvalue()

    for category, group in _group_cves(cves).items():
        w(f"\n## {category} ({len(group)})\n")
        for cve in group:
            score = cve.cvss_score
            score_str = f" **CVSS {score} {cve.cvss_severity or ''}**" if score else ""
            badges = []
            if cve.kev:
                badges.append("`KEV`")
            if cve.epss_score is not None:
                badges.append(f"`EPSS {cve.epss_score:.1%}`")
            badge_str = " ".join(badges)
            w(f"- **{cve.id}**{score_str} {badge_str}")
            w(f"  > {cve.description[:200]}")
            if cve.attack_tags:
                w(f"  tags: `{'`, `'.join(cve.attack_tags)}`")
            for ap in cve.affected[:3]:
                ver = f" ({', '.join(ap.versions[:2])})" if ap.versions else ""
                w(f"  affects: *{ap.vendor}/{ap.product}*{ver}")
            for poc in links.get(cve.id.upper(), []):
                src_tag = f" [{poc.source}]"
                if poc.source in ("twitter", "x"):
                    w(f"  PoC: [{poc.url}]({poc.url}) {poc.stars or 0}* [tweet{src_tag}]")
                else:
                    w(f"  PoC: [{poc.url}]({poc.url}) {poc.stars or 0}*{src_tag}")

    if standalone:
        w(f"\n## Standalone PoCs ({len(standalone)})\n")
        for poc in sorted(standalone, key=lambda p: p.stars or 0, reverse=True):
            refs = f" -- refs: {', '.join(poc.cve_refs)}" if poc.cve_refs else ""
            src_tag = " [tweet]" if poc.source in ("twitter", "x") else ""
            w(f"- [{poc.url}]({poc.url}) {poc.stars or 0}* {poc.age_days or 0}d{refs}{src_tag}")
            if poc.description:
                w(f"  > {poc.description[:200]}")

    return out.getvalue()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def render_report(
    cves: list[CVE],
    pocs: list[PoC],
    links: dict[str, list[PoC]],
    fmt: str = "text",
) -> str:
    if fmt == "md":
        return _render_markdown(cves, pocs, links)
    return _render_text(cves, pocs, links)
