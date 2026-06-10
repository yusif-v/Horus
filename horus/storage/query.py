"""CVE query and enrichment report system.

Look up any CVE from the local database and produce a structured report
with all enrichment data: PoCs, EPSS, KEV, attack tags, affected products,
related CVEs, and exploitability score.

Usage:
    python3 -m horus --query CVE-2026-11413
    python3 -m horus --query CVE-2026-11413 --format md
    python3 -m horus --query 2026-11413        # CVE- prefix optional
    python3 -m horus --query log4j              # keyword search
"""

from __future__ import annotations

import sqlite3
import sys

from horus.config import STATE_DIR

DB_PATH = STATE_DIR / "horus.db"


# ─── Data fetching ──────────────────────────────────────────────────────────


def _fetch_cve(conn: sqlite3.Connection, cve_id: str) -> dict | None:
    """Fetch a CVE record with all enrichment data."""
    row = conn.execute("SELECT * FROM cve WHERE id = ?", (cve_id.upper(),)).fetchone()
    if not row:
        return None
    return dict(row)


def _fetch_cve_attack_tags(conn: sqlite3.Connection, cve_id: str) -> list[str]:
    return [
        r[0]
        for r in conn.execute("SELECT tag FROM cve_attack_tag WHERE cve_id = ?", (cve_id.upper(),))
    ]


def _fetch_cve_cwes(conn: sqlite3.Connection, cve_id: str) -> list[str]:
    return [
        r[0] for r in conn.execute("SELECT cwe_id FROM cve_cwe WHERE cve_id = ?", (cve_id.upper(),))
    ]


def _fetch_cve_products(conn: sqlite3.Connection, cve_id: str) -> list[dict]:
    return [
        {"vendor": r[0], "product": r[1], "versions": r[2], "category": r[3]}
        for r in conn.execute(
            """
            SELECT p.vendor, p.product, cp.versions, p.category
            FROM cve_product cp
            JOIN product p ON p.id = cp.product_id
            WHERE cp.cve_id = ?
        """,
            (cve_id.upper(),),
        )
    ]


def _fetch_cve_sources(conn: sqlite3.Connection, cve_id: str) -> list[str]:
    return [
        r[0]
        for r in conn.execute("SELECT source FROM cve_source WHERE cve_id = ?", (cve_id.upper(),))
    ]


def _fetch_linked_pocs(conn: sqlite3.Connection, cve_id: str) -> list[dict]:
    """Fetch PoCs directly linked to this CVE via poc_cve."""
    return [
        dict(r)
        for r in conn.execute(
            """
            SELECT p.url, p.source, p.stars, p.age_days, p.description
            FROM poc_cve pc
            JOIN poc p ON p.url = pc.poc_url
            WHERE pc.cve_id = ?
            ORDER BY p.stars DESC NULLS LAST
        """,
            (cve_id.upper(),),
        )
    ]


def _fetch_related_pocs(conn: sqlite3.Connection, cve_id: str) -> list[dict]:
    """Fetch PoCs that mention this CVE in their description but aren't formally linked."""
    cve_short = cve_id.upper().replace("CVE-", "")
    return [
        dict(r)
        for r in conn.execute(
            """
            SELECT url, source, stars, age_days, description
            FROM poc
            WHERE (description LIKE ? OR url LIKE ?)
              AND url NOT IN (SELECT poc_url FROM poc_cve WHERE cve_id = ?)
            ORDER BY stars DESC NULLS LAST
        """,
            (f"%{cve_id.upper()}%", f"%{cve_short}%", cve_id.upper()),
        )
    ]


def _fetch_related_cves(conn: sqlite3.Connection, cve_id: str) -> list[dict]:
    """Find related CVEs: same attack tags, same products, or overlapping PoCs."""
    cve_id_upper = cve_id.upper()

    # Get this CVE's tags and products
    tags = _fetch_cve_attack_tags(conn, cve_id_upper)
    products = _fetch_cve_products(conn, cve_id_upper)

    related: dict[str, dict] = {}

    # Same attack tags
    if tags:
        placeholders = ",".join("?" * len(tags))
        for r in conn.execute(
            f"""
            SELECT DISTINCT c.id, c.cvss_score, c.cvss_severity, c.description
            FROM cve c
            JOIN cve_attack_tag cat ON cat.cve_id = c.id
            WHERE cat.tag IN ({placeholders}) AND c.id != ?
            ORDER BY c.cvss_score DESC
            LIMIT 10
        """,
            (*tags, cve_id_upper),
        ):
            rid = r[0]
            if rid not in related:
                related[rid] = {
                    "id": rid,
                    "cvss_score": r[1],
                    "cvss_severity": r[2],
                    "description": r[3][:100] if r[3] else "",
                    "relation": "same_attack_tag",
                }

    # Same products
    for prod in products:
        for r in conn.execute(
            """
            SELECT DISTINCT c.id, c.cvss_score, c.cvss_severity, c.description
            FROM cve c
            JOIN cve_product cp ON cp.cve_id = c.id
            JOIN product p ON p.id = cp.product_id
            WHERE p.vendor = ? AND p.product = ? AND c.id != ?
            ORDER BY c.cvss_score DESC
            LIMIT 5
        """,
            (prod["vendor"], prod["product"], cve_id_upper),
        ):
            rid = r[0]
            if rid not in related:
                related[rid] = {
                    "id": rid,
                    "cvss_score": r[1],
                    "cvss_severity": r[2],
                    "description": r[3][:100] if r[3] else "",
                    "relation": "same_product",
                }

    return list(related.values())


def _search_cves_by_keyword(conn: sqlite3.Connection, keyword: str) -> list[dict]:
    """Search CVEs by keyword in description or ID."""
    pattern = f"%{keyword}%"
    return [
        {
            "id": r[0],
            "cvss_score": r[1],
            "cvss_severity": r[2],
            "description": r[3][:150] if r[3] else "",
            "epss_score": r[4],
            "kev": r[5],
        }
        for r in conn.execute(
            """
            SELECT id, cvss_score, cvss_severity, description, epss_score, kev
            FROM cve
            WHERE id LIKE ? OR description LIKE ?
            ORDER BY cvss_score DESC NULLS LAST
            LIMIT 20
        """,
            (pattern, pattern),
        )
    ]


# ─── Report rendering ───────────────────────────────────────────────────────


def _render_text(data: dict) -> str:
    """Render a CVE enrichment report as plain text."""
    lines: list[str] = []
    cve = data["cve"]

    lines.append("=" * 60)
    lines.append(f"  CVE ENRICHMENT REPORT: {cve['id']}")
    lines.append("=" * 60)
    lines.append("")

    # Basic info
    score = cve.get("cvss_score")
    severity = cve.get("cvss_severity", "")
    lines.append(f"  CVSS:     {score} {severity}" if score else "  CVSS:     N/A")
    lines.append(
        f"  EPSS:     {cve['epss_score']:.4f} ({cve['epss_score'] * 100:.2f}%)"
        if cve.get("epss_score") is not None
        else "  EPSS:     N/A"
    )
    lines.append(f"  KEV:      {'YES — CISA Known Exploited' if cve.get('kev') else 'No'}")
    expl = cve.get("reputation_score")
    lines.append(f"  Reputation:  {expl:.1f}/10" if expl is not None else "  Reputation:  N/A")
    lines.append(f"  Sources:  {', '.join(data['sources']) if data['sources'] else 'N/A'}")
    published = cve.get("published_at", "")
    lines.append(f"  Published: {published[:10] if published else 'N/A'}")
    lines.append("")

    # Description
    desc = cve.get("description", "")
    if desc:
        lines.append("  Description:")
        # Word-wrap description
        words = desc.split()
        current = "    "
        for word in words:
            if len(current) + len(word) + 1 > 64:
                lines.append(current)
                current = "    " + word
            else:
                current += " " + word if current.strip() else "    " + word
        if current.strip():
            lines.append(current)
        lines.append("")

    # Attack tags
    if data["attack_tags"]:
        lines.append(f"  Attack tags: {', '.join(data['attack_tags'])}")
        lines.append("")

    # CWEs
    if data["cwes"]:
        lines.append(f"  CWEs: {', '.join(data['cwes'])}")
        lines.append("")

    # Affected products
    if data["products"]:
        lines.append("  Affected products:")
        for p in data["products"]:
            ver = f" ({', '.join(p['versions'].split('; '))})" if p.get("versions") else ""
            lines.append(f"    {p['vendor']}/{p['product']}{ver} [{p['category']}]")
        lines.append("")

    # Linked PoCs (direct links)
    if data["linked_pocs"]:
        lines.append(f"  Exploits / PoCs ({len(data['linked_pocs'])}):")
        for poc in data["linked_pocs"]:
            stars = f"★{poc['stars']}" if poc.get("stars") else ""
            age = f"{poc['age_days']}d" if poc.get("age_days") is not None else ""
            src = f"[{poc['source']}]" if poc.get("source") else ""
            lines.append(f"    {poc['url']} {stars} {age} {src}")
            if poc.get("description"):
                lines.append(f"      {poc['description'][:120]}")
        lines.append("")

    # Related PoCs (mentioned in description)
    if data["related_pocs"]:
        lines.append(f"  Related PoCs (mentioned) ({len(data['related_pocs'])}):")
        for poc in data["related_pocs"][:5]:
            stars = f"★{poc['stars']}" if poc.get("stars") else ""
            src = f"[{poc['source']}]" if poc.get("source") else ""
            lines.append(f"    {poc['url']} {stars} {src}")
        lines.append("")

    # Related CVEs
    if data["related_cves"]:
        lines.append(f"  Related CVEs ({len(data['related_cves'])}):")
        for rc in data["related_cves"][:10]:
            score = f"CVSS {rc['cvss_score']}" if rc.get("cvss_score") else "no CVSS"
            rel = rc.get("relation", "").replace("_", " ")
            lines.append(f"    {rc['id']} [{score}] ({rel})")
            if rc.get("description"):
                lines.append(f"      {rc['description'][:100]}")
        lines.append("")

    lines.append("=" * 60)
    return "\n".join(lines)


def _render_markdown(data: dict) -> str:
    """Render a CVE enrichment report as markdown."""
    lines: list[str] = []
    cve = data["cve"]

    lines.append(f"# {cve['id']} — Enrichment Report")
    lines.append("")

    # Score badges
    score = cve.get("cvss_score")
    severity = cve.get("cvss_severity", "")
    badges = []
    if score:
        sev_color = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(
            severity, "⚪"
        )
        badges.append(f"{sev_color} **CVSS {score} {severity}**")
    if cve.get("kev"):
        badges.append("🔒 **CISA KEV**")
    if cve.get("epss_score") is not None:
        badges.append(f"📊 EPSS `{cve['epss_score']:.4f}` ({cve['epss_score'] * 100:.2f}%)")
    expl = cve.get("reputation_score")
    if expl is not None:
        badges.append(f"🏆 Reputation `{expl:.1f}/10`")

    if badges:
        lines.append(" | ".join(badges))
        lines.append("")

    # Meta
    lines.append(f"- **Sources:** {', '.join(data['sources']) if data['sources'] else 'N/A'}")
    published = cve.get("published_at", "")
    lines.append(f"- **Published:** {published[:10] if published else 'N/A'}")
    lines.append(f"- **First seen:** {cve.get('first_seen', 'N/A')[:10]}")
    lines.append(f"- **Last seen:** {cve.get('last_seen', 'N/A')[:10]}")
    lines.append("")

    # Description
    desc = cve.get("description", "")
    if desc:
        lines.append("## Description")
        lines.append("")
        lines.append(desc)
        lines.append("")

    # Attack tags + CWEs
    if data["attack_tags"]:
        lines.append(f"**Attack tags:** `{'` `'.join(data['attack_tags'])}`")
    if data["cwes"]:
        lines.append(f"**CWEs:** `{'` `'.join(data['cwes'])}`")
    if data["attack_tags"] or data["cwes"]:
        lines.append("")

    # Affected products
    if data["products"]:
        lines.append("## Affected Products")
        lines.append("")
        lines.append("| Vendor | Product | Versions | Category |")
        lines.append("|--------|---------|----------|----------|")
        for p in data["products"]:
            ver = p.get("versions", "") or "—"
            lines.append(f"| {p['vendor']} | {p['product']} | {ver} | {p['category']} |")
        lines.append("")

    # Linked PoCs
    if data["linked_pocs"]:
        lines.append(f"## Exploits / PoCs ({len(data['linked_pocs'])})")
        lines.append("")
        for poc in data["linked_pocs"]:
            stars = f" ★{poc['stars']}" if poc.get("stars") else ""
            age = f" ({poc['age_days']}d)" if poc.get("age_days") is not None else ""
            src = f" `{poc['source']}`" if poc.get("source") else ""
            lines.append(f"- [{poc['url']}]({poc['url']}){stars}{age}{src}")
            if poc.get("description"):
                lines.append(f"  > {poc['description'][:150]}")
        lines.append("")

    # Related PoCs
    if data["related_pocs"]:
        lines.append(f"## Related PoCs — mentioned ({len(data['related_pocs'])})")
        lines.append("")
        for poc in data["related_pocs"][:5]:
            stars = f" ★{poc['stars']}" if poc.get("stars") else ""
            src = f" `{poc['source']}`" if poc.get("source") else ""
            lines.append(f"- [{poc['url']}]({poc['url']}){stars}{src}")
        lines.append("")

    # Related CVEs
    if data["related_cves"]:
        lines.append(f"## Related CVEs ({len(data['related_cves'])})")
        lines.append("")
        lines.append("| CVE | CVSS | Relation | Description |")
        lines.append("|-----|------|----------|-------------|")
        for rc in data["related_cves"][:10]:
            score = (
                f"{rc['cvss_score']} {rc.get('cvss_severity', '')}"
                if rc.get("cvss_score")
                else "N/A"
            )
            rel = rc.get("relation", "").replace("_", " ")
            desc = (rc.get("description") or "")[:80]
            lines.append(f"| [{rc['id']}](#) | {score} | {rel} | {desc} |")
        lines.append("")

    return "\n".join(lines)


# ─── Main query function ────────────────────────────────────────────────────


def query_cve(cve_id: str, fmt: str = "text") -> str:
    """Look up a CVE and return a formatted enrichment report."""
    cve_id = cve_id.upper()
    if not cve_id.startswith("CVE-"):
        # Try to auto-prepend if it looks like a CVE number
        import re

        if re.match(r"^\d{4}-\d{4,}$", cve_id):
            cve_id = f"CVE-{cve_id}"

    if not DB_PATH.exists():
        return f"Error: database not found at {DB_PATH}"

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    try:
        cve = _fetch_cve(conn, cve_id)
        if not cve:
            # Try keyword search
            results = _search_cves_by_keyword(conn, cve_id)
            if results:
                lines = [f"CVE '{cve_id}' not found. Did you mean one of these?", ""]
                for r in results[:10]:
                    kev = " [KEV]" if r.get("kev") else ""
                    epss = f" EPSS={r['epss_score']:.4f}" if r.get("epss_score") is not None else ""
                    lines.append(
                        f"  {r['id']} [CVSS {r.get('cvss_score', '?')} {r.get('cvss_severity', '')}]{kev}{epss}"
                    )
                    if r.get("description"):
                        lines.append(f"    {r['description'][:100]}")
                return "\n".join(lines)
            return f"CVE '{cve_id}' not found in database."

        data = {
            "cve": cve,
            "attack_tags": _fetch_cve_attack_tags(conn, cve_id),
            "cwes": _fetch_cve_cwes(conn, cve_id),
            "products": _fetch_cve_products(conn, cve_id),
            "sources": _fetch_cve_sources(conn, cve_id),
            "linked_pocs": _fetch_linked_pocs(conn, cve_id),
            "related_pocs": _fetch_related_pocs(conn, cve_id),
            "related_cves": _fetch_related_cves(conn, cve_id),
        }

        if fmt == "md":
            return _render_markdown(data)
        return _render_text(data)
    finally:
        conn.close()


def query_keyword(keyword: str, fmt: str = "text") -> str:
    """Search CVEs by keyword and return a summary report."""
    if not DB_PATH.exists():
        return f"Error: database not found at {DB_PATH}"

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    try:
        results = _search_cves_by_keyword(conn, keyword)
        if not results:
            return f"No CVEs found matching '{keyword}'."

        lines = [f"Search results for '{keyword}' ({len(results)} CVEs):", ""]
        for r in results:
            kev = " [KEV]" if r.get("kev") else ""
            epss = f" EPSS={r['epss_score']:.4f}" if r.get("epss_score") is not None else ""
            lines.append(
                f"  {r['id']} [CVSS {r.get('cvss_score', '?')} {r.get('cvss_severity', '')}]{kev}{epss}"
            )
            if r.get("description"):
                lines.append(f"    {r['description'][:120]}")
            lines.append("")

        return "\n".join(lines)
    finally:
        conn.close()


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 -m horus.storage.query <CVE-ID> [--md]")
        sys.exit(1)
    cve_id = sys.argv[1]
    fmt = "md" if "--md" in sys.argv else "text"
    print(query_cve(cve_id, fmt))
