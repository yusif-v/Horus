"""Horus web interface — Flask app.

Usage:
    python3 -m horus.web
    python3 -m horus.web --port 8080
    python3 -m horus.web --host 0.0.0.0 --port 8080
"""

from __future__ import annotations

import json
import sqlite3
import sys
from datetime import datetime
from pathlib import Path

from flask import Flask, jsonify, redirect, render_template_string, request, url_for

from horus.config import STATE_DIR
from horus.storage.db import connect

DB_PATH = STATE_DIR / "horus.db"
PER_PAGE = 20

app = Flask(__name__)


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _db():
    """Get a database connection."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _row_to_dict(row) -> dict:
    if row is None:
        return {}
    return dict(row)


def _rows_to_dicts(rows) -> list[dict]:
    return [dict(r) for r in rows]


def _safe_int(value: str, default: int = 1, min_val: int = 1, max_val: int = 10000) -> int:
    """Safely parse an integer from query string with bounds checking."""
    try:
        return max(min_val, min(int(value), max_val))
    except (ValueError, TypeError):
        return default


def _rail_stats() -> dict:
    """Cheap counts for the status rail at the top of every page."""
    try:
        with _db() as conn:
            cve_n = conn.execute("SELECT COUNT(*) FROM cve").fetchone()[0]
            poc_n = conn.execute("SELECT COUNT(*) FROM poc").fetchone()[0]
            last = conn.execute("SELECT MAX(first_seen) FROM cve").fetchone()[0]
        return {"cve_n": cve_n, "poc_n": poc_n, "last": last}
    except Exception:
        return {"cve_n": "—", "poc_n": "—", "last": None}


def _error_page(message: str, active: str = "", search_query: str = "") -> str:
    """Render an error within the standard page chrome."""
    return render_page(
        '<div class="eyebrow" style="color:var(--critical);">System error</div>'
        '<h1 class="page-title">Something went wrong.</h1>'
        '<div class="panel"><div class="panel-body" style="font-family:var(--mono);font-size:13px;color:var(--text-mid);white-space:pre-wrap;">{{ msg }}</div></div>',
        title="Error", active=active, msg=message, search_query=search_query,
    )


def render_page(template: str, title: str, active: str = "", **context) -> str:
    """Render a page template inside the base template."""
    context.setdefault("title", title)
    page_html = render_template_string(template, **context)
    rail = _rail_stats()
    return render_template_string(
        BASE_TEMPLATE,
        title=title,
        content=page_html,
        active=active,
        search_query=context.get("search_query", ""),
        db_cve_count=rail["cve_n"],
        db_poc_count=rail["poc_n"],
        db_last_update=rail["last"] or "",
        now=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
    )


# ─── Data access ─────────────────────────────────────────────────────────────

def get_stats() -> dict:
    """Get dashboard statistics."""
    with _db() as conn:
        cve_count = conn.execute("SELECT COUNT(*) FROM cve").fetchone()[0]
        poc_count = conn.execute("SELECT COUNT(*) FROM poc").fetchone()[0]
        kev_count = conn.execute("SELECT COUNT(*) FROM cve WHERE kev = 1").fetchone()[0]
        with_epss = conn.execute("SELECT COUNT(*) FROM cve WHERE epss_score IS NOT NULL").fetchone()[0]
        linked_pocs = conn.execute("SELECT COUNT(DISTINCT poc_url) FROM poc_cve").fetchone()[0]
        cves_with_pocs = conn.execute("SELECT COUNT(DISTINCT cve_id) FROM poc_cve").fetchone()[0]

        # Average EPSS
        avg_epss = conn.execute("SELECT AVG(epss_score) FROM cve WHERE epss_score IS NOT NULL").fetchone()[0]

        # Average exploitability
        avg_exploit = conn.execute("SELECT AVG(exploitability_score) FROM cve WHERE exploitability_score IS NOT NULL").fetchone()[0]

        # Severity breakdown
        severity_breakdown = _rows_to_dicts(conn.execute(
            "SELECT cvss_severity, COUNT(*) as cnt FROM cve WHERE cvss_severity IS NOT NULL GROUP BY cvss_severity ORDER BY cnt DESC"
        ).fetchall())

        # EPSS distribution buckets
        epss_buckets = _rows_to_dicts(conn.execute("""
            SELECT CASE
                WHEN epss_score >= 0.5 THEN 'Very High (≥0.5)'
                WHEN epss_score >= 0.1 THEN 'High (0.1-0.5)'
                WHEN epss_score >= 0.01 THEN 'Medium (0.01-0.1)'
                WHEN epss_score IS NOT NULL THEN 'Low (<0.01)'
            END as bucket, COUNT(*) as cnt
            FROM cve WHERE epss_score IS NOT NULL
            GROUP BY bucket ORDER BY cnt DESC
        """).fetchall())

        # Source breakdown
        sources = _rows_to_dicts(conn.execute(
            "SELECT source, COUNT(*) as cnt FROM poc GROUP BY source ORDER BY cnt DESC"
        ).fetchall())

        # Category breakdown
        categories = _rows_to_dicts(conn.execute(
            "SELECT p.category, COUNT(DISTINCT cp.cve_id) as cnt FROM cve_product cp JOIN product p ON p.id = cp.product_id GROUP BY p.category ORDER BY cnt DESC"
        ).fetchall())

        # Top attack tags
        top_tags = _rows_to_dicts(conn.execute("""
            SELECT tag, COUNT(*) as cnt FROM cve_attack_tag GROUP BY tag ORDER BY cnt DESC LIMIT 15
        """).fetchall())

        # Recent CVEs (last 10)
        recent_cves = _rows_to_dicts(conn.execute(
            "SELECT id, cvss_score, cvss_severity, description, epss_score, kev, published_at FROM cve ORDER BY published_at DESC NULLS LAST LIMIT 10"
        ).fetchall())

        # Top PoCs by stars
        top_pocs = _rows_to_dicts(conn.execute(
            "SELECT url, source, stars, description FROM poc WHERE stars IS NOT NULL ORDER BY stars DESC LIMIT 10"
        ).fetchall())

        # Highest EPSS CVEs
        highest_epss = _rows_to_dicts(conn.execute("""
            SELECT id, cvss_score, cvss_severity, epss_score, kev FROM cve
            WHERE epss_score IS NOT NULL ORDER BY epss_score DESC LIMIT 10
        """).fetchall())

        # KEV CVEs with details
        kev_cves = _rows_to_dicts(conn.execute("""
            SELECT id, cvss_score, cvss_severity, epss_score, description FROM cve
            WHERE kev = 1 ORDER BY cvss_score DESC NULLS LAST LIMIT 10
        """).fetchall())

        # CVEs published per month (last 6 months)
        monthly_cves = _rows_to_dicts(conn.execute("""
            SELECT strftime('%Y-%m', published_at) as month, COUNT(*) as cnt
            FROM cve WHERE published_at IS NOT NULL
              AND published_at >= date('now', '-6 months')
            GROUP BY month ORDER BY month
        """).fetchall())

        # Actionable threat metrics — what a security pro actually triages on
        weaponized = conn.execute("""
            SELECT COUNT(DISTINCT c.id) FROM cve c
            JOIN poc_cve pc ON pc.cve_id = c.id
            WHERE c.cvss_score >= 9
        """).fetchone()[0]
        imminent = conn.execute(
            "SELECT COUNT(*) FROM cve WHERE epss_score >= 0.5"
        ).fetchone()[0]
        actionable = conn.execute("""
            SELECT COUNT(DISTINCT c.id) FROM cve c
            LEFT JOIN poc_cve pc ON pc.cve_id = c.id
            WHERE c.kev = 1
               OR (c.epss_score >= 0.5 AND pc.cve_id IS NOT NULL)
        """).fetchone()[0]
        latest_update = conn.execute(
            "SELECT MAX(first_seen) FROM cve"
        ).fetchone()[0]

    return {
        "cve_count": cve_count,
        "poc_count": poc_count,
        "kev_count": kev_count,
        "with_epss": with_epss,
        "linked_pocs": linked_pocs,
        "cves_with_pocs": cves_with_pocs,
        "avg_epss": avg_epss,
        "avg_exploit": avg_exploit,
        "severity_breakdown": severity_breakdown,
        "epss_buckets": epss_buckets,
        "sources": sources,
        "categories": categories,
        "top_tags": top_tags,
        "recent_cves": recent_cves,
        "top_pocs": top_pocs,
        "highest_epss": highest_epss,
        "kev_cves": kev_cves,
        "monthly_cves": monthly_cves,
        "weaponized": weaponized,
        "imminent": imminent,
        "actionable": actionable,
        "latest_update": latest_update,
    }


def search_cves(query: str, page: int = 1, per_page: int = 20) -> tuple[list[dict], int]:
    """Search CVEs by ID or keyword. Returns (results, total)."""
    query = query.strip()
    is_cve_id = query.upper().startswith("CVE-") or query.replace("-", "").isdigit()

    with _db() as conn:
        if is_cve_id:
            # Exact or prefix match on ID
            cve_id = query.upper()
            if not cve_id.startswith("CVE-"):
                cve_id = f"CVE-{cve_id}"
            rows = conn.execute(
                "SELECT id, cvss_score, cvss_severity, description, epss_score, kev, published_at FROM cve WHERE id LIKE ? ORDER BY cvss_score DESC NULLS LAST",
                (f"{cve_id}%",)
            ).fetchall()
            results = _rows_to_dicts(rows)
            return results, len(results)
        else:
            # Keyword search
            pattern = f"%{query}%"
            total = conn.execute(
                "SELECT COUNT(*) FROM cve WHERE id LIKE ? OR description LIKE ?",
                (pattern, pattern)
            ).fetchone()[0]
            offset = (page - 1) * per_page
            rows = conn.execute(
                "SELECT id, cvss_score, cvss_severity, description, epss_score, kev, published_at FROM cve WHERE id LIKE ? OR description LIKE ? ORDER BY cvss_score DESC NULLS LAST LIMIT ? OFFSET ?",
                (pattern, pattern, per_page, offset)
            ).fetchall()
            return _rows_to_dicts(rows), total


def get_cve_detail(cve_id: str) -> dict | None:
    """Get full CVE detail with all enrichment data."""
    cve_id = cve_id.upper()
    if not cve_id.startswith("CVE-"):
        import re
        if re.match(r"^\d{4}-\d{4,}$", cve_id):
            cve_id = f"CVE-{cve_id}"

    with _db() as conn:
        cve = _row_to_dict(conn.execute("SELECT * FROM cve WHERE id = ?", (cve_id,)).fetchone())
        if not cve:
            return None

        tags = [r[0] for r in conn.execute("SELECT tag FROM cve_attack_tag WHERE cve_id = ?", (cve_id,))]
        cwes = [r[0] for r in conn.execute("SELECT cwe_id FROM cve_cwe WHERE cve_id = ?", (cve_id,))]
        products = _rows_to_dicts(conn.execute("""
            SELECT p.vendor, p.product, cp.versions, p.category
            FROM cve_product cp JOIN product p ON p.id = cp.product_id
            WHERE cp.cve_id = ?
        """, (cve_id,)))
        sources = [r[0] for r in conn.execute("SELECT source FROM cve_source WHERE cve_id = ?", (cve_id,))]
        linked_pocs = _rows_to_dicts(conn.execute("""
            SELECT p.url, p.source, p.stars, p.age_days, p.description
            FROM poc_cve pc JOIN poc p ON p.url = pc.poc_url
            WHERE pc.cve_id = ? ORDER BY p.stars DESC NULLS LAST
        """, (cve_id,)))

        # Related CVEs (same tags or same products)
        related = {}
        if tags:
            placeholders = ",".join("?" * len(tags))
            for r in conn.execute(f"""
                SELECT DISTINCT c.id, c.cvss_score, c.cvss_severity, c.description
                FROM cve c JOIN cve_attack_tag cat ON cat.cve_id = c.id
                WHERE cat.tag IN ({placeholders}) AND c.id != ?
                ORDER BY c.cvss_score DESC LIMIT 10
            """, (*tags, cve_id)):
                rid = r[0]
                if rid not in related:
                    related[rid] = {"id": rid, "cvss_score": r[1], "cvss_severity": r[2], "description": (r[3] or "")[:100], "relation": "same_attack_tag"}

        for prod in products:
            for r in conn.execute("""
                SELECT DISTINCT c.id, c.cvss_score, c.cvss_severity, c.description
                FROM cve c JOIN cve_product cp ON cp.cve_id = c.id JOIN product p ON p.id = cp.product_id
                WHERE p.vendor = ? AND p.product = ? AND c.id != ?
                ORDER BY c.cvss_score DESC LIMIT 5
            """, (prod["vendor"], prod["product"], cve_id)):
                rid = r[0]
                if rid not in related:
                    related[rid] = {"id": rid, "cvss_score": r[1], "cvss_severity": r[2], "description": (r[3] or "")[:100], "relation": "same_product"}

    return {
        "cve": cve,
        "tags": tags,
        "cwes": cwes,
        "products": products,
        "sources": sources,
        "linked_pocs": linked_pocs,
        "related_cves": list(related.values()),
    }


def fetch_pocs(page: int = 1, per_page: int = 20, source_filter: str | None = None) -> tuple[list[dict], int]:
    """List PoCs with optional source filter."""
    with _db() as conn:
        where = ""
        params: list = []
        if source_filter:
            where = "WHERE source = ?"
            params = [source_filter]

        total = conn.execute(f"SELECT COUNT(*) FROM poc {where}", params).fetchone()[0]
        offset = (page - 1) * per_page
        rows = conn.execute(
            f"SELECT url, source, stars, age_days, description, first_seen FROM poc {where} ORDER BY stars DESC NULLS LAST LIMIT ? OFFSET ?",
            params + [per_page, offset]
        ).fetchall()
        return _rows_to_dicts(rows), total


# ─── Template ────────────────────────────────────────────────────────────────

BASE_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{{ title }} — Horus</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@300;400;500;600&family=IBM+Plex+Sans:wght@400;500;600&family=IBM+Plex+Sans+Condensed:wght@500;600;700&family=Instrument+Serif:ital@0;1&display=swap" rel="stylesheet">
<style>
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
:root {
  --bg:        #0a0d0c;
  --bg-deep:   #07090a;
  --surface:   #11161a;
  --surface-2: #161c21;
  --border:    #1f2a30;
  --border-hi: #2c3a42;
  --text:      #d8dcd9;
  --text-mid:  #8a9590;
  --text-dim:  #586460;
  --accent:    #ffb627;        /* operational amber */
  --info:      #7eddd3;        /* terminal teal */
  --critical:  #ff3b3b;
  --high:      #ff8a3b;
  --medium:    #f0c419;
  --low:       #6bbf8a;
  --kev-bg:    #2a0e0e;
  --shadow:    0 0 0 1px rgba(255,182,39,.06), 0 24px 60px -30px rgba(0,0,0,.6);
  --serif:     'Instrument Serif', Georgia, serif;
  --sans:      'IBM Plex Sans', system-ui, sans-serif;
  --display:   'IBM Plex Sans Condensed', 'IBM Plex Sans', system-ui, sans-serif;
  --mono:      'IBM Plex Mono', ui-monospace, SFMono-Regular, monospace;
}
html, body { height: 100%; }
body {
  background:
    radial-gradient(1200px 600px at 75% -200px, rgba(255,182,39,.04), transparent 60%),
    radial-gradient(900px 500px at -10% 110%, rgba(126,221,211,.03), transparent 60%),
    var(--bg);
  color: var(--text);
  font-family: var(--sans);
  font-size: 14px;
  line-height: 1.55;
  font-feature-settings: "ss01", "cv11";
  -webkit-font-smoothing: antialiased;
}
body::before {
  content: ""; position: fixed; inset: 0; pointer-events: none; z-index: 100;
  background-image:
    repeating-linear-gradient(0deg, rgba(255,255,255,.012) 0 1px, transparent 1px 3px);
  mix-blend-mode: overlay;
}
a { color: var(--text); text-decoration: none; }
a:hover { color: var(--accent); }
::selection { background: var(--accent); color: #0a0d0c; }

/* ── Top status rail ─────────────────────────────────── */
.rail {
  display: flex; align-items: center; gap: 1.5rem;
  height: 28px; padding: 0 1.5rem;
  background: var(--bg-deep);
  border-bottom: 1px solid var(--border);
  font-family: var(--mono);
  font-size: 10.5px; letter-spacing: .08em;
  color: var(--text-dim); text-transform: uppercase;
}
.rail .pulse {
  display: inline-block; width: 7px; height: 7px; border-radius: 50%;
  background: var(--low); box-shadow: 0 0 0 0 rgba(107,191,138,.6);
  animation: pulse 2.4s infinite;
}
.rail .pulse.warn { background: var(--accent); box-shadow: 0 0 0 0 rgba(255,182,39,.6); }
@keyframes pulse {
  0%   { box-shadow: 0 0 0 0 rgba(107,191,138,.55); }
  70%  { box-shadow: 0 0 0 10px rgba(107,191,138,0); }
  100% { box-shadow: 0 0 0 0 rgba(107,191,138,0); }
}
.rail .sep { color: var(--border-hi); }
.rail .right { margin-left: auto; display: flex; gap: 1.25rem; }

/* ── Nav ──────────────────────────────────────────────── */
.nav {
  background: var(--surface);
  border-bottom: 1px solid var(--border);
  padding: 0 1.5rem;
  display: flex; align-items: center; gap: 2rem;
  height: 64px;
}
.nav .logo {
  font-family: var(--serif);
  font-style: italic;
  font-size: 1.7rem;
  letter-spacing: -.01em;
  color: var(--text);
  display: flex; align-items: baseline; gap: .35rem;
}
.nav .logo .dot { color: var(--accent); font-style: normal; }
.nav .logo .sub {
  font-family: var(--mono); font-style: normal;
  font-size: 9.5px; letter-spacing: .25em;
  color: var(--text-dim); text-transform: uppercase;
  align-self: center; padding-left: .5rem;
  border-left: 1px solid var(--border);
}
.nav .links { display: flex; gap: .25rem; margin-left: 1rem; }
.nav .links a {
  font-family: var(--mono);
  font-size: 11.5px; letter-spacing: .12em;
  color: var(--text-mid); text-transform: uppercase;
  padding: .45rem .85rem;
  border-radius: 2px;
  position: relative;
  transition: color .15s;
}
.nav .links a:hover { color: var(--text); background: var(--surface-2); }
.nav .links a.active { color: var(--accent); }
.nav .links a.active::after {
  content: ""; position: absolute; left: .85rem; right: .85rem; bottom: -.45rem;
  height: 2px; background: var(--accent);
}
.nav .search { margin-left: auto; position: relative; }
.nav .search input {
  background: var(--bg-deep);
  border: 1px solid var(--border);
  color: var(--text);
  font-family: var(--mono);
  padding: .55rem .85rem .55rem 2rem;
  width: 320px; font-size: 12px;
  border-radius: 2px;
  letter-spacing: .02em;
}
.nav .search input::placeholder { color: var(--text-dim); letter-spacing: .08em; }
.nav .search input:focus { outline: none; border-color: var(--accent); background: var(--bg); }
.nav .search::before {
  content: "/"; position: absolute; left: .75rem; top: 50%;
  transform: translateY(-50%);
  font-family: var(--mono); color: var(--text-dim); font-size: 12px;
  pointer-events: none;
}

/* ── Layout ───────────────────────────────────────────── */
.container { max-width: 1320px; margin: 0 auto; padding: 2rem 1.5rem 4rem; }

.eyebrow {
  font-family: var(--mono);
  font-size: 10.5px; letter-spacing: .22em;
  color: var(--text-dim); text-transform: uppercase;
  display: flex; align-items: center; gap: .6rem;
  margin-bottom: 1rem;
}
.eyebrow::before {
  content: ""; width: 18px; height: 1px; background: var(--accent);
}

.page-title {
  font-family: var(--display);
  font-size: 2.2rem; font-weight: 600;
  letter-spacing: -.015em;
  line-height: 1.05;
  margin-bottom: .35rem;
}
.page-title em {
  font-family: var(--serif); font-style: italic; font-weight: 400;
  color: var(--accent);
}
.page-subtitle {
  color: var(--text-mid); font-size: 13px; max-width: 60ch;
  margin-bottom: 2rem;
}

/* ── Hero threat-posture grid ────────────────────────── */
.posture {
  display: grid;
  grid-template-columns: 1.4fr 1fr 1fr 1fr;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 3px;
  overflow: hidden;
  margin-bottom: 2.5rem;
  box-shadow: var(--shadow);
}
.posture .cell {
  padding: 1.5rem 1.5rem 1.4rem;
  border-right: 1px solid var(--border);
  position: relative;
  display: flex; flex-direction: column; gap: .4rem;
  min-height: 150px;
}
.posture .cell:last-child { border-right: none; }
.posture .cell .k {
  font-family: var(--mono);
  font-size: 10px; letter-spacing: .22em;
  color: var(--text-dim); text-transform: uppercase;
}
.posture .cell .v {
  font-family: var(--serif);
  font-size: 4.2rem; line-height: .95; letter-spacing: -.02em;
  font-weight: 400;
  color: var(--text);
  font-variant-numeric: tabular-nums;
  margin-top: .25rem;
}
.posture .cell .v.danger { color: var(--critical); }
.posture .cell .v.warn   { color: var(--accent);   }
.posture .cell .v.info   { color: var(--info);     }
.posture .cell .meta {
  font-family: var(--mono);
  font-size: 11px; color: var(--text-mid);
  margin-top: auto;
  display: flex; align-items: baseline; gap: .35rem;
}
.posture .cell .meta strong { color: var(--text); font-weight: 500; }
.posture .cell .tick {
  position: absolute; top: 1.5rem; right: 1.5rem;
  font-family: var(--mono); font-size: 10px;
  color: var(--text-dim); letter-spacing: .15em;
}

/* ── Section ──────────────────────────────────────────── */
.section { margin: 2.5rem 0; }
.section-head {
  display: flex; align-items: baseline; gap: 1rem;
  padding-bottom: .75rem; margin-bottom: 1.25rem;
  border-bottom: 1px dashed var(--border);
}
.section-head h2 {
  font-family: var(--display);
  font-size: 1.25rem; font-weight: 600;
  letter-spacing: -.005em;
}
.section-head .count {
  font-family: var(--mono);
  font-size: 11px; letter-spacing: .15em;
  color: var(--text-dim); text-transform: uppercase;
}
.section-head .actions { margin-left: auto; }
.section-head .actions a {
  font-family: var(--mono); font-size: 11px;
  color: var(--text-mid); letter-spacing: .12em;
  text-transform: uppercase;
}
.section-head .actions a:hover { color: var(--accent); }

/* ── Card / Panel ─────────────────────────────────────── */
.panel {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 3px;
}
.panel-head {
  padding: .9rem 1.25rem;
  border-bottom: 1px solid var(--border);
  display: flex; align-items: center; gap: .75rem;
  font-family: var(--mono);
  font-size: 11px; letter-spacing: .15em;
  text-transform: uppercase;
  color: var(--text-mid);
}
.panel-head .dot {
  width: 6px; height: 6px; background: var(--accent); border-radius: 50%;
}
.panel-body { padding: 1.25rem; }
.panel-body.flush { padding: 0; }

/* ── Tables ──────────────────────────────────────────── */
table { width: 100%; border-collapse: collapse; font-variant-numeric: tabular-nums; }
thead th {
  text-align: left;
  padding: .65rem 1rem;
  font-family: var(--mono);
  font-size: 10px; letter-spacing: .15em;
  text-transform: uppercase;
  color: var(--text-dim);
  border-bottom: 1px solid var(--border);
  font-weight: 500;
  background: var(--bg-deep);
}
tbody td {
  padding: .7rem 1rem;
  border-bottom: 1px solid var(--border);
  font-size: 13px;
  vertical-align: middle;
}
tbody tr { position: relative; }
tbody tr:last-child td { border-bottom: none; }
tbody tr:hover td { background: rgba(255,182,39,.025); }
tbody tr.sev-CRITICAL td:first-child { box-shadow: inset 3px 0 0 var(--critical); }
tbody tr.sev-HIGH td:first-child     { box-shadow: inset 3px 0 0 var(--high);     }
tbody tr.sev-MEDIUM td:first-child   { box-shadow: inset 3px 0 0 var(--medium);   }
tbody tr.sev-LOW td:first-child      { box-shadow: inset 3px 0 0 var(--low);      }
.cve-id-cell {
  font-family: var(--mono); font-size: 12.5px;
  color: var(--text); font-weight: 500; letter-spacing: -.01em;
}
.cve-id-cell:hover { color: var(--accent); }
.num { font-family: var(--mono); font-size: 12px; }
.num.strong { font-weight: 500; color: var(--text); }
.desc-cell { color: var(--text-mid); max-width: 520px; }

/* ── Badges ──────────────────────────────────────────── */
.badge {
  display: inline-flex; align-items: center; gap: .35rem;
  padding: .15rem .55rem;
  font-family: var(--mono);
  font-size: 9.5px; letter-spacing: .18em;
  font-weight: 500;
  text-transform: uppercase;
  border-radius: 2px;
  border: 1px solid transparent;
  white-space: nowrap;
}
.badge-critical { background: rgba(255,59,59,.12);  color: var(--critical); border-color: rgba(255,59,59,.35); }
.badge-high     { background: rgba(255,138,59,.1);  color: var(--high);     border-color: rgba(255,138,59,.3); }
.badge-medium   { background: rgba(240,196,25,.08); color: var(--medium);   border-color: rgba(240,196,25,.25); }
.badge-low      { background: rgba(107,191,138,.08);color: var(--low);      border-color: rgba(107,191,138,.25); }
.badge-kev {
  background: var(--kev-bg); color: var(--critical);
  border-color: var(--critical); font-weight: 600;
}
.badge-kev::before { content: "⏵"; font-size: 10px; }
.badge-epss     { background: rgba(126,221,211,.08); color: var(--info); border-color: rgba(126,221,211,.25); }
.badge-source   { background: var(--surface-2); color: var(--text-mid); border-color: var(--border); }
.badge-tag      { background: rgba(255,182,39,.06); color: var(--accent); border-color: rgba(255,182,39,.2); }

/* ── Bar chart (horizontal) ──────────────────────────── */
.bar-chart { display: flex; flex-direction: column; gap: .6rem; }
.bar-row { display: grid; grid-template-columns: 150px 1fr 60px; align-items: center; gap: 1rem; }
.bar-label {
  font-family: var(--mono); font-size: 11px;
  color: var(--text-mid); letter-spacing: .08em;
  text-transform: uppercase; text-align: right;
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
.bar-track {
  height: 6px; background: var(--bg-deep);
  border-radius: 2px; overflow: hidden;
  position: relative;
}
.bar-fill { height: 100%; transition: width .6s cubic-bezier(.2,.7,.2,1); min-width: 2px; }
.bar-fill.critical  { background: linear-gradient(90deg, var(--critical), #ff7060); }
.bar-fill.high      { background: linear-gradient(90deg, var(--high), #ffb573); }
.bar-fill.medium    { background: linear-gradient(90deg, var(--medium), #f5d96b); }
.bar-fill.low       { background: linear-gradient(90deg, var(--low), #9fd8b5); }
.bar-fill.epss-vhigh{ background: linear-gradient(90deg, var(--critical), var(--accent)); }
.bar-fill.epss-high { background: linear-gradient(90deg, var(--accent), #ffd166); }
.bar-fill.epss-med  { background: linear-gradient(90deg, var(--info), #a5e9e0); }
.bar-fill.epss-low  { background: linear-gradient(90deg, var(--low), #9fd8b5); }
.bar-fill.monthly   { background: linear-gradient(90deg, var(--accent), var(--info)); }
.bar-value {
  font-family: var(--mono); font-size: 12px;
  color: var(--text); font-weight: 500;
  text-align: right;
  font-variant-numeric: tabular-nums;
}

/* ── EPSS micro-bar ──────────────────────────────────── */
.epss-bar {
  display: inline-block; width: 50px; height: 4px;
  background: var(--bg-deep); border-radius: 2px;
  overflow: hidden; vertical-align: middle;
  margin-right: .4rem;
}
.epss-bar-fill { height: 100%; background: linear-gradient(90deg, var(--info), var(--accent)); }
.epss-text { font-family: var(--mono); font-size: 11px; color: var(--text-mid); }

/* ── Tag cloud ───────────────────────────────────────── */
.tag-cloud { display: flex; flex-wrap: wrap; gap: .35rem .4rem; }
.tag-cloud .badge.large {
  font-size: 11px; padding: .25rem .7rem;
  background: rgba(255,182,39,.12); border-color: rgba(255,182,39,.4);
}

/* ── CVE detail ──────────────────────────────────────── */
.cve-hero {
  display: grid; grid-template-columns: 1fr auto;
  gap: 2rem;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 3px;
  padding: 2rem;
  margin-bottom: 2rem;
  position: relative; overflow: hidden;
}
.cve-hero::before {
  content: ""; position: absolute; inset: 0;
  background: radial-gradient(600px 200px at 90% 0%, rgba(255,182,39,.06), transparent 60%);
  pointer-events: none;
}
.cve-hero .id {
  font-family: var(--mono);
  font-size: 1.5rem; font-weight: 500;
  letter-spacing: -.01em; color: var(--text);
  margin-bottom: .75rem;
}
.cve-hero .meta-line {
  display: flex; gap: .5rem; flex-wrap: wrap;
  margin-bottom: 1.25rem;
}
.cve-hero .desc {
  color: var(--text-mid); font-size: 14.5px;
  max-width: 70ch; line-height: 1.65;
  margin-bottom: 1rem;
}
.cve-hero .timeline {
  display: flex; gap: 2rem; flex-wrap: wrap;
  font-family: var(--mono); font-size: 11px;
  color: var(--text-dim); letter-spacing: .08em;
  text-transform: uppercase;
  padding-top: 1rem; border-top: 1px dashed var(--border);
}
.cve-hero .timeline strong { color: var(--text); font-weight: 500; }

.gauges { display: flex; flex-direction: column; gap: 1.25rem; min-width: 220px; }
.gauge { text-align: right; }
.gauge .label {
  font-family: var(--mono); font-size: 10px;
  color: var(--text-dim); letter-spacing: .2em;
  text-transform: uppercase; margin-bottom: .3rem;
}
.gauge .val {
  font-family: var(--serif);
  font-size: 2.6rem; line-height: 1; letter-spacing: -.02em;
  color: var(--text); font-variant-numeric: tabular-nums;
}
.gauge .val.crit { color: var(--critical); }
.gauge .val.hi   { color: var(--high);     }
.gauge .val.md   { color: var(--medium);   }
.gauge .val.lo   { color: var(--low);      }
.gauge .val.info { color: var(--info);     }
.gauge .track {
  height: 3px; background: var(--bg-deep);
  margin-top: .4rem; border-radius: 2px; overflow: hidden;
}
.gauge .track .f { height: 100%; background: var(--accent); transition: width .6s; }
.gauge .track .f.crit { background: var(--critical); }
.gauge .track .f.hi   { background: var(--high);     }
.gauge .track .f.lo   { background: var(--low);      }
.gauge .track .f.info { background: var(--info);     }

.kv-grid {
  display: grid; grid-template-columns: 140px 1fr;
  row-gap: .55rem; column-gap: 1.25rem;
  font-size: 13px;
}
.kv-grid dt {
  font-family: var(--mono); font-size: 10.5px;
  color: var(--text-dim); letter-spacing: .12em;
  text-transform: uppercase; padding-top: .15rem;
}
.kv-grid dd { color: var(--text); }

/* PoC list */
.poc-list { display: flex; flex-direction: column; }
.poc-item {
  display: grid; grid-template-columns: 1fr auto;
  gap: 1rem; padding: 1rem 1.25rem;
  border-bottom: 1px solid var(--border);
  align-items: start;
}
.poc-item:last-child { border-bottom: none; }
.poc-url {
  font-family: var(--mono); font-size: 12.5px;
  word-break: break-all; color: var(--text);
}
.poc-url:hover { color: var(--accent); }
.poc-meta {
  display: flex; gap: .5rem; flex-wrap: wrap; align-items: center;
  margin-top: .35rem;
  font-family: var(--mono); font-size: 11px; color: var(--text-mid);
}
.poc-desc { color: var(--text-mid); font-size: 13px; margin-top: .5rem; max-width: 70ch; }
.poc-stars {
  font-family: var(--mono); font-size: 12px; color: var(--accent);
  white-space: nowrap; text-align: right;
}

/* ── Filter bar ──────────────────────────────────────── */
.filter-bar {
  display: flex; gap: 1.5rem; align-items: center; flex-wrap: wrap;
  background: var(--surface); border: 1px solid var(--border);
  padding: .75rem 1rem; border-radius: 3px;
  margin-bottom: 1.5rem;
}
.filter-group { display: flex; gap: .35rem; align-items: center; flex-wrap: wrap; }
.filter-group .label {
  font-family: var(--mono); font-size: 10px;
  letter-spacing: .2em; color: var(--text-dim);
  text-transform: uppercase; margin-right: .35rem;
}
.chip {
  font-family: var(--mono);
  font-size: 11px; letter-spacing: .1em;
  text-transform: uppercase;
  padding: .3rem .7rem;
  border-radius: 2px;
  border: 1px solid var(--border);
  background: var(--bg-deep);
  color: var(--text-mid);
  transition: all .15s;
}
.chip:hover { color: var(--text); border-color: var(--border-hi); }
.chip.active { background: var(--accent); color: #0a0d0c; border-color: var(--accent); font-weight: 500; }

/* ── Pagination ──────────────────────────────────────── */
.pagination {
  display: flex; align-items: center; gap: .5rem;
  margin-top: 1.5rem; justify-content: center;
  font-family: var(--mono); font-size: 11px;
  letter-spacing: .1em; text-transform: uppercase;
}
.pagination a, .pagination span {
  padding: .5rem .9rem;
  border: 1px solid var(--border);
  background: var(--surface); color: var(--text-mid);
  border-radius: 2px;
}
.pagination a:hover { color: var(--accent); border-color: var(--accent); }
.pagination .current { background: var(--accent); color: #0a0d0c; border-color: var(--accent); }

/* ── Search results ──────────────────────────────────── */
.result-item {
  padding: 1.25rem 0;
  border-bottom: 1px solid var(--border);
}
.result-item:last-child { border-bottom: none; }
.result-id {
  font-family: var(--mono); font-size: 1.05rem;
  font-weight: 500; color: var(--text);
}
.result-id:hover { color: var(--accent); }
.result-meta {
  display: flex; gap: .5rem; flex-wrap: wrap;
  align-items: center; margin: .5rem 0;
}
.result-desc {
  font-size: 13px; color: var(--text-mid);
  max-width: 80ch; line-height: 1.6;
}

/* ── Layouts ─────────────────────────────────────────── */
.two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; }
.three-col { display: grid; grid-template-columns: 2fr 1fr 1fr; gap: 1.5rem; }
.triage-grid { display: grid; grid-template-columns: 1fr; gap: 1.5rem; }

/* ── Responsive ──────────────────────────────────────── */
@media (max-width: 960px) {
  .posture { grid-template-columns: 1fr 1fr; }
  .posture .cell:nth-child(2) { border-right: none; }
  .posture .cell:nth-child(-n+2) { border-bottom: 1px solid var(--border); }
  .two-col, .three-col { grid-template-columns: 1fr; }
  .cve-hero { grid-template-columns: 1fr; }
  .gauges { flex-direction: row; flex-wrap: wrap; }
  .gauge { text-align: left; flex: 1 1 140px; }
}
@media (max-width: 640px) {
  .nav { padding: 0 1rem; gap: 1rem; height: auto; flex-wrap: wrap; padding: .75rem 1rem; }
  .nav .search { margin-left: 0; width: 100%; }
  .nav .search input { width: 100%; }
  .nav .links { margin-left: 0; flex-wrap: wrap; }
  .container { padding: 1.25rem 1rem 3rem; }
  .posture { grid-template-columns: 1fr; }
  .posture .cell { border-right: none; border-bottom: 1px solid var(--border); }
  .posture .cell:last-child { border-bottom: none; }
  .bar-row { grid-template-columns: 100px 1fr 50px; gap: .6rem; }
}
</style>
</head>
<body>
<div class="rail">
  <span><span class="pulse"></span> SYSTEM ONLINE</span>
  <span class="sep">│</span>
  <span>DB · {{ db_cve_count|default('—') }} CVE / {{ db_poc_count|default('—') }} POC</span>
  <span class="sep">│</span>
  <span>LAST INGEST · {{ db_last_update[:16] if db_last_update else '—' }}</span>
  <div class="right">
    <span>BUILD · HORUS v0.5</span>
    <span class="sep">│</span>
    <span>{{ now }}</span>
  </div>
</div>
<nav class="nav">
  <a href="/" class="logo">Horus<span class="dot">.</span><span class="sub">CVE INTEL</span></a>
  <div class="links">
    <a href="/" class="{% if active == 'dashboard' %}active{% endif %}">Overview</a>
    <a href="/triage" class="{% if active == 'triage' %}active{% endif %}">Triage</a>
    <a href="/cves" class="{% if active == 'cves' %}active{% endif %}">CVEs</a>
    <a href="/pocs" class="{% if active == 'pocs' %}active{% endif %}">PoCs</a>
  </div>
  <form class="search" action="/search" method="get">
    <input type="text" name="q" placeholder="CVE-ID OR KEYWORD" value="{{ search_query|default('') }}" autocomplete="off">
  </form>
</nav>
<div class="container">
{{ content|safe }}
</div>
</body>
</html>"""

DASHBOARD_TEMPLATE = """
<div class="eyebrow">Threat posture · live</div>
<h1 class="page-title">Operating <em>picture</em>.</h1>
<p class="page-subtitle">Aggregated CVE and exploit intelligence from NVD, CISA KEV, EPSS, GitHub PoC, and Exploit-DB. Numbers reflect the current state of the local index.</p>

<div class="posture">
  <div class="cell">
    <div class="k">Actionable now</div>
    <div class="v warn">{{ stats.actionable }}</div>
    <div class="meta">KEV <strong>{{ stats.kev_count }}</strong> · EPSS≥0.5 with PoC <strong>{{ stats.imminent }}</strong></div>
    <div class="tick">01</div>
  </div>
  <div class="cell">
    <div class="k">Weaponized</div>
    <div class="v danger">{{ stats.weaponized }}</div>
    <div class="meta">CVSS≥9 with public PoC</div>
    <div class="tick">02</div>
  </div>
  <div class="cell">
    <div class="k">Imminent (EPSS≥0.5)</div>
    <div class="v">{{ stats.imminent }}</div>
    <div class="meta">avg EPSS <strong>{{ "%.2f%%"|format(stats.avg_epss * 100) if stats.avg_epss else '—' }}</strong></div>
    <div class="tick">03</div>
  </div>
  <div class="cell">
    <div class="k">PoCs linked</div>
    <div class="v info">{{ stats.linked_pocs }}</div>
    <div class="meta">across <strong>{{ stats.cves_with_pocs }}</strong> CVEs</div>
    <div class="tick">04</div>
  </div>
</div>

{% if stats.kev_cves %}
<div class="section">
  <div class="section-head">
    <h2>Known exploited <em style="font-family:var(--serif);font-style:italic;color:var(--critical);">/ kev</em></h2>
    <span class="count">{{ stats.kev_count }} total</span>
    <div class="actions"><a href="/triage?lens=kev">View all →</a></div>
  </div>
  <div class="panel">
    <div class="panel-body flush">
      <table>
        <thead><tr><th>CVE</th><th>CVSS</th><th>Severity</th><th>EPSS</th><th>Vector summary</th></tr></thead>
        <tbody>
        {% for cve in stats.kev_cves %}
        <tr class="sev-{{ cve.cvss_severity }}">
          <td><a href="/cve/{{ cve.id }}" class="cve-id-cell">{{ cve.id }}</a></td>
          <td><span class="num strong">{{ cve.cvss_score or '—' }}</span></td>
          <td>{% if cve.cvss_severity %}<span class="badge badge-{{ cve.cvss_severity|lower }}">{{ cve.cvss_severity }}</span>{% else %}—{% endif %}</td>
          <td>{% if cve.epss_score is not none %}<span class="epss-bar"><span class="epss-bar-fill" style="width: {{ (cve.epss_score * 100)|int }}%;"></span></span><span class="epss-text">{{ "%.1f%%"|format(cve.epss_score * 100) }}</span>{% else %}—{% endif %}</td>
          <td class="desc-cell" style="max-width:480px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">{{ cve.description[:140] if cve.description else '—' }}</td>
        </tr>
        {% endfor %}
        </tbody>
      </table>
    </div>
  </div>
</div>
{% endif %}

<div class="two-col">
  {% if stats.severity_breakdown %}
  <div>
    <div class="section-head">
      <h2>Severity mix</h2>
      <span class="count">{{ stats.cve_count }} indexed</span>
    </div>
    <div class="panel"><div class="panel-body">
      <div class="bar-chart">
      {% set sev_max = stats.severity_breakdown|map(attribute='cnt')|max %}
      {% for sev in stats.severity_breakdown %}
        <div class="bar-row">
          <span class="bar-label">{{ sev.cvss_severity }}</span>
          <div class="bar-track"><div class="bar-fill {{ sev.cvss_severity|lower }}" style="width: {{ (sev.cnt / sev_max * 100)|int }}%;"></div></div>
          <span class="bar-value">{{ sev.cnt }}</span>
        </div>
      {% endfor %}
      </div>
    </div></div>
  </div>
  {% endif %}

  {% if stats.epss_buckets %}
  <div>
    <div class="section-head">
      <h2>Exploit probability</h2>
      <span class="count">EPSS · {{ stats.with_epss }} scored</span>
    </div>
    <div class="panel"><div class="panel-body">
      <div class="bar-chart">
      {% set epss_max = stats.epss_buckets|map(attribute='cnt')|max %}
      {% set epss_classes = {'Very High (≥0.5)': 'epss-vhigh', 'High (0.1-0.5)': 'epss-high', 'Medium (0.01-0.1)': 'epss-med', 'Low (<0.01)': 'epss-low'} %}
      {% for bucket in stats.epss_buckets %}
        <div class="bar-row">
          <span class="bar-label">{{ bucket.bucket }}</span>
          <div class="bar-track"><div class="bar-fill {{ epss_classes.get(bucket.bucket, 'epss-low') }}" style="width: {{ (bucket.cnt / epss_max * 100)|int }}%;"></div></div>
          <span class="bar-value">{{ bucket.cnt }}</span>
        </div>
      {% endfor %}
      </div>
    </div></div>
  </div>
  {% endif %}
</div>

<div class="section">
  <div class="section-head">
    <h2>Highest <em>EPSS</em></h2>
    <span class="count">most likely to be exploited</span>
    <div class="actions"><a href="/cves?sort=epss">All by EPSS →</a></div>
  </div>
  <div class="panel">
    <div class="panel-body flush">
      <table>
        <thead><tr><th>CVE</th><th>CVSS</th><th>EPSS</th><th>KEV</th><th>Description</th></tr></thead>
        <tbody>
        {% for cve in stats.highest_epss %}
        <tr class="sev-{{ cve.cvss_severity }}">
          <td><a href="/cve/{{ cve.id }}" class="cve-id-cell">{{ cve.id }}</a></td>
          <td><span class="num strong">{{ cve.cvss_score or '—' }}</span></td>
          <td><span class="epss-bar"><span class="epss-bar-fill" style="width: {{ (cve.epss_score * 100)|int }}%;"></span></span><span class="badge badge-epss">{{ "%.2f%%"|format(cve.epss_score * 100) }}</span></td>
          <td>{% if cve.kev %}<span class="badge badge-kev">KEV</span>{% else %}<span style="color:var(--text-dim);">—</span>{% endif %}</td>
          <td class="desc-cell" style="max-width:420px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">{% if cve.description %}{{ cve.description[:140] }}{% else %}—{% endif %}</td>
        </tr>
        {% endfor %}
        </tbody>
      </table>
    </div>
  </div>
</div>

<div class="two-col">
  <div>
    <div class="section-head"><h2>Recent ingest</h2><span class="count">last 10</span></div>
    <div class="panel"><div class="panel-body flush">
      <table>
        <thead><tr><th>CVE</th><th>CVSS</th><th>EPSS</th><th>Published</th></tr></thead>
        <tbody>
        {% for cve in stats.recent_cves %}
        <tr class="sev-{{ cve.cvss_severity }}">
          <td><a href="/cve/{{ cve.id }}" class="cve-id-cell">{{ cve.id }}</a></td>
          <td><span class="num strong">{{ cve.cvss_score or '—' }}</span> {% if cve.cvss_severity %}<span class="badge badge-{{ cve.cvss_severity|lower }}">{{ cve.cvss_severity[:3] }}</span>{% endif %}</td>
          <td>{% if cve.epss_score is not none %}<span class="epss-text">{{ "%.1f%%"|format(cve.epss_score * 100) }}</span>{% else %}<span style="color:var(--text-dim);">—</span>{% endif %}</td>
          <td><span class="num">{{ cve.published_at[:10] if cve.published_at else '—' }}</span></td>
        </tr>
        {% endfor %}
        </tbody>
      </table>
    </div></div>
  </div>
  <div>
    <div class="section-head"><h2>Top PoCs <em>by reach</em></h2><span class="count">★ ranked</span></div>
    <div class="panel"><div class="panel-body flush">
      <table>
        <thead><tr><th>Source</th><th>Stars</th><th>URL</th></tr></thead>
        <tbody>
        {% for poc in stats.top_pocs %}
        <tr>
          <td><span class="badge badge-source">{{ poc.source }}</span></td>
          <td><span class="num strong" style="color:var(--accent);">★ {{ poc.stars }}</span></td>
          <td style="max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"><a href="{{ poc.url }}" target="_blank" style="font-family:var(--mono);font-size:12px;">{{ poc.url[:55] }}…</a></td>
        </tr>
        {% endfor %}
        </tbody>
      </table>
    </div></div>
  </div>
</div>

{% if stats.top_tags %}
<div class="section">
  <div class="section-head"><h2>Attack surface</h2><span class="count">top vectors observed</span></div>
  <div class="panel"><div class="panel-body">
    {% set max_tag = stats.top_tags|map(attribute='cnt')|max %}
    <div class="tag-cloud">
      {% for tag in stats.top_tags %}
      <span class="badge badge-tag {% if tag.cnt > max_tag * 0.6 %}large{% endif %}">{{ tag.tag }} · {{ tag.cnt }}</span>
      {% endfor %}
    </div>
  </div></div>
</div>
{% endif %}

<div class="two-col">
  {% if stats.monthly_cves %}
  <div>
    <div class="section-head"><h2>Publication tempo</h2><span class="count">last 6 months</span></div>
    <div class="panel"><div class="panel-body">
      <div class="bar-chart">
      {% set month_max = stats.monthly_cves|map(attribute='cnt')|max %}
      {% for m in stats.monthly_cves %}
        <div class="bar-row">
          <span class="bar-label">{{ m.month }}</span>
          <div class="bar-track"><div class="bar-fill monthly" style="width: {{ (m.cnt / month_max * 100)|int }}%;"></div></div>
          <span class="bar-value">{{ m.cnt }}</span>
        </div>
      {% endfor %}
      </div>
    </div></div>
  </div>
  {% endif %}

  {% if stats.sources %}
  <div>
    <div class="section-head"><h2>PoC sources</h2><span class="count">{{ stats.poc_count }} artifacts</span></div>
    <div class="panel"><div class="panel-body">
      <div class="bar-chart">
      {% set src_max = stats.sources|map(attribute='cnt')|max %}
      {% for src in stats.sources %}
        <div class="bar-row">
          <span class="bar-label">{{ src.source }}</span>
          <div class="bar-track"><div class="bar-fill epss-high" style="width: {{ (src.cnt / src_max * 100)|int }}%;"></div></div>
          <span class="bar-value">{{ src.cnt }}</span>
        </div>
      {% endfor %}
      </div>
    </div></div>
  </div>
  {% endif %}
</div>

{% if stats.categories %}
<div class="section">
  <div class="section-head"><h2>Affected product categories</h2><span class="count">{{ stats.categories|length }} categories</span></div>
  <div class="panel"><div class="panel-body">
    <div class="tag-cloud">
    {% for cat in stats.categories %}
    <span class="badge badge-tag {% if cat.cnt > 50 %}large{% endif %}">{{ cat.category }} · {{ cat.cnt }}</span>
    {% endfor %}
    </div>
  </div></div>
</div>
{% endif %}
"""

SEARCH_TEMPLATE = """
<div class="eyebrow">Query</div>
<h1 class="page-title">"{{ query }}" <em>· {{ total }} match{% if total != 1 %}es{% endif %}</em></h1>

{% if results %}
<div class="panel"><div class="panel-body">
{% for cve in results %}
<div class="result-item">
  <a href="/cve/{{ cve.id }}" class="result-id">{{ cve.id }}</a>
  <div class="result-meta">
    {% if cve.cvss_score %}<span class="badge badge-{{ cve.cvss_severity|lower }}">{{ cve.cvss_severity }} · {{ cve.cvss_score }}</span>{% endif %}
    {% if cve.kev %}<span class="badge badge-kev">KEV</span>{% endif %}
    {% if cve.epss_score is not none %}
    <span class="epss-bar"><span class="epss-bar-fill" style="width: {{ (cve.epss_score * 100)|int }}%;"></span></span>
    <span class="badge badge-epss">EPSS {{ "%.2f%%"|format(cve.epss_score * 100) }}</span>
    {% endif %}
    {% if cve.published_at %}<span style="font-family:var(--mono);font-size:11px;color:var(--text-dim);">{{ cve.published_at[:10] }}</span>{% endif %}
  </div>
  <div class="result-desc">{{ cve.description[:240] if cve.description else '—' }}</div>
</div>
{% endfor %}
</div></div>

{% if total > per_page %}
<div class="pagination">
  {% if page > 1 %}<a href="/search?q={{ query }}&page={{ page - 1 }}">← Prev</a>{% endif %}
  <span class="current">{{ page }} / {{ (total / per_page)|round(0, 'ceil')|int }}</span>
  {% if page * per_page < total %}<a href="/search?q={{ query }}&page={{ page + 1 }}">Next →</a>{% endif %}
</div>
{% endif %}

{% else %}
<div class="panel"><div class="panel-body" style="padding:3rem 2rem;text-align:center;">
  <div style="font-family:var(--mono);font-size:11px;letter-spacing:.2em;color:var(--text-dim);text-transform:uppercase;margin-bottom:.5rem;">No results</div>
  <div style="color:var(--text-mid);">No CVEs in the local index match "<span style="font-family:var(--mono);color:var(--text);">{{ query }}</span>".</div>
</div></div>
{% endif %}
"""

CVE_DETAIL_TEMPLATE = """
<div class="eyebrow">Vulnerability dossier</div>

<div class="cve-hero">
  <div>
    <div class="id">{{ data.cve.id }}</div>
    <div class="meta-line">
      {% if data.cve.cvss_severity %}<span class="badge badge-{{ data.cve.cvss_severity|lower }}">{{ data.cve.cvss_severity }}</span>{% endif %}
      {% if data.cve.kev %}<span class="badge badge-kev">CISA KEV</span>{% endif %}
      {% if data.cve.epss_score is not none and data.cve.epss_score >= 0.5 %}<span class="badge badge-epss">IMMINENT</span>{% endif %}
      {% if data.linked_pocs %}<span class="badge badge-tag">PUBLIC POC × {{ data.linked_pocs|length }}</span>{% endif %}
      {% for tag in data.tags %}<span class="badge badge-tag">{{ tag }}</span>{% endfor %}
    </div>
    <div class="desc">{{ data.cve.description or 'No description available.' }}</div>
    <div class="timeline">
      {% if data.cve.published_at %}<span>Published · <strong>{{ data.cve.published_at[:10] }}</strong></span>{% endif %}
      {% if data.cve.first_seen %}<span>First seen · <strong>{{ data.cve.first_seen[:10] }}</strong></span>{% endif %}
      {% if data.sources %}<span>Sources · <strong>{{ data.sources|join(', ') }}</strong></span>{% endif %}
    </div>
  </div>

  <div class="gauges">
    <div class="gauge">
      <div class="label">CVSS</div>
      <div class="val {% if data.cve.cvss_score is not none and data.cve.cvss_score >= 9 %}crit{% elif data.cve.cvss_score is not none and data.cve.cvss_score >= 7 %}hi{% elif data.cve.cvss_score is not none and data.cve.cvss_score >= 4 %}md{% else %}lo{% endif %}">{{ data.cve.cvss_score if data.cve.cvss_score is not none else '—' }}</div>
      <div class="track"><div class="f {% if data.cve.cvss_score is not none and data.cve.cvss_score >= 9 %}crit{% elif data.cve.cvss_score is not none and data.cve.cvss_score >= 7 %}hi{% else %}lo{% endif %}" style="width: {{ ((data.cve.cvss_score or 0) * 10)|int }}%;"></div></div>
    </div>
    {% if data.cve.epss_score is not none %}
    <div class="gauge">
      <div class="label">EPSS</div>
      <div class="val info">{{ "%.2f%%"|format(data.cve.epss_score * 100) }}</div>
      <div class="track"><div class="f info" style="width: {{ (data.cve.epss_score * 100)|int }}%;"></div></div>
    </div>
    {% endif %}
    {% if data.cve.exploitability_score is not none %}
    <div class="gauge">
      <div class="label">Exploitability</div>
      <div class="val">{{ "%.1f"|format(data.cve.exploitability_score) }}<span style="font-size:1rem;color:var(--text-dim);">/10</span></div>
      <div class="track"><div class="f" style="width: {{ (data.cve.exploitability_score * 10)|int }}%;"></div></div>
    </div>
    {% endif %}
  </div>
</div>

{% if data.cwes %}
<div class="section">
  <div class="section-head"><h2>Weakness classification</h2><span class="count">CWE</span></div>
  <div class="panel"><div class="panel-body">
    <div class="tag-cloud">
    {% for cwe in data.cwes %}<span class="badge badge-tag">{{ cwe }}</span>{% endfor %}
    </div>
  </div></div>
</div>
{% endif %}

{% if data.products %}
<div class="section">
  <div class="section-head"><h2>Affected products</h2><span class="count">{{ data.products|length }} entries</span></div>
  <div class="panel"><div class="panel-body flush">
    <table>
      <thead><tr><th>Vendor</th><th>Product</th><th>Versions</th><th>Category</th></tr></thead>
      <tbody>
      {% for p in data.products %}
      <tr>
        <td style="font-family:var(--mono);font-size:12.5px;">{{ p.vendor }}</td>
        <td style="font-family:var(--mono);font-size:12.5px;">{{ p.product }}</td>
        <td style="color:var(--text-mid);font-family:var(--mono);font-size:11.5px;">{{ p.versions or '—' }}</td>
        <td><span class="badge badge-source">{{ p.category }}</span></td>
      </tr>
      {% endfor %}
      </tbody>
    </table>
  </div></div>
</div>
{% endif %}

{% if data.linked_pocs %}
<div class="section">
  <div class="section-head"><h2>Exploits <em>/ proof-of-concept</em></h2><span class="count">{{ data.linked_pocs|length }} artifact{% if data.linked_pocs|length != 1 %}s{% endif %}</span></div>
  <div class="panel">
    <div class="poc-list">
    {% for poc in data.linked_pocs %}
    <div class="poc-item">
      <div>
        <a href="{{ poc.url }}" target="_blank" rel="noopener noreferrer" class="poc-url">{{ poc.url }}</a>
        <div class="poc-meta">
          <span class="badge badge-source">{{ poc.source }}</span>
          {% if poc.age_days is not none %}<span>{{ poc.age_days }}d old</span>{% endif %}
        </div>
        {% if poc.description %}<div class="poc-desc">{{ poc.description[:240] }}</div>{% endif %}
      </div>
      <div class="poc-stars">{% if poc.stars %}★ {{ poc.stars }}{% endif %}</div>
    </div>
    {% endfor %}
    </div>
  </div>
</div>
{% endif %}

{% if data.related_cves %}
<div class="section">
  <div class="section-head"><h2>Related vulnerabilities</h2><span class="count">{{ data.related_cves|length }} linked</span></div>
  <div class="panel"><div class="panel-body flush">
    <table>
      <thead><tr><th>CVE</th><th>CVSS</th><th>Relation</th><th>Description</th></tr></thead>
      <tbody>
      {% for rc in data.related_cves %}
      <tr class="sev-{{ rc.cvss_severity }}">
        <td><a href="/cve/{{ rc.id }}" class="cve-id-cell">{{ rc.id }}</a></td>
        <td><span class="num strong">{{ rc.cvss_score or '—' }}</span> {% if rc.cvss_severity %}<span class="badge badge-{{ rc.cvss_severity|lower }}">{{ rc.cvss_severity[:3] }}</span>{% endif %}</td>
        <td><span class="badge badge-source">{{ rc.relation|replace('_', ' ') }}</span></td>
        <td class="desc-cell" style="max-width:420px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">{{ rc.description[:120] }}</td>
      </tr>
      {% endfor %}
      </tbody>
    </table>
  </div></div>
</div>
{% endif %}
"""

LIST_TEMPLATE = """
<div class="eyebrow">{{ eyebrow|default('Database · live index') }}</div>
<h1 class="page-title">{{ title }} <em>· {{ total }}</em></h1>
{% if subtitle %}<p class="page-subtitle">{{ subtitle }}</p>{% endif %}

{% if filters or sort_filters %}
<div class="filter-bar">
  {% if filters %}
  <div class="filter-group">
    <span class="label">Filter</span>
    {% for f in filters %}
    <a href="{{ f.url }}" class="chip {% if f.active %}active{% endif %}">{{ f.label }}</a>
    {% endfor %}
  </div>
  {% endif %}
  {% if sort_filters %}
  <div class="filter-group">
    <span class="label">Sort</span>
    {% for f in sort_filters %}
    <a href="{{ f.url }}" class="chip {% if f.active %}active{% endif %}">{{ f.label }}</a>
    {% endfor %}
  </div>
  {% endif %}
</div>
{% endif %}

{% if rows %}
<div class="panel">
  <div class="panel-body flush">
    <table>
      <thead><tr>{% for col in columns %}<th>{{ col }}</th>{% endfor %}</tr></thead>
      <tbody>
      {% for row in rows %}
      <tr class="{% if row.cvss_severity %}sev-{{ row.cvss_severity }}{% endif %}">
        {% for cell in cells %}
        <td>
          {% if cell.type == 'cve_link' %}<a href="/cve/{{ row[cell.key] }}" class="cve-id-cell">{{ row[cell.key] }}</a>
          {% elif cell.type == 'poc_link' %}<a href="{{ row[cell.key] }}" target="_blank" rel="noopener" style="font-family:var(--mono);font-size:12px;">{{ row[cell.key][:60] }}…</a>
          {% elif cell.type == 'badge' %}{% if row[cell.key] %}<span class="badge badge-{{ row[cell.key]|lower }}">{{ row[cell.key] }}</span>{% else %}<span style="color:var(--text-dim);">—</span>{% endif %}
          {% elif cell.type == 'score' %}<span class="num strong" style="color:{% if row[cell.key] is not none and row[cell.key] >= 9 %}var(--critical){% elif row[cell.key] is not none and row[cell.key] >= 7 %}var(--high){% elif row[cell.key] is not none and row[cell.key] >= 4 %}var(--medium){% else %}var(--low){% endif %};">{{ row[cell.key] or '—' }}</span>
          {% elif cell.type == 'stars' %}<span class="num" style="color:var(--accent);">★ {{ row[cell.key] }}</span>
          {% elif cell.type == 'truncate' %}<span class="desc-cell">{{ row[cell.key][:140] if row[cell.key] else '—' }}</span>
          {% elif cell.type == 'epss' %}
            {% if row[cell.key] is not none %}
            <span class="epss-bar"><span class="epss-bar-fill" style="width: {{ (row[cell.key] * 100)|int }}%;"></span></span><span class="epss-text">{{ "%.1f%%"|format(row[cell.key] * 100) }}</span>
            {% else %}<span style="color:var(--text-dim);">—</span>{% endif %}
          {% elif cell.type == 'kev' %}{% if row[cell.key] %}<span class="badge badge-kev">KEV</span>{% else %}<span style="color:var(--text-dim);">—</span>{% endif %}
          {% elif cell.type == 'date' %}<span class="num">{{ row[cell.key][:10] if row[cell.key] else '—' }}</span>
          {% else %}{% if row[cell.key] is not none %}<span class="num">{{ row[cell.key] }}</span>{% else %}<span style="color:var(--text-dim);">—</span>{% endif %}{% endif %}
        </td>
        {% endfor %}
      </tr>
      {% endfor %}
      </tbody>
    </table>
  </div>
</div>

{% if total > per_page %}
<div class="pagination">
  {% if page > 1 %}<a href="{{ prev_url }}">← Prev</a>{% endif %}
  <span class="current">{{ page }} / {{ (total / per_page)|round(0, 'ceil')|int }}</span>
  {% if page * per_page < total %}<a href="{{ next_url }}">Next →</a>{% endif %}
</div>
{% endif %}

{% else %}
<div class="panel"><div class="panel-body" style="padding:3rem 2rem;text-align:center;">
  <div style="font-family:var(--mono);font-size:11px;letter-spacing:.2em;color:var(--text-dim);text-transform:uppercase;">No matching records</div>
</div></div>
{% endif %}
"""


# ─── Routes ──────────────────────────────────────────────────────────────────

@app.route("/")
def dashboard():
    try:
        stats = get_stats()
    except Exception as e:
        return _error_page(f"Database Error: {e}", active="", search_query=""), 500
    return render_page(DASHBOARD_TEMPLATE, title="Dashboard", active="dashboard", stats=stats)


@app.route("/search")
def search():
    query = request.args.get("q", "").strip()
    page = _safe_int(request.args.get("page", "1"))
    if not query:
        return redirect(url_for("dashboard"))
    try:
        results, total = search_cves(query, page=page, per_page=PER_PAGE)
    except Exception as e:
        return _error_page(f"Search Error: {e}", active="", search_query=query), 500
    return render_page(
        SEARCH_TEMPLATE, title=f"Search: {query}", active="",
        query=query, results=results, total=total, page=page, per_page=PER_PAGE,
        search_query=query,
    )


@app.route("/cve/<cve_id>")
def cve_detail(cve_id):
    try:
        data = get_cve_detail(cve_id)
    except Exception as e:
        return _error_page(f"Database Error: {e}", active="", search_query=""), 500
    if not data:
        return render_page(
            """<div class="eyebrow" style="color:var(--high);">404 · not indexed</div>
            <h1 class="page-title">No record for <em>{{ cve_id }}</em>.</h1>
            <p class="page-subtitle">This CVE is not in the local index.
              <a href="/search?q={{ cve_id }}" style="color:var(--accent);">Try a keyword search &rarr;</a>
            </p>""",
            title="CVE Not Found", active="", cve_id=cve_id,
        ), 404
    return render_page(
        CVE_DETAIL_TEMPLATE, title=data["cve"]["id"], active="", data=data,
    )


@app.route("/cves")
def list_cves():
    page = _safe_int(request.args.get("page", "1"))
    severity = request.args.get("severity")
    kev_only = request.args.get("kev")
    sort = request.args.get("sort", "cvss")

    try:
        with _db() as conn:
            where, params = "", []
            if severity:
                where = "WHERE cvss_severity = ?"
                params = [severity.upper()]
            if kev_only:
                where = "WHERE kev = 1" if not where else where + " AND kev = 1"

            # Sort options
            order_map = {
                "cvss": "cvss_score DESC NULLS LAST",
                "epss": "epss_score DESC NULLS LAST",
                "exploit": "exploitability_score DESC NULLS LAST",
                "kev": "kev DESC, cvss_score DESC NULLS LAST",
                "date": "published_at DESC NULLS LAST",
                "newest": "first_seen DESC NULLS LAST",
            }
            order = order_map.get(sort, order_map["cvss"])

            total = conn.execute(f"SELECT COUNT(*) FROM cve {where}", params).fetchone()[0]
            offset = (page - 1) * PER_PAGE
            rows = _rows_to_dicts(conn.execute(
                f"SELECT id, cvss_score, cvss_severity, description, epss_score, kev, published_at FROM cve {where} ORDER BY {order} LIMIT ? OFFSET ?",
                params + [PER_PAGE, offset]
            ).fetchall())
    except Exception as e:
        return _error_page(f"Database Error: {e}", active="cves", search_query=""), 500

    filters = [
        {"label": "All", "url": "/cves", "active": not severity and not kev_only},
        {"label": "Critical", "url": "/cves?severity=CRITICAL", "active": severity == "CRITICAL"},
        {"label": "High", "url": "/cves?severity=HIGH", "active": severity == "HIGH"},
        {"label": "Medium", "url": "/cves?severity=MEDIUM", "active": severity == "MEDIUM"},
        {"label": "Low", "url": "/cves?severity=LOW", "active": severity == "LOW"},
        {"label": "KEV Only", "url": "/cves?kev=1", "active": bool(kev_only)},
    ]
    sort_filters = [
        {"label": "By CVSS", "url": "/cves?sort=cvss" + (f"&severity={severity}" if severity else "") + ("&kev=1" if kev_only else ""), "active": sort == "cvss"},
        {"label": "By EPSS", "url": "/cves?sort=epss" + (f"&severity={severity}" if severity else "") + ("&kev=1" if kev_only else ""), "active": sort == "epss"},
        {"label": "By Exploitability", "url": "/cves?sort=exploit" + (f"&severity={severity}" if severity else "") + ("&kev=1" if kev_only else ""), "active": sort == "exploit"},
        {"label": "Newest", "url": "/cves?sort=date" + (f"&severity={severity}" if severity else "") + ("&kev=1" if kev_only else ""), "active": sort == "date"},
    ]
    columns = ["CVE", "CVSS", "Severity", "EPSS", "KEV", "Description", "Published"]
    cells = [
        {"type": "cve_link", "key": "id"}, {"type": "score", "key": "cvss_score"},
        {"type": "badge", "key": "cvss_severity"},
        {"type": "epss", "key": "epss_score"},
        {"type": "kev", "key": "kev"},
        {"type": "truncate", "key": "description"},
        {"type": "date", "key": "published_at"},
    ]
    prev_q = f"&sort={sort}" if sort != "cvss" else ""
    if severity:
        prev_q += f"&severity={severity}"
    if kev_only:
        prev_q += "&kev=1"

    return render_page(
        LIST_TEMPLATE, title="CVE index", active="cves",
        eyebrow="Database · live index",
        subtitle="Browse and filter the full set of indexed vulnerabilities. Severity stripe on the left edge of each row maps to the CVSS band.",
        rows=rows, total=total, page=page, per_page=PER_PAGE,
        filters=filters, sort_filters=sort_filters, columns=columns, cells=cells,
        prev_url=f"/cves?page={page - 1}{prev_q}" if page > 1 else None,
        next_url=f"/cves?page={page + 1}{prev_q}" if page * PER_PAGE < total else None,
    )


@app.route("/triage")
def triage():
    """Curated action queue — KEV ∪ EPSS≥0.5 ∪ critical-with-PoC, exploit-likelihood first."""
    page = _safe_int(request.args.get("page", "1"))
    lens = request.args.get("lens", "all")  # all | kev | imminent | weaponized

    where_clauses = {
        "all": """(c.kev = 1
                   OR c.epss_score >= 0.5
                   OR (c.cvss_score >= 9 AND pc.cve_id IS NOT NULL))""",
        "kev": "c.kev = 1",
        "imminent": "c.epss_score >= 0.5",
        "weaponized": "c.cvss_score >= 9 AND pc.cve_id IS NOT NULL",
    }
    where = where_clauses.get(lens, where_clauses["all"])

    try:
        with _db() as conn:
            total = conn.execute(f"""
                SELECT COUNT(DISTINCT c.id) FROM cve c
                LEFT JOIN poc_cve pc ON pc.cve_id = c.id
                WHERE {where}
            """).fetchone()[0]
            offset = (page - 1) * PER_PAGE
            rows = _rows_to_dicts(conn.execute(f"""
                SELECT DISTINCT c.id, c.cvss_score, c.cvss_severity, c.description,
                       c.epss_score, c.kev, c.published_at,
                       (SELECT COUNT(*) FROM poc_cve WHERE cve_id = c.id) AS poc_count
                FROM cve c
                LEFT JOIN poc_cve pc ON pc.cve_id = c.id
                WHERE {where}
                ORDER BY c.kev DESC,
                         COALESCE(c.epss_score, 0) DESC,
                         COALESCE(c.cvss_score, 0) DESC
                LIMIT ? OFFSET ?
            """, (PER_PAGE, offset)).fetchall())
    except Exception as e:
        return _error_page(f"Database Error: {e}", active="triage"), 500

    filters = [
        {"label": "All actionable", "url": "/triage", "active": lens == "all"},
        {"label": "KEV only", "url": "/triage?lens=kev", "active": lens == "kev"},
        {"label": "Imminent · EPSS≥0.5", "url": "/triage?lens=imminent", "active": lens == "imminent"},
        {"label": "Weaponized · CVSS≥9 + PoC", "url": "/triage?lens=weaponized", "active": lens == "weaponized"},
    ]
    columns = ["CVE", "CVSS", "Severity", "EPSS", "KEV", "PoCs", "Description"]
    cells = [
        {"type": "cve_link", "key": "id"},
        {"type": "score", "key": "cvss_score"},
        {"type": "badge", "key": "cvss_severity"},
        {"type": "epss", "key": "epss_score"},
        {"type": "kev", "key": "kev"},
        {"type": "plain", "key": "poc_count"},
        {"type": "truncate", "key": "description"},
    ]
    qs = f"&lens={lens}" if lens != "all" else ""
    return render_page(
        LIST_TEMPLATE, title="Triage queue", active="triage",
        eyebrow="Action queue · prioritised",
        subtitle="Vulnerabilities you should look at first: anything in CISA KEV, anything with EPSS ≥ 0.5, or critical CVEs with public proof-of-concept. Ordered by KEV → EPSS → CVSS.",
        rows=rows, total=total, page=page, per_page=PER_PAGE,
        filters=filters, columns=columns, cells=cells,
        prev_url=f"/triage?page={page - 1}{qs}" if page > 1 else None,
        next_url=f"/triage?page={page + 1}{qs}" if page * PER_PAGE < total else None,
    )


@app.route("/pocs")
def list_pocs():
    page = _safe_int(request.args.get("page", "1"))
    source = request.args.get("source")

    try:
        rows, total = fetch_pocs(page=page, per_page=PER_PAGE, source_filter=source)
        with _db() as conn:
            sources = [r[0] for r in conn.execute("SELECT DISTINCT source FROM poc ORDER BY source").fetchall()]
    except Exception as e:
        return _error_page(f"Database Error: {e}", active="pocs", search_query=""), 500

    filters = [{"label": "All", "url": "/pocs", "active": not source}]
    for s in sources:
        filters.append({"label": s, "url": f"/pocs?source={s}", "active": source == s})
    columns = ["URL", "Source", "Stars", "Age (d)", "Description"]
    cells = [
        {"type": "poc_link", "key": "url"}, {"type": "badge", "key": "source"},
        {"type": "stars", "key": "stars"}, {"type": "plain", "key": "age_days"},
        {"type": "truncate", "key": "description"},
    ]
    src_q = f"&source={source}" if source else ""

    return render_page(
        LIST_TEMPLATE, title="Public exploits", active="pocs",
        eyebrow="Proof-of-concept artifacts",
        subtitle="Public exploit artifacts harvested from GitHub, Exploit-DB and other sources. Ranked by GitHub stars when available.",
        rows=rows, total=total, page=page, per_page=PER_PAGE,
        filters=filters, columns=columns, cells=cells,
        prev_url=f"/pocs?page={page - 1}{src_q}" if page > 1 else None,
        next_url=f"/pocs?page={page + 1}{src_q}" if page * PER_PAGE < total else None,
    )


@app.route("/api/stats")
def api_stats():
    """JSON API endpoint for stats."""
    try:
        return jsonify(get_stats())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/cve/<cve_id>")
def api_cve(cve_id):
    """JSON API endpoint for CVE detail."""
    try:
        data = get_cve_detail(cve_id)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    if not data:
        return jsonify({"error": "not found"}), 404
    return jsonify(data)


# ─── Entry point ─────────────────────────────────────────────────────────────

def main():
    import argparse
    p = argparse.ArgumentParser(description="Horus web interface")
    p.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    p.add_argument("--port", type=int, default=8080, help="Bind port (default: 8080)")
    p.add_argument("--debug", action="store_true", help="Enable debug mode")
    args = p.parse_args()

    if not DB_PATH.exists():
        print(f"[ERROR] Database not found at {DB_PATH}", file=sys.stderr)
        print("Run 'python3 -m horus' first to populate the database.", file=sys.stderr)
        sys.exit(1)

    print(f"Horus web interface starting at http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
