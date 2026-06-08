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


def render_page(template: str, title: str, active: str = "", **context) -> str:
    """Render a page template inside the base template."""
    page_html = render_template_string(template, **context)
    return render_template_string(
        BASE_TEMPLATE,
        title=title,
        content=page_html,
        active=active,
        search_query=context.get("search_query", ""),
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
<style>
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
:root {
  --bg: #0d1117; --surface: #161b22; --border: #30363d;
  --text: #c9d1d9; --text-dim: #8b949e; --accent: #58a6ff;
  --red: #f85149; --orange: #d29922; --green: #3fb950; --purple: #bc8cff;
  --critical: #f85149; --high: #d29922; --medium: #d2992266; --low: #3fb95066;
}
body { background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; line-height: 1.6; }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }

/* Nav */
.nav { background: var(--surface); border-bottom: 1px solid var(--border); padding: 0 2rem; display: flex; align-items: center; gap: 2rem; height: 56px; }
.nav .logo { font-weight: 700; font-size: 1.2rem; color: var(--text); }
.nav .logo span { color: var(--accent); }
.nav a { color: var(--text-dim); font-size: .9rem; }
.nav a:hover, .nav a.active { color: var(--text); text-decoration: none; }
.nav .search { margin-left: auto; }
.nav .search input { background: var(--bg); border: 1px solid var(--border); color: var(--text); padding: .4rem .8rem; border-radius: 6px; width: 260px; font-size: .85rem; }
.nav .search input:focus { outline: none; border-color: var(--accent); }

/* Layout */
.container { max-width: 1200px; margin: 0 auto; padding: 2rem; }

/* Stats grid */
.stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
.stat { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1.25rem; }
.stat .label { font-size: .8rem; color: var(--text-dim); text-transform: uppercase; letter-spacing: .05em; }
.stat .value { font-size: 1.75rem; font-weight: 700; margin-top: .25rem; }
.stat .value.red { color: var(--red); }
.stat .value.orange { color: var(--orange); }
.stat .value.green { color: var(--green); }
.stat .value.purple { color: var(--purple); }
.stat .sub { font-size: .75rem; color: var(--text-dim); margin-top: .25rem; }

/* Cards */
.card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 1.5rem; }
.card-header { padding: 1rem 1.25rem; border-bottom: 1px solid var(--border); font-weight: 600; font-size: .95rem; }
.card-body { padding: 1.25rem; }

/* Tables */
table { width: 100%; border-collapse: collapse; }
th { text-align: left; padding: .6rem .75rem; font-size: .75rem; text-transform: uppercase; letter-spacing: .05em; color: var(--text-dim); border-bottom: 1px solid var(--border); }
td { padding: .6rem .75rem; border-bottom: 1px solid var(--border); font-size: .85rem; }
tr:hover td { background: rgba(88,166,255,.03); }
td .id { font-family: 'SF Mono', 'Fira Code', monospace; font-size: .8rem; }

/* Badges */
.badge { display: inline-block; padding: .15rem .5rem; border-radius: 12px; font-size: .7rem; font-weight: 600; text-transform: uppercase; }
.badge-critical { background: var(--critical); color: #fff; }
.badge-high { background: var(--high); color: #fff; }
.badge-medium { background: var(--medium); color: var(--text); }
.badge-low { background: var(--low); color: var(--text); }
.badge-kev { background: var(--red); color: #fff; }
.badge-epss { background: var(--purple); color: #fff; }
.badge-source { background: var(--border); color: var(--text-dim); }
.badge-tag { background: rgba(88,166,255,.15); color: var(--accent); }

/* Bar chart */
.bar-chart { display: flex; flex-direction: column; gap: .5rem; }
.bar-row { display: flex; align-items: center; gap: .75rem; }
.bar-label { min-width: 140px; font-size: .8rem; color: var(--text-dim); text-align: right; flex-shrink: 0; }
.bar-track { flex: 1; height: 20px; background: var(--bg); border-radius: 4px; overflow: hidden; position: relative; }
.bar-fill { height: 100%; border-radius: 4px; transition: width .3s ease; min-width: 2px; }
.bar-fill.critical { background: var(--critical); }
.bar-fill.high { background: var(--high); }
.bar-fill.medium { background: #d2992266; }
.bar-fill.low { background: #3fb95066; }
.bar-fill.epss-vhigh { background: var(--purple); }
.bar-fill.epss-high { background: var(--accent); }
.bar-fill.epss-med { background: var(--orange); }
.bar-fill.epss-low { background: var(--green); }
.bar-fill.kev { background: var(--red); }
.bar-fill.monthly { background: var(--accent); }
.bar-value { min-width: 40px; font-size: .8rem; font-weight: 600; color: var(--text); flex-shrink: 0; }

/* EPSS bar */
.epss-bar { display: inline-block; width: 60px; height: 8px; background: var(--bg); border-radius: 4px; overflow: hidden; vertical-align: middle; margin-right: .25rem; }
.epss-bar-fill { height: 100%; border-radius: 4px; background: var(--purple); }

/* Tag cloud */
.tag-cloud { display: flex; flex-wrap: wrap; gap: .4rem; }
.tag-cloud .badge-tag { font-size: .7rem; }
.tag-cloud .badge-tag.large { font-size: .85rem; padding: .25rem .65rem; }

/* CVE detail */
.cve-header { display: flex; align-items: flex-start; gap: 1rem; margin-bottom: 1.5rem; flex-wrap: wrap; }
.cve-id { font-family: 'SF Mono', 'Fira Code', monospace; font-size: 1.5rem; font-weight: 700; }
.cve-score { margin-left: auto; text-align: right; }
.cve-score .score { font-size: 2rem; font-weight: 700; }
.cve-score .severity { font-size: .8rem; }
.section { margin-bottom: 1.5rem; }
.section-title { font-size: .8rem; text-transform: uppercase; letter-spacing: .05em; color: var(--text-dim); margin-bottom: .75rem; }
.description { color: var(--text-dim); line-height: 1.7; }
.poc-item { display: flex; align-items: flex-start; gap: .75rem; padding: .75rem 0; border-bottom: 1px solid var(--border); }
.poc-item:last-child { border-bottom: none; }
.poc-url { font-family: 'SF Mono', 'Fira Code', monospace; font-size: .8rem; word-break: break-all; }
.poc-meta { font-size: .75rem; color: var(--text-dim); margin-top: .25rem; }
.poc-desc { font-size: .8rem; color: var(--text-dim); margin-top: .25rem; }

/* Pagination */
.pagination { display: flex; align-items: center; gap: .5rem; margin-top: 1rem; justify-content: center; }
.pagination a, .pagination span { padding: .4rem .75rem; border-radius: 6px; font-size: .85rem; }
.pagination a { background: var(--surface); border: 1px solid var(--border); }
.pagination a:hover { background: var(--border); text-decoration: none; }
.pagination .current { background: var(--accent); color: #fff; }

/* Search results */
.result-item { padding: 1rem 0; border-bottom: 1px solid var(--border); }
.result-item:last-child { border-bottom: none; }
.result-id { font-family: 'SF Mono', 'Fira Code', monospace; font-weight: 600; font-size: 1rem; }
.result-desc { font-size: .85rem; color: var(--text-dim); margin-top: .25rem; }

/* Two column layout */
.two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; }
.three-col { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 1.5rem; }

/* Responsive */
@media (max-width: 768px) {
  .nav { padding: 0 1rem; gap: 1rem; }
  .nav .search input { width: 160px; }
  .container { padding: 1rem; }
  .cve-score { margin-left: 0; text-align: left; }
  .two-col { grid-template-columns: 1fr; }
  .three-col { grid-template-columns: 1fr; }
  .bar-label { min-width: 80px; font-size: .7rem; }
}
</style>
</head>
<body>
<nav class="nav">
  <a href="/" class="logo">Horus<span>.</span></a>
  <a href="/" class="{% if active == 'dashboard' %}active{% endif %}">Dashboard</a>
  <a href="/cves" class="{% if active == 'cves' %}active{% endif %}">CVEs</a>
  <a href="/cves?sort=exploit" class="{% if active == 'priority' %}active{% endif %}">Priority</a>
  <a href="/pocs" class="{% if active == 'pocs' %}active{% endif %}">PoCs</a>
  <form class="search" action="/search" method="get">
    <input type="text" name="q" placeholder="Search CVE..." value="{{ search_query|default('') }}">
  </form>
</nav>
<div class="container">
{{ content }}
</div>
</body>
</html>"""

DASHBOARD_TEMPLATE = """
<div class="stats">
  <div class="stat"><div class="label">Total CVEs</div><div class="value">{{ stats.cve_count }}</div></div>
  <div class="stat"><div class="label">Total PoCs</div><div class="value orange">{{ stats.poc_count }}</div><div class="sub">{{ stats.cves_with_pocs }} CVEs linked</div></div>
  <div class="stat"><div class="label">KEV</div><div class="value red">{{ stats.kev_count }}</div><div class="sub">known exploited</div></div>
  <div class="stat"><div class="label">With EPSS</div><div class="value purple">{{ stats.with_epss }}</div><div class="sub">avg: {{ "%.2f%%"|format(stats.avg_epss * 100) if stats.avg_epss else 'N/A' }}</div></div>
  <div class="stat"><div class="label">Avg Exploitability</div><div class="value green">{{ "%.1f"|format(stats.avg_exploit) if stats.avg_exploit else 'N/A' }}<span style="font-size:.6em;">/10</span></div></div>
</div>

<!-- Severity breakdown bar chart -->
{% if stats.severity_breakdown %}
<div class="card">
  <div class="card-header">CVEs by Severity</div>
  <div class="card-body">
    <div class="bar-chart">
    {% set sev_max = stats.severity_breakdown|map(attribute='cnt')|max %}
    {% for sev in stats.severity_breakdown %}
      <div class="bar-row">
        <span class="bar-label">{{ sev.cvss_severity }}</span>
        <div class="bar-track">
          <div class="bar-fill {{ sev.cvss_severity|lower }}" style="width: {{ (sev.cnt / sev_max * 100)|int }}%;"></div>
        </div>
        <span class="bar-value">{{ sev.cnt }}</span>
      </div>
    {% endfor %}
    </div>
  </div>
</div>
{% endif %}

<!-- EPSS distribution -->
{% if stats.epss_buckets %}
<div class="card">
  <div class="card-header">EPSS Distribution</div>
  <div class="card-body">
    <div class="bar-chart">
    {% set epss_max = stats.epss_buckets|map(attribute='cnt')|max %}
    {% set epss_classes = {'Very High (≥0.5)': 'epss-vhigh', 'High (0.1-0.5)': 'epss-high', 'Medium (0.01-0.1)': 'epss-med', 'Low (<0.01)': 'epss-low'} %}
    {% for bucket in stats.epss_buckets %}
      <div class="bar-row">
        <span class="bar-label">{{ bucket.bucket }}</span>
        <div class="bar-track">
          <div class="bar-fill {{ epss_classes.get(bucket.bucket, 'epss-low') }}" style="width: {{ (bucket.cnt / epss_max * 100)|int }}%;"></div>
        </div>
        <span class="bar-value">{{ bucket.cnt }}</span>
      </div>
    {% endfor %}
    </div>
  </div>
</div>
{% endif %}

<div class="two-col">
  <div class="card">
    <div class="card-header">Recent CVEs</div>
    <div class="card-body" style="padding:0;">
      <table>
        <thead><tr><th>ID</th><th>CVSS</th><th>Severity</th><th>EPSS</th><th>Published</th></tr></thead>
        <tbody>
        {% for cve in stats.recent_cves %}
        <tr>
          <td><a href="/cve/{{ cve.id }}" class="id">{{ cve.id }}</a></td>
          <td>{{ cve.cvss_score or 'N/A' }}</td>
          <td>{% if cve.cvss_severity %}<span class="badge badge-{{ cve.cvss_severity|lower }}">{{ cve.cvss_severity }}</span>{% else %}N/A{% endif %}</td>
          <td>{% if cve.epss_score is not none %}
            <span class="epss-bar"><span class="epss-bar-fill" style="width: {{ (cve.epss_score * 100)|int }}%;"></span></span>
            {{ "%.1f%%"|format(cve.epss_score * 100) }}
          {% else %}—{% endif %}</td>
          <td>{{ cve.published_at[:10] if cve.published_at else 'N/A' }}</td>
        </tr>
        {% endfor %}
        </tbody>
      </table>
    </div>
  </div>
  <div class="card">
    <div class="card-header">Highest EPSS CVEs</div>
    <div class="card-body" style="padding:0;">
      <table>
        <thead><tr><th>ID</th><th>CVSS</th><th>EPSS</th><th>KEV</th></tr></thead>
        <tbody>
        {% for cve in stats.highest_epss %}
        <tr>
          <td><a href="/cve/{{ cve.id }}" class="id">{{ cve.id }}</a></td>
          <td>{{ cve.cvss_score or 'N/A' }}</td>
          <td>
            <span class="epss-bar"><span class="epss-bar-fill" style="width: {{ (cve.epss_score * 100)|int }}%;"></span></span>
            <span class="badge badge-epss">{{ "%.2f%%"|format(cve.epss_score * 100) }}</span>
          </td>
          <td>{% if cve.kev %}<span class="badge badge-kev">KEV</span>{% else %}—{% endif %}</td>
        </tr>
        {% endfor %}
        </tbody>
      </table>
    </div>
  </div>
</div>

<!-- KEV CVEs -->
{% if stats.kev_cves %}
<div class="card">
  <div class="card-header">Known Exploited Vulnerabilities (KEV)</div>
  <div class="card-body" style="padding:0;">
    <table>
      <thead><tr><th>ID</th><th>CVSS</th><th>Severity</th><th>EPSS</th><th>Description</th></tr></thead>
      <tbody>
      {% for cve in stats.kev_cves %}
      <tr>
        <td><a href="/cve/{{ cve.id }}" class="id">{{ cve.id }}</a></td>
        <td>{{ cve.cvss_score or 'N/A' }}</td>
        <td>{% if cve.cvss_severity %}<span class="badge badge-{{ cve.cvss_severity|lower }}">{{ cve.cvss_severity }}</span>{% else %}N/A{% endif %}</td>
        <td>{% if cve.epss_score is not none %}
          <span class="epss-bar"><span class="epss-bar-fill" style="width: {{ (cve.epss_score * 100)|int }}%;"></span></span>
          {{ "%.1f%%"|format(cve.epss_score * 100) }}
        {% else %}—{% endif %}</td>
        <td style="max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">{{ cve.description[:120] if cve.description else '—' }}</td>
      </tr>
      {% endfor %}
      </tbody>
    </table>
  </div>
</div>
{% endif %}

<div class="two-col">
  <div class="card">
    <div class="card-header">Top PoCs by Stars</div>
    <div class="card-body" style="padding:0;">
      <table>
        <thead><tr><th>Source</th><th>Stars</th><th>URL</th></tr></thead>
        <tbody>
        {% for poc in stats.top_pocs %}
        <tr>
          <td><span class="badge badge-source">{{ poc.source }}</span></td>
          <td>★ {{ poc.stars }}</td>
          <td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"><a href="{{ poc.url }}" target="_blank">{{ poc.url[:60] }}...</a></td>
        </tr>
        {% endfor %}
        </tbody>
      </table>
    </div>
  </div>
  <div class="card">
    <div class="card-header">Attack Tags</div>
    <div class="card-body">
      {% if stats.top_tags %}
      <div class="tag-cloud">
        {% set max_tag = stats.top_tags|map(attribute='cnt')|max %}
        {% for tag in stats.top_tags %}
        <span class="badge badge-tag {% if tag.cnt > max_tag * 0.6 %}large{% endif %}">{{ tag.tag }} ({{ tag.cnt }})</span>
        {% endfor %}
      </div>
      {% else %}
      <p style="color:var(--text-dim);">No attack tags available.</p>
      {% endif %}
    </div>
  </div>
</div>

<!-- Monthly trend -->
{% if stats.monthly_cves %}
<div class="card">
  <div class="card-header">CVEs Published per Month (Last 6 Months)</div>
  <div class="card-body">
    <div class="bar-chart">
    {% set month_max = stats.monthly_cves|map(attribute='cnt')|max %}
    {% for m in stats.monthly_cves %}
      <div class="bar-row">
        <span class="bar-label">{{ m.month }}</span>
        <div class="bar-track">
          <div class="bar-fill monthly" style="width: {{ (m.cnt / month_max * 100)|int }}%;"></div>
        </div>
        <span class="bar-value">{{ m.cnt }}</span>
      </div>
    {% endfor %}
    </div>
  </div>
</div>
{% endif %}

{% if stats.categories %}
<div class="card">
  <div class="card-header">CVEs by Product Category</div>
  <div class="card-body">
    <div class="tag-cloud">
    {% for cat in stats.categories %}
    <span class="badge badge-tag {% if cat.cnt > 50 %}large{% endif %}">{{ cat.category }} ({{ cat.cnt }})</span>
    {% endfor %}
    </div>
  </div>
</div>
{% endif %}

{% if stats.sources %}
<div class="card">
  <div class="card-header">PoC Sources</div>
  <div class="card-body">
    <div class="bar-chart">
    {% set src_max = stats.sources|map(attribute='cnt')|max %}
    {% for src in stats.sources %}
      <div class="bar-row">
        <span class="bar-label">{{ src.source }}</span>
        <div class="bar-track">
          <div class="bar-fill high" style="width: {{ (src.cnt / src_max * 100)|int }}%;"></div>
        </div>
        <span class="bar-value">{{ src.cnt }}</span>
      </div>
    {% endfor %}
    </div>
  </div>
</div>
{% endif %}
"""

SEARCH_TEMPLATE = """
<h2 style="margin-bottom:1rem;">Search results for "{{ query }}" <span style="color:var(--text-dim);font-weight:400;">({{ total }} found)</span></h2>

{% if results %}
{% for cve in results %}
<div class="result-item">
  <a href="/cve/{{ cve.id }}" class="result-id">{{ cve.id }}</a>
  <div style="display:flex;gap:.5rem;margin-top:.25rem;flex-wrap:wrap;align-items:center;">
    {% if cve.cvss_score %}<span class="badge badge-{{ cve.cvss_severity|lower }}">{{ cve.cvss_score }} {{ cve.cvss_severity }}</span>{% endif %}
    {% if cve.kev %}<span class="badge badge-kev">KEV</span>{% endif %}
    {% if cve.epss_score is not none %}
    <span class="epss-bar"><span class="epss-bar-fill" style="width: {{ (cve.epss_score * 100)|int }}%;"></span></span>
    <span class="badge badge-epss">{{ "%.2f%%"|format(cve.epss_score * 100) }}</span>
    {% endif %}
  </div>
  <div class="result-desc">{{ cve.description[:200] }}</div>
</div>
{% endfor %}

{% if total > per_page %}
<div class="pagination">
  {% if page > 1 %}<a href="/search?q={{ query }}&page={{ page - 1 }}">← Prev</a>{% endif %}
  <span class="current">Page {{ page }} of {{ (total / per_page)|round(0, 'ceil')|int }}</span>
  {% if page * per_page < total %}<a href="/search?q={{ query }}&page={{ page + 1 }}">Next →</a>{% endif %}
</div>
{% endif %}

{% else %}
<p style="color:var(--text-dim);">No CVEs found matching "{{ query }}".</p>
{% endif %}
"""

CVE_DETAIL_TEMPLATE = """
<div class="cve-header">
  <div>
    <div class="cve-id">{{ data.cve.id }}</div>
    <div style="display:flex;gap:.5rem;margin-top:.5rem;flex-wrap:wrap;">
      {% if data.cve.cvss_severity %}<span class="badge badge-{{ data.cve.cvss_severity|lower }}">{{ data.cve.cvss_severity }}</span>{% endif %}
      {% if data.cve.kev %}<span class="badge badge-kev">CISA KEV</span>{% endif %}
      {% if data.cve.epss_score is not none %}<span class="badge badge-epss">EPSS {{ "%.4f"|format(data.cve.epss_score) }}</span>{% endif %}
      {% for tag in data.tags %}<span class="badge badge-tag">{{ tag }}</span>{% endfor %}
    </div>
  </div>
  <div class="cve-score">
    <div class="score" style="color:{% if data.cve.cvss_score is not none and data.cve.cvss_score >= 9 %}var(--critical){% elif data.cve.cvss_score is not none and data.cve.cvss_score >= 7 %}var(--high){% elif data.cve.cvss_score is not none and data.cve.cvss_score >= 4 %}var(--orange){% else %}var(--green){% endif %};">
      {{ data.cve.cvss_score or 'N/A' }}
    </div>
    <div class="severity">CVSS Score</div>
    {% if data.cve.epss_score is not none %}
    <div style="margin-top:.5rem;">
      <div style="font-size:.75rem;color:var(--text-dim);margin-bottom:.25rem;">EPSS: {{ "%.2f%%"|format(data.cve.epss_score * 100) }} exploit probability</div>
      <div class="epss-bar" style="width:100px;height:10px;"><div class="epss-bar-fill" style="width: {{ (data.cve.epss_score * 100)|int }}%;"></div></div>
    </div>
    {% endif %}
    {% if data.cve.exploitability_score is not none %}
    <div style="margin-top:.5rem;font-size:.8rem;color:var(--text-dim);">
      Exploitability: <strong>{{ "%.1f"|format(data.cve.exploitability_score) }}/10</strong>
      <div style="margin-top:.25rem;background:var(--bg);border-radius:4px;height:6px;width:100px;overflow:hidden;">
        <div style="background:var(--accent);height:100%;width: {{ (data.cve.exploitability_score * 10)|int }}%;border-radius:4px;"></div>
      </div>
    </div>
    {% endif %}
  </div>
</div>

<div class="description">{{ data.cve.description or 'No description available.' }}</div>

<div style="display:flex;gap:2rem;margin:1rem 0;font-size:.85rem;color:var(--text-dim);flex-wrap:wrap;">
  {% if data.cve.published_at %}<span>Published: {{ data.cve.published_at[:10] }}</span>{% endif %}
  {% if data.cve.first_seen %}<span>First seen: {{ data.cve.first_seen[:10] }}</span>{% endif %}
  {% if data.sources %}<span>Sources: {{ data.sources|join(', ') }}</span>{% endif %}
  {% if data.linked_pocs %}<span>PoCs: {{ data.linked_pocs|length }}</span>{% endif %}
</div>

{% if data.cwes %}
<div class="section">
  <div class="section-title">CWEs</div>
  <div style="display:flex;gap:.5rem;flex-wrap:wrap;">
    {% for cwe in data.cwes %}<span class="badge badge-tag">{{ cwe }}</span>{% endfor %}
  </div>
</div>
{% endif %}

{% if data.products %}
<div class="section">
  <div class="section-title">Affected Products</div>
  <table>
    <thead><tr><th>Vendor</th><th>Product</th><th>Versions</th><th>Category</th></tr></thead>
    <tbody>
    {% for p in data.products %}
    <tr><td>{{ p.vendor }}</td><td>{{ p.product }}</td><td>{{ p.versions or '—' }}</td><td><span class="badge badge-source">{{ p.category }}</span></td></tr>
    {% endfor %}
    </tbody>
  </table>
</div>
{% endif %}

{% if data.linked_pocs %}
<div class="section">
  <div class="section-title">Exploits / PoCs ({{ data.linked_pocs|length }})</div>
  {% for poc in data.linked_pocs %}
  <div class="poc-item">
    <div>
      <a href="{{ poc.url }}" target="_blank" class="poc-url">{{ poc.url }}</a>
      <div class="poc-meta">
        <span class="badge badge-source">{{ poc.source }}</span>
        {% if poc.stars %}★ {{ poc.stars }}{% endif %}
        {% if poc.age_days is not none %}<span style="margin-left:.5rem;">{{ poc.age_days }}d old</span>{% endif %}
      </div>
      {% if poc.description %}<div class="poc-desc">{{ poc.description[:200] }}</div>{% endif %}
    </div>
  </div>
  {% endfor %}
</div>
{% endif %}

{% if data.related_cves %}
<div class="section">
  <div class="section-title">Related CVEs ({{ data.related_cves|length }})</div>
  <table>
    <thead><tr><th>CVE</th><th>CVSS</th><th>Relation</th><th>Description</th></tr></thead>
    <tbody>
    {% for rc in data.related_cves %}
    <tr>
      <td><a href="/cve/{{ rc.id }}" class="id">{{ rc.id }}</a></td>
      <td>{{ rc.cvss_score or 'N/A' }} {{ rc.cvss_severity or '' }}</td>
      <td><span class="badge badge-source">{{ rc.relation|replace('_', ' ') }}</span></td>
      <td style="color:var(--text-dim);">{{ rc.description[:100] }}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
</div>
{% endif %}
"""

LIST_TEMPLATE = """
<h2 style="margin-bottom:1rem;">{{ title }} <span style="color:var(--text-dim);font-weight:400;">({{ total }})</span></h2>

{% if filters %}
<div style="display:flex;gap:.5rem;margin-bottom:.5rem;flex-wrap:wrap;">
  {% for f in filters %}
  <a href="{{ f.url }}" class="badge {% if f.active %}badge-kev{% else %}badge-source{% endif %}">{{ f.label }}</a>
  {% endfor %}
</div>
{% endif %}

{% if sort_filters %}
<div style="display:flex;gap:.5rem;margin-bottom:1rem;flex-wrap:wrap;">
  <span style="font-size:.75rem;color:var(--text-dim);align-self:center;margin-right:.25rem;">Sort:</span>
  {% for f in sort_filters %}
  <a href="{{ f.url }}" class="badge {% if f.active %}badge-epss{% else %}badge-source{% endif %}" style="font-size:.7rem;">{{ f.label }}</a>
  {% endfor %}
</div>
{% endif %}

{% if rows %}
<div class="card">
  <div class="card-body" style="padding:0;">
    <table>
      <thead><tr>{% for col in columns %}<th>{{ col }}</th>{% endfor %}</tr></thead>
      <tbody>
      {% for row in rows %}
      <tr>
        {% for cell in cells %}
        <td>
          {% if cell.type == 'cve_link' %}<a href="/cve/{{ row[cell.key] }}" class="id">{{ row[cell.key] }}</a>
          {% elif cell.type == 'poc_link' %}<a href="{{ row[cell.key] }}" target="_blank" style="font-family:monospace;font-size:.75rem;">{{ row[cell.key][:50] }}...</a>
          {% elif cell.type == 'badge' %}<span class="badge badge-{{ row[cell.key]|lower }}">{{ row[cell.key] }}</span>
          {% elif cell.type == 'score' %}<span style="color:{% if row[cell.key] is not none and row[cell.key] >= 9 %}var(--critical){% elif row[cell.key] is not none and row[cell.key] >= 7 %}var(--high){% elif row[cell.key] is not none and row[cell.key] >= 4 %}var(--orange){% else %}var(--green){% endif %};font-weight:600;">{{ row[cell.key] }}</span>
          {% elif cell.type == 'stars' %}★ {{ row[cell.key] }}
          {% elif cell.type == 'truncate' %}{{ row[cell.key][:120] if row[cell.key] else '—' }}
          {% elif cell.type == 'epss' %}
            {% if row[cell.key] is not none %}
            <span class="epss-bar"><span class="epss-bar-fill" style="width: {{ (row[cell.key] * 100)|int }}%;"></span></span>
            <span style="font-size:.75rem;">{{ "%.1f%%"|format(row[cell.key] * 100) }}</span>
            {% else %}—{% endif %}
          {% elif cell.type == 'kev' %}
            {% if row[cell.key] %}<span class="badge badge-kev">KEV</span>{% else %}—{% endif %}
          {% else %}{{ row[cell.key] or '—' }}{% endif %}
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
  <span class="current">Page {{ page }} of {{ (total / per_page)|round(0, 'ceil')|int }}</span>
  {% if page * per_page < total %}<a href="{{ next_url }}">Next →</a>{% endif %}
</div>
{% endif %}

{% else %}
<p style="color:var(--text-dim);">No results found.</p>
{% endif %}
"""


# ─── Routes ──────────────────────────────────────────────────────────────────

@app.route("/")
def dashboard():
    try:
        stats = get_stats()
    except Exception as e:
        return render_template_string(
            BASE_TEMPLATE, title="Error",
            content=f'<h2>Database Error</h2><p>{e}</p>',
            active="", search_query="",
        ), 500
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
        return render_template_string(
            BASE_TEMPLATE, title="Error",
            content=f'<h2>Search Error</h2><p>{e}</p>',
            active="", search_query=query,
        ), 500
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
        return render_template_string(
            BASE_TEMPLATE, title="Error",
            content=f'<h2>Database Error</h2><p>{e}</p>',
            active="", search_query="",
        ), 500
    if not data:
        not_found = render_template_string(
            '<h2>CVE not found</h2><p>The CVE <code>{{ cve_id }}</code> was not found. <a href="/search?q={{ cve_id }}">Search?</a></p>',
            cve_id=cve_id,
        )
        return render_template_string(
            BASE_TEMPLATE, title="CVE Not Found", content=not_found,
            active="", search_query="",
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
        return render_template_string(
            BASE_TEMPLATE, title="Error",
            content=f'<h2>Database Error</h2><p>{e}</p>',
            active="cves", search_query="",
        ), 500

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
    columns = ["ID", "CVSS", "Severity", "EPSS", "KEV", "Description", "Published"]
    cells = [
        {"type": "cve_link", "key": "id"}, {"type": "score", "key": "cvss_score"},
        {"type": "badge", "key": "cvss_severity"},
        {"type": "epss", "key": "epss_score"},
        {"type": "kev", "key": "kev"},
        {"type": "truncate", "key": "description"},
        {"type": "plain", "key": "published_at"},
    ]
    prev_q = f"&sort={sort}" if sort != "cvss" else ""
    if severity:
        prev_q += f"&severity={severity}"
    if kev_only:
        prev_q += "&kev=1"

    return render_page(
        LIST_TEMPLATE, title="CVEs", active="cves",
        rows=rows, total=total, page=page, per_page=PER_PAGE,
        filters=filters, sort_filters=sort_filters, columns=columns, cells=cells,
        prev_url=f"/cves?page={page - 1}{prev_q}" if page > 1 else None,
        next_url=f"/cves?page={page + 1}{prev_q}" if page * PER_PAGE < total else None,
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
        return render_template_string(
            BASE_TEMPLATE, title="Error",
            content=f'<h2>Database Error</h2><p>{e}</p>',
            active="pocs", search_query="",
        ), 500

    filters = [{"label": "All", "url": "/pocs", "active": not source}]
    for s in sources:
        filters.append({"label": s, "url": f"/pocs?source={s}", "active": source == s})
    columns = ["URL", "Source", "Stars", "Age", "Description"]
    cells = [
        {"type": "poc_link", "key": "url"}, {"type": "badge", "key": "source"},
        {"type": "stars", "key": "stars"}, {"type": "plain", "key": "age_days"},
        {"type": "truncate", "key": "description"},
    ]
    src_q = f"&source={source}" if source else ""

    return render_page(
        LIST_TEMPLATE, title="Proof of Concepts", active="pocs",
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
