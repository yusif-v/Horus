"""SQL queries for the web UI.

Pure read-side data access. No Flask, no templates — call from any
route or test. Returns plain dicts / lists of dicts.
"""

from __future__ import annotations

import re

from ..storage import db as _storage

# Re-export for tests that monkey-patch DB_PATH on the web module.
DB_PATH = _storage.DB_PATH
PER_PAGE_DEFAULT = 20


# ── connection ──────────────────────────────────────────────────────────────


def db_connect():
    """Open the SQLite DB via the storage layer's context manager.

    One DB-access path across the whole codebase. Web is read-only so
    the commit-on-clean-exit semantics from storage.db.connect() are
    harmless.
    """
    return _storage.connect()


def _row_to_dict(row) -> dict:
    return dict(row) if row else {}


def _rows_to_dicts(rows) -> list[dict]:
    return [dict(r) for r in rows]


# ── rail (top status strip) ─────────────────────────────────────────────────


def rail_stats() -> dict:
    try:
        with db_connect() as conn:
            cve_n = conn.execute("SELECT COUNT(*) FROM cve").fetchone()[0]
            poc_n = conn.execute("SELECT COUNT(*) FROM poc").fetchone()[0]
            last = conn.execute("SELECT MAX(first_seen) FROM cve").fetchone()[0]
        return {"cve_n": cve_n, "poc_n": poc_n, "last": last}
    except Exception:
        return {"cve_n": "—", "poc_n": "—", "last": None}


# ── dashboard ───────────────────────────────────────────────────────────────


def get_stats() -> dict:
    """All counts/breakdowns for the dashboard + /api/stats."""
    with db_connect() as conn:
        cve_count = conn.execute("SELECT COUNT(*) FROM cve").fetchone()[0]
        poc_count = conn.execute("SELECT COUNT(*) FROM poc").fetchone()[0]
        kev_count = conn.execute("SELECT COUNT(*) FROM cve WHERE kev = 1").fetchone()[0]
        with_epss = conn.execute(
            "SELECT COUNT(*) FROM cve WHERE epss_score IS NOT NULL"
        ).fetchone()[0]
        linked_pocs = conn.execute("SELECT COUNT(DISTINCT poc_url) FROM poc_cve").fetchone()[0]
        cves_with_pocs = conn.execute("SELECT COUNT(DISTINCT cve_id) FROM poc_cve").fetchone()[0]

        avg_epss = conn.execute(
            "SELECT AVG(epss_score) FROM cve WHERE epss_score IS NOT NULL"
        ).fetchone()[0]
        avg_reputation = conn.execute(
            "SELECT AVG(reputation_score) FROM cve WHERE reputation_score IS NOT NULL"
        ).fetchone()[0]

        social_heat = conn.execute("SELECT COUNT(*) FROM cve WHERE social_mentions > 0").fetchone()[
            0
        ]
        social_mentions_total = conn.execute(
            "SELECT COALESCE(SUM(social_mentions), 0) FROM cve"
        ).fetchone()[0]

        try:
            watchlist_count = conn.execute(
                "SELECT COUNT(*) FROM cve_watchlist WHERE resolved = 0"
            ).fetchone()[0]
        except Exception:
            watchlist_count = 0

        severity_breakdown = _rows_to_dicts(
            conn.execute(
                "SELECT cvss_severity, COUNT(*) as cnt FROM cve WHERE cvss_severity IS NOT NULL"
                " GROUP BY cvss_severity ORDER BY cnt DESC"
            ).fetchall()
        )

        epss_buckets = _rows_to_dicts(
            conn.execute("""
            SELECT CASE
                WHEN epss_score >= 0.5 THEN 'Very High (≥0.5)'
                WHEN epss_score >= 0.1 THEN 'High (0.1-0.5)'
                WHEN epss_score >= 0.01 THEN 'Medium (0.01-0.1)'
                WHEN epss_score IS NOT NULL THEN 'Low (<0.01)'
            END as bucket, COUNT(*) as cnt
            FROM cve WHERE epss_score IS NOT NULL
            GROUP BY bucket ORDER BY cnt DESC
        """).fetchall()
        )

        sources = _rows_to_dicts(
            conn.execute(
                "SELECT source, COUNT(*) as cnt FROM poc GROUP BY source ORDER BY cnt DESC"
            ).fetchall()
        )

        categories = _rows_to_dicts(
            conn.execute(
                "SELECT p.category, COUNT(DISTINCT cp.cve_id) as cnt FROM cve_product cp"
                " JOIN product p ON p.id = cp.product_id"
                " GROUP BY p.category ORDER BY cnt DESC"
            ).fetchall()
        )

        top_tags = _rows_to_dicts(
            conn.execute(
                "SELECT tag, COUNT(*) as cnt FROM cve_attack_tag GROUP BY tag ORDER BY cnt DESC LIMIT 15"
            ).fetchall()
        )

        recent_cves = _rows_to_dicts(
            conn.execute(
                "SELECT id, cvss_score, cvss_severity, description, epss_score, kev, published_at"
                " FROM cve ORDER BY published_at DESC NULLS LAST LIMIT 10"
            ).fetchall()
        )

        top_pocs = _rows_to_dicts(
            conn.execute(
                "SELECT url, source, stars, description FROM poc WHERE stars IS NOT NULL"
                " ORDER BY stars DESC LIMIT 10"
            ).fetchall()
        )

        highest_epss = _rows_to_dicts(
            conn.execute("""
            SELECT id, cvss_score, cvss_severity, epss_score, kev FROM cve
            WHERE epss_score IS NOT NULL ORDER BY epss_score DESC LIMIT 10
        """).fetchall()
        )

        kev_cves = _rows_to_dicts(
            conn.execute("""
            SELECT id, cvss_score, cvss_severity, epss_score, description FROM cve
            WHERE kev = 1 ORDER BY cvss_score DESC NULLS LAST LIMIT 10
        """).fetchall()
        )

        monthly_cves = _rows_to_dicts(
            conn.execute("""
            SELECT strftime('%Y-%m', published_at) as month, COUNT(*) as cnt
            FROM cve WHERE published_at IS NOT NULL
              AND published_at >= date('now', '-6 months')
            GROUP BY month ORDER BY month
        """).fetchall()
        )

        weaponized = conn.execute("""
            SELECT COUNT(DISTINCT c.id) FROM cve c
            JOIN poc_cve pc ON pc.cve_id = c.id
            WHERE c.cvss_score >= 9
        """).fetchone()[0]
        imminent = conn.execute("SELECT COUNT(*) FROM cve WHERE epss_score >= 0.5").fetchone()[0]
        actionable = conn.execute("""
            SELECT COUNT(DISTINCT c.id) FROM cve c
            LEFT JOIN poc_cve pc ON pc.cve_id = c.id
            WHERE c.kev = 1 OR (c.epss_score >= 0.5 AND pc.cve_id IS NOT NULL)
        """).fetchone()[0]
        latest_update = conn.execute("SELECT MAX(first_seen) FROM cve").fetchone()[0]

    return {
        "cve_count": cve_count,
        "poc_count": poc_count,
        "kev_count": kev_count,
        "with_epss": with_epss,
        "linked_pocs": linked_pocs,
        "cves_with_pocs": cves_with_pocs,
        "avg_epss": avg_epss,
        "avg_reputation": avg_reputation,
        "social_heat": social_heat,
        "social_mentions_total": social_mentions_total,
        "watchlist_count": watchlist_count,
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


# ── search ──────────────────────────────────────────────────────────────────


def search_cves(query: str, page: int = 1, per_page: int = 20) -> tuple[list[dict], int]:
    query = query.strip()
    is_cve_id = query.upper().startswith("CVE-") or query.replace("-", "").isdigit()

    with db_connect() as conn:
        if is_cve_id:
            cve_id = query.upper()
            if not cve_id.startswith("CVE-"):
                cve_id = f"CVE-{cve_id}"
            rows = conn.execute(
                "SELECT id, cvss_score, cvss_severity, description, epss_score, kev, published_at"
                " FROM cve WHERE id LIKE ? ORDER BY cvss_score DESC NULLS LAST",
                (f"{cve_id}%",),
            ).fetchall()
            results = _rows_to_dicts(rows)
            return results, len(results)

        pattern = f"%{query}%"
        total = conn.execute(
            "SELECT COUNT(*) FROM cve WHERE id LIKE ? OR description LIKE ?",
            (pattern, pattern),
        ).fetchone()[0]
        offset = (page - 1) * per_page
        rows = conn.execute(
            "SELECT id, cvss_score, cvss_severity, description, epss_score, kev, published_at"
            " FROM cve WHERE id LIKE ? OR description LIKE ?"
            " ORDER BY cvss_score DESC NULLS LAST LIMIT ? OFFSET ?",
            (pattern, pattern, per_page, offset),
        ).fetchall()
        return _rows_to_dicts(rows), total


# ── CVE detail ──────────────────────────────────────────────────────────────


def group_products_by_vendor(products: list[dict]) -> list[dict]:
    """Group flat product list into vendor → products hierarchy.

    Input:  [{"vendor": "nginx", "product": "nginx", "versions": [...], "category": "web-server"}, ...]
    Output: [{"vendor": "nginx", "products": [{"product": "nginx", "versions": [...], "category": "web-server"}, ...]}, ...]
    """
    vendors: dict[str, dict] = {}
    for p in products:
        vendor = p.get("vendor", "unknown")
        if vendor not in vendors:
            vendors[vendor] = {"vendor": vendor, "products": []}
        versions_raw = p.get("versions", "")
        versions_list = (
            [v.strip() for v in versions_raw.split(";") if v.strip()] if versions_raw else []
        )
        vendors[vendor]["products"].append(
            {
                "product": p.get("product", "unknown"),
                "versions": versions_list,
                "category": p.get("category", "unknown"),
            }
        )
    # Sort vendors alphabetically, unknown last
    return sorted(vendors.values(), key=lambda v: (v["vendor"] == "unknown", v["vendor"]))


def get_cve_detail(cve_id: str) -> dict | None:
    cve_id = cve_id.upper()
    if not cve_id.startswith("CVE-") and re.match(r"^\d{4}-\d{4,}$", cve_id):
        cve_id = f"CVE-{cve_id}"

    with db_connect() as conn:
        cve = _row_to_dict(conn.execute("SELECT * FROM cve WHERE id = ?", (cve_id,)).fetchone())
        if not cve:
            return None

        tags = [
            r[0] for r in conn.execute("SELECT tag FROM cve_attack_tag WHERE cve_id = ?", (cve_id,))
        ]
        cwes = [
            r[0] for r in conn.execute("SELECT cwe_id FROM cve_cwe WHERE cve_id = ?", (cve_id,))
        ]
        products = _rows_to_dicts(
            conn.execute(
                """
            SELECT p.vendor, p.product, cp.versions, p.category
            FROM cve_product cp JOIN product p ON p.id = cp.product_id
            WHERE cp.cve_id = ?
        """,
                (cve_id,),
            )
        )
        sources = [
            r[0] for r in conn.execute("SELECT source FROM cve_source WHERE cve_id = ?", (cve_id,))
        ]
        linked_pocs = _rows_to_dicts(
            conn.execute(
                """
            SELECT p.url, p.source, p.stars, p.age_days, p.description
            FROM poc_cve pc JOIN poc p ON p.url = pc.poc_url
            WHERE pc.cve_id = ? ORDER BY p.stars DESC NULLS LAST
        """,
                (cve_id,),
            )
        )
        social_posts = _rows_to_dicts(
            conn.execute(
                """
            SELECT url, source, screen_name, likes, retweets, replies, views, first_seen
            FROM cve_social_post
            WHERE cve_id = ?
            ORDER BY (COALESCE(likes,0) + COALESCE(retweets,0) * 3) DESC,
                     first_seen DESC
            LIMIT 20
        """,
                (cve_id,),
            )
        )

        related: dict[str, dict] = {}
        if tags:
            placeholders = ",".join("?" * len(tags))
            for r in conn.execute(
                f"""
                SELECT DISTINCT c.id, c.cvss_score, c.cvss_severity, c.description
                FROM cve c JOIN cve_attack_tag cat ON cat.cve_id = c.id
                WHERE cat.tag IN ({placeholders}) AND c.id != ?
                ORDER BY c.cvss_score DESC LIMIT 10
            """,
                (*tags, cve_id),
            ):
                rid = r[0]
                if rid not in related:
                    related[rid] = {
                        "id": rid,
                        "cvss_score": r[1],
                        "cvss_severity": r[2],
                        "description": (r[3] or "")[:100],
                        "relation": "same_attack_tag",
                    }
        for prod in products:
            for r in conn.execute(
                """
                SELECT DISTINCT c.id, c.cvss_score, c.cvss_severity, c.description
                FROM cve c JOIN cve_product cp ON cp.cve_id = c.id
                JOIN product p ON p.id = cp.product_id
                WHERE p.vendor = ? AND p.product = ? AND c.id != ?
                ORDER BY c.cvss_score DESC LIMIT 5
            """,
                (prod["vendor"], prod["product"], cve_id),
            ):
                rid = r[0]
                if rid not in related:
                    related[rid] = {
                        "id": rid,
                        "cvss_score": r[1],
                        "cvss_severity": r[2],
                        "description": (r[3] or "")[:100],
                        "relation": "same_product",
                    }

    return {
        "cve": cve,
        "tags": tags,
        "cwes": cwes,
        "products": products,
        "products_grouped": group_products_by_vendor(products),
        "product_count": len(set((p["vendor"], p["product"]) for p in products)),
        "sources": sources,
        "linked_pocs": linked_pocs,
        "social_posts": social_posts,
        "related_cves": list(related.values()),
    }


# ── PoC list ────────────────────────────────────────────────────────────────


def fetch_pocs(
    page: int = 1,
    per_page: int = 20,
    source_filter: str | None = None,
    sort: str = "age",
    direction: str = "desc",
) -> tuple[list[dict], int]:
    with db_connect() as conn:
        where, params = "", []
        if source_filter:
            where, params = "WHERE source = ?", [source_filter]
        total = conn.execute(f"SELECT COUNT(*) FROM poc {where}", params).fetchone()[0]
        offset = (page - 1) * per_page
        # Dynamic age computation from repo_created_at, with fallback to first_seen
        age_expr = """CAST((julianday('now') - julianday(
            COALESCE(p.repo_created_at, p.first_seen)
        )) AS INTEGER)"""
        d = "ASC" if direction == "asc" else "DESC"
        nulls = "NULLS FIRST" if d == "ASC" else "NULLS LAST"
        # "newest=desc" means newest first (smallest age). Flip when asc.
        if sort == "newest":
            primary = f"{age_expr} {'DESC' if direction == 'asc' else 'ASC'}"
            order_by = f"{primary}, p.first_seen DESC"
        elif sort == "stars":
            order_by = f"p.stars {d} {nulls}, p.first_seen DESC"
        elif sort == "source":
            order_by = f"p.source {d}, p.first_seen DESC"
        else:
            order_by = f"{age_expr} ASC, p.first_seen DESC"
        rows = conn.execute(
            f"""SELECT p.url, p.source, p.stars, p.description, p.first_seen,
                       p.repo_created_at,
                       {age_expr} AS age_days,
                       GROUP_CONCAT(pc.cve_id) AS cve_ids
                FROM poc p
                LEFT JOIN poc_cve pc ON pc.poc_url = p.url
                {where}
                GROUP BY p.url
                ORDER BY {order_by} LIMIT ? OFFSET ?""",
            [*params, per_page, offset],
        ).fetchall()
        results = []
        for r in rows:
            d = dict(r)
            d["cve_ids"] = d["cve_ids"].split(",") if d["cve_ids"] else []
            results.append(d)
        return results, total


def safe_int(value: str, default: int = 1, min_val: int = 1, max_val: int = 10000) -> int:
    try:
        return max(min_val, min(int(value), max_val))
    except (ValueError, TypeError):
        return default
