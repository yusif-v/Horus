"""SQL queries for the web UI.

Pure read-side data access. No Flask, no templates — call from any
route or test. Returns plain dicts / lists of dicts.
"""

from __future__ import annotations

import re
from datetime import date, timedelta
from typing import Any

from ..core.forecast import epss_velocity
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


def _window_clause(window: str | None) -> str:
    """Return a SQL WHERE fragment that filters CVEs by publication time window.

    Supported values:
        '7d'  → published_at >= date('now', '-7 days')
        '30d' → published_at >= date('now', '-30 days')
        '90d' → published_at >= date('now', '-90 days')
        '1y'  → published_at >= date('now', '-1 year')
        None / 'all' → '' (no filter)
    """
    if not window or window == "all":
        return ""
    mapping = {
        "7d": "-7 days",
        "30d": "-30 days",
        "90d": "-90 days",
        "1y": "-1 year",
    }
    offset = mapping.get(window)
    if offset is None:
        return ""
    return f"published_at >= date('now', '{offset}')"


def get_stats(year: int | None = None, window: str | None = None, recent_limit: int = 5) -> dict:
    """All counts/breakdowns for the dashboard + /api/stats.

    If *year* is given, every query is scoped to CVEs published in that
    year (``strftime('%Y', published_at) = <year>``).

    *window* is a time-window filter applied on top of the year filter:
      '7d'   → last 7 days
      '30d'  → last 30 days
      '90d'  → last 90 days
      '1y'   → last 1 year
      None/'all' → no time window
    """
    with db_connect() as conn:
        # Build WHERE clause fragments for year-scoping
        year_where = ""
        year_param: list[str] = []
        if year is not None:
            year_where = "strftime('%Y', published_at) = ?"
            year_param = [str(year)]

        # Time-window clause
        window_clause = _window_clause(window)

        def _extra(*conds: str) -> str:
            """Build WHERE clause from year + window + extra conditions."""
            parts = [year_where, window_clause, *conds]
            parts = [p for p in parts if p]
            if parts:
                return "WHERE " + " AND ".join(parts)
            return ""

        def _cve_count(*extra_conds: str) -> int:
            where = _extra(*extra_conds)
            return conn.execute(f"SELECT COUNT(*) FROM cve {where}", year_param).fetchone()[0]

        cve_count = _cve_count()
        poc_count = conn.execute("SELECT COUNT(*) FROM poc").fetchone()[0]
        kev_count = _cve_count("kev = 1")
        with_epss = _cve_count("epss_score IS NOT NULL")
        linked_pocs = conn.execute("SELECT COUNT(DISTINCT poc_url) FROM poc_cve").fetchone()[0]
        cves_with_pocs = conn.execute("SELECT COUNT(DISTINCT cve_id) FROM poc_cve").fetchone()[0]

        avg_epss = conn.execute(
            f"SELECT AVG(epss_score) FROM cve {_extra('epss_score IS NOT NULL')}",
            year_param,
        ).fetchone()[0]
        avg_reputation = conn.execute(
            f"SELECT AVG(reputation_score) FROM cve {_extra('reputation_score IS NOT NULL')}",
            year_param,
        ).fetchone()[0]

        social_heat = conn.execute(
            f"SELECT COUNT(*) FROM cve {_extra('social_mentions > 0')}",
            year_param,
        ).fetchone()[0]
        social_mentions_total = conn.execute(
            f"SELECT COALESCE(SUM(social_mentions), 0) FROM cve {_extra()}",
            year_param,
        ).fetchone()[0]

        try:
            watchlist_count = conn.execute(
                "SELECT COUNT(*) FROM cve_watchlist WHERE resolved = 0"
            ).fetchone()[0]
        except Exception:
            watchlist_count = 0

        severity_breakdown = _rows_to_dicts(
            conn.execute(
                f"SELECT cvss_severity, COUNT(*) as cnt FROM cve"
                f" {_extra('cvss_severity IS NOT NULL')}"
                f" GROUP BY cvss_severity ORDER BY cnt DESC",
                year_param,
            ).fetchall()
        )

        epss_buckets = _rows_to_dicts(
            conn.execute(
                f"""
            SELECT CASE
                WHEN epss_score >= 0.5 THEN 'Very High (≥0.5)'
                WHEN epss_score >= 0.1 THEN 'High (0.1-0.5)'
                WHEN epss_score >= 0.01 THEN 'Medium (0.01-0.1)'
                WHEN epss_score IS NOT NULL THEN 'Low (<0.01)'
            END as bucket, COUNT(*) as cnt
            FROM cve {_extra("epss_score IS NOT NULL")}
            GROUP BY bucket ORDER BY cnt DESC
        """,
                year_param,
            ).fetchall()
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
                f"SELECT id, cvss_score, cvss_severity, description, epss_score, kev, published_at, trust_score, threatfox_ioc_count, stealer_hits"
                f" FROM cve {_extra()}"
                f" ORDER BY published_at DESC LIMIT ?",
                [*year_param, recent_limit],
            ).fetchall()
        )

        top_pocs = _rows_to_dicts(
            conn.execute(
                "SELECT url, source, stars, description FROM poc WHERE stars IS NOT NULL"
                " ORDER BY stars DESC LIMIT 10"
            ).fetchall()
        )

        highest_epss = _rows_to_dicts(
            conn.execute(
                f"""
            SELECT id, cvss_score, cvss_severity, epss_score, kev FROM cve
            {_extra("epss_score IS NOT NULL")} ORDER BY epss_score DESC LIMIT 10
        """,
                year_param,
            ).fetchall()
        )

        kev_cves = _rows_to_dicts(
            conn.execute(
                f"""
            SELECT id, cvss_score, cvss_severity, epss_score, description FROM cve
            {_extra("kev = 1")} ORDER BY cvss_score DESC LIMIT 10
        """,
                year_param,
            ).fetchall()
        )

        monthly_cves = _rows_to_dicts(
            conn.execute(
                f"""
            SELECT strftime('%Y-%m', published_at) as month, COUNT(*) as cnt
            FROM cve {_extra("published_at IS NOT NULL")}
              AND published_at >= date('now', '-6 months')
            GROUP BY month ORDER BY month
        """,
                year_param,
            ).fetchall()
        )

        weaponized = conn.execute(
            f"""
            SELECT COUNT(DISTINCT c.id) FROM cve c
            JOIN poc_cve pc ON pc.cve_id = c.id
            {_extra("c.cvss_score >= 9")}
        """,
            year_param,
        ).fetchone()[0]
        imminent = _cve_count("epss_score >= 0.5")
        actionable = conn.execute(
            f"""
            SELECT COUNT(DISTINCT c.id) FROM cve c
            LEFT JOIN poc_cve pc ON pc.cve_id = c.id
            {_extra("c.kev = 1 OR (c.epss_score >= 0.5 AND pc.cve_id IS NOT NULL)")}
        """,
            year_param,
        ).fetchone()[0]
        latest_update = conn.execute(
            f"SELECT MAX(first_seen) FROM cve {_extra()}", year_param
        ).fetchone()[0]
        imminence_buckets = _rows_to_dicts(
            conn.execute(
                f"""
            SELECT imminence_bucket as bucket, COUNT(*) as cnt
            FROM cve {_extra("imminence_bucket IS NOT NULL")}
            GROUP BY bucket ORDER BY cnt DESC
        """,
                year_param,
            ).fetchall()
        )

        high_trust_count = _cve_count("trust_score >= 50")
        threatfox_hits = conn.execute(
            f"SELECT COUNT(*) FROM cve {_extra('threatfox_ioc_count > 0')}",
            year_param,
        ).fetchone()[0]
        stealer_compromised_count = conn.execute(
            f"SELECT COUNT(*) FROM cve {_extra('stealer_hits > 0')}",
            year_param,
        ).fetchone()[0]

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
        "imminence_buckets": imminence_buckets,
        "actionable": actionable,
        "latest_update": latest_update,
        "high_trust_count": high_trust_count,
        "threatfox_hits": threatfox_hits,
        "stealer_compromised_count": stealer_compromised_count,
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
                " FROM cve WHERE id LIKE ? ORDER BY cvss_score DESC",
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
            " ORDER BY cvss_score DESC LIMIT ? OFFSET ?",
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
            SELECT p.url, p.source, p.stars, p.age_days, p.description, p.exploit_type
            FROM poc_cve pc JOIN poc p ON p.url = pc.poc_url
            WHERE pc.cve_id = ? ORDER BY p.stars DESC
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

        # "newest=desc" means newest first (smallest age). Flip when asc.
        if sort == "newest":
            primary = f"{age_expr} {'DESC' if direction == 'asc' else 'ASC'}"
            order_by = f"{primary}, p.first_seen DESC"
        elif sort == "stars":
            order_by = f"p.stars {d}, p.first_seen DESC"
        elif sort == "source":
            order_by = f"p.source {d}, p.first_seen DESC"
        else:
            order_by = f"{age_expr} ASC, p.first_seen DESC"
        rows = conn.execute(
            f"""SELECT p.url, p.source, p.stars, p.description, p.first_seen,
                       p.repo_created_at, p.exploit_type,
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


# ── Linked sources (CVE ↔ news) ─────────────────────────────────────────────


def linked_sources(cve_id: str, limit: int = 10) -> list[dict]:
    """Return linked intelligence sources (news articles) for a CVE.

    Latest *limit* articles by ``published_at`` joined through
    ``news_article_cve``.  Each dict carries the news-article fields
    plus the ``snippet`` and ``context`` from the link table.
    """
    cve_id = cve_id.upper()
    with db_connect() as conn:
        rows = conn.execute(
            """
            SELECT na.id, na.title, na.url, na.source, na.tier,
                   na.published_at, nac.snippet, nac.context
            FROM news_article_cve nac
            JOIN news_article na ON na.id = nac.article_id
            WHERE nac.cve_id = ?
            ORDER BY na.published_at DESC
            LIMIT ?
            """,
            (cve_id, limit),
        ).fetchall()
        return _rows_to_dicts(rows)


# ── News ─────────────────────────────────────────────────────────────────────


def get_news(
    page: int = 1,
    per_page: int = 20,
    tier_filter: int | None = None,
    source_filter: str | None = None,
    sort: str = "newest",
    direction: str = "desc",
) -> tuple[list[dict], int]:
    conditions: list[str] = []
    params: list[Any] = []
    if tier_filter is not None:
        conditions.append("tier = ?")
        params.append(tier_filter)
    if source_filter:
        conditions.append("source = ?")
        params.append(source_filter)
    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    with db_connect() as conn:
        total = conn.execute(f"SELECT COUNT(*) FROM news_article {where}", params).fetchone()[0]
        offset = (page - 1) * per_page
        d_kw = "ASC" if direction == "asc" else "DESC"
        sort_cols = {
            "newest": "first_seen",
            "tier": "tier",
            "source": "source",
            "published": "published_at",
        }
        col = sort_cols.get(sort, "first_seen")
        order_by = f"{col} {d_kw}, first_seen DESC"
        rows = conn.execute(
            f"""SELECT id, title, url, source, tier, summary, published_at, first_seen
                FROM news_article
                {where}
                ORDER BY {order_by} LIMIT ? OFFSET ?""",
            [*params, per_page, offset],
        ).fetchall()
        return _rows_to_dicts(rows), total


_EPSS_TREND_THRESHOLD = 0.005


def _classify_trend(velocity: float) -> str:
    if velocity > _EPSS_TREND_THRESHOLD:
        return "rising"
    if velocity < -_EPSS_TREND_THRESHOLD:
        return "falling"
    return "stable"


# ── EPSS trends ─────────────────────────────────────────────────────────────


def epss_trend(cve_id: str) -> dict:
    """Get EPSS history + computed trend for a CVE."""
    since = (date.today() - timedelta(days=30)).isoformat()
    with db_connect() as conn:
        rows = conn.execute(
            "SELECT score, recorded_at FROM epss_history"
            " WHERE cve_id = ? AND recorded_at >= ?"
            " ORDER BY recorded_at ASC",
            (cve_id, since),
        ).fetchall()
        history = [{"score": r[0], "recorded_at": r[1]} for r in rows]
        velocity = epss_velocity(cve_id, conn)
        trend = _classify_trend(velocity)
        days_above = sum(1 for r in rows if r[0] >= 0.50)
        current = rows[-1][0] if rows else None
    return {
        "cve_id": cve_id,
        "current_score": current,
        "velocity": velocity,
        "trend": trend,
        "days_above_50pct": days_above,
        "history": history,
    }


def epss_movers(days: int = 7, limit: int = 20) -> list[dict]:
    """Top EPSS velocity changes in last N days."""
    since = (date.today() - timedelta(days=days)).isoformat()
    with db_connect() as conn:
        cve_ids = [
            r[0]
            for r in conn.execute(
                "SELECT DISTINCT cve_id FROM epss_history WHERE recorded_at >= ?",
                (since,),
            ).fetchall()
        ]
        results = []
        for cid in cve_ids:
            rows = conn.execute(
                "SELECT score, recorded_at FROM epss_history"
                " WHERE cve_id = ? AND recorded_at >= ?"
                " ORDER BY recorded_at DESC LIMIT 2",
                (cid, since),
            ).fetchall()
            if len(rows) < 2:
                continue
            (s_new, d_new), (s_old, d_old) = rows[0], rows[1]
            try:
                day_diff = (date.fromisoformat(d_new) - date.fromisoformat(d_old)).days
            except ValueError:
                continue
            if day_diff <= 0:
                continue
            velocity = float((float(s_new) - float(s_old)) / day_diff)
            current_score = rows[0][0]
            previous_score = rows[1][0]
            cve = conn.execute("SELECT cvss_score, kev FROM cve WHERE id = ?", (cid,)).fetchone()
            results.append(
                {
                    "cve_id": cid,
                    "current_score": current_score,
                    "previous_score": previous_score,
                    "velocity": velocity,
                    "trend": _classify_trend(velocity),
                    "cvss_score": cve[0] if cve else None,
                    "kev": cve[1] if cve else 0,
                }
            )
    results.sort(key=lambda x: abs(x["velocity"]), reverse=True)
    return results[:limit]


def epss_threshold_alerts(days: int = 7) -> list[dict]:
    """CVEs that crossed 50% EPSS in last N days."""
    since = (date.today() - timedelta(days=days)).isoformat()
    with db_connect() as conn:
        cve_ids = [
            r[0]
            for r in conn.execute(
                "SELECT DISTINCT cve_id FROM epss_history WHERE recorded_at >= ?",
                (since,),
            ).fetchall()
        ]
        results = []
        for cid in cve_ids:
            rows = conn.execute(
                "SELECT score, recorded_at FROM epss_history"
                " WHERE cve_id = ? AND recorded_at >= ?"
                " ORDER BY recorded_at ASC",
                (cid, since),
            ).fetchall()
            if len(rows) < 2:
                continue
            first_score, _first_date = rows[0]
            last_score, last_date = rows[-1]
            if first_score < 0.50 and last_score >= 0.50:
                results.append({"cve_id": cid, "crossed_at": last_date, "direction": "above"})
            elif first_score >= 0.50 and last_score < 0.50:
                results.append({"cve_id": cid, "crossed_at": last_date, "direction": "below"})
    return results


# ── correlations ─────────────────────────────────────────────────────────


def related_cves(cve_id: str, limit: int = 10) -> list[dict]:
    """Return related CVEs for a given CVE, ordered by correlation score desc."""
    cve_id = cve_id.upper()
    with db_connect() as conn:
        rows = conn.execute(
            """
            SELECT c.related_id AS id, c.score, c.reasons,
                   cv.cvss_score, cv.cvss_severity, cv.description
            FROM cve_correlation c
            JOIN cve cv ON cv.id = c.related_id
            WHERE c.cve_id = ?
            ORDER BY c.score DESC
            LIMIT ?
            """,
            (cve_id, limit),
        ).fetchall()
        return _rows_to_dicts(rows)


def correlation_clusters(limit: int = 50) -> list[dict]:
    """Return all correlation clusters with their metadata."""
    with db_connect() as conn:
        rows = conn.execute(
            """
            SELECT id, label, centroid_cve, cve_count, created_at
            FROM cve_cluster
            ORDER BY cve_count DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return _rows_to_dicts(rows)


def cluster_members(cluster_id: int) -> list[dict]:
    """Return members of a correlation cluster, ordered by membership score desc."""
    with db_connect() as conn:
        rows = conn.execute(
            """
            SELECT cm.cve_id AS id, cm.membership_score,
                   c.cvss_score, c.cvss_severity, c.description
            FROM cve_cluster_member cm
            JOIN cve c ON c.id = cm.cve_id
            WHERE cm.cluster_id = ?
            ORDER BY cm.membership_score DESC
            """,
            (cluster_id,),
        ).fetchall()
        return _rows_to_dicts(rows)
