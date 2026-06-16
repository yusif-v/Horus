"""Vendors exposure dashboard — /vendors."""

from __future__ import annotations

from flask import Blueprint, request

from .._render import error_page, page
from ..queries import PER_PAGE_DEFAULT, _rows_to_dicts, db_connect, safe_int
from .auth import READ_ALL, role_required

bp = Blueprint("vendors", __name__)

VALID_SORTS = {"count", "cvss", "epss", "name"}


@bp.route("/vendors")
@role_required(*READ_ALL)
def list_vendors():
    pg = safe_int(request.args.get("page", "1"))
    sort = request.args.get("sort", "count")
    if sort not in VALID_SORTS:
        sort = "count"
    category_filter = request.args.get("category")
    watchlist_only = request.args.get("watchlist")

    sort_map = {
        "count": "cve_count DESC",
        "cvss": "avg_cvss DESC NULLS LAST",
        "epss": "avg_epss DESC NULLS LAST",
        "name": "v.vendor ASC",
    }
    order = sort_map.get(sort, sort_map["count"])

    try:
        with db_connect() as conn:
            # Build vendor stats query
            where_clauses = []
            params: list = []

            if category_filter:
                where_clauses.append("p.category = ?")
                params.append(category_filter)

            if watchlist_only:
                where_clauses.append(
                    "EXISTS (SELECT 1 FROM team_watchlist tw WHERE tw.vendor = p.vendor)"
                )

            where = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

            vendor_sql = (
                "SELECT p.vendor,"
                " COUNT(DISTINCT cp.cve_id) AS cve_count,"
                " ROUND(AVG(c.cvss_score), 1) AS avg_cvss,"
                " ROUND(AVG(c.epss_score), 4) AS avg_epss,"
                " COUNT(DISTINCT CASE WHEN c.kev = 1 THEN c.id END) AS kev_count,"
                " GROUP_CONCAT(DISTINCT p.category) AS categories"
                " FROM cve_product cp"
                " JOIN product p ON p.id = cp.product_id"
                " JOIN cve c ON c.id = cp.cve_id"
                f" {where}"
                " GROUP BY p.vendor"
                f" ORDER BY {order}"
            )
            all_rows = _rows_to_dicts(conn.execute(vendor_sql, params).fetchall())

            # Check watchlist status
            watchlist_vendors = set()
            try:
                watchlist_rows = conn.execute(
                    "SELECT DISTINCT vendor FROM team_watchlist"
                ).fetchall()
                watchlist_vendors = {r[0] for r in watchlist_rows}
            except Exception:
                pass

            for row in all_rows:
                row["in_watchlist"] = row["vendor"] in watchlist_vendors

            total = len(all_rows)
            offset = (pg - 1) * PER_PAGE_DEFAULT
            rows = all_rows[offset : offset + PER_PAGE_DEFAULT]

            # Fetch categories for filter
            categories = [
                r[0]
                for r in conn.execute(
                    "SELECT DISTINCT p.category FROM cve_product cp JOIN product p ON p.id = cp.product_id ORDER BY p.category"
                ).fetchall()
            ]
    except Exception as e:
        return error_page(f"Database Error: {e}", active="vendors"), 500

    sort_filters = [
        {"label": "By CVE count", "url": "/vendors?sort=count", "active": sort == "count"},
        {"label": "By avg CVSS", "url": "/vendors?sort=cvss", "active": sort == "cvss"},
        {"label": "By avg EPSS", "url": "/vendors?sort=epss", "active": sort == "epss"},
        {"label": "A-Z", "url": "/vendors?sort=name", "active": sort == "name"},
    ]

    # Category filter chips
    cat_filters = [
        {"label": "All categories", "url": f"/vendors?sort={sort}", "active": not category_filter},
    ]
    for cat in categories:
        cat_filters.append(
            {
                "label": cat,
                "url": f"/vendors?sort={sort}&category={cat}",
                "active": category_filter == cat,
            }
        )

    # Watchlist toggle
    wl_filters = [
        {
            "label": "All vendors",
            "url": f"/vendors?sort={sort}"
            + (f"&category={category_filter}" if category_filter else ""),
            "active": not watchlist_only,
        },
        {
            "label": "Watchlist only",
            "url": f"/vendors?sort={sort}&watchlist=1"
            + (f"&category={category_filter}" if category_filter else ""),
            "active": bool(watchlist_only),
        },
    ]

    columns = ["Vendor", "CVEs", "Avg CVSS", "Avg EPSS", "KEV", "Categories", "Watchlist"]
    col_widths = ["200px", "80px", "100px", "100px", "70px", "auto", "100px"]
    cells = [
        {"type": "vendor_link", "key": "vendor"},
        {"type": "plain", "key": "cve_count"},
        {"type": "score", "key": "avg_cvss"},
        {"type": "epss", "key": "avg_epss"},
        {"type": "plain", "key": "kev_count"},
        {"type": "categories", "key": "categories"},
        {"type": "watchlist_badge", "key": "in_watchlist"},
    ]

    qs = (
        f"&sort={sort}"
        + (f"&category={category_filter}" if category_filter else "")
        + ("&watchlist=1" if watchlist_only else "")
    )
    total_pages = (total + PER_PAGE_DEFAULT - 1) // PER_PAGE_DEFAULT if total > 0 else 1

    return page(
        "vendors.html",
        title="Vendor exposure",
        active="vendors",
        eyebrow="Attack surface · vendors",
        subtitle=f"CVE exposure across {total} vendors indexed in the local database. Click a vendor to see all its CVEs.",
        rows=rows,
        total=total,
        page=pg,
        per_page=PER_PAGE_DEFAULT,
        sort_filters=sort_filters,
        cat_filters=cat_filters,
        wl_filters=wl_filters,
        columns=columns,
        col_widths=col_widths,
        cells=cells,
        prev_url=f"/vendors?page={pg - 1}{qs}" if pg > 1 else None,
        next_url=f"/vendors?page={pg + 1}{qs}" if pg * PER_PAGE_DEFAULT < total else None,
        total_pages=total_pages,
    )
