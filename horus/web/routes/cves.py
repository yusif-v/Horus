"""CVE index route — /cves with filter + sort + pagination."""

from __future__ import annotations

from flask import Blueprint, request

from .._render import error_page, page
from ..queries import PER_PAGE_DEFAULT, _rows_to_dicts, db_connect, safe_int
from .auth import READ_ALL, role_required

bp = Blueprint("cves", __name__)

ORDER_COLS = {
    "cvss": "cvss_score",
    "epss": "epss_score",
    "kev": "kev",
    "date": "published_at",
    "newest": "first_seen",
    "social": "social_mentions",
    "poc_count": "(SELECT COUNT(*) FROM poc_cve WHERE cve_id = c.id)",
}


def _order_clause(sort: str, direction: str) -> str:
    col = ORDER_COLS.get(sort, ORDER_COLS["cvss"])
    d = "ASC" if direction == "asc" else "DESC"
    nulls = "NULLS FIRST" if d == "ASC" else "NULLS LAST"
    if sort == "kev":
        return f"kev {d} {nulls}, cvss_score DESC NULLS LAST"
    return f"{col} {d} {nulls}"


WINDOW_DAYS = {"day": 1, "week": 7, "month": 30}


def _build_qs(**kwargs) -> str:
    """Build query string from kwargs, skipping None values."""
    parts = {k: v for k, v in kwargs.items() if v is not None and v != ""}
    return "?" + "&".join(f"{k}={v}" for k, v in parts.items()) if parts else ""


@bp.route("/cves")
@role_required(*READ_ALL)
def list_cves():
    pg = safe_int(request.args.get("page", "1"))
    severity = request.args.get("severity")
    kev_only = request.args.get("kev")
    sort = request.args.get("sort", "cvss")
    sort_dir = request.args.get("dir", "desc")
    if sort_dir not in ("asc", "desc"):
        sort_dir = "desc"
    if sort not in ORDER_COLS:
        sort = "cvss"
    window = request.args.get("window", "all")
    month = request.args.get("month")
    tag = request.args.get("tag")
    category = request.args.get("category")
    vendor = request.args.get("vendor")
    has_poc = request.args.get("has_poc")
    has_epss = request.args.get("has_epss")
    has_social = request.args.get("has_social")
    epss_min = request.args.get("epss_min")
    epss_max = request.args.get("epss_max")
    cvss_min = request.args.get("cvss_min")
    watchlist = request.args.get("watchlist")
    cwe = request.args.get("cwe")
    source = request.args.get("source")

    if window not in WINDOW_DAYS and window != "all":
        window = "all"

    clauses, params = [], []
    if severity:
        clauses.append("cvss_severity = ?")
        params.append(severity.upper())
    if kev_only:
        clauses.append("kev = 1")
    if window in WINDOW_DAYS:
        clauses.append("published_at >= datetime('now', ?)")
        params.append(f"-{WINDOW_DAYS[window]} days")
    if month:
        clauses.append("strftime('%Y-%m', published_at) = ?")
        params.append(month)
    if tag:
        clauses.append("EXISTS (SELECT 1 FROM cve_attack_tag WHERE cve_id = c.id AND tag = ?)")
        params.append(tag)
    if category:
        clauses.append(
            "EXISTS (SELECT 1 FROM cve_product cp JOIN product p ON p.id = cp.product_id WHERE cp.cve_id = c.id AND p.category = ?)"
        )
        params.append(category)
    if vendor:
        clauses.append(
            "EXISTS (SELECT 1 FROM cve_product cp JOIN product p ON p.id = cp.product_id WHERE cp.cve_id = c.id AND p.vendor = ?)"
        )
        params.append(vendor)
    if has_poc:
        clauses.append("EXISTS (SELECT 1 FROM poc_cve WHERE cve_id = c.id)")
    if has_epss:
        clauses.append("epss_score IS NOT NULL")
    if has_social:
        clauses.append("social_mentions > 0")
    if epss_min:
        clauses.append("epss_score >= ?")
        params.append(float(epss_min))
    if epss_max:
        clauses.append("epss_score < ?")
        params.append(float(epss_max))
    if cvss_min:
        clauses.append("cvss_score >= ?")
        params.append(float(cvss_min))
    if watchlist:
        clauses.append(
            "EXISTS (SELECT 1 FROM cve_product cp JOIN product p ON p.id = cp.product_id "
            "JOIN team_watchlist tw ON tw.vendor = p.vendor "
            "AND (tw.product = '' OR tw.product = p.product) WHERE cp.cve_id = c.id)"
        )
    if cwe:
        clauses.append("EXISTS (SELECT 1 FROM cve_cwe WHERE cve_id = c.id AND cwe_id = ?)")
        params.append(cwe)
    if source:
        clauses.append("EXISTS (SELECT 1 FROM cve_source WHERE cve_id = c.id AND source = ?)")
        params.append(source)

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    order = _order_clause(sort, sort_dir)

    try:
        with db_connect() as conn:
            total = conn.execute(f"SELECT COUNT(*) FROM cve c {where}", params).fetchone()[0]
            offset = (pg - 1) * PER_PAGE_DEFAULT
            rows = _rows_to_dicts(
                conn.execute(
                    f"SELECT c.id, c.cvss_score, c.cvss_severity, c.description,"
                    f" c.epss_score, c.kev, c.published_at,"
                    f" c.social_mentions,"
                    f" (SELECT COUNT(*) FROM poc_cve WHERE cve_id = c.id) AS poc_count"
                    f" FROM cve c {where} ORDER BY {order} LIMIT ? OFFSET ?",
                    [*params, PER_PAGE_DEFAULT, offset],
                ).fetchall()
            )
            # Fetch dropdown options
            vendors = [
                r[0]
                for r in conn.execute(
                    "SELECT DISTINCT p.vendor FROM cve_product cp JOIN product p ON p.id = cp.product_id ORDER BY p.vendor"
                ).fetchall()
            ]
            tags = [
                r[0]
                for r in conn.execute(
                    "SELECT tag FROM cve_attack_tag GROUP BY tag ORDER BY COUNT(*) DESC LIMIT 50"
                ).fetchall()
            ]
            categories = [
                r[0]
                for r in conn.execute(
                    "SELECT DISTINCT p.category FROM cve_product cp JOIN product p ON p.id = cp.product_id ORDER BY p.category"
                ).fetchall()
            ]
            cwes = [
                r[0]
                for r in conn.execute(
                    "SELECT cwe_id FROM cve_cwe GROUP BY cwe_id ORDER BY COUNT(*) DESC LIMIT 30"
                ).fetchall()
            ]
            sources = [
                r[0]
                for r in conn.execute(
                    "SELECT DISTINCT source FROM cve_source ORDER BY source"
                ).fetchall()
            ]
    except Exception as e:
        return error_page(f"Database Error: {e}", active="cves"), 500

    # Active filter state for building URLs
    active = {}
    for k, v in [
        ("severity", severity),
        ("kev", kev_only),
        ("window", window if window != "all" else None),
        ("month", month),
        ("tag", tag),
        ("category", category),
        ("vendor", vendor),
        ("has_poc", has_poc),
        ("has_epss", has_epss),
        ("has_social", has_social),
        ("epss_min", epss_min),
        ("epss_max", epss_max),
        ("cvss_min", cvss_min),
        ("watchlist", watchlist),
        ("cwe", cwe),
        ("source", source),
        ("sort", sort if sort != "cvss" else None),
        ("dir", sort_dir if sort_dir != "desc" else None),
    ]:
        if v:
            active[k] = v

    def _qs(**overrides):
        d = dict(active)
        d.update(overrides)
        return _build_qs(**d)

    def _page_qs(page_num):
        d = dict(active)
        d["page"] = str(page_num)
        return _build_qs(**d)

    # Severity filters
    base_no_sev = _qs(severity=None, kev=None)
    filters = [
        {
            "label": "All",
            "url": "/cves" if not base_no_sev else f"/cves{base_no_sev}",
            "active": not severity and not kev_only,
        },
        {
            "label": "Critical",
            "url": f"/cves?severity=CRITICAL{_qs(severity=None, kev=None).replace('?', '&') if _qs(severity=None, kev=None) else ''}",
            "active": severity == "CRITICAL",
        },
        {
            "label": "High",
            "url": f"/cves?severity=HIGH{_qs(severity=None, kev=None).replace('?', '&') if _qs(severity=None, kev=None) else ''}",
            "active": severity == "HIGH",
        },
        {
            "label": "Medium",
            "url": f"/cves?severity=MEDIUM{_qs(severity=None, kev=None).replace('?', '&') if _qs(severity=None, kev=None) else ''}",
            "active": severity == "MEDIUM",
        },
        {
            "label": "Low",
            "url": f"/cves?severity=LOW{_qs(severity=None, kev=None).replace('?', '&') if _qs(severity=None, kev=None) else ''}",
            "active": severity == "LOW",
        },
        {
            "label": "KEV Only",
            "url": f"/cves?kev=1{_qs(severity=None, kev=None).replace('?', '&') if _qs(severity=None, kev=None) else ''}",
            "active": bool(kev_only),
        },
    ]

    # Quick filter chips
    quick_filters = [
        {
            "label": "Critical + PoC",
            "url": "/cves?severity=CRITICAL&has_poc=1",
            "active": severity == "CRITICAL" and bool(has_poc),
        },
        {
            "label": "Weaponized",
            "url": "/cves?cvss_min=9&has_poc=1",
            "active": bool(has_poc) and cvss_min == "9",
        },
        {"label": "EPSS >= 0.5", "url": "/cves?epss_min=0.5", "active": epss_min == "0.5"},
        {
            "label": "Social buzz",
            "url": "/cves?has_social=1&sort=social",
            "active": bool(has_social),
        },
        {"label": "Watchlist hits", "url": "/cves?watchlist=1", "active": bool(watchlist)},
    ]

    def _col_sort(key: str) -> dict:
        if key == sort:
            new_dir = "asc" if sort_dir == "desc" else "desc"
            url_dir = new_dir if new_dir != "desc" else None
            url_sort = key if key != "cvss" else None
            return {
                "url": f"/cves{_qs(sort=url_sort, dir=url_dir)}",
                "active": True,
                "dir": sort_dir,
            }
        url_sort = key if key != "cvss" else None
        return {"url": f"/cves{_qs(sort=url_sort, dir=None)}", "active": False, "dir": "desc"}

    # Window filters
    window_filters = [
        {"label": "Last 24h", "url": f"/cves{_qs(window='day')}", "active": window == "day"},
        {"label": "Last week", "url": f"/cves{_qs(window='week')}", "active": window == "week"},
        {"label": "Last month", "url": f"/cves{_qs(window='month')}", "active": window == "month"},
        {"label": "All time", "url": f"/cves{_qs(window=None)}", "active": window == "all"},
    ]

    # Toggle filters
    toggle_filters = [
        {
            "label": "Has PoC",
            "url": f"/cves{_qs(has_poc='1')}" if not has_poc else f"/cves{_qs(has_poc=None)}",
            "active": bool(has_poc),
        },
        {
            "label": "Has EPSS",
            "url": f"/cves{_qs(has_epss='1')}" if not has_epss else f"/cves{_qs(has_epss=None)}",
            "active": bool(has_epss),
        },
        {
            "label": "Has Social",
            "url": f"/cves{_qs(has_social='1')}"
            if not has_social
            else f"/cves{_qs(has_social=None)}",
            "active": bool(has_social),
        },
    ]

    columns = [
        "CVE",
        "CVSS",
        "Severity",
        "EPSS",
        "KEV",
        "PoCs",
        "Social",
        "Description",
        "Ingested",
    ]
    col_widths = ["140px", "70px", "120px", "130px", "60px", "60px", "70px", "auto", "110px"]
    cells = [
        {"type": "cve_link", "key": "id"},
        {"type": "score", "key": "cvss_score"},
        {"type": "badge", "key": "cvss_severity"},
        {"type": "epss", "key": "epss_score"},
        {"type": "kev", "key": "kev"},
        {"type": "plain", "key": "poc_count"},
        {"type": "plain", "key": "social_mentions"},
        {"type": "truncate", "key": "description"},
        {"type": "date", "key": "published_at"},
    ]
    column_sorts = [
        None,
        _col_sort("cvss"),
        _col_sort("cvss"),
        _col_sort("epss"),
        _col_sort("kev"),
        _col_sort("poc_count"),
        _col_sort("social"),
        None,
        _col_sort("date"),
    ]

    return page(
        "list.html",
        title="CVE index",
        active="cves",
        eyebrow="Database · live index",
        subtitle="Browse and filter the full set of indexed vulnerabilities. "
        "Severity stripe on the left edge of each row maps to the CVSS band.",
        rows=rows,
        total=total,
        page=pg,
        per_page=PER_PAGE_DEFAULT,
        filters=filters,
        quick_filters=quick_filters,
        window_filters=window_filters,
        toggle_filters=toggle_filters,
        columns=columns,
        col_widths=col_widths,
        cells=cells,
        column_sorts=column_sorts,
        prev_url=_page_qs(pg - 1) if pg > 1 else None,
        next_url=_page_qs(pg + 1) if pg * PER_PAGE_DEFAULT < total else None,
        # Dropdown filter data
        all_vendors=vendors,
        all_tags=tags,
        all_categories=categories,
        all_cwes=cwes,
        all_sources=sources,
        # Active filter state for summary bar
        active_filters=active,
        # Current query string for export/share
        current_qs=_build_qs(**active) if active else "",
    )


@bp.route("/cves/export.csv")
@role_required(*READ_ALL)
def export_csv():
    """Export current filtered CVE list as CSV."""
    import csv
    import io

    from flask import Response

    # Re-parse all the same filter params
    severity = request.args.get("severity")
    kev_only = request.args.get("kev")
    sort = request.args.get("sort", "cvss")
    sort_dir = request.args.get("dir", "desc")
    if sort_dir not in ("asc", "desc"):
        sort_dir = "desc"
    if sort not in ORDER_COLS:
        sort = "cvss"
    window = request.args.get("window", "all")
    month = request.args.get("month")
    tag = request.args.get("tag")
    category = request.args.get("category")
    vendor = request.args.get("vendor")
    has_poc = request.args.get("has_poc")
    has_epss = request.args.get("has_epss")
    has_social = request.args.get("has_social")
    epss_min = request.args.get("epss_min")
    epss_max = request.args.get("epss_max")
    cvss_min = request.args.get("cvss_min")
    watchlist = request.args.get("watchlist")
    cwe = request.args.get("cwe")
    source = request.args.get("source")

    if window not in WINDOW_DAYS and window != "all":
        window = "all"

    clauses, params = [], []
    if severity:
        clauses.append("cvss_severity = ?")
        params.append(severity.upper())
    if kev_only:
        clauses.append("kev = 1")
    if window in WINDOW_DAYS:
        clauses.append("published_at >= datetime('now', ?)")
        params.append(f"-{WINDOW_DAYS[window]} days")
    if month:
        clauses.append("strftime('%Y-%m', published_at) = ?")
        params.append(month)
    if tag:
        clauses.append("EXISTS (SELECT 1 FROM cve_attack_tag WHERE cve_id = c.id AND tag = ?)")
        params.append(tag)
    if category:
        clauses.append(
            "EXISTS (SELECT 1 FROM cve_product cp JOIN product p ON p.id = cp.product_id WHERE cp.cve_id = c.id AND p.category = ?)"
        )
        params.append(category)
    if vendor:
        clauses.append(
            "EXISTS (SELECT 1 FROM cve_product cp JOIN product p ON p.id = cp.product_id WHERE cp.cve_id = c.id AND p.vendor = ?)"
        )
        params.append(vendor)
    if has_poc:
        clauses.append("EXISTS (SELECT 1 FROM poc_cve WHERE cve_id = c.id)")
    if has_epss:
        clauses.append("epss_score IS NOT NULL")
    if has_social:
        clauses.append("social_mentions > 0")
    if epss_min:
        clauses.append("epss_score >= ?")
        params.append(float(epss_min))
    if epss_max:
        clauses.append("epss_score < ?")
        params.append(float(epss_max))
    if cvss_min:
        clauses.append("cvss_score >= ?")
        params.append(float(cvss_min))
    if watchlist:
        clauses.append(
            "EXISTS (SELECT 1 FROM cve_product cp JOIN product p ON p.id = cp.product_id "
            "JOIN team_watchlist tw ON tw.vendor = p.vendor "
            "AND (tw.product = '' OR tw.product = p.product) WHERE cp.cve_id = c.id)"
        )
    if cwe:
        clauses.append("EXISTS (SELECT 1 FROM cve_cwe WHERE cve_id = c.id AND cwe_id = ?)")
        params.append(cwe)
    if source:
        clauses.append("EXISTS (SELECT 1 FROM cve_source WHERE cve_id = c.id AND source = ?)")
        params.append(source)

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    order = _order_clause(sort, sort_dir)

    try:
        with db_connect() as conn:
            rows = _rows_to_dicts(
                conn.execute(
                    f"SELECT c.id, c.cvss_score, c.cvss_severity, c.description,"
                    f" c.epss_score, c.kev, c.published_at, c.social_mentions,"
                    f" (SELECT COUNT(*) FROM poc_cve WHERE cve_id = c.id) AS poc_count"
                    f" FROM cve c {where} ORDER BY {order}",
                    params,
                ).fetchall()
            )
    except Exception as e:
        return error_page(f"Export Error: {e}", active="cves"), 500

    # Build CSV
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        ["CVE", "CVSS", "Severity", "EPSS", "KEV", "PoCs", "Social", "Published", "Description"]
    )
    for r in rows:
        writer.writerow(
            [
                r.get("id", ""),
                r.get("cvss_score", ""),
                r.get("cvss_severity", ""),
                r.get("epss_score", ""),
                "yes" if r.get("kev") else "no",
                r.get("poc_count", 0),
                r.get("social_mentions", 0),
                r.get("published_at", "")[:10] if r.get("published_at") else "",
                (r.get("description", "") or "").replace("\n", " ")[:500],
            ]
        )

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=cves_export.csv"},
    )
