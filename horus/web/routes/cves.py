"""CVE index route — /cves with filter + sort + pagination."""

from __future__ import annotations

from flask import Blueprint, request

from .._render import error_page, page
from ..queries import PER_PAGE_DEFAULT, _rows_to_dicts, db_connect, safe_int
from .auth import login_required

bp = Blueprint("cves", __name__)

ORDER_MAP = {
    "cvss": "cvss_score DESC NULLS LAST",
    "epss": "epss_score DESC NULLS LAST",
    "exploit": "reputation_score DESC NULLS LAST",
    "kev": "kev DESC, cvss_score DESC NULLS LAST",
    "date": "published_at DESC NULLS LAST",
    "newest": "first_seen DESC NULLS LAST",
}

# Time window → days back from now (matched against published_at).
# "all" means no window filter.
WINDOW_DAYS = {"day": 1, "week": 7, "month": 30}


@bp.route("/cves")
@login_required
def list_cves():
    pg = safe_int(request.args.get("page", "1"))
    severity = request.args.get("severity")
    kev_only = request.args.get("kev")
    sort = request.args.get("sort", "cvss")
    window = request.args.get("window", "all")
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
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    order = ORDER_MAP.get(sort, ORDER_MAP["cvss"])

    try:
        with db_connect() as conn:
            total = conn.execute(f"SELECT COUNT(*) FROM cve {where}", params).fetchone()[0]
            offset = (pg - 1) * PER_PAGE_DEFAULT
            rows = _rows_to_dicts(
                conn.execute(
                    f"SELECT id, cvss_score, cvss_severity, description, epss_score, kev, published_at"
                    f" FROM cve {where} ORDER BY {order} LIMIT ? OFFSET ?",
                    [*params, PER_PAGE_DEFAULT, offset],
                ).fetchall()
            )
    except Exception as e:
        return error_page(f"Database Error: {e}", active="cves"), 500

    win_q = f"&window={window}" if window != "all" else ""
    extra = (f"&severity={severity}" if severity else "") + ("&kev=1" if kev_only else "") + win_q
    sev_extra = ("&kev=1" if kev_only else "") + win_q
    kev_extra = (f"&severity={severity}" if severity else "") + win_q
    filters = [
        {
            "label": "All",
            "url": f"/cves?{win_q.lstrip('&')}" if win_q else "/cves",
            "active": not severity and not kev_only,
        },
        {
            "label": "Critical",
            "url": f"/cves?severity=CRITICAL{sev_extra}",
            "active": severity == "CRITICAL",
        },
        {"label": "High", "url": f"/cves?severity=HIGH{sev_extra}", "active": severity == "HIGH"},
        {
            "label": "Medium",
            "url": f"/cves?severity=MEDIUM{sev_extra}",
            "active": severity == "MEDIUM",
        },
        {"label": "Low", "url": f"/cves?severity=LOW{sev_extra}", "active": severity == "LOW"},
        {
            "label": "KEV Only",
            "url": (f"/cves?{kev_extra.lstrip('&')}" if kev_extra else "/cves")
            if kev_only
            else f"/cves?kev=1{kev_extra}",
            "active": bool(kev_only),
        },
    ]
    sort_filters = [
        {"label": "By CVSS", "url": f"/cves?sort=cvss{extra}", "active": sort == "cvss"},
        {"label": "By EPSS", "url": f"/cves?sort=epss{extra}", "active": sort == "epss"},
        {
            "label": "By Exploitability",
            "url": f"/cves?sort=exploit{extra}",
            "active": sort == "exploit",
        },
        {"label": "Newest", "url": f"/cves?sort=date{extra}", "active": sort == "date"},
    ]
    base_q = (
        (f"&severity={severity}" if severity else "")
        + ("&kev=1" if kev_only else "")
        + (f"&sort={sort}" if sort != "cvss" else "")
    )
    window_filters = [
        {"label": "Last 24h", "url": f"/cves?window=day{base_q}", "active": window == "day"},
        {"label": "Last week", "url": f"/cves?window=week{base_q}", "active": window == "week"},
        {"label": "Last month", "url": f"/cves?window=month{base_q}", "active": window == "month"},
        {
            "label": "All time",
            "url": f"/cves?{base_q.lstrip('&')}" if base_q else "/cves",
            "active": window == "all",
        },
    ]
    columns = ["CVE", "CVSS", "Severity", "EPSS", "KEV", "Description", "Published"]
    col_widths = ["140px", "70px", "140px", "120px", "90px", "auto", "110px"]
    cells = [
        {"type": "cve_link", "key": "id"},
        {"type": "score", "key": "cvss_score"},
        {"type": "badge", "key": "cvss_severity"},
        {"type": "epss", "key": "epss_score"},
        {"type": "kev", "key": "kev"},
        {"type": "truncate", "key": "description"},
        {"type": "date", "key": "published_at"},
    ]
    prev_q = (
        (f"&sort={sort}" if sort != "cvss" else "")
        + (f"&severity={severity}" if severity else "")
        + ("&kev=1" if kev_only else "")
        + win_q
    )

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
        sort_filters=sort_filters,
        window_filters=window_filters,
        columns=columns,
        col_widths=col_widths,
        cells=cells,
        prev_url=f"/cves?page={pg - 1}{prev_q}" if pg > 1 else None,
        next_url=f"/cves?page={pg + 1}{prev_q}" if pg * PER_PAGE_DEFAULT < total else None,
    )
