"""CVE index route — /cves with filter + sort + pagination."""

from __future__ import annotations

from flask import Blueprint, request

from .._render import error_page, page
from ..queries import PER_PAGE_DEFAULT, _rows_to_dicts, db_connect, safe_int

bp = Blueprint("cves", __name__)

ORDER_MAP = {
    "cvss":    "cvss_score DESC NULLS LAST",
    "epss":    "epss_score DESC NULLS LAST",
    "exploit": "reputation_score DESC NULLS LAST",
    "kev":     "kev DESC, cvss_score DESC NULLS LAST",
    "date":    "published_at DESC NULLS LAST",
    "newest":  "first_seen DESC NULLS LAST",
}


@bp.route("/cves")
def list_cves():
    pg = safe_int(request.args.get("page", "1"))
    severity = request.args.get("severity")
    kev_only = request.args.get("kev")
    sort = request.args.get("sort", "cvss")

    where, params = "", []
    if severity:
        where, params = "WHERE cvss_severity = ?", [severity.upper()]
    if kev_only:
        where = "WHERE kev = 1" if not where else where + " AND kev = 1"
    order = ORDER_MAP.get(sort, ORDER_MAP["cvss"])

    try:
        with db_connect() as conn:
            total = conn.execute(f"SELECT COUNT(*) FROM cve {where}", params).fetchone()[0]
            offset = (pg - 1) * PER_PAGE_DEFAULT
            rows = _rows_to_dicts(conn.execute(
                f"SELECT id, cvss_score, cvss_severity, description, epss_score, kev, published_at"
                f" FROM cve {where} ORDER BY {order} LIMIT ? OFFSET ?",
                params + [PER_PAGE_DEFAULT, offset],
            ).fetchall())
    except Exception as e:
        return error_page(f"Database Error: {e}", active="cves"), 500

    extra = (f"&severity={severity}" if severity else "") + ("&kev=1" if kev_only else "")
    filters = [
        {"label": "All", "url": "/cves", "active": not severity and not kev_only},
        {"label": "Critical", "url": "/cves?severity=CRITICAL", "active": severity == "CRITICAL"},
        {"label": "High",     "url": "/cves?severity=HIGH",     "active": severity == "HIGH"},
        {"label": "Medium",   "url": "/cves?severity=MEDIUM",   "active": severity == "MEDIUM"},
        {"label": "Low",      "url": "/cves?severity=LOW",      "active": severity == "LOW"},
        {"label": "KEV Only", "url": "/cves?kev=1",             "active": bool(kev_only)},
    ]
    sort_filters = [
        {"label": "By CVSS",           "url": f"/cves?sort=cvss{extra}",    "active": sort == "cvss"},
        {"label": "By EPSS",           "url": f"/cves?sort=epss{extra}",    "active": sort == "epss"},
        {"label": "By Exploitability", "url": f"/cves?sort=exploit{extra}", "active": sort == "exploit"},
        {"label": "Newest",            "url": f"/cves?sort=date{extra}",    "active": sort == "date"},
    ]
    columns = ["CVE", "CVSS", "Severity", "EPSS", "KEV", "Description", "Published"]
    cells = [
        {"type": "cve_link", "key": "id"},
        {"type": "score",    "key": "cvss_score"},
        {"type": "badge",    "key": "cvss_severity"},
        {"type": "epss",     "key": "epss_score"},
        {"type": "kev",      "key": "kev"},
        {"type": "truncate", "key": "description"},
        {"type": "date",     "key": "published_at"},
    ]
    prev_q = (f"&sort={sort}" if sort != "cvss" else "") + extra

    return page(
        "list.html",
        title="CVE index", active="cves",
        eyebrow="Database · live index",
        subtitle="Browse and filter the full set of indexed vulnerabilities. "
                 "Severity stripe on the left edge of each row maps to the CVSS band.",
        rows=rows, total=total, page=pg, per_page=PER_PAGE_DEFAULT,
        filters=filters, sort_filters=sort_filters, columns=columns, cells=cells,
        prev_url=f"/cves?page={pg-1}{prev_q}" if pg > 1 else None,
        next_url=f"/cves?page={pg+1}{prev_q}" if pg * PER_PAGE_DEFAULT < total else None,
    )
