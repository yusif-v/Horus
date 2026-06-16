"""Security resources route — broad intelligence beyond CVE-linked PoCs."""

from __future__ import annotations

from flask import Blueprint, request

from horus.storage import db

from .._render import error_page, page
from ..queries import PER_PAGE_DEFAULT, safe_int
from .auth import READ_ALL, role_required

bp = Blueprint("resources", __name__)

VALID_SORTS = {"newest", "engagement", "stars", "type", "source", "author"}
VALID_TYPES = {"poc", "exploit", "tool", "technique", "advisory", "bypass", "disclosure"}


@bp.route("/resources")
@role_required(*READ_ALL)
def list_resources():
    pg = safe_int(request.args.get("page", "1"))
    resource_type = request.args.get("resource_type")
    source = request.args.get("source")
    tag = request.args.get("tag")
    sort = request.args.get("sort", "newest")
    sort_dir = request.args.get("dir", "desc")
    if sort_dir not in ("asc", "desc"):
        sort_dir = "desc"
    has_cve = request.args.get("has_cve")
    engagement_min = request.args.get("engagement_min")
    author = request.args.get("author")
    if sort not in VALID_SORTS:
        sort = "newest"
    if resource_type and resource_type not in VALID_TYPES:
        resource_type = None

    try:
        rows, total = db.fetch_resources(
            page=pg,
            per_page=PER_PAGE_DEFAULT,
            resource_type_filter=resource_type,
            source_filter=source,
            tag_filter=tag,
            sort=sort,
            direction=sort_dir,
        )
        with db.connect() as conn:
            sources = [
                r[0]
                for r in conn.execute(
                    "SELECT DISTINCT source FROM security_resource ORDER BY source"
                ).fetchall()
            ]
            types = [
                r[0]
                for r in conn.execute(
                    "SELECT DISTINCT resource_type FROM security_resource ORDER BY resource_type"
                ).fetchall()
            ]
            authors = [
                r[0]
                for r in conn.execute(
                    "SELECT DISTINCT source_author FROM security_resource WHERE source_author IS NOT NULL ORDER BY source_author"
                ).fetchall()
            ]
    except Exception as e:
        return error_page(f"Database Error: {e}", active="resources"), 500

    # Post-filter for CVE refs and engagement
    if has_cve:
        rows = [r for r in rows if r.get("cve_refs")]
        total = len(rows)
    if engagement_min:
        try:
            emin = int(engagement_min)
            rows = [r for r in rows if (r.get("engagement_score") or 0) >= emin]
            total = len(rows)
        except ValueError:
            pass
    if author:
        rows = [r for r in rows if r.get("source_author") == author]
        total = len(rows)

    # Build filter chips
    type_filters = [
        {
            "label": "All Types",
            "url": _qs(sort=sort, source=source, tag=tag),
            "active": not resource_type,
        }
    ]
    for t in types:
        type_filters.append(
            {
                "label": t,
                "url": _qs(sort=sort, source=source, tag=tag, resource_type=t),
                "active": resource_type == t,
            }
        )

    source_filters = [
        {
            "label": "All Sources",
            "url": _qs(sort=sort, resource_type=resource_type, tag=tag),
            "active": not source,
        }
    ]
    for s in sources:
        source_filters.append(
            {
                "label": s,
                "url": _qs(sort=sort, resource_type=resource_type, tag=tag, source=s),
                "active": source == s,
            }
        )

    def _col_sort(key: str) -> dict:
        kw = dict(resource_type=resource_type, source=source, tag=tag)
        if key == sort:
            new_dir = "asc" if sort_dir == "desc" else "desc"
            url = _qs(
                sort=key if key != "newest" else None,
                dir=new_dir if new_dir != "desc" else None,
                **kw,
            )
            return {"url": url, "active": True, "dir": sort_dir}
        url = _qs(sort=key if key != "newest" else None, **kw)
        return {"url": url, "active": False, "dir": "desc"}

    # Quick filter chips
    quick_filters = [
        {"label": "With CVE refs", "url": "/resources?has_cve=1", "active": bool(has_cve)},
        {
            "label": "High engagement",
            "url": "/resources?engagement_min=50",
            "active": engagement_min == "50",
        },
        {
            "label": "PoCs only",
            "url": "/resources?resource_type=poc",
            "active": resource_type == "poc",
        },
        {
            "label": "Tools only",
            "url": "/resources?resource_type=tool",
            "active": resource_type == "tool",
        },
    ]

    columns = ["Type", "Title / URL", "Source", "Author", "Engagement", "Tags", "Published"]
    cells = [
        {"type": "badge", "key": "resource_type"},
        {"type": "resource_title", "key": "url"},
        {"type": "badge", "key": "source"},
        {"type": "plain", "key": "source_author"},
        {"type": "engagement", "key": "engagement_score"},
        {"type": "tags", "key": "tags"},
        {"type": "date", "key": "published_date"},
    ]
    column_sorts = [
        _col_sort("type"),
        None,
        _col_sort("source"),
        _col_sort("author"),
        _col_sort("engagement"),
        None,
        _col_sort("newest"),
    ]

    query_parts = _current_qs(
        resource_type=resource_type,
        source=source,
        tag=tag,
        sort=sort,
        has_cve=has_cve,
        engagement_min=engagement_min,
        author=author,
    )
    prev_url = f"/resources?page={pg - 1}{query_parts}" if pg > 1 else None
    next_url = f"/resources?page={pg + 1}{query_parts}" if pg * PER_PAGE_DEFAULT < total else None

    return page(
        "resources.html",
        title="Security Resources",
        active="resources",
        eyebrow="Security intelligence",
        subtitle="Security-relevant resources discovered from X/Twitter: exploit tools, bypass techniques, "
        "vulnerability disclosures, red team tools, security advisories, and more.",
        rows=rows,
        total=total,
        page=pg,
        per_page=PER_PAGE_DEFAULT,
        type_filters=type_filters,
        source_filters=source_filters,
        quick_filters=quick_filters,
        columns=columns,
        cells=cells,
        column_sorts=column_sorts,
        prev_url=prev_url,
        next_url=next_url,
        # New filter data
        all_authors=authors,
        current_has_cve=has_cve,
        current_engagement_min=engagement_min,
        current_author=author,
    )


def _qs(**kwargs) -> str:
    """Build query string from non-None kwargs."""
    parts = {k: v for k, v in kwargs.items() if v}
    return "?" + "&".join(f"{k}={v}" for k, v in parts.items()) if parts else ""


def _current_qs(**kwargs) -> str:
    """Build query string from current filter state."""
    parts = {k: v for k, v in kwargs.items() if v}
    return "&" + "&".join(f"{k}={v}" for k, v in parts.items()) if parts else ""
