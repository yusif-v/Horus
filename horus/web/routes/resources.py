"""Security resources route — broad intelligence beyond CVE-linked PoCs."""

from __future__ import annotations

from flask import Blueprint, request

from horus.storage import db

from .._render import error_page, page
from ..queries import PER_PAGE_DEFAULT, safe_int
from .auth import READ_ALL, role_required

bp = Blueprint("resources", __name__)

VALID_SORTS = {"newest", "engagement", "stars"}
VALID_TYPES = {"poc", "exploit", "tool", "technique", "advisory", "bypass", "disclosure"}


@bp.route("/resources")
@role_required(*READ_ALL)
def list_resources():
    pg = safe_int(request.args.get("page", "1"))
    resource_type = request.args.get("resource_type")
    source = request.args.get("source")
    tag = request.args.get("tag")
    sort = request.args.get("sort", "newest")
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
    except Exception as e:
        return error_page(f"Database Error: {e}", active="resources"), 500

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

    sort_filters = [
        {
            "label": "Newest",
            "url": _qs(sort="newest", resource_type=resource_type, source=source, tag=tag),
            "active": sort == "newest",
        },
        {
            "label": "Engagement",
            "url": _qs(sort="engagement", resource_type=resource_type, source=source, tag=tag),
            "active": sort == "engagement",
        },
        {
            "label": "Stars",
            "url": _qs(sort="stars", resource_type=resource_type, source=source, tag=tag),
            "active": sort == "stars",
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

    query_parts = _current_qs(resource_type=resource_type, source=source, tag=tag, sort=sort)
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
        sort_filters=sort_filters,
        columns=columns,
        cells=cells,
        prev_url=prev_url,
        next_url=next_url,
    )


def _qs(**kwargs) -> str:
    """Build query string from non-None kwargs."""
    parts = {k: v for k, v in kwargs.items() if v}
    return "?" + "&".join(f"{k}={v}" for k, v in parts.items()) if parts else ""


def _current_qs(**kwargs) -> str:
    """Build query string from current filter state."""
    parts = {k: v for k, v in kwargs.items() if v}
    return "&" + "&".join(f"{k}={v}" for k, v in parts.items()) if parts else ""
