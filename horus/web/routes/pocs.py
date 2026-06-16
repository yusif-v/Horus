"""PoC list route — public exploit artifacts."""

from __future__ import annotations

from flask import Blueprint, request

from .._render import error_page, page
from ..queries import PER_PAGE_DEFAULT, db_connect, fetch_pocs, safe_int
from .auth import READ_ALL, role_required

bp = Blueprint("pocs", __name__)

VALID_SORTS = {"newest", "stars"}


@bp.route("/pocs")
@role_required(*READ_ALL)
def list_pocs():
    pg = safe_int(request.args.get("page", "1"))
    source = request.args.get("source")
    sort = request.args.get("sort", "newest")
    if sort not in VALID_SORTS:
        sort = "newest"
    only_linked = request.args.get("linked")

    try:
        rows, total = fetch_pocs(
            page=pg, per_page=PER_PAGE_DEFAULT, source_filter=source, sort=sort
        )
        with db_connect() as conn:
            sources = [
                r[0]
                for r in conn.execute("SELECT DISTINCT source FROM poc ORDER BY source").fetchall()
            ]
    except Exception as e:
        return error_page(f"Database Error: {e}", active="pocs"), 500

    # Filter for linked PoCs
    if only_linked:
        rows = [r for r in rows if r.get("cve_ids")]
        total = len(rows)

    filters = [{"label": "All", "url": f"/pocs?sort={sort}", "active": not source}]
    for s in sources:
        filters.append({"label": s, "url": f"/pocs?source={s}&sort={sort}", "active": source == s})

    sort_filters = [
        {
            "label": "Newest",
            "url": f"/pocs?sort=newest&source={source or ''}",
            "active": sort == "newest",
        },
        {
            "label": "Stars",
            "url": f"/pocs?sort=stars&source={source or ''}",
            "active": sort == "stars",
        },
    ]

    # Quick filter chips
    quick_filters = [
        {
            "label": "Linked to CVEs",
            "url": f"/pocs?linked=1&sort={sort}&source={source or ''}",
            "active": bool(only_linked),
        },
        {
            "label": "Popular (>100★)",
            "url": f"/pocs?sort=stars&source={source or ''}",
            "active": sort == "stars",
        },
    ]

    columns = ["CVE", "URL", "Source", "Stars", "Age (d)", "Description"]
    cells = [
        {"type": "cve_links", "key": "cve_ids"},
        {"type": "poc_link", "key": "url"},
        {"type": "badge", "key": "source"},
        {"type": "stars", "key": "stars"},
        {"type": "plain", "key": "age_days"},
        {"type": "truncate", "key": "description"},
    ]
    src_q = f"&source={source}" if source else ""
    linked_q = "&linked=1" if only_linked else ""

    return page(
        "list.html",
        title="Public exploits",
        active="pocs",
        eyebrow="Proof-of-concept artifacts",
        subtitle="Public exploit artifacts harvested from GitHub, Exploit-DB and other sources. "
        "Sorted by most recently seen.",
        rows=rows,
        total=total,
        page=pg,
        per_page=PER_PAGE_DEFAULT,
        filters=filters,
        sort_filters=sort_filters,
        quick_filters=quick_filters,
        columns=columns,
        cells=cells,
        prev_url=f"/pocs?page={pg - 1}{src_q}{linked_q}&sort={sort}" if pg > 1 else None,
        next_url=f"/pocs?page={pg + 1}{src_q}{linked_q}&sort={sort}"
        if pg * PER_PAGE_DEFAULT < total
        else None,
    )
