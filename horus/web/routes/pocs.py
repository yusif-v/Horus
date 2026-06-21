"""PoC list route — public exploit artifacts."""

from __future__ import annotations

from flask import Blueprint, request

from .._render import error_page, page
from ..queries import PER_PAGE_DEFAULT, db_connect, fetch_pocs, safe_int
from .auth import READ_ALL, role_required

bp = Blueprint("pocs", __name__)

VALID_SORTS = {"newest", "stars", "source"}
# Column sort key -> sort= value the fetch_pocs() backend understands
COL_TO_SORT = {"date": "newest", "stars": "stars"}


@bp.route("/pocs")
@role_required(*READ_ALL)
def list_pocs():
    pg = safe_int(request.args.get("page", "1"))
    source = request.args.get("source")
    sort = request.args.get("sort", "newest")
    sort_dir = request.args.get("dir", "desc")
    if sort_dir not in ("asc", "desc"):
        sort_dir = "desc"
    if sort not in VALID_SORTS:
        sort = "newest"
    only_linked = request.args.get("linked")

    try:
        rows, total = fetch_pocs(
            page=pg,
            per_page=PER_PAGE_DEFAULT,
            source_filter=source,
            sort=sort,
            direction=sort_dir,
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

    # Quick filter chips
    quick_filters = [
        {
            "label": "Linked to CVEs",
            "url": f"/pocs?linked=1&sort={sort}&source={source or ''}",
            "active": bool(only_linked),
        },
    ]

    def _col_sort(key: str) -> dict:
        params = []
        if source:
            params.append(f"source={source}")
        if only_linked:
            params.append("linked=1")
        if key == sort:
            new_dir = "asc" if sort_dir == "desc" else "desc"
            if key != "newest":
                params.append(f"sort={key}")
            if new_dir != "desc":
                params.append(f"dir={new_dir}")
            url = "/pocs" + (("?" + "&".join(params)) if params else "")
            return {"url": url, "active": True, "dir": sort_dir}
        if key != "newest":
            params.append(f"sort={key}")
        url = "/pocs" + (("?" + "&".join(params)) if params else "")
        return {"url": url, "active": False, "dir": "desc"}

    columns = ["CVE", "URL", "Source", "Type", "Stars", "Age (d)", "Description"]
    cells = [
        {"type": "cve_links", "key": "cve_ids"},
        {"type": "poc_link", "key": "url"},
        {"type": "badge", "key": "source"},
        {"type": "exploit_type", "key": "exploit_type"},
        {"type": "stars", "key": "stars"},
        {"type": "plain", "key": "age_days"},
        {"type": "truncate", "key": "description"},
    ]
    column_sorts = [
        None,
        None,
        _col_sort("source"),
        None,
        _col_sort("stars"),
        _col_sort("newest"),
        None,
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
        quick_filters=quick_filters,
        columns=columns,
        cells=cells,
        column_sorts=column_sorts,
        prev_url=f"/pocs?page={pg - 1}{src_q}{linked_q}&sort={sort}" if pg > 1 else None,
        next_url=f"/pocs?page={pg + 1}{src_q}{linked_q}&sort={sort}"
        if pg * PER_PAGE_DEFAULT < total
        else None,
    )
