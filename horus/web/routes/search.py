"""Search route + CVE-detail route (search is the entry point for ad-hoc lookups)."""

from __future__ import annotations

from flask import Blueprint, redirect, request, url_for

from .._render import error_page, page
from ..queries import PER_PAGE_DEFAULT, get_cve_detail, linked_sources, safe_int, search_cves
from .auth import READ_ALL, role_required

bp = Blueprint("search", __name__)


@bp.route("/search")
@role_required(*READ_ALL)
def search():
    query = request.args.get("q", "").strip()
    query = query[:200]  # Cap input length
    pg = safe_int(request.args.get("page", "1"))
    if not query:
        return redirect(url_for("dashboard.index"))
    try:
        results, total = search_cves(query, page=pg, per_page=PER_PAGE_DEFAULT)
    except Exception as e:
        return error_page(f"Search Error: {e}", search_query=query), 500
    return page(
        "search.html",
        title=f"Search: {query}",
        query=query,
        results=results,
        total=total,
        page=pg,
        per_page=PER_PAGE_DEFAULT,
        search_query=query,
    )


@bp.route("/cve/<cve_id>")
@role_required(*READ_ALL)
def cve_detail(cve_id):
    try:
        data = get_cve_detail(cve_id)
    except Exception as e:
        return error_page(f"Database Error: {e}"), 500
    if not data:
        return page(
            "error.html",
            title="CVE Not Found",
            msg=f"No record for {cve_id} in the local index. "
            f"Try a keyword search: /search?q={cve_id}",
        ), 404
    data["linked_sources"] = linked_sources(cve_id, limit=10)
    return page("cve_detail.html", title=data["cve"]["id"], data=data)
