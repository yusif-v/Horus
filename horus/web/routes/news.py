"""News route — classified security news from RSS feeds."""

from __future__ import annotations

from flask import Blueprint, request

from horus.web._render import error_page, page
from horus.web.queries import PER_PAGE_DEFAULT, get_news, safe_int

from .auth import READ_ALL, role_required

bp = Blueprint("news", __name__)

VALID_SORTS = {"newest", "tier", "source", "published"}
TIER_LABELS = {1: "Critical", 2: "High", 3: "Medium", 4: "Low"}


@bp.route("/news")
@role_required(*READ_ALL)
def list_news():
    pg = safe_int(request.args.get("page", "1"))
    tier_filter = request.args.get("tier", type=int)
    source = request.args.get("source")
    sort = request.args.get("sort", "newest")
    sort_dir = request.args.get("dir", "desc")
    if sort_dir not in ("asc", "desc"):
        sort_dir = "desc"
    if sort not in VALID_SORTS:
        sort = "newest"

    try:
        rows, total = get_news(
            page=pg,
            per_page=PER_PAGE_DEFAULT,
            tier_filter=tier_filter,
            source_filter=source,
            sort=sort,
            direction=sort_dir,
        )
    except Exception as e:
        return error_page(f"Database Error: {e}", active="news"), 500

    # Build tier filter chips
    tier_filters = [
        {
            "label": "All Tiers",
            "url": _qs(sort=sort, source=source),
            "active": tier_filter is None,
        }
    ]
    for tier_val, tier_label in sorted(TIER_LABELS.items()):
        tier_filters.append(
            {
                "label": f"T{tier_val} — {tier_label}",
                "url": _qs(sort=sort, source=source, tier=tier_val),
                "active": tier_filter == tier_val,
            }
        )

    # Build source filter chips from available sources
    from horus.core.feeds import FEEDS

    source_filters = [
        {
            "label": "All Sources",
            "url": _qs(sort=sort, tier=tier_filter),
            "active": not source,
        }
    ]
    for feed_key in FEEDS:
        source_filters.append(
            {
                "label": feed_key,
                "url": _qs(sort=sort, tier=tier_filter, source=feed_key),
                "active": source == feed_key,
            }
        )

    def _col_sort(key: str) -> dict:
        kw = {}
        if tier_filter is not None:
            kw["tier"] = tier_filter
        if source:
            kw["source"] = source
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

    columns = ["Tier", "Title", "Source", "Published"]
    cells = [
        {"type": "tier_badge", "key": "tier"},
        {"type": "news_title", "key": "url"},
        {"type": "badge", "key": "source"},
        {"type": "date", "key": "published_at"},
    ]
    column_sorts = [
        _col_sort("tier"),
        None,
        _col_sort("source"),
        _col_sort("published"),
    ]

    query_parts = _current_qs(tier=tier_filter, source=source, sort=sort)
    prev_url = f"/news?page={pg - 1}{query_parts}" if pg > 1 else None
    next_url = f"/news?page={pg + 1}{query_parts}" if pg * PER_PAGE_DEFAULT < total else None

    return page(
        "news.html",
        title="News",
        active="news",
        eyebrow="Security news · RSS feeds",
        subtitle="Classified security news articles from RSS feeds, ranked by relevance tier.",
        rows=rows,
        total=total,
        page=pg,
        per_page=PER_PAGE_DEFAULT,
        filters=tier_filters,
        source_filters=source_filters,
        columns=columns,
        cells=cells,
        column_sorts=column_sorts,
        prev_url=prev_url,
        next_url=next_url,
    )


def _qs(**kwargs) -> str:
    """Build query string from non-None kwargs."""
    parts = {k: v for k, v in kwargs.items() if v is not None}
    return "?" + "&".join(f"{k}={v}" for k, v in parts.items()) if parts else ""


def _current_qs(**kwargs) -> str:
    """Build query string from current filter state."""
    parts = {k: v for k, v in kwargs.items() if v is not None}
    return "&" + "&".join(f"{k}={v}" for k, v in parts.items()) if parts else ""
