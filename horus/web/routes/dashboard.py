"""Overview/dashboard route."""

from __future__ import annotations

from flask import Blueprint, request

from .._render import error_page, page
from ..queries import get_news, get_stats
from .auth import READ_ALL, role_required

bp = Blueprint("dashboard", __name__)


@bp.route("/")
@role_required(*READ_ALL)
def index():
    try:
        year = request.args.get("year", type=int)
        window = request.args.get("window", default=None, type=str)
        if window == "all":
            window = None
        stats = get_stats(year=year, window=window, recent_limit=5)
        news_articles, _ = get_news(page=1, per_page=5)
    except Exception as e:
        return error_page(f"Database Error: {e}"), 500
    return page(
        "dashboard.html",
        title="Dashboard",
        active="dashboard",
        stats=stats,
        news_articles=news_articles,
        year=year,
        window=window,
    )
