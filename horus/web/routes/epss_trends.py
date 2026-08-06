"""EPSS trends dashboard — /epss-trends."""

from __future__ import annotations

from flask import Blueprint, request

from .._render import error_page, page
from ..queries import epss_movers, epss_threshold_alerts
from .auth import READ_ALL, role_required

bp = Blueprint("epss_trends", __name__)


@bp.route("/epss-trends")
@role_required(*READ_ALL)
def index():
    try:
        days = request.args.get("days", default=7, type=int)
        limit = request.args.get("limit", default=20, type=int)
        days = max(1, min(days, 90))
        limit = max(1, min(limit, 100))
        movers = epss_movers(days=days, limit=limit)
        threshold_alerts = epss_threshold_alerts(days=days)
    except Exception as e:
        return error_page(f"Database Error: {e}", active="epss-trends"), 500

    total_movers = len(movers)
    total_alerts = len(threshold_alerts)
    above = sum(1 for a in threshold_alerts if a["direction"] == "above")
    below = total_alerts - above

    return page(
        "epss_trends.html",
        title="EPSS Trends",
        active="epss-trends",
        movers=movers,
        threshold_alerts=threshold_alerts,
        days=days,
        limit=limit,
        total_movers=total_movers,
        total_alerts=total_alerts,
        above=above,
        below=below,
    )
