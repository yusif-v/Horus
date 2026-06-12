"""Overview/dashboard route."""

from __future__ import annotations

from flask import Blueprint

from .._render import error_page, page
from ..queries import get_stats
from .auth import login_required

bp = Blueprint("dashboard", __name__)


@bp.route("/")
@login_required
def index():
    try:
        stats = get_stats()
    except Exception as e:
        return error_page(f"Database Error: {e}"), 500
    return page("dashboard.html", title="Dashboard", active="dashboard", stats=stats)
