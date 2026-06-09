"""Page-render helper. Pulls rail stats + version once per render."""

from __future__ import annotations

from datetime import datetime

from flask import render_template

from .. import __version__
from .queries import rail_stats


def page(template: str, *, title: str, active: str = "", **context) -> str:
    """Render a page that extends base.html, with rail/version/now in scope."""
    return render_template(
        template,
        title=title,
        active=active,
        rail=rail_stats(),
        version=__version__,
        now=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        **context,
    )


def error_page(message: str, *, active: str = "", search_query: str = "") -> str:
    return page(
        "error.html",
        title="Error",
        active=active,
        msg=message,
        search_query=search_query,
    )
