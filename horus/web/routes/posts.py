"""Posts route — AI-curated security news feed."""

from __future__ import annotations

from flask import Blueprint, request

from horus.storage import db
from horus.web._render import error_page, page
from horus.web.queries import PER_PAGE_DEFAULT, safe_int

from .auth import READ_ALL, role_required

bp = Blueprint("posts", __name__)


@bp.route("/posts")
@role_required(*READ_ALL)
def list_posts():
    pg = safe_int(request.args.get("page", "1"))
    try:
        with db.connect() as conn:
            rows, total = db.get_news_posts(conn, page=pg, per_page=PER_PAGE_DEFAULT)
    except Exception as e:
        return error_page(f"Database Error: {e}", active="posts"), 500

    prev_url = f"/posts?page={pg - 1}" if pg > 1 else None
    next_url = f"/posts?page={pg + 1}" if pg * PER_PAGE_DEFAULT < total else None

    return page(
        "posts.html",
        title="Posts",
        active="posts",
        eyebrow="AI news feed",
        subtitle="Security news selected by the AI as important.",
        rows=rows,
        total=total,
        page=pg,
        per_page=PER_PAGE_DEFAULT,
        prev_url=prev_url,
        next_url=next_url,
    )
