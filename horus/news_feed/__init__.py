"""AI-curated news feed — score new articles, post the important ones.

Entry point: `score_and_post(conn, ...)`. Wired into the server as a
pipeline end-hook and exposed as `horus --news-feed` on the CLI.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from ..ai import selector
from ..ai.base import AIError, AIMalformedResponseError
from ..storage import db
from .prompts import build_scoring_prompt, parse_scoring_response

logger = logging.getLogger(__name__)


@dataclass
class NewsFeedResult:
    scored: int = 0
    posted: int = 0
    error: str | None = None


def score_and_post(
    conn: Any,
    *,
    threshold: int,
    max_articles: int = 50,
    provider: str | None = None,
) -> NewsFeedResult:
    """Score un-scored news articles via AI and post those above `threshold`."""
    articles = db.get_unscored_news(conn, limit=max_articles)
    if not articles:
        return NewsFeedResult()

    rows = [dict(a) for a in articles]
    try:
        ai_provider = selector.select_provider(provider)
    except AIError as e:
        logger.warning("news-feed AI unavailable: %s", e)
        return NewsFeedResult(error=str(e))

    try:
        result = ai_provider.analyze(build_scoring_prompt(rows))
    except AIError as e:
        logger.warning("news-feed AI scoring failed: %s", e)
        return NewsFeedResult(error=str(e))

    try:
        scores = parse_scoring_response(result.narrative, known_ids={a["id"] for a in rows})
    except AIMalformedResponseError as e:
        logger.warning("news-feed AI response malformed: %s", e)
        return NewsFeedResult(error=str(e))

    if not scores:
        return NewsFeedResult(error="no parseable scores")

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    scored = 0
    posted = 0
    by_id = {a["id"]: a for a in rows}
    for aid, s in scores.items():
        article = by_id[aid]
        db.save_news_score(
            conn,
            aid,
            score=s["score"],
            rationale=s["rationale"],
            headline=s["headline"] or article["title"],
            summary=s["summary"] or article["summary"] or "",
            scored_at=now,
        )
        scored += 1
        if s["score"] >= threshold and db.post_news_article(conn, aid, now):
            posted += 1

    return NewsFeedResult(scored=scored, posted=posted)
