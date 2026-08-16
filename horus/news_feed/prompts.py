"""Prompt building + strict JSON parsing for AI news scoring."""

from __future__ import annotations

import json
import re
from typing import Any

from horus.ai.base import AIMalformedResponseError

SYSTEM_PROMPT = """You are a cybersecurity news curator. Given a list of security news articles, score each one's importance to a security operations team on a 0-100 scale.

Scoring guidance:
- 90-100: actively exploited, critical CVE, mass compromise
- 70-89: significant vulnerability or breach, wide impact
- 50-69: noteworthy but limited impact
- 0-49: routine / low relevance

Respond with valid JSON only — no markdown, no preamble. Format:
{"articles": [{"id": <article_id>, "score": <0-100>, "rationale": "<one line>", "headline": "<short headline>", "summary": "<1-2 sentence summary>"}]}
"""

USER_PROMPT_TEMPLATE = """Score each article below by importance.

{articles_text}
"""


def build_scoring_prompt(articles: list[dict[str, Any]]) -> str:
    lines = []
    for a in articles:
        lines.append(
            f"- id={a['id']} | tier={a.get('tier')} | source={a.get('source')} | "
            f"published={a.get('published_at')} | title={a['title']} | "
            f"summary={a.get('summary') or '(none)'}"
        )
    user_prompt = USER_PROMPT_TEMPLATE.format(articles_text="\n".join(lines))
    return SYSTEM_PROMPT + "\n\n" + user_prompt


def _strip_code_fence(raw: str) -> str:
    raw = raw.strip()
    if raw.startswith("```"):
        raw = re.sub(r"^```(?:json)?\s*\n?", "", raw)
        raw = re.sub(r"\n?```\s*$", "", raw)
    return raw.strip()


def parse_scoring_response(raw: str, known_ids: set[int]) -> dict[int, dict[str, Any]]:
    try:
        data = json.loads(_strip_code_fence(raw))
    except json.JSONDecodeError as e:
        raise AIMalformedResponseError(f"Invalid JSON response: {e}") from e

    articles = data.get("articles") if isinstance(data, dict) else None
    if not isinstance(articles, list):
        raise AIMalformedResponseError("Response missing 'articles' list")

    out: dict[int, dict[str, Any]] = {}
    for item in articles:
        if not isinstance(item, dict):
            continue
        aid = item.get("id")
        if not isinstance(aid, int) or aid not in known_ids:
            continue
        score = item.get("score")
        try:
            score = int(float(score))
        except (TypeError, ValueError):
            score = 0
        score = max(0, min(100, score))
        out[aid] = {
            "score": score,
            "rationale": str(item.get("rationale") or ""),
            "headline": str(item.get("headline") or ""),
            "summary": str(item.get("summary") or ""),
        }
    return out
