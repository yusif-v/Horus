"""Unit tests for AI news-feed prompt builder + response parser."""

from __future__ import annotations

import pytest

from horus.ai.base import AIMalformedResponseError
from horus.news_feed.prompts import build_scoring_prompt, parse_scoring_response

ARTICLES = [
    {
        "id": 1,
        "title": "Critical RCE in Apache",
        "summary": "Actively exploited.",
        "source": "hacker_news",
        "tier": 1,
        "published_at": "2026-08-15T00:00:00Z",
    },
    {
        "id": 2,
        "title": "Patch Tuesday roundup",
        "summary": "Routine updates.",
        "source": "bleepingcomputer",
        "tier": 3,
        "published_at": "2026-08-14T00:00:00Z",
    },
]


def test_build_scoring_prompt_contains_article_fields():
    prompt = build_scoring_prompt(ARTICLES)
    assert "Critical RCE in Apache" in prompt
    assert "Patch Tuesday roundup" in prompt
    assert "score" in prompt
    assert "rationale" in prompt


def test_parse_scoring_response_valid():
    raw = """{"articles": [{"id": 1, "score": 92, "rationale": "actively exploited",
              "headline": "Apache RCE critical", "summary": "Patch now"}]}"""
    out = parse_scoring_response(raw, known_ids={1, 2})
    assert out[1]["score"] == 92
    assert out[1]["rationale"] == "actively exploited"
    assert out[1]["headline"] == "Apache RCE critical"
    assert 2 not in out


def test_parse_scoring_response_skips_unknown_id():
    raw = """{"articles": [{"id": 999, "score": 50, "rationale": "x",
              "headline": "h", "summary": "s"}]}"""
    out = parse_scoring_response(raw, known_ids={1})
    assert out == {}


def test_parse_scoring_response_missing_articles_key_raises():
    with pytest.raises(AIMalformedResponseError):
        parse_scoring_response('{"foo": 1}', known_ids={1})


def test_parse_scoring_response_not_json_raises():
    with pytest.raises(AIMalformedResponseError):
        parse_scoring_response("not json at all", known_ids={1})


def test_parse_scoring_response_code_fence_stripped():
    raw = '```json\n{"articles": [{"id": 1, "score": 70, "rationale": "r", "headline": "h", "summary": "s"}]}\n```'
    out = parse_scoring_response(raw, known_ids={1})
    assert out[1]["score"] == 70
