"""Integration tests for score_and_post with a stubbed AI provider."""

from __future__ import annotations

from horus.ai.base import AIUnavailableError
from horus.news_feed import score_and_post
from horus.storage import db


def _seed_article(title="Article A", url="http://a", tier=1, summary="s") -> int:
    with db.connect() as conn:
        conn.execute(
            "INSERT INTO news_article (title, url, source, tier, summary, first_seen)"
            " VALUES (?, ?, 'hacker_news', ?, ?, '2026-08-01T00:00:00Z')",
            (title, url, tier, summary),
        )
        return conn.execute("SELECT id FROM news_article WHERE url = ?", (url,)).fetchone()[0]


class _StubProvider:
    def __init__(self, response: str):
        self._response = response
        self.calls: list[str] = []

    def analyze(self, prompt: str):
        self.calls.append(prompt)
        from horus.ai.base import AIAnalysisResult

        return AIAnalysisResult(narrative=self._response)


def _patch_provider(monkeypatch, response: str) -> _StubProvider:
    stub = _StubProvider(response)
    monkeypatch.setattr("horus.ai.selector.select_provider", lambda provider=None: stub)
    return stub


def test_score_and_post_above_threshold(monkeypatch):
    db.initialize()
    aid = _seed_article(title="Critical RCE")
    _patch_provider(
        monkeypatch,
        f'{{"articles": [{{"id": {aid}, "score": 95, "rationale": "exploited", '
        f'"headline": "RCE Critical", "summary": "Patch now"}}]}}',
    )
    with db.connect() as conn:
        result = score_and_post(conn, threshold=80, provider="openai")
    assert result.scored == 1
    assert result.posted == 1
    with db.connect() as conn:
        posts = db.get_news_posts(conn)
        assert posts[1] == 1
        assert posts[0][0]["headline"] == "RCE Critical"
        assert posts[0][0]["ai_score"] == 95


def test_score_and_post_below_threshold_scores_but_no_post(monkeypatch):
    db.initialize()
    aid = _seed_article(title="Routine")
    _patch_provider(
        monkeypatch,
        f'{{"articles": [{{"id": {aid}, "score": 20, "rationale": "low", '
        f'"headline": "Routine", "summary": "meh"}}]}}',
    )
    with db.connect() as conn:
        result = score_and_post(conn, threshold=80)
    assert result.scored == 1
    assert result.posted == 0
    with db.connect() as conn:
        assert db.get_news_posts(conn)[1] == 0


def test_score_and_post_no_unscored_is_noop(monkeypatch):
    db.initialize()
    with db.connect() as conn:
        result = score_and_post(conn, threshold=80)
    assert result.scored == 0
    assert result.posted == 0
    assert result.error is None


def test_score_and_post_ai_down_skips(monkeypatch):
    db.initialize()
    _seed_article(title="Unscored")

    def _raise(provider=None):
        raise AIUnavailableError("no key")

    monkeypatch.setattr("horus.ai.selector.select_provider", _raise)
    with db.connect() as conn:
        result = score_and_post(conn, threshold=80)
    assert result.scored == 0
    assert result.error is not None
    # Article remains unscored → retried next cycle.
    with db.connect() as conn:
        assert len(db.get_unscored_news(conn, limit=10)) == 1


def test_score_and_post_malformed_response_no_score(monkeypatch):
    db.initialize()
    _seed_article(title="Bad response")
    _patch_provider(monkeypatch, "this is not json")
    with db.connect() as conn:
        result = score_and_post(conn, threshold=80)
    assert result.scored == 0
    assert result.posted == 0
    assert result.error is not None


def test_score_and_post_idempotent_post(monkeypatch):
    db.initialize()
    aid = _seed_article(title="Once")
    _patch_provider(
        monkeypatch,
        f'{{"articles": [{{"id": {aid}, "score": 90, "rationale": "r", '
        f'"headline": "H", "summary": "S"}}]}}',
    )
    with db.connect() as conn:
        score_and_post(conn, threshold=80)
        score_and_post(conn, threshold=80)  # second run: nothing unscored
    with db.connect() as conn:
        assert db.get_news_posts(conn)[1] == 1
