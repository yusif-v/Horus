# AI News Feed Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** AI scores every newly-ingested RSS news article (0-100 importance) and, above a configurable threshold, publishes it as a post on a new `/posts` web page.

**Architecture:** A new `horus/news_feed/` package with one entry point `score_and_post(conn, *, threshold, max_articles, provider)` — it reads un-scored `news_article` rows, sends them in one batched AI call via the existing `horus/ai/select_provider()`, writes score/rationale/AI-content back to `news_article`, and inserts `news_post` rows for articles above threshold. The server registers it as a pipeline end-hook; a CLI command runs it manually. A new `/posts` web route renders the feed.

**Tech Stack:** Python 3.10+, sqlite3, Flask, existing `horus/ai/` (openai/anthropic/ollama), pytest.

## Global Constraints

- Python floor: `requires-python = ">=3.10"` — use `from __future__ import annotations` in every module.
- DB migrations must be idempotent (`ADD COLUMN` guarded by `PRAGMA table_info`), mirroring `_migrate_columns` in `horus/storage/db.py`.
- AI responses are parsed strictly: malformed whole response → `AIMalformedResponseError`; unknown IDs skipped; partial subsets scored.
- No new dependencies. Reuse `horus/ai/select_provider` + `horus/ai/base` exceptions.
- Every scored article gets persisted even below threshold (never re-scored: `WHERE ai_score IS NULL`).
- Web routes are role-gated with `@role_required(*READ_ALL)` like `horus/web/routes/news.py`.
- Commits use conventional prefixes (`feat:`, `test:`, `fix:`, `docs:`).

---

### Task 1: Config + DB schema for news_feed

**Files:**
- Modify: `horus/storage/schema.sql` (add `news_post` table)
- Modify: `horus/storage/db.py` (`_migrate_columns` + `news_post` table init + `get_unscored_news`/`get_news_post_rows` helpers)
- Modify: `horus/server.py` (`NewsFeedConfig` dataclass + `Config.news_feed` + `load_config` parsing)
- Test: `tests/test_server.py`, `tests/storage/test_db.py`

**Interfaces:**
- Consumes: `db.connect()` context manager; `_migrate_columns(conn)` runs before `_init_schema(conn)`.
- Produces:
  - `server.NewsFeedConfig(enabled: bool = True, threshold: int = 80, max_articles_per_run: int = 50)`
  - `Config.news_feed: NewsFeedConfig`
  - `db.get_unscored_news(conn, limit: int) -> list[sqlite3.Row]` — rows with columns `id, title, url, source, tier, summary, published_at, first_seen`
  - `db.save_news_score(conn, article_id, *, score, rationale, headline, summary, scored_at) -> None`
  - `db.post_news_article(conn, article_id, posted_at) -> bool` (True if inserted)
  - `db.get_news_posts(conn, *, page, per_page) -> tuple[list[dict], int]`

- [ ] **Step 1: Update `news_article` + add the `news_post` table in `horus/storage/schema.sql`**

The AI score columns must be in the `CREATE TABLE` (for fresh DBs) AND added via migration (for existing DBs) — `_migrate_columns` runs before `_init_schema`, so a fresh install never hits the migration path. Update the `news_article` definition:

```sql
CREATE TABLE IF NOT EXISTS news_article (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    title           TEXT NOT NULL,
    url             TEXT NOT NULL UNIQUE,
    source          TEXT NOT NULL,              -- feed key (cisa, hacker_news, etc.)
    tier            INTEGER NOT NULL DEFAULT 3, -- 1 (critical) .. 5 (noise)
    summary         TEXT,
    published_at    TEXT,
    first_seen      TEXT NOT NULL,
    ai_score        INTEGER,                    -- v0.17 AI news feed
    ai_rationale    TEXT,
    ai_headline     TEXT,
    ai_summary      TEXT,
    scored_at       TEXT
);
```

Then append:

```sql
-- ─── AI News Feed posts (v0.17) ───────────────────────────────────────

CREATE TABLE IF NOT EXISTS news_post (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    article_id INTEGER NOT NULL UNIQUE REFERENCES news_article(id) ON DELETE CASCADE,
    posted_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_news_post_posted_at ON news_post(posted_at);
```

- [ ] **Step 2: Add news_article column migration in `db.py`**

In `_migrate_columns(conn)` (after the existing user-table block), add:

```python
    # news_article — additions from v0.17 (AI news feed).
    news_exists = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='news_article'"
    ).fetchone()
    if news_exists:
        existing_news = {row[1] for row in conn.execute("PRAGMA table_info(news_article)")}
        news_additions = [
            ("ai_score", "INTEGER"),
            ("ai_rationale", "TEXT"),
            ("ai_headline", "TEXT"),
            ("ai_summary", "TEXT"),
            ("scored_at", "TEXT"),
        ]
        for col, decl in news_additions:
            if col not in existing_news:
                conn.execute(f"ALTER TABLE news_article ADD COLUMN {col} {decl}")
```

- [ ] **Step 3: Write failing tests for config + db helpers**

In `tests/test_server.py`, add:

```python
def test_config_news_feed_defaults():
    cfg = server.Config()
    assert cfg.news_feed.enabled is True
    assert cfg.news_feed.threshold == 80
    assert cfg.news_feed.max_articles_per_run == 50


def test_load_config_news_feed_block(tmp_path):
    cfg = server.load_config(str(tmp_path / "nope.yaml"))  # defaults
    assert cfg.news_feed.threshold == 80
```

In `tests/storage/test_db.py`, add:

```python
def test_news_article_score_columns_exist_after_init():
    db.initialize()
    with db.connect() as conn:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(news_article)")}
    for col in ("ai_score", "ai_rationale", "ai_headline", "ai_summary", "scored_at"):
        assert col in cols


def test_news_post_table_exists_after_init():
    db.initialize()
    with db.connect() as conn:
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='news_post'"
        ).fetchall()
    assert len(rows) == 1


def test_get_unscored_news_and_save_score(tmp_path):
    db.initialize()
    with db.connect() as conn:
        conn.execute(
            "INSERT INTO news_article (title, url, source, tier, summary, first_seen)"
            " VALUES ('A', 'http://a', 'hacker_news', 1, 's', '2026-08-01T00:00:00Z')"
        )
        conn.execute(
            "INSERT INTO news_article (title, url, source, tier, summary, first_seen)"
            " VALUES ('B', 'http://b', 'hacker_news', 3, 's', '2026-08-01T00:00:00Z')"
        )
        unscored = db.get_unscored_news(conn, limit=10)
        assert len(unscored) == 2
        first_id = unscored[0]["id"]
        db.save_news_score(conn, first_id, score=90, rationale="r", headline="h",
                           summary="sm", scored_at="2026-08-15T00:00:00Z")
        again = db.get_unscored_news(conn, limit=10)
        assert len(again) == 1  # scored article no longer returned
```

Note: `get_unscored_news` must return rows that behave like dicts (`row["id"]`). Use `conn.row_factory = sqlite3.Row` inside the helper.

- [ ] **Step 4: Run tests, expect the new ones to fail (missing helpers)**

Run: `pytest tests/test_server.py tests/storage/test_db.py -q --no-cov`
Expected: FAIL — `NewsFeedConfig`/`Config.news_feed`/`get_unscored_news` not defined.

- [ ] **Step 5: Implement `NewsFeedConfig` + `load_config` parsing**

In `horus/server.py`, add near `TelegramConfig`:

```python
@dataclass
class NewsFeedConfig:
    enabled: bool = True
    threshold: int = 80
    max_articles_per_run: int = 50
```

Add field to `Config`:

```python
    news_feed: NewsFeedConfig = field(default_factory=NewsFeedConfig)
```

In `load_config`, after the `plugins` block, add:

```python
    if "news_feed" in data and isinstance(data["news_feed"], dict):
        nf = data["news_feed"]
        cfg.news_feed.enabled = bool(nf.get("enabled", cfg.news_feed.enabled))
        cfg.news_feed.threshold = int(nf.get("threshold", cfg.news_feed.threshold))
        cfg.news_feed.max_articles_per_run = int(
            nf.get("max_articles_per_run", cfg.news_feed.max_articles_per_run)
        )
```

- [ ] **Step 6: Implement the db helpers**

In `horus/storage/db.py`, add near the other news helpers:

```python
def get_unscored_news(conn: sqlite3.Connection, limit: int) -> list[sqlite3.Row]:
    conn.row_factory = sqlite3.Row
    return conn.execute(
        """SELECT id, title, url, source, tier, summary, published_at, first_seen
           FROM news_article WHERE ai_score IS NULL
           ORDER BY first_seen LIMIT ?""",
        (limit,),
    ).fetchall()


def save_news_score(
    conn: sqlite3.Connection,
    article_id: int,
    *,
    score: int,
    rationale: str,
    headline: str,
    summary: str,
    scored_at: str,
) -> None:
    conn.execute(
        """UPDATE news_article
           SET ai_score = ?, ai_rationale = ?, ai_headline = ?, ai_summary = ?, scored_at = ?
           WHERE id = ?""",
        (score, rationale, headline, summary, scored_at, article_id),
    )


def post_news_article(conn: sqlite3.Connection, article_id: int, posted_at: str) -> bool:
    cur = conn.execute(
        "INSERT OR IGNORE INTO news_post (article_id, posted_at) VALUES (?, ?)",
        (article_id, posted_at),
    )
    return cur.rowcount > 0


def get_news_posts(
    conn: sqlite3.Connection, *, page: int = 1, per_page: int = 20
) -> tuple[list[dict], int]:
    conn.row_factory = sqlite3.Row
    offset = (page - 1) * per_page
    total = conn.execute(
        "SELECT COUNT(*) FROM news_post p JOIN news_article a ON a.id = p.article_id"
    ).fetchone()[0]
    rows = conn.execute(
        """SELECT p.id, p.posted_at, a.id AS article_id, a.title, a.url, a.source, a.tier,
                  COALESCE(a.ai_headline, a.title) AS headline,
                  COALESCE(a.ai_summary, a.summary) AS post_summary,
                  a.ai_score, a.ai_rationale
           FROM news_post p JOIN news_article a ON a.id = p.article_id
           ORDER BY p.posted_at DESC LIMIT ? OFFSET ?""",
        (per_page, offset),
    ).fetchall()
    return [dict(r) for r in rows], int(total)
```

- [ ] **Step 7: Run tests to verify pass**

Run: `pytest tests/test_server.py tests/storage/test_db.py -q --no-cov`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add horus/storage/schema.sql horus/storage/db.py horus/server.py tests/test_server.py tests/storage/test_db.py
git commit -m "feat: add news_feed config + DB schema (score columns, news_post table)"
```

---

### Task 2: Prompt builder + response parser for news scoring

**Files:**
- Create: `horus/news_feed/prompts.py`
- Test: `tests/news_feed/test_prompts.py`

**Interfaces:**
- Consumes: `AIMalformedResponseError` from `horus.ai.base`.
- Produces:
  - `build_scoring_prompt(articles: list[dict]) -> str` — returns a full system+user prompt string.
  - `parse_scoring_response(raw: str, known_ids: set[int]) -> dict[int, dict]` — maps `article_id -> {"score": int, "rationale": str, "headline": str, "summary": str}`. Raises `AIMalformedResponseError` if the whole JSON is unparseable or the `articles` key is missing. Skips unknown ids.

- [ ] **Step 1: Write failing tests**

Create `tests/news_feed/test_prompts.py`:

```python
"""Unit tests for AI news-feed prompt builder + response parser."""

from __future__ import annotations

import pytest

from horus.ai.base import AIMalformedResponseError
from horus.news_feed.prompts import build_scoring_prompt, parse_scoring_response

ARTICLES = [
    {"id": 1, "title": "Critical RCE in Apache", "summary": "Actively exploited.",
     "source": "hacker_news", "tier": 1, "published_at": "2026-08-15T00:00:00Z"},
    {"id": 2, "title": "Patch Tuesday roundup", "summary": "Routine updates.",
     "source": "bleepingcomputer", "tier": 3, "published_at": "2026-08-14T00:00:00Z"},
]


def test_build_scoring_prompt_contains_article_fields():
    prompt = build_scoring_prompt(ARTICLES)
    assert "Critical RCE in Apache" in prompt
    assert "Patch Tuesday roundup" in prompt
    assert "score" in prompt
    assert "rationale" in prompt


def test_parse_scoring_response_valid():
    raw = '''{"articles": [{"id": 1, "score": 92, "rationale": "actively exploited",
              "headline": "Apache RCE critical", "summary": "Patch now"}]}'''
    out = parse_scoring_response(raw, known_ids={1, 2})
    assert out[1]["score"] == 92
    assert out[1]["rationale"] == "actively exploited"
    assert out[1]["headline"] == "Apache RCE critical"
    assert 2 not in out


def test_parse_scoring_response_skips_unknown_id():
    raw = '''{"articles": [{"id": 999, "score": 50, "rationale": "x",
              "headline": "h", "summary": "s"}]}'''
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
```

- [ ] **Step 2: Run tests, expect failure**

Run: `pytest tests/news_feed/test_prompts.py -q --no-cov`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement `horus/news_feed/prompts.py`**

```python
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
            score = int(score)
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
```

- [ ] **Step 4: Run tests, verify pass**

Run: `pytest tests/news_feed/test_prompts.py -q --no-cov`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add horus/news_feed/prompts.py tests/news_feed/test_prompts.py
git commit -m "feat: news-feed prompt builder + strict scoring response parser"
```

---

### Task 3: Core `score_and_post` orchestration

**Files:**
- Create: `horus/news_feed/__init__.py` (entry point + result type)
- Test: `tests/news_feed/test_core.py`

**Interfaces:**
- Consumes:
  - `db.get_unscored_news(conn, limit)`, `db.save_news_score(...)`, `db.post_news_article(conn, article_id, posted_at)`
  - `build_scoring_prompt(articles)`, `parse_scoring_response(raw, known_ids)`
  - `horus.ai.selector.select_provider(provider)`
  - `horus.ai.base.AIError`, `AIMalformedResponseError`
- Produces:
  - `news_feed.NewsFeedResult(scored: int, posted: int, error: str | None = None)`
  - `news_feed.score_and_post(conn, *, threshold: int, max_articles: int = 50, provider: str | None = None) -> NewsFeedResult`

- [ ] **Step 1: Write failing tests**

Create `tests/news_feed/test_core.py`:

```python
"""Integration tests for score_and_post with a stubbed AI provider."""

from __future__ import annotations

import pytest

from horus.ai.base import AIUnavailableError
from horus.news_feed import NewsFeedResult, score_and_post
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
    stub = _patch_provider(
        monkeypatch,
        '{"articles": [{"id": %d, "score": 95, "rationale": "exploited", '
        '"headline": "RCE Critical", "summary": "Patch now"}]}' % aid,
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
        '{"articles": [{"id": %d, "score": 20, "rationale": "low", '
        '"headline": "Routine", "summary": "meh"}]}' % aid,
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
    aid = _seed_article(title="Unscored")

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
        '{"articles": [{"id": %d, "score": 90, "rationale": "r", '
        '"headline": "H", "summary": "S"}]}' % aid,
    )
    with db.connect() as conn:
        score_and_post(conn, threshold=80)
        score_and_post(conn, threshold=80)  # second run: nothing unscored
    with db.connect() as conn:
        assert db.get_news_posts(conn)[1] == 1
```

- [ ] **Step 2: Run tests, expect failure**

Run: `pytest tests/news_feed/test_core.py -q --no-cov`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement `horus/news_feed/__init__.py`**

```python
"""AI-curated news feed — score new articles, post the important ones.

Entry point: `score_and_post(conn, ...)`. Wired into the server as a
pipeline end-hook and exposed as `horus news-feed` on the CLI.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from ..ai.base import AIError, AIMalformedResponseError
from ..ai.selector import select_provider
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
        ai_provider = select_provider(provider)
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
```

- [ ] **Step 4: Run tests, verify pass**

Run: `pytest tests/news_feed/test_core.py -q --no-cov`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add horus/news_feed/__init__.py tests/news_feed/test_core.py
git commit -m "feat: score_and_post news-feed orchestration"
```

---

### Task 4: Server end-hook + CLI command

**Files:**
- Modify: `horus/server.py` (`_register_news_feed_hook` + wire into `start()`)
- Modify: `horus/cli.py` (`news-feed` arg + `_cmd_news_feed`)
- Modify: `horus.yaml.example`
- Test: `tests/test_server.py`, `tests/test_cli.py`

**Interfaces:**
- Consumes: `news_feed.score_and_post(conn, *, threshold, max_articles, provider)`, `Config.news_feed`.
- Produces:
  - `Server._register_news_feed_hook() -> None` (registers a pipeline end-hook).
  - CLI `horus news-feed` one-shot command.

- [ ] **Step 1: Write failing tests**

In `tests/test_server.py`, add:

```python
def test_news_feed_hook_registered_when_enabled(monkeypatch):
    from horus import server as srv

    registered: list = []
    monkeypatch.setattr(
        "horus.pipeline.register_end_hook", lambda fn: registered.append(fn)
    )
    cfg = srv.Config()
    srv.Server(cfg)._register_news_feed_hook()
    assert len(registered) == 1


def test_news_feed_hook_not_registered_when_disabled(monkeypatch):
    from horus import server as srv

    registered: list = []
    monkeypatch.setattr(
        "horus.pipeline.register_end_hook", lambda fn: registered.append(fn)
    )
    cfg = srv.Config()
    cfg.news_feed.enabled = False
    srv.Server(cfg)._register_news_feed_hook()
    assert registered == []
```

In `tests/test_cli.py`, add:

```python
def test_cli_news_feed_flag_registered():
    from horus.cli import _build_parser
    from horus.pipeline import discover_enrichers, discover_sources

    p = _build_parser(discover_sources(), discover_enrichers())
    args = p.parse_args(["--news-feed"])
    assert args.news_feed is True
```

- [ ] **Step 2: Run tests, expect failure**

Run: `pytest tests/test_server.py tests/test_cli.py -q --no-cov`
Expected: FAIL — `_register_news_feed_hook` / `--news-feed` not found.

- [ ] **Step 3: Implement the server hook**

In `horus/server.py`, add:

```python
    def _register_news_feed_hook(self) -> None:
        """Register the pipeline end-hook that scores + posts AI-curated news."""
        if not self.cfg.news_feed.enabled:
            return
        try:
            from .news_feed import score_and_post
            from .pipeline import register_end_hook

            threshold = self.cfg.news_feed.threshold
            max_articles = self.cfg.news_feed.max_articles_per_run

            def _hook(result) -> None:
                from .storage import db as _storage

                with _storage.connect() as conn:
                    outcome = score_and_post(
                        conn, threshold=threshold, max_articles=max_articles
                    )
                if outcome.scored or outcome.posted:
                    self._log(
                        f"news-feed: scored {outcome.scored}, posted {outcome.posted}"
                    )
                elif outcome.error:
                    self._log(f"[WARN] news-feed skipped: {outcome.error}")

            register_end_hook(_hook)
        except Exception as e:
            self._log(f"[WARN] failed to register news-feed hook: {e}")
```

In `start()`, after the notification hook registration block, add:

```python
        self._register_news_feed_hook()
```

- [ ] **Step 4: Implement the CLI command**

In `horus/cli.py`:

Add argument near `--backfill-epss`:

```python
    p.add_argument(
        "--news-feed",
        action="store_true",
        help="Score new news articles with AI and post important ones, then exit.",
    )
```

Add handler:

```python
def _cmd_news_feed(args) -> None:
    from .news_feed import score_and_post
    from .server import load_config
    from .storage import db

    cfg = load_config(args.config)
    db.initialize()
    with db.connect() as conn:
        outcome = score_and_post(
            conn,
            threshold=cfg.news_feed.threshold,
            max_articles=cfg.news_feed.max_articles_per_run,
            provider=getattr(args, "ai_provider", None),
        )
    if outcome.error:
        logger.warning("news-feed: %s", outcome.error)
    logger.info("news-feed: scored %d, posted %d", outcome.scored, outcome.posted)
```

Wire dispatch in `main()` before the default pipeline run:

```python
    if args.news_feed:
        return _cmd_news_feed(args)
```

- [ ] **Step 5: Update `horus.yaml.example`**

Add under the `news_feed:` comment block (after `plugins:`):

```yaml
# AI news feed — score new RSS articles with AI, post the important ones to /posts.
news_feed:
  enabled: true
  threshold: 80           # min importance score (0-100) to become a post
  max_articles_per_run: 50
```

- [ ] **Step 6: Run tests, verify pass**

Run: `pytest tests/test_server.py tests/test_cli.py -q --no-cov`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add horus/server.py horus/cli.py horus.yaml.example tests/test_server.py tests/test_cli.py
git commit -m "feat: wire news-feed into server end-hook + CLI"
```

---

### Task 5: Web `/posts` page

**Files:**
- Create: `horus/web/routes/posts.py`
- Create: `horus/web/templates/posts.html`
- Modify: `horus/web/routes/__init__.py` (register blueprint)
- Test: `tests/web/test_posts.py`

**Interfaces:**
- Consumes: `db.get_news_posts(conn, *, page, per_page)`, `web.queries.safe_int`, `web.queries.PER_PAGE_DEFAULT`, `web._render.page`, `web.routes.auth.role_required`/`READ_ALL`.
- Produces: Flask blueprint `bp` with `GET /posts`.

- [ ] **Step 1: Write failing tests**

Create `tests/web/test_posts.py` (following the `auth_client` fixture convention from `tests/web/test_vendors.py`):

```python
"""Tests for the /posts AI news-feed page."""

from __future__ import annotations

import pytest

from horus.storage import db
from horus.web import app as flask_app


@pytest.fixture(scope="module", autouse=True)
def _seed_db():
    db.initialize()
    with db.connect() as c:
        c.execute(
            "INSERT INTO news_article (title, url, source, tier, summary, first_seen,"
            " ai_score, ai_rationale, ai_headline, ai_summary, scored_at)"
            " VALUES ('Apache RCE', 'http://a', 'hacker_news', 1, 's',"
            " '2026-08-01T00:00:00Z', 95, 'exploited', 'RCE Critical', 'Patch now',"
            " '2026-08-15T00:00:00Z')"
        )
        article_id = c.execute(
            "SELECT id FROM news_article WHERE url = 'http://a'"
        ).fetchone()[0]
        c.execute(
            "INSERT INTO news_post (article_id, posted_at) VALUES (?, ?)",
            (article_id, "2026-08-15T00:00:00Z"),
        )
        c.commit()


@pytest.fixture()
def auth_client():
    flask_app.config.update(TESTING=True, SECRET_KEY="test-secret")
    with flask_app.test_client() as c:
        c.post(
            "/register",
            data={
                "username": "postuser",
                "email": "post@example.com",
                "password": "password123",
                "password_confirm": "password123",
            },
            follow_redirects=True,
        )
        c.post(
            "/login",
            data={"username": "postuser", "password": "password123"},
            follow_redirects=True,
        )
        yield c


def test_posts_page_renders_seeded_posts(auth_client):
    r = auth_client.get("/posts")
    assert r.status_code == 200
    assert b"RCE Critical" in r.data
    assert b"Apache RCE" in r.data
```

- [ ] **Step 2: Run tests, expect failure**

Run: `pytest tests/web/test_posts.py -q --no-cov`
Expected: FAIL — 404 or module not found.

- [ ] **Step 3: Implement `horus/web/routes/posts.py`**

Mirror the news route structure:

```python
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
```

- [ ] **Step 4: Implement `horus/web/templates/posts.html`**

Create a template modeled on `news.html` (extends base.html, uses `.panel`):

```html
{% extends "base.html" %}
{% block content %}
<div class="eyebrow">{{ eyebrow|default('AI news feed') }}</div>
<h1 class="page-title">{{ title }} <em>· {{ total }}</em></h1>
{% if subtitle %}<p class="page-subtitle">{{ subtitle }}</p>{% endif %}

{% if rows %}
<div class="panel">
  <div class="panel-body flush">
    <table class="table">
      <thead>
        <tr><th>Score</th><th>Headline</th><th>Source</th><th>Posted</th></tr>
      </thead>
      <tbody>
        {% for r in rows %}
        <tr>
          <td><span class="badge">{{ r.ai_score }}</span></td>
          <td>
            <a href="{{ r.url }}" target="_blank" rel="noopener">{{ r.headline }}</a>
            {% if r.ai_rationale %}<div class="text-muted small">{{ r.ai_rationale }}</div>{% endif %}
            <div class="text-muted small">{{ r.post_summary }}</div>
          </td>
          <td>{{ r.source }}</td>
          <td>{{ r.posted_at }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
</div>
<div class="pagination">
  {% if prev_url %}<a href="{{ prev_url }}">← Newer</a>{% endif %}
  {% if next_url %}<a href="{{ next_url }}">Older →</a>{% endif %}
</div>
{% else %}
<p class="empty-state">No posts yet — the AI hasn't flagged any news as important.</p>
{% endif %}
{% endblock %}
```

- [ ] **Step 5: Register the blueprint**

In `horus/web/routes/__init__.py`:

```python
from .posts import bp as posts_bp
```

and add `posts_bp` to `ALL_BLUEPRINTS` (after `news_bp`).

- [ ] **Step 6: Run tests, verify pass**

Run: `pytest tests/web/test_posts.py -q --no-cov`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add horus/web/routes/posts.py horus/web/templates/posts.html horus/web/routes/__init__.py tests/web/test_posts.py
git commit -m "feat: /posts web page for the AI news feed"
```

---

### Task 6: Docs + changelog + final verification

**Files:**
- Modify: `docs/FEATURES.md`
- Modify: `docs/architecture.md`
- Modify: `CHANGELOG.md`
- Modify: `docs/superpowers/specs/2026-08-15-ai-news-feed-design.md` (mark as implemented)

- [ ] **Step 1: Update `docs/FEATURES.md`**

Add a feature bullet under the main list and a section describing the AI news feed (what it does, `/posts`, `horus news-feed`, config keys).

- [ ] **Step 2: Update `docs/architecture.md`**

Add a short paragraph in the news section: news articles are scored by AI via `horus/news_feed`, above-threshold items become posts on `/posts`.

- [ ] **Step 3: Update `CHANGELOG.md`**

Under `## [Unreleased]`, add:

```markdown
### Added
- **AI news feed**: new articles from RSS are scored for importance by the AI; articles above `news_feed.threshold` become posts on a new `/posts` page. New `horus news-feed` CLI command.
```

- [ ] **Step 4: Update the spec doc**

At the top of `docs/superpowers/specs/2026-08-15-ai-news-feed-design.md`, change `Status: approved design, pending implementation plan` to `Status: implemented`.

- [ ] **Step 5: Run the full test suite + lint**

Run: `pytest tests/ -q --no-cov`
Expected: all pass (except any pre-existing failures unrelated to this feature).

Run: `ruff check horus/ tests/`
Expected: no new errors.

- [ ] **Step 6: Commit**

```bash
git add docs/FEATURES.md docs/architecture.md CHANGELOG.md docs/superpowers/specs/2026-08-15-ai-news-feed-design.md
git commit -m "docs: document AI news feed"
```
