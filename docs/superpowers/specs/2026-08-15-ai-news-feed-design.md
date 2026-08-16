# AI News Feed — Design Spec

*Date: 2026-08-15*
*Branch: `refactor/plugin-system`*
*Status: implemented*

## Goal

Curate the RSS security-news already ingested by Horus into a **posts feed**: the
AI scores every new article for importance and, above a configurable threshold,
the article becomes a **post** on a new web feed page. Human analysts can read a
ranked, AI-curated feed instead of the raw, keyword-tagged news table.

Existing pieces reused:
- `horus/plugins/sources/news/main.py` — ingests RSS into `news_article` (tier 1-4 keyword tags).
- `horus/ai/` — provider-agnostic AI interface (`select_provider` → OpenAI/Anthropic/Ollama), JSON prompt/parse patterns.
- `horus/pipeline.py` `register_end_hook` — server-side post-pipeline hooks (already used by notification dispatch).

## Decisions locked (from clarifying questions)

1. **Output surface**: posts live on a new **Horus web feed page** (`/posts`). No Telegram/external publishing in v1.
2. **AI decision**: score **every new article** 0-100 + one-line rationale + AI headline/summary; post those above a config `threshold`.
3. **Trigger**: automatic via a server pipeline **end-hook** after each cycle; plus a `horus news-feed` CLI command for manual/backfill.
4. **Scoring granularity**: all new articles (no keyword pre-filter) — AI is the authority, keyword tiers stay as display metadata.
5. **Threshold semantics**: config threshold; each article scored **once** when first seen; changing the threshold affects only future articles.
6. **Failure handling**: AI provider down → skip that cycle, retry next cycle (articles stay un-scored). No keyword fallback.
7. **Post content**: posts store **AI-generated** headline + summary + rationale + original link.
8. **Moderation**: read-only feed. AI verdict is final (score + rationale displayed).

---

## Section 1 — Architecture & data model

### New package: `horus/news_feed/`

Single entry point:

```python
def score_and_post(conn, *, threshold: int, max_articles: int = 50,
                   provider: str | None = None) -> NewsFeedResult
```

- `NewsFeedResult` (dataclass): `scored: int`, `posted: int`, `skipped: int`, `error: str | None`.
- Purely DB + AI; no Flask, no CLI glue.

### DB changes

**1. Columns added to `news_article`** (scored once, persisted forever):

```sql
ALTER TABLE news_article ADD COLUMN ai_score     INTEGER;
ALTER TABLE news_article ADD COLUMN ai_rationale TEXT;
ALTER TABLE news_article ADD COLUMN ai_headline  TEXT;
ALTER TABLE news_article ADD COLUMN ai_summary   TEXT;
ALTER TABLE news_article ADD COLUMN scored_at    TEXT;
```

Applied as idempotent `ADD COLUMN IF NOT EXISTS`-style migrations in `db.initialize()`.

**2. New table `news_post`** (one row per posted article):

```sql
CREATE TABLE IF NOT EXISTS news_post (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    article_id INTEGER NOT NULL UNIQUE REFERENCES news_article(id) ON DELETE CASCADE,
    posted_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_news_post_posted_at ON news_post(posted_at);
```

`article_id UNIQUE` makes posting idempotent (`INSERT OR IGNORE`).

---

## Section 2 — AI scoring & data flow

### Batched prompt (one AI call per cycle)

1. Select un-scored articles: `WHERE ai_score IS NULL ORDER BY first_seen LIMIT ?`
   (`max_articles` bounds token cost).
2. Build prompt: one line per article —
   `ID | title | summary | source | tier | published_at`.
3. Prompt asks for JSON only:
   ```json
   {"articles": [{"id": <id>, "score": 0-100, "rationale": "...",
                  "headline": "...", "summary": "..."}]}
   ```

### Parsing rules

- Strict: each returned item must have a known `id`, integer `score` 0-100,
  and string fields. Unknown IDs are skipped.
- Malformed **whole** response → `AIMalformedResponseError` (reuse from `horus/ai/base.py`).
- Partial subset parses → score the valid subset, log the error.

### Persistence

- Every scored article (above **and** below threshold) gets
  `ai_score/ai_rationale/ai_headline/ai_summary/scored_at` written back —
  never re-scored.
- `ai_score >= threshold` → `INSERT OR IGNORE INTO news_post(article_id, posted_at)`.
- AI headline/summary fall back to the article's title/summary if empty.

### Failure handling

- No un-scored articles → immediate no-op (`scored=0, posted=0`).
- `AIUnavailableError` (no key, provider down) → log warning, return
  `NewsFeedResult(error=..., ...)`; articles retried next cycle.
- `AIMalformedResponseError` → log warning; nothing scored this cycle.

### Config (`horus.yaml`)

```yaml
news_feed:
  enabled: true
  threshold: 80           # min ai_score to become a post
  max_articles_per_run: 50
```

`Config` dataclass gains a `NewsFeedConfig` (`enabled`, `threshold`, `max_articles_per_run`).

---

## Section 3 — Server + CLI integration & web page

### Server hook (`horus/server.py`)

- `Server._register_news_feed_hook()`: registers a pipeline end-hook (existing
  `register_end_hook`) that calls `score_and_post(conn, ...)` guarded by
  `cfg.news_feed.enabled`. Called from `start()` alongside the notification hook.
- Fires after full pipeline runs (where the news source ingests). Not wired into
  the enrichers-only cycle.

### CLI (`horus/cli.py`)

- `horus news-feed`: loads config, initializes DB, runs `score_and_post`, prints
  summary (`scored N, posted M`). Mirrors `--backfill-epss` style.

### Web page (`horus/web/routes/posts.py` + template)

- `GET /posts` (role-gated like `/news`): `news_post` JOIN `news_article`,
  columns: AI headline, score badge, rationale, source, original link, posted_at.
- Reuses the existing `page()` render helper + table pattern from the news route.
- Paginated (`per_page` + page query params, same as `/news`).

---

## Out of scope (YAGNI)

- Posting to Telegram / external services.
- Human moderation / review queue (read-only feed in v1).
- Re-scoring previously-scored articles.
- Per-feed importance weights / keywords.

## Risks

- **AI cost**: one batched call per cycle bounded by `max_articles_per_run`.
- **Prompt drift**: strict JSON parsing + `INSERT OR IGNORE` dedupe keeps a bad
  response from corrupting the feed.
- **Migration**: `ALTER TABLE` must be idempotent for existing installs.
