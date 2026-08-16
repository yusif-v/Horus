# Changelog

All notable changes to Horus will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **AI news feed**: new articles from RSS are scored for importance by the AI; articles above `news_feed.threshold` become posts on a new `/posts` page. New `horus --news-feed` CLI command.

## [0.16.0] - 2026-08-13

### Added
- **Plugin system**: sources, enrichers, and notifications are now folder+`plugin.toml` plugins loaded by a single `PluginManager` (bundled `horus/plugins/<kind>/<name>/` + external `plugin_dirs`).
- **`horus plugin` CLI**: `list`, `enable`/`disable`, `config`, `add`, `remove`, `scaffold`, `validate`.

### Changed
- **Unified config schema**: `horus.yaml` now uses `plugin_dirs:` + `plugins:` (per-plugin `enabled`/`interval_seconds`/`config`). Legacy `sources_enabled`/`poll_intervals`/`telegram` keys still honored with a `DeprecationWarning`; removed in the next minor.
- **`horus plugin config <name> <key> <value>`** writes under `plugins.<name>.config` so the value is actually applied by `apply_config`.
- **Notification prefs are per-user**: `NotificationContext.prefs` is now `{user_id: {kind: bool}}`; a user who disabled a kind no longer receives it just because another user enabled it.
- **One-shot runs honor config**: `horus` (non-server) builds its plugin set from horus.yaml, so `plugins.<name>.enabled`/`.config` apply to one-shot scans too.

### Added
- `PluginManager.all()` + `Plugin.path` surfaced by `horus plugin list` (enabled state + location).
- Server enrichers-only cycle also backfills OTX + darkweb (deliberate extension beyond the epss+kev plan).
- `horus/core/feeds.py` FEEDS registry de-couples the web layer and news linker from the news plugin package.

### Cleaned up
- Removed the dead `_discover_plugins` (pkgutil-based) from `pipeline.py`; plugin discovery lives in `PluginManager`. Deleted its now-obsolete test file.
- Typed all bundled plugin entrypoints (`run(ctx: SourceContext)` / `enrich(ctx: EnricherContext)`).
- Replaced the dynamic `_override_enabled` attribute on `Plugin` with a declared `enabled_override` field.
- Unified YAML/JSON config parsing into `horus/core/config_io.py` (shared by server + CLI).
- Standardized test module docstrings in `tests/plugin_manager/`.

## [0.15.0] - 2026-08-07

### Added
- **CVE correlation engine**: pairwise correlation scoring from shared tags, CWEs, products, PoCs, and temporal proximity. Related CVEs on each dossier page grouped by reason. Correlation Clusters dashboard at `/correlations` showing attack campaign groups.
- **Automated PoC verification**: composite confidence score (0-100, grade A-F) from 6 signals — CVE presence in description, repo freshness, star count, URL quality, description quality, NVD cross-reference. Stored in `poc_verification` table.
- **MITRE ATT&CK technique mapping**: 22 attack tags mapped to ATT&CK technique IDs (T1059, T1190, T1068, etc.). Techniques persisted per-CVE and exposed via API.
- **EPSS trend tracking**: CVE-level EPSS history chart (Chart.js), velocity badge, days-above-threshold counter. Global movers dashboard at `/epss-trends`.
- **CVE-news intelligence linking**: extract CVE IDs from RSS articles, link to CVEs with context (exploit status, severity mention). Latest 10 sources shown on each CVE page.

## [0.14.0] - 2026-08-06

### Added
- **Weekly threat intelligence report**: `horus --weekly-report` generates aggregated weekly reports with executive summary, top CVEs by risk score, KEV entries, EPSS exploitability rankings, most targeted vendors, attack technique distribution (MITRE ATT&CK), security news highlights, ThreatFox IOC summary, triage workflow status, and source health observability.
- **AI-powered report analysis**: `--ai` flag augments the weekly report with LLM-generated narrative analysis (executive summary, trend analysis, risk assessment, recommended actions) and automated QA bug detection (data anomalies + report correctness). Configurable providers: OpenAI, Anthropic, Ollama (local).
- `horus/ai/` package: provider-agnostic AI interface with pluggable backends.
- `--weekly-format` flag supporting text, markdown, and HTML output.
- `--ai-provider` flag to override the AI provider per-run.

### Fixed
- Test isolation: `tests/conftest.py` now snapshots `os.environ` before importing `horus.web` to prevent `.env` leakage from polluting test config.

## [0.10.0] - 2026-06-17

### Added
- **User self-service**: `/profile/settings` — users can change their own email, team assignment, and password (current password required for password changes). Audit-logged as `user.self_update`.
- `docs/plans/v0.10.md` — Telegram bot listener, notification dispatch, bot command reference, work items.
- `.github/workflows/security.yml` — pip-audit on PRs, main pushes, weekly schedule. Fails on HIGH+ advisories.
- `.github/dependabot.yml` — grouped dev-deps weekly PR, separate runtime-deps PRs.
- `make audit` / `make sbom` — pip-audit + CycloneDX SBOM generation targets in Makefile.
- Supply chain deps: `pip-audit>=2.7`, `cyclonedx-bom>=4.4` in `[project.optional-dependencies] dev`.

### Changed
- **Search input capped at 200 characters** — both client-side (`maxlength`) and server-side truncation.
- **mypy --strict** expanded to `horus/storage/*`, `horus/net/http`, `horus/net/auth` (was only core + pipeline).

### Fixed
- `tests/test_server.py` — added missing `import sys` and `from unittest.mock import MagicMock` (7 tests were failing).
- `pyproject.toml` (PEP 621) replaces `setup.py` and
  `requirements.txt`. Dev tooling lives under `[project.optional-dependencies] dev`:
  ruff, mypy, pytest-cov, pre-commit.
- `.pre-commit-config.yaml` — ruff lint + format, plus whitespace /
  EOL / YAML / TOML / merge-conflict checks. `pre-commit install` wires
  it into `git commit`.
- `horus.yaml` — top-level server config (poll intervals, source
  toggles, web supervision) with every key the server's loader
  recognizes pre-filled with defaults.
- `/cves` page: **Window** filter chip group (Last 24h / Last week /
  Last month / All time) that composes with severity, KEV, and sort.

### Changed
- **Server scheduling now includes GitLab.** `SOURCE_KEYS` and
  `DEFAULT_POLL_INTERVALS` in `horus/server.py` previously omitted
  `gitlab`, so the source was registered but never polled by the
  server's `run_due` loop. Its `last_run` row only updated when the
  CLI was invoked manually.
- **`datetime.utcnow()` purged** across `horus/` (13 sites in
  `db.py`, `_render.py`, `model.py`, `merge.py`, `health.py`,
  `nvd.py`, `gitlab.py`, `github.py`, `server.py`). Replaced with
  `datetime.now(timezone.utc)` and the deprecation warnings (~42 per
  test run) are gone.
- **`mypy --strict`** is green on `horus/core/*` and
  `horus/pipeline.py`. Configured in `[tool.mypy]` so other modules
  remain on relaxed settings until they're ratcheted up.
- `PipelineResult.watchlist_counts` retyped
  `dict[str, int]` → `list[tuple[str, str, int]]` to match what
  `merge_findings()` actually returns (caught by mypy; downstream code
  was already unpacking three-tuples).
- `/cves` table now uses `table-layout: fixed` with an explicit
  `<colgroup>` so column widths no longer shift between filter
  combinations. Description column ellipses on overflow.
- `/cves?kev=1` chip toggles off when clicked while active (was
  re-applying `kev=1` and staying on).

### Fixed
- `tests/core/test_reputation.py::test_merge_split_social_into_watchlist_when_not_in_nvd`
  asserted the watchlist as a dict, but `merge_findings()` returns a
  list of `(cve_id, source, count)` tuples. Test updated.

### Tooling
- `ruff` (lint + format) — 58 files clean. Ruleset: E/F/W/I/B/UP/SIM/RUF.
- `pytest-cov` with `--cov-fail-under=25` (current 27.6 %). The 70 %
  target from the original v0.9 plan is tracked in `docs/plans/v0.9.x.md`.

### Changed
- **Package restructure.** No behavior change; pure structural. See
  `docs/architecture.md` for the full map.
  - `horus/pipeline.py` (new) is the single source of truth for the
    sources → merge → enrich → persist → render flow. `cli.main` and
    `server.Server` both call `run_pipeline(opts)` — kills the
    synthesised-argv hack server.py used to drive cli.main.
  - `horus/config/` split into `paths.py` + `queries.py` + `tunables.py`
    with flat re-exports for back-compat.
  - `horus/net/` collects the transport layer (`http.py`, `auth.py`,
    `xsearch.py`) that was scattered across `core/` and `sources/`.
  - `horus/web/` is now a package with `routes/` blueprints,
    `templates/*.html` as real Jinja files, and `static/horus.css`
    extracted from the old inline 600-line CSS string.
  - `tests/` (new): 30 pytest tests pinning the reputation formula,
    v0.7 → v0.8 schema migration, plugin discovery, and every web
    route. `/api/stats` JSON contract locked.
  - `PLAN_v0.8.md` moved from repo root to `docs/plans/v0.8.md`.
    `docs/architecture.md` added.

## [0.8.0] - 2026-06-09

### Added
- **Source-purity model.** NVD is the only authoritative source for
  CVE data. GitHub, X/Twitter, and Exploit-DB are demoted to signal
  sources that corroborate NVD records but never create their own.
- **Reputation score** (`reputation_score`, 0–10) replacing the old
  `exploitability_score`. Formula:
  - CVSS × 0.35
  - + EPSS × 10 × 0.25
  - + 1.5 if KEV
  - + min(social_mentions × 0.15, 1.0)
  - + min(poc_source_count × 0.5, 1.5)
  - + 1.0 if affected product is in the ubiquitous-impact set
    (nginx, php, wordpress, openssl, kubernetes, openssh, apache,
    mysql, chrome, linux kernel, …)
- **Watchlist** (`cve_watchlist` table) for CVE IDs mentioned only by
  third-party signals (no NVD record yet). Auto-resolves once NVD
  confirms them.
- **24/7 server mode** (`horus/server.py`, `--server`,
  `--server-once`, `--config`). Per-source poll intervals (NVD 1h,
  X 30m, GitHub 1h, Exploit-DB 2h, EPSS/KEV daily), YAML/JSON config,
  SIGTERM-clean main loop.
- **Production web supervisor.** With `web.enabled: true` the server
  spawns gunicorn as a subprocess in its own process group (clean
  signal propagation across the whole tree), supervises it across
  cycles, and falls back to Flask's dev server only when
  `allow_dev_fallback: true`.
- **`--backfill-epss` CLI flag.** EPSS now scores every previously
  unscored CVE in the DB after the current batch, not just the batch.
- **Web UI v0.8.** Reputation column, social-mentions / confidence /
  watchlist counts surfaced via `/api/stats`.

### Changed
- **X/Twitter source** no longer creates PoC records with `source="x"`.
  Each tweet mentioning a CVE increments `social_mentions`; tweets
  linking to a `github.com` PoC repo feed that URL into the GitHub
  source for star/age enrichment in the same pass.
- **GitHub source** accepts `x_discovered_urls` from the X source.
- **DB schema** gains `social_mentions`, `poc_source_count`,
  `reputation_score`, `confidence` on `cve`. Migration runs
  `ALTER TABLE` against existing v0.7 databases *before* `schema.sql`
  so its new indexes don't reference columns that don't exist yet.

### Fixed
- **Scrollbar layout shift** between pages. Short pages (Overview) had
  no vertical scrollbar; long ones (Triage, CVEs) did. `margin: 0 auto`
  re-centered the container, visibly shifting the title horizontally on
  navigation. Fixed with `scrollbar-gutter: stable` +
  `overflow-y: scroll`.
- **Nav / page-title misalignment** on wide screens. The nav was
  full-width while `.container` was centered at `max-width: 1320px`,
  so the logo and the page title under it didn't share a left edge.
  `.nav` now mirrors the container's `max-width` and `margin: 0 auto`,
  wrapped in `.nav-wrap` so the surface band still spans edge to edge.
- **Path-traversal hardening** in `horus/sources/github.py` for URLs
  surfaced by X. Rejects empty / `.` / `..` segments and url-quotes
  before forming `api.github.com/repos/...`.
- **Web UI version string** bumped from `HORUS v0.5` to `HORUS v0.8`.

## [0.7.0] - 2026-06-07

### Added
- **Plugin architecture** — complete refactor. Sources and enrichers are now self-discovering plugins. Adding a new source = creating ONE file in `sources/` with a `run()` function. No other files change. Flags `--no-<source>` and `--skip-<enricher>` auto-generated.
- **X/Twitter Chrome auth source** (`horus/sources/x_twitter.py` + `horus/core/xsearch.py`) — birdnode-compatible X search using Chrome cookie authentication. Extracts auth_token+ct0 from Chrome's encrypted cookie DB, dynamically discovers GraphQL query IDs from JS bundles, POSTs to SearchTimeline endpoint. No API key, no Nitter, no browser needed.
- **Exploit-DB source** (`horus/sources/exploitdb.py`) — searches exploit-db.com for each new CVE. Rate-limited to 1 query/2s, max 50 per run.
- **CISA KEV enricher** (`horus/enrichers/kev.py`) — fetches Known Exploited Vulnerabilities catalog, marks matching CVEs.
- **EPSS score enricher** (`horus/enrichers/epss.py`) — fetches Exploit Prediction Scoring System probabilities from FIRST.org API.
- **Composite exploitability score** — computed from CVSS (×0.4), EPSS (×0.3), KEV bonus (+2.0), PoC count bonus. Stored in `cve.exploitability_score`.
- New DB columns: `cve.epss_score`, `cve.kev`, `cve.exploitability_score`, `poc.fetched_date`.
- New DB indexes: `idx_cve_epss_score`, `idx_cve_kev`.
- `--list-sources` flag to show all discovered plugins.
- `--sources A,B` / `--enrichers A,B` flags to run only specific plugins.
- Report output now shows KEV badge, EPSS percentage, PoC source tag, and exploitability score.

### Changed
- **NVD filtering** — removed `is_fresh_poc()` keyword filter for CVEs. Was dropping valid entries; NVD results are inherently relevant.
- **Merge pipeline** — `merge_findings()` now accepts CVE and PoC lists from any Source, deduplicates by ID/URL.
- **CVE model** — added `epss_score`, `kev`, `exploitability_score` fields.
- **PoC model** — source enum expanded: `github|exploit-db|nitter|twitter|x|manual`.
- **DB persistence** — `persist_cve()` writes new columns, computes exploitability score.
- **Module reorganization** — `epss.py` and `kev.py` moved from `sources/` to `enrichers/`. `xsearch.py` moved to `core/` (utility, not a plugin).

### Removed
- Hardcoded source imports from `cli.py` — replaced with plugin discovery via `pkgutil`.
- `--use-nitter` flag — Nitter is no longer the Twitter source.
- Old `twitter.py`, `nitter.py` from `sources/`.
- `is_fresh_poc` import from `nvd.py`.

## [0.5.0] - 2026-05-21

### Added
- Interactive graph viewer (`horus/render/graph.py`) — single self-contained HTML file per run, written to `reports/YYYY/MM/YYYY-MM-DD.graph.html`
- Cytoscape.js (loaded via CDN) for force-directed layout
- Node types: CVE (size by CVSS), PoC (size by stars), Product, AttackTag — distinct shapes and colors
- Edge types: `tagged` (CVE→tag), `affects` (CVE→product), `references` (PoC→CVE)
- Click a node to highlight its neighborhood and view details in a side panel
- Floating/orphan nodes filtered out so the graph stays readable
- `--no-graph` flag to skip generation
- All untrusted strings (descriptions, URLs) rendered via `textContent` / DOM construction — no `innerHTML` for user data

## [0.4.1] - 2026-05-21

### Added
- SQLite storage layer at `state/horus.db` — full normalized schema (CVE, PoC, Product, AttackTag, CWE + 5 join tables for graph edges)
- `horus/storage/db.py` — schema init, vocab seeding, JSON migration, CRUD
- `horus/storage/schema.sql` — DDL, idempotent (`CREATE TABLE IF NOT EXISTS`)
- One-shot migration on first run: imports `seen_items.json` (CVE stubs + PoCs) and `last_run.json` (into `meta` table), then renames originals to `.migrated`

### Changed
- Source modules now dedupe on the actual key (CVE id, PoC URL) rather than prefixed strings — cleaner signature
- Last-run timestamps moved from JSON file to the `meta` table
- Strict PoC↔CVE linking: edges only created when the referenced CVE exists in the table

### Removed
- `horus/storage/state.py` — superseded by `db.py`
- JSON state files (`state/seen_items.json`, `state/last_run.json`) — migrated and renamed

## [0.4.0] - 2026-05-21

### Added
- Typed domain model (`horus/model.py`): `CVE`, `PoC`, `AffectedProduct`
- Closed vocabularies (`horus/vocab.py`): 21 attack tags, 18 product categories, CWE→tag and product→category lookup tables
- Classifier (`horus/classify.py`): CWE-priority + keyword-fallback attack tagging; substring-based product categorisation
- Merge layer (`horus/merge.py`): folds raw NVD + GitHub results into typed CVE/PoC objects; derives PoC↔CVE links
- NVD source now extracts CWE IDs and CPE-derived affected vendor/product/version ranges
- Reports group CVEs by product category and show attack tags, affected products, and linked PoCs inline
- Standalone PoCs (GitHub repos with no matching CVE in the run) appear in their own section

### Changed
- `print_report` signature is now `(cves, pocs, links, fmt)` — operates on the typed model rather than raw dicts
- Report ordering: CVEs grouped by category (alphabetical, `unknown` last), within each group sorted by CVSS descending
- **Restructured package layout** into four subpackages with single responsibilities:
  - `horus.core` — pure domain (model, vocab, classify, filters, merge)
  - `horus.sources` — network ingestion (http, auth, github, nvd)
  - `horus.storage` — local persistence (state)
  - `horus.render` — output formatting (report)
  No public CLI changes; `python3 -m horus` works as before.

## [0.3.1] - 2026-05-20

### Added
- GitHub authentication: token resolved automatically from `GITHUB_TOKEN`, `GH_TOKEN`, or `gh auth token` (CLI keyring). Raises GitHub API rate limit from 60 to 5000 requests/hour
- `--auth-status` flag to verify token detection

## [0.3.0] - 2026-05-20

### Added
- CLI flags: `--min-cvss`, `--max-results`, `--format {text,md}`, `--quiet`, `--version`
- Markdown output mode for chat-friendly delivery (Telegram, Slack, etc.)
- Per-source last-run tracking in `state/last_run.json`
- Adaptive NVD lookback: window stretches back to the previous run (capped at 14 days), so missed days are recovered automatically

### Changed
- Progress lines now go to **stderr** (was stdout). `--format md > report.md` produces clean markdown
- GitHub and NVD sources sort and cap results internally; the orchestrator no longer reshuffles them

## [0.2.0] - 2026-05-20

### Changed
- Split monolithic `horus.py` into a `horus/` package: `config`, `state`, `filters`, `http`, `report`, `cli`, and `sources/{github,nvd}`
- Entry point is now `python3 -m horus` (replaces `python3 horus.py`)

### Removed
- X/Twitter (`xurl`) integration and related queries — no longer used

## [0.1.0] - 2026-05-19

### Added
- GitHub PoC repo scanner with smart filtering (<30d old, >10 stars, fresh PoC keywords)
- NVD CVE feed integration with CVSS scores and severity levels
- Deduplication system to avoid reporting previously seen items
- Telegram delivery integration via Hermes cron job
- Optional xurl backend for X/Twitter search (pay-per-use)
- State persistence in `state/seen_items.json`
- README with usage documentation

### Data Sources
- GitHub API (free, no auth) — new PoC repositories
- NVD API (free, no auth) — recent CVEs with CVSS scores
- X/Twitter via xurl (pay-per-use) — early vulnerability disclosures

### Known Limitations
- X/Twitter search requires paid X API (no free tier for new users)
- Nitter mirrors unreliable for web scraping
- GitHub search limited to public repositories
