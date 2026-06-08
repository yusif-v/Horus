# Changelog

All notable changes to Horus will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
