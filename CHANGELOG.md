# Changelog

All notable changes to Horus will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
