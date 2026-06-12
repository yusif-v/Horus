# Horus — Remaining Test Work List

**Status: 106 tests passing, 47% coverage (2824 stmts total, 1493 missed)**
**Target: raise coverage to 80%+ by testing all uncovered modules**

Priority order: testable pure logic first, then integration, then network-mocking.

---

## P0 — Pure logic, no I/O mocking needed (highest value)

### 1. `tests/render/test_report.py` — horus/render/report.py (115 stmts, 0%)
- `render_report()` dispatches to text vs markdown correctly
- `_group_cves()` groups by primary category, sorts by CVSS desc, unknown last
- `_standalone_pocs()` filters PoCs whose refs are all unknown
- `_poc_label()` adds `[tweet]` for twitter/x sources
- `_poc_detail()` formats star/age/tweet label
- `_render_text()` output contains header, CVE lines, PoC lines, KEV/EPSS badges
- `_render_markdown()` output contains markdown headers, bullet points, badges
- Empty cves + empty pocs → "No new findings" message in both formats
- CVE with no affected products → category "unknown"
- CVE with attack_tags shows tags in output
- Standalone PoCs sorted by stars desc

### 2. `tests/render/test_graph.py` — horus/render/graph.py (58 stmts, 0%)
- `_fetch_graph()` returns nodes + edges from an in-memory SQLite DB
- CVE nodes: included if connected OR has description; excluded if disconnected + no desc
- PoC nodes: included if connected OR has stars; excluded if disconnected + no stars
- Product nodes: only included if connected; unknown/unknown placeholder excluded
- Tag nodes: only included if connected
- Edges filtered to valid endpoints only
- `render_graph_html()` returns HTML string with cytoscape.js, contains date, node/edge counts
- `save_graph()` writes to reports/YYYY/MM/YYYY-MM-DD.graph.html
- Empty DB → empty graph (no nodes, no edges)

### 3. `tests/render/test_persist.py` — horus/render/persist.py (12 stmts, 42%)
- `save_report()` writes content to correct path (reports/YYYY/MM/YYYY-MM-DD.{md,txt})
- Same-day rerun overwrites
- Returns the Path object
- fmt="md" → .md extension, fmt="txt" → .txt extension

### 4. `tests/net/test_auth.py` — horus/net/auth.py (19 stmts, 32%)
- `github_token()` returns GITHUB_TOKEN env var when set
- `github_token()` falls back to GH_TOKEN when GITHUB_TOKEN unset
- `github_token()` returns None when no env vars and gh not installed
- `github_token()` caches result (lru_cache)
- Token is stripped of whitespace

### 5. `tests/net/test_http.py` — horus/net/http.py (38 stmts, 18%)
- `fetch_json()` returns parsed JSON on success
- `fetch_json()` retries on 429/500/502/503/504 with exponential backoff
- `fetch_json()` respects Retry-After header
- `fetch_json()` raises on 4xx (non-retryable) immediately
- `fetch_json()` raises after max_retries exhausted
- `fetch_json()` merges custom headers with User-Agent
- `fetch_json()` sends Accept header when provided

### 6. `tests/core/test_merge.py` — horus/core/merge.py (132 stmts, 58%)
- `merge_findings()` deduplicates CVEs by ID (keeps highest CVSS)
- `merge_findings()` deduplicates PoCs by URL
- `merge_findings()` aggregates social_signals into watchlist_counts
- `link_pocs_to_cves()` links PoCs to CVEs by ref
- PoC with no matching CVE refs → not linked
- CVE with no PoCs → empty links list
- Social signals for unknown CVE IDs → watchlist entries
- Social signals for known CVE IDs → merged into CVE social_mentions

---

## P1 — CLI + config parsing (argparse mocking)

### 7. `tests/test_cli.py` — horus/cli.py (90 stmts, 43%)
- `_build_parser()` includes all expected flags (--sources, --enrichers, --format, --quiet, etc.)
- `_build_parser()` includes --no-<source> and --skip-<enricher> flags
- `_build_parser()` --version outputs version
- `_cmd_list_sources()` prints sources and enrichers sections
- `--list-sources` exits without running pipeline
- `--health-check` calls run_health_check
- `--query CVE-2026-0001` calls query_cve with correct args
- `--auth-status` calls github_token and prints result
- `--server` flag triggers server path
- `--backfill-epss` triggers backfill path
- Default (no flags) runs full pipeline
- `--sources nvd,github` sets source_filter correctly
- `--no-nvd` adds to disabled_sources

### 8. `tests/test_server.py` — horus/server.py (209 stmts, 0%)
- `load_config(None)` returns defaults
- `load_config(path)` reads YAML config
- `load_config(path)` reads JSON config
- `load_config(path)` returns defaults for missing file (warns)
- `load_config(path)` handles missing PyYAML (falls back to JSON)
- `Config.interval()` returns configured value or default
- `Config.enabled()` returns configured value or True default
- `Server.run_once()` calls _invoke_pipeline with all enabled sources
- `Server.run_due()` skips sources not yet due
- `Server.run_due()` runs sources whose interval elapsed
- `Server._invoke_pipeline()` with sources calls run_pipeline
- `Server._invoke_pipeline()` with enrichers-only calls backfill_all + KEV enrich
- `Server._invoke_pipeline()` with no sources and no enrichers is a no-op
- `_last_run_epoch()` returns 0.0 for never-run source
- `_last_run_epoch()` parses ISO timestamp correctly
- WebConfig defaults: enabled=True, host=127.0.0.1, port=8080

---

## P2 — Source modules (network mocking with unittest.mock)

### 9. `tests/sources/test_github.py` — horus/sources/github.py (94 stmts, 15%)
- `_confidence_for_stars()` returns high/medium/low correctly
- `run()` with empty known_cve_ids returns empty results
- `run()` searches GitHub API with correct query
- `run()` parses API response into PoC objects
- `run()` enriches x_discovered_urls when provided
- `run()` handles API errors gracefully
- `run()` respects max_results and min_cvss from context

### 10. `tests/sources/test_gitlab.py` — horus/sources/gitlab.py (66 stmts, 20%)
- `run()` fetches GitLab CSV and parses results
- `run()` returns PoCs linked to known CVEs
- `run()` handles HTTP errors gracefully
- `run()` with empty known_cve_ids returns empty

### 11. `tests/sources/test_nvd.py` — horus/sources/nvd.py (140 stmts, 13%)
- `_extract_cwes()` extracts CWE IDs from weaknesses list
- `_extract_cwes()` returns empty for no weaknesses
- `run()` fetches from NVD API with correct date range
- `run()` parses CVE items into CVE objects
- `run()` handles vendor alias normalization
- `run()` respects min_cvss filter
- `run()` handles API errors gracefully
- `run()` deduplicates against known_cve_ids

### 12. `tests/sources/test_x_twitter.py` — horus/sources/x_twitter.py (54 stmts, 24%)
- `run()` extracts CVE IDs from tweets
- `run()` extracts GitHub URLs from tweets
- `run()` returns social_signals for CVE mentions
- `run()` returns x_discovered_urls for GitHub links
- `run()` handles XAuthError gracefully
- `run()` handles XSearchError gracefully
- `run()` with empty queries returns empty

### 13. `tests/sources/test_exploitdb.py` — horus/sources/exploitdb.py (40 stmts, 25%)
- `run()` fetches Exploit-DB CSV from GitLab
- `run()` parses CSV rows into PoC objects
- `run()` links PoCs to known CVE IDs
- `run()` with empty known_cve_ids returns empty
- `run()` handles HTTP errors gracefully

---

## P3 — Pipeline integration (mock sources/enrichers)

### 14. `tests/test_pipeline_extended.py` — horus/pipeline.py (162 stmts, 37%)
- `run_pipeline()` with no sources and no enrichers → empty result
- `run_pipeline()` with mock source that returns CVEs → CVEs in result
- `run_pipeline()` with mock source that returns PoCs → PoCs in result
- `run_pipeline()` with disabled source → source not called
- `run_pipeline()` with source_filter → only selected sources run
- `run_pipeline()` with enricher_filter → only selected enrichers run
- `run_pipeline()` persists CVEs to DB
- `run_pipeline()` persists PoCs to DB
- `run_pipeline()` links PoCs to CVEs in DB
- `run_pipeline()` marks run timestamps
- `run_pipeline()` generates report text
- `run_pipeline()` saves report when save_report_md=True
- `run_pipeline()` saves graph when save_graph_html=True
- `run_pipeline()` skips save when flags are False
- `run_pipeline()` handles source errors gracefully (continues other sources)
- `run_pipeline()` handles enricher errors gracefully
- CVE sources run before PoC sources (ordering)
- x_twitter runs before github (ordering for URL enrichment)

---

## P4 — Storage health + query (SQLite in-memory)

### 15. `tests/storage/test_health_extended.py` — horus/storage/health.py (277 stmts, 48%)
- Schema integrity check passes on fresh DB
- Schema integrity check fails on missing table
- CVE data quality: valid ID format check
- CVE data quality: CVSS range validation (0-10)
- CVE data quality: severity enum validation
- PoC data quality: URL format check
- PoC data quality: source enum validation
- Referential integrity: orphan detection in poc_cve
- Referential integrity: orphan detection in cve_attack_tag
- Enum consistency: attack tag validation
- Enum consistency: product category validation
- Stale data detection: old records flagged
- Duplicate detection: logical duplicates found
- Coverage metrics: EPSS coverage percentage
- Coverage metrics: KEV coverage percentage
- Source tracking: CVEs without source entries flagged
- `run_health_check().print()` outputs report

### 16. `tests/storage/test_query_extended.py` — horus/storage/query.py (249 stmts, 76%)
- `query_cve()` with valid ID returns CVE data
- `query_cve()` with unknown ID falls back to keyword search
- `query_cve()` with missing DB returns error string
- `query_cve()` text format contains core fields
- `query_cve()` markdown format contains headers
- `query_keyword()` finds match in description
- `query_keyword()` empty result returns "no results"
- `get_cve_detail()` returns grouped products
- `get_cve_detail()` returns None for unknown ID
- `get_cve_detail()` normalizes naked ID (adds CVE- prefix)
- `get_stats()` returns correct counts
- `safe_int()` clamps and defaults correctly

---

## P5 — Web layer (Flask test client)

### 17. `tests/web/test_api.py` — horus/web/routes/api.py (22 stmts, 77%)
- GET /api/stats returns JSON with correct keys
- GET /api/stats requires auth (redirects when not logged in)
- GET /api/cve/CVE-2026-0001 returns JSON for known CVE
- GET /api/cve/unknown returns 404 JSON
- GET /api/cve/<id> requires auth

### 18. `tests/web/test_cves_route.py` — horus/web/routes/cves.py (49 stmts, 84%)
- GET /cves returns 200 with auth
- GET /cves requires auth (redirects when not logged in)
- GET /cves?severity=CRITICAL filters correctly
- GET /cves?kev=1 filters to KEV only
- GET /cves?sort=epss sorts by EPSS
- GET /cves?window=day filters to last 24h
- GET /cves?window=week filters to last 7 days
- GET /cves?page=2 paginates correctly
- Invalid window param defaults to "all"
- Invalid sort param defaults to "cvss"

### 19. `tests/web/test_app.py` — horus/web/__init__.py (31 stmts, 58%)
- `create_app()` returns Flask app
- `create_app()` registers all blueprints
- `create_app()` sets secret_key
- `create_app()` sets template_folder and static_folder
- Module-level `app` is a Flask instance

---

## P6 — X/Twitter network layer (heavy mocking)

### 20. `tests/net/test_xsearch.py` — horus/net/xsearch.py (256 stmts, 14%)
- Cookie extraction from Chrome DB (mock SQLite)
- Cookie decryption with mock keychain
- `XSearch` auth with valid cookies
- `XSearch` raises XAuthError on invalid cookies
- `XSearch.search()` returns parsed tweets
- `XSearch.search()` handles rate limits
- `XSearch.search()` handles empty results
- Query ID discovery fallback
- `_KNOWN_QUERY_IDS` list is non-empty

---

## Summary

| Priority | Test files | Modules covered | Est. tests |
|----------|-----------|----------------|------------|
| P0 | 6 | report, graph, persist, auth, http, merge | ~45 |
| P1 | 2 | cli, server | ~30 |
| P2 | 5 | github, gitlab, nvd, x_twitter, exploitdb | ~35 |
| P3 | 1 | pipeline (extended) | ~18 |
| P4 | 2 | health (extended), query (extended) | ~25 |
| P5 | 3 | api, cves route, app factory | ~15 |
| P6 | 1 | xsearch | ~12 |
| **Total** | **20** | **22 modules** | **~180** |

Expected coverage after completion: **85-90%**
