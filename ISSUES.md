# Horus — Known Issues & Technical Debt

*Last updated: 2026-06-11*
*Current version: v0.9.0-dev*
*Health score: 62/100*

---

## Scoring Breakdown

| Category | Score | Max | Notes |
|----------|-------|-----|-------|
| Core pipeline | 85 | 100 | Solid architecture, plugin-based sources, clean merge layer |
| Data quality | 45 | 100 | Product data mostly `unknown`, PoC→CVE links empty, thin social data |
| Web UI | 75 | 100 | Functional, fast, good design. Missing filters, news feed |
| Test coverage | 27 | 100 | 34 tests pass, 27% coverage. Gate at 25%, target 70% |
| Code quality | 80 | 100 | Ruff clean, mypy strict on core. Needs expansion to sources/web |
| Documentation | 70 | 100 | Good plan docs, README. Missing API docs, architecture overview |
| Security | 55 | 100 | No auth on server, no input validation on search, open localhost |
| Ops/Deploy | 40 | 100 | No CI/CD, no release workflow, no SBOM, no dependabot |
| **Overall** | **62** | **100** | Functional prototype, needs data quality + test coverage work |

---

## Critical Issues (Fix First)

### CRIT-01: Product data quality is poor
**Severity:** High | **Status:** Partially fixed (v0.9)
**Impact:** CVE detail pages show "unknown" for most vendors/products

- Only 7 unique products in DB, 1 is `unknown`
- 530 cve_product entries but most have vendor=unknown
- Root cause: NVD CPE parsing didn't normalize vendor names or skip wildcards
- **Fix applied:** 600+ vendor aliases, 400+ product aliases, description-based fallback
- **Remaining:** Need next pipeline run to populate improved data

### CRIT-02: PoC → CVE linking is empty
**Severity:** High | **Status:** Fixed (v0.9), awaiting pipeline run
**Impact:** PoC list shows no CVE badges, `poc_cve` table is empty

- 3 PoCs in DB, 0 links in `poc_cve`
- All 3 PoCs have CVE IDs in their URLs but `extract_cves()` didn't scan URLs
- **Fix applied:** `poc_from_github()` and `poc_from_gitlab()` now include URL in CVE scan
- **Remaining:** Need next pipeline run to create links

### CRIT-03: No test coverage for sources/web/storage
**Severity:** High | **Status:** Open
**Impact:** Regressions go undetected, refactoring is risky

- 27% overall coverage (34 tests)
- `tests/sources/` — missing entirely
- `tests/web/` — only `test_routes.py`, no filter/window/API tests
- `tests/storage/` — only migration test, no persist/health/query tests
- **Target:** 70% coverage (v0.9.1 plan)

---

## High Priority Issues

### HIGH-01: No authentication on web server
**Severity:** High | **Status:** Planned (v0.10)
**Impact:** Anyone with network access can query all data

- Server binds to 127.0.0.1:8080 with no auth
- No API keys, no login, no rate limiting
- **Plan:** Login page + user profile in v0.10

### HIGH-02: News feed not implemented
**Severity:** Medium | **Status:** Planned (v0.9)
**Impact:** Dashboard shows CVEs but no contextual intelligence

- Spec written (`docs/plans/web-v0.9.md`) but not built
- No `news_item` table, no RSS sources, no news routes
- **Plan:** RSS feeds (BleepingComputer, THN, CISA) + X/Twitter news

### HIGH-03: Severity filter doesn't work on /cves
**Severity:** Medium | **Status:** Open
**Impact:** Users can't filter CVEs by severity from the web UI

- `/cves?severity=CRITICAL` route exists but template doesn't pass filter to API
- Filter chips don't show active state
- **Fix:** Add severity query param handling in `cves.py` route + template

---

## Medium Priority Issues

### MED-01: Exploit-DB source disabled by default
**Severity:** Medium | **Status:** Open
**Impact:** Missing exploit data from a major source

- `DEFAULT_ENABLED = False` in `exploitdb.py`
- Only 3 PoCs in DB (all from GitHub)
- **Fix:** Enable by default, or document why it's opt-in

### MED-02: Social posts data is thin
**Severity:** Medium | **Status:** Open
**Impact:** Only 1 social post in DB, social_heat metric is 0 for most CVEs

- X/Twitter source works but data volume is low
- Only 1 CVE has social_mentions > 0
- **Fix:** Increase search queries, add more sources (Mastodon, Reddit)

### MED-03: No input validation on search
**Severity:** Medium | **Status:** Open
**Impact:** Potential for SQL injection or XSS via search parameter

- Search query passed directly to SQL LIKE
- No sanitization of user input
- **Fix:** Parameterized queries (already used), add input length limits

### MED-04: Dashboard tag filters not clickable
**Severity:** Medium | **Status:** Planned (v0.9)
**Impact:** Users can't click attack tags to filter CVEs

- Tags shown as static badges, not links
- **Fix:** Make tags link to `/cves?tag=<tag>` (spec in `web-v0.9.md`)

---

## Low Priority Issues

### LOW-01: No CI/CD pipeline
**Severity:** Low | **Status:** Planned (v0.9.3)
**Impact:** Manual testing only, no automated quality gates

- No GitHub Actions workflow
- No automated testing on PR
- **Fix:** Add GHA workflow with pytest, ruff, mypy, pip-audit

### LOW-02: No release workflow
**Severity:** Low | **Status:** Planned (v0.9.3)
**Impact:** No automated releases, no SBOM, no provenance

- **Fix:** Add release workflow with wheel/sdist build, SBOM, sigstore signing

### LOW-03: mypy strict not expanded beyond core
**Severity:** Low | **Status:** Planned (v0.9.2)
**Impact:** Type safety gaps in sources/web/storage

- Currently only `horus/core/*` and `pipeline.py` are strict
- **Fix:** Expand to storage → sources → net → web (v0.9.2 plan)

### LOW-04: No API documentation
**Severity:** Low | **Status:** Open
**Impact:** API endpoints are undocumented

- `/api/stats`, `/api/cve/<id>` exist but no docs
- **Fix:** Add OpenAPI/Swagger spec or markdown API docs

---

## Resolved Issues

### RES-01: Version strings displayed character-by-character ✅
**Fixed:** 2026-06-11 | **Commit:** `4b91f45`
- `group_products_by_vendor()` now splits semicolon-separated version strings into lists
- Template renders each version as a separate badge

### RES-02: Vendor names missing on CVE detail page ✅
**Fixed:** 2026-06-11 | **Commit:** `43838ca`
- Added `group_products_by_vendor()` helper in queries.py
- CVE detail page shows vendor → product → versions hierarchy
- New CSS for vendor grouping display

### RES-03: PoC list doesn't show linked CVEs ✅
**Fixed:** 2026-06-11 | **Commit:** `666f984`
- `fetch_pocs()` now JOINs `poc_cve` to get CVE IDs per PoC
- New "CVE" column with clickable badges

### RES-04: Nested venv and stale files in git ✅
**Fixed:** 2026-06-11 | **Commit:** `180d0ee`
- Removed `horus/.venv/` (18MB), stale backups, old logs
- Updated `.gitignore` with comprehensive patterns
- Added `.example` templates for config files

### RES-05: Duplicate vendor alias keys ✅
**Fixed:** 2026-06-11 | **Commit:** `338c4f2`
- Removed 17 duplicate keys from `_VENDOR_ALIASES`
- 601 unique vendor aliases remain

---

## Data Health Snapshot

```
Database: state/horus.db
CVEs:              1,062
PoCs:                  3
PoC→CVE links:         0  (will populate on next pipeline run)
Products:              7  (was 7 before fix, will improve on re-fetch)
CVE-Product links:   530
Attack tags:         951
CWE links:         1,180
Social posts:          1
Watchlist:             8
Sources:           1,062

Severity:  CRITICAL=46, HIGH=382, MEDIUM=330, LOW=29, NULL=275
EPSS:      941/1062 scored (89%)
KEV:       1/1062 (0.1%)
Social:    1/1062 with mentions (0.1%)

Product vendor distribution:
  adobe=2, apple=1, checkmk=1, microsoft=1, perl=1, unknown=1
  (will improve significantly after next NVD fetch with new aliases)
```

---

## Version Roadmap

### v0.9 (current)
- [x] Vendor/product data quality (CPE parsing + aliases)
- [x] Description-based vendor fallback
- [x] PoC → CVE linking (URL scanning)
- [x] Vendor-grouped products on CVE detail page
- [x] CVE badges in PoC list
- [ ] Clickable tag filters on dashboard
- [ ] News feed (RSS + X/Twitter)
- [ ] Severity filter on /cves

### v0.9.1
- [ ] Test coverage lift to 70%
- [ ] Web route tests (window, kev, pocs, search, triage, API)
- [ ] Source tests with mock fixtures
- [ ] Storage health + persist round-trip tests

### v0.9.2
- [ ] Expand mypy --strict to storage, sources, net, web

### v0.9.3
- [ ] CI/CD pipeline (GitHub Actions)
- [ ] pip-audit in CI
- [ ] Dependabot
- [ ] SBOM + sigstore signing on release

### v0.10
- [ ] Login page + user profile
- [ ] API key management
- [ ] Rate limiting
