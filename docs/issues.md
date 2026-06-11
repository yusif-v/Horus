# Horus — Known Issues & Technical Debt

*Last updated: 2026-06-12*
*Current version: v0.9.0-dev*
*Health score: 64/100 (CVEs grew 1062 → 1231 after pipeline run)*

---

## Scoring Breakdown

| Category | Score | Max | Notes |
|----------|-------|-----|-------|
| Core pipeline | 85 | 100 | Solid architecture, plugin-based sources, clean merge layer |
| Data quality | 50 | 100 | New CVEs use improved aliases; existing rows not backfilled |
| Web UI | 75 | 100 | Functional, fast, good design. Missing filters, news feed |
| Test coverage | 27 | 100 | 34 tests pass, 27% coverage. Gate at 25%, target 70% |
| Code quality | 80 | 100 | Ruff clean, mypy strict on core. Needs expansion to sources/web |
| Documentation | 75 | 100 | Plan docs, README, consolidated roadmap. Missing API docs |
| Security | 55 | 100 | No auth on server, no input validation on search, open localhost |
| Ops/Deploy | 40 | 100 | No CI/CD, no release workflow, no SBOM, no dependabot |
| **Overall** | **64** | **100** | Functional prototype; data quality + test coverage remain the bottleneck |

---

## Critical Issues

### CRIT-01: Product data quality — partial backfill
**Severity:** High | **Status:** Code fixed, backfill pending
**Impact:** Existing CVE rows still show "unknown" vendors

- 8 unique products in DB after fresh run; new CVEs benefit from 600+ vendor / 400+ product aliases
- Existing 1062 CVE rows were persisted before the alias expansion and aren't reprocessed
- **Next step:** Either (a) write a one-shot backfill script to re-parse CPE strings for existing rows, or (b) accept the gradual improvement as old CVEs roll off the active window

### CRIT-02: PoC → CVE linking — awaiting new PoCs
**Severity:** High | **Status:** Code fixed, awaiting new PoC discoveries
**Impact:** `poc_cve` table empty for the 3 existing PoCs (URLs not rescanned)

- `poc_from_github()` and `poc_from_gitlab()` now scan URL for CVE IDs
- 3 PoCs persisted before fix — they won't be relinked unless we add a backfill pass
- **Next step:** Add a backfill that re-runs `extract_cves(url + description)` over existing `poc` rows and writes to `poc_cve`

### CRIT-03: No test coverage for sources/web/storage
**Severity:** High | **Status:** Tracked in v0.9.1
**Impact:** Regressions go undetected, refactoring is risky

- 27% overall coverage (34 tests)
- See `docs/plans/v0.9.x.md` for the coverage-lift plan

---

## High Priority

### HIGH-01: No authentication on web server (v0.10)
- Server binds to 127.0.0.1:8080, no auth, no API keys, no rate limiting

### HIGH-02: News feed not implemented (v0.9)
- Spec in `docs/plans/web-v0.9.md`; no `news_item` table, no RSS sources yet

### HIGH-03: Severity filter doesn't work on /cves
- Route accepts `?severity=`, template doesn't pass it to the API
- Fix in `horus/web/routes/cves.py` + template

---

## Medium Priority

- **MED-01: Exploit-DB disabled by default** — `DEFAULT_ENABLED = False` in `exploitdb.py`. Decide: enable or document opt-in rationale.
- **MED-02: Social posts thin** — 1 CVE has `social_mentions > 0`. Increase X queries; consider Mastodon/Reddit sources.
- **MED-03: No input length limits on search** — params are parameterized but no bounds. Add length caps.
- **MED-04: Dashboard tag filters not clickable** — tags render as static badges. Spec in `web-v0.9.md`.

---

## Low Priority

- **LOW-01: No CI/CD** — tracked v0.9.3
- **LOW-02: No release workflow / SBOM** — tracked v0.9.3
- **LOW-03: mypy strict not expanded** — tracked v0.9.2
- **LOW-04: No API docs** — `/api/stats`, `/api/cve/<id>` undocumented

---

## Recently Resolved

| ID | Fix | Commit |
|----|-----|--------|
| RES-01 | Version strings rendered char-by-char | `4b91f45` |
| RES-02 | Vendor names missing on CVE detail | `43838ca` |
| RES-03 | PoC list missing CVE column | `666f984` |
| RES-04 | Nested venv / stale files in git | `180d0ee` |
| RES-05 | Duplicate vendor alias keys | `338c4f2` |
| RES-06 | Social posts (X) on CVE pages | (v0.9 Tier 4) |
| RES-07 | `persist_social_posts` scope bug | (v0.9 Tier 4) |

---

## Data Health Snapshot (post pipeline run 2026-06-12)

```
CVEs:              1,231
PoCs:                  3
PoC→CVE links:         0   (backfill needed)
Products:              8
CVE-Product links:   616
Attack tags:         951+
CWE links:         1,180+
Social posts:          1+
Watchlist:             8
```

See `docs/plans/v0.9.x.md` for the active workstream and `docs/roadmap.md` for longer-term ideas.
