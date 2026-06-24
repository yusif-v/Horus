# Horus — Known Issues & Technical Debt

*Last updated: 2026-06-24*
*Current version: v0.10.0*
*Health score: 86/100*

---

## Scoring Breakdown

| Category | Score | Max | Notes |
|----------|-------|-----|-------|
| Core pipeline | 90 | 100 | Plugin sources, source-purity model, clean merge layer, lifecycle hooks |
| Data quality | 80 | 100 | Products backfilled (1 unknown of 163), EPSS on 1081/1090, PoC→CVE relinked |
| Web UI | 88 | 100 | Auth/RBAC, Chart.js dashboard, news feed, vendor exposure, triage, themes |
| Test coverage | 74 | 100 | 610 tests, 74.5% coverage. Gate at 70% |
| Code quality | 82 | 100 | Ruff clean; mypy strict on core+pipeline only (expansion pending) |
| Documentation | 80 | 100 | Plan docs per version, README, roadmap. API docs still thin |
| Security | 80 | 100 | Auth + RBAC + CSRF + audit log; bot token via env; search length-capped |
| Ops/Deploy | 75 | 100 | CI, pip-audit, CycloneDX SBOM, Dependabot, GH Actions security workflow |
| **Overall** | **86** | **100** | Mature internal tool; remaining gaps are mypy breadth + intel depth |

---

## Open Issues

### OPEN-01: mypy --strict not expanded beyond core
**Severity:** Low | **Status:** Tracked (was v0.9.2)
Strict scope is still `horus/core/*` + `pipeline.py`. `storage/`, `sources/`,
`enrichers/`, `net/`, `web/` remain untyped under strict. Expand layer by
layer per `docs/plans/v0.9.x.md`.

### OPEN-02: PoC→CVE linkage limited to published CVEs
**Severity:** Low | **Status:** By design, candidate feature
17 of 43 PoCs link to a CVE. The remaining ~26 reference CVE IDs not yet in
NVD (signal-only). Today these PoCs are stored but neither linked nor pushed
to `cve_watchlist`. A future enhancement could create watchlist entries from
PoC-discovered CVE IDs so pre-NVD PoCs surface.

### OPEN-03: X/Twitter social intel thin
**Severity:** Low | **Status:** Runtime/config
Only 7 CVEs have `social_mentions > 0`. Depends on the X source running with
Chrome-cookie auth and query breadth. Consider widening X queries and/or
adding Mastodon/Reddit signal sources.

### OPEN-04: API docs thin
**Severity:** Low
`/api/stats`, `/api/cves`, `/api/cve/<id>` (incl. `?year=`) are stable but
undocumented. Add a short API reference.

---

## Recently Resolved (v0.10.0 + 2026-06-24 hygiene sweep)

| ID | Fix |
|----|-----|
| RES-10 | `feedparser` missing from venv broke test collection + `/news` — declared in extras, installed; news source now lazy-imports feedparser so a core-only install degrades gracefully |
| RES-11 | `extract_cves` now normalizes underscore separators (`cve_2026_31431` → `CVE-2026-31431`) |
| RES-12 | PoC→CVE backfill re-run: links 9 → 17 |
| RES-13 | `/vendors` route test coverage 12% → 95% |
| RES-14 | Stale `issues.md` / `roadmap.md` rewritten to v0.10.0 reality |
| RES-01 | CRIT-01 product vendor backfill (`horus --backfill=products`) |
| RES-02 | CRIT-02 PoC→CVE backfill (`horus --backfill=poc_cve`) |
| RES-03 | Web auth + RBAC (admin/analyst/viewer), CSRF, audit log |
| RES-04 | News feed (RSS, 4-tier classification, `/news`) |
| RES-05 | Dashboard Chart.js (severity donut, EPSS bars, trend, attack tags) |
| RES-06 | Telegram bot (link tokens, commands, notification dispatch) |
| RES-07 | Supply chain: pip-audit, CycloneDX SBOM, Dependabot, GH security workflow |
| RES-08 | Exploit-type auto-classification + badges; year-scoped API |
| RES-09 | Search input length-capped (200 chars) |

---

## Data Health Snapshot (2026-06-24)

```
CVEs:              1,090
PoCs:                 43
PoC→CVE links:        17
Products:            163   (1 unknown vendor)
CVEs w/ EPSS:      1,081
News articles:       145
Security resources:   12
Social mentions:       7 CVEs
Watchlist:            33
Tests:               610   (74.5% coverage)
```

See `docs/roadmap.md` for forward-looking work and `docs/plans/` for
per-version detail.
