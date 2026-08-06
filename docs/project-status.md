# Horus — Project Status

*Compiled 2026-07-27, from the `v0.13-source-health` branch, a live test run, and the docs in this folder. Internal reference — not for external distribution.*

**Version:** 0.13.0 · **Tests:** 671 passing · **Coverage:** 76% (gate: 70%)

---

## 1. What Horus is

A CVE + PoC discovery pipeline with reputation scoring, exploitability forecasting, and a Flask dashboard — built for internal use. Sources: NVD (authoritative), GitHub, Codeberg, GitLab, Exploit-DB, X/Twitter, News/RSS. Enrichers: KEV, EPSS, dark-web trust scoring. SQLite persistence, per-team (red/blue) RBAC, audit log, Telegram account linking, source-health observability.

**Stated differentiation gap:** Horus collects and delivers, but doesn't yet *correlate, verify, or predict* — no correlation engine, no automated PoC verification beyond EPSS-velocity heuristics, no ATT&CK mapping, no STIX/TAXII publishing. See [roadmap.md](roadmap.md) for the full plan.

---

## 2. Pipeline architecture

One function, `run_pipeline()`, is the entire product — the CLI's one-shot scan and the 24/7 `Server` daemon both call it. Sources/enrichers are discovered as plugins (any module in `horus/sources/` exporting `run()`, or `horus/enrichers/` exporting `enrich()`).

```
1a  CVE sources (NVD)
1b  PoC sources (x_twitter first — provides discovered URLs to github/codeberg)
1c  CVE backfill from PoC refs (fetch CVEs PoCs mention that NVD hasn't surfaced yet)
2   Merge & dedupe (core/merge.py — reputation score, social-signal aggregation)
3   Enrich (KEV, EPSS, dark web)
4   Persist (imminence scoring, then SQLite)
5   Render (text/markdown report, graph HTML)
6   End-of-run event hooks (kev_new, kev_overdue, kev_due_soon, epss_jump, critical_cve, watchlist_match, poc_new)
```

NVD runs first so authoritative CVE IDs exist before PoC sources try to link against them. Merge dedupes CVEs by ID (NVD always wins) and PoCs by URL, and computes the composite **reputation score**: `CVSS×0.35 + EPSS×10×0.25 + KEV bonus + capped social/PoC-source-count + ubiquity bonus`, capped at 10. Unmatched social mentions of CVE IDs NVD hasn't published yet become **watchlist** candidates instead of being dropped.

### Context contracts

| Contract | Carries |
|---|---|
| `SourceContext` | Dedup state (`known_cve_ids`, `known_poc_urls`), tunables (`max_results`, `min_cvss`), adaptive lookback (`last_run`), and `provided` — the generic inter-source handoff dict keyed by declared `PROVIDES`/`CONSUMES` |
| `EnricherContext` | Just `cves` and `pocs` — enrichers mutate the lists in place |
| `PipelineOptions` | Every CLI-facing tunable, decoupled from `argparse` so `Server` can build one without faking a Namespace |
| `PipelineResult` | `cves`, `pocs`, `links`, `watchlist_counts`, per-source `source_results`, rendered report text, end-of-run `events` |

---

## 3. CLI

Single entry point (`horus = horus.cli:main`), argparse-based, flags generated dynamically from discovered plugins — no subcommand verbs.

| Flag | Does |
|---|---|
| `--min-cvss` / `--max-results` | Tunables for the default scan-once flow |
| `--sources a,b,c` / `--enrichers a,b,c` | Explicit allow-list, plus auto-generated `--no-<source>` per plugin |
| `--format {text,md}`, `--no-save`, `--no-graph`, `--quiet` | Output shaping |
| `--list-sources` | Print discovered sources/enrichers with on/off status |
| `--query CVE-XXXX-XXXX` | Full enrichment report for one CVE straight from the DB |
| `--health-check` | Schema/integrity/data-quality checks |
| `--backfill-epss` | EPSS-score every unscored CVE in the DB |
| `--backfill {products,poc_cve,all}` | Re-normalize vendor/product names and/or re-link PoC↔CVE refs |
| `--export-json DIR` | Export DB to CVE-Intel-compatible JSON files |
| `--server` / `--server-once` / `--config PATH` | 24/7 daemon (per-source poll intervals from YAML/JSON) or a single cycle for cron |
| `--auth-status` | GitHub token rate-limit tier |

---

## 4. Sources

| Source | Feed | Kind | Notes |
|---|---|---|---|
| `nvd` | NVD CVE 2.0 API | CVE | Authoritative; adaptive lookback window; vendor alias normalization |
| `x_twitter` | X/Twitter (Chrome-cookie auth) | PoC + social | Runs first in the PoC stage; provides discovered URLs to GitHub/Codeberg |
| `github` | GitHub code/repo search | PoC | Confidence tiered by star count; consumes X/Twitter's discovered URLs |
| `codeberg` | Codeberg repo search | PoC | Same confidence model as GitHub |
| `gitlab` | GitLab public search API | PoC | No auth required (500 req/hr); single-keyword queries only |
| `exploit_db` | Exploit-DB via GitLab-hosted CSV mirror | PoC | Downloads the CSV once per run, matches locally against known CVE IDs |
| `resource_intelligence` | X/Twitter, broad | resource | Wider net than `x_twitter` — tools, bypasses, disclosures |
| `news` | RSS (CISA, THN, BleepingComputer, etc.) | news | Bypasses the CVE/PoC pipeline, writes straight to `news_article` with a 1–5 severity tier |

Recent hardening: gaming/noise PoC filtering added to ingestion. `nvd_fetch.py` and `url_resolve.py` are internal helpers, not discovered plugins.

---

## 5. Enrichers

| Enricher | Adds | Notes |
|---|---|---|
| `kev` | `kev`, `kev_due_date` | CISA KEV catalog match + remediation deadline, feeds the overdue/due-soon triage lenses |
| `epss` | `epss_score`, `epss_history` row | Daily EPSS CSV, gzip + SHA256-verified; backs `--backfill-epss` |
| `darkweb` | `trust_score` + breakdown, `threatfox_ioc_count`, `stealer_hits` | Calls an external `darknet-mcp-server` (ThreatFox IOCs, Hudson Rock stealer-log search); fully optional — missing keys just skip |

Reputation scoring and imminence forecasting aren't plugin enrichers — they run directly inside the pipeline's merge/persist stages (`core/merge.py`, `core/forecast.py`). Imminence buckets (*imminent / weeks / months / unlikely*) come from EPSS velocity weighted toward ubiquitous products.

---

## 6. Storage

SQLite, one schema file, foreign keys on.

**Core intel** — `cve` (CVSS/EPSS/KEV/reputation/confidence/imminence/trust score + breakdown), `poc`, `product`, `attack_tag`, `cwe`, plus join tables `cve_attack_tag`, `cve_cwe`, `cve_product`, `cve_source`, `poc_cve`.

**Signal & workflow** — `cve_social_post`, `cve_watchlist` (unconfirmed social mentions), `cve_triage` (analyst workflow state), `team_watchlist` (red/blue pins), `epss_history`, `cve_threatfox_ioc`, `security_resource`, `news_article`.

**Auth, ops & audit** — `user`/`role`/`user_role` (viewer/analyst/admin + red/blue/both/none team), `telegram_link_token`, `notification_pref`, `audit_event` (append-only, never logs password_hash), `source_health` (**new in v0.13**), `meta` (run metadata).

---

## 7. Web application

Flask app factory, 13 blueprints, session auth. Every response gets security headers (`X-Frame-Options: DENY`, HSTS over TLS, CSP scoped to allow Chart.js from jsdelivr). Access levels: **read all** (any logged-in user) · **write** (analyst/admin) · **admin** · **team** (red/blue/both members).

| Page | Route | Access | Purpose |
|---|---|---|---|
| Overview | `GET /` | read all | KPI tiles, Chart.js severity/trend charts, live news panel, slide-out CVE detail panel, Telegram-connect banner |
| CVE index | `GET /cves` | read all | Full filterable/sortable CVE table; quick-filter chips; CSV export at `/cves/export.csv` |
| CVE dossier | `GET /cve/<id>` | read all | Badges, gauges, affected products, linked PoCs, auto-generated detection-rule links, social discussion, related CVEs |
| PoCs | `GET /pocs` | read all | Exploit-artifact index; source/linked-only filters |
| Vendors | `GET /vendors` | read all | Exposure dashboard — CVE count, avg CVSS/EPSS, KEV count per vendor |
| Search | `GET /search` | read all | Ad-hoc CVE ID / keyword lookup |
| Triage | `GET /triage` | read all (edit: write) | Action queue (KEV/EPSS≥0.5/CVSS≥9+PoC); inline status/assignee/note editing, audit-logged |
| Watchlist | `GET /watchlist/` | team: red/blue | Per-team vendor/product pins + live matching-CVEs table; bulk CSV/JSON import |
| News | `GET /news` | read all | Classified RSS security news, tier 1–4 |
| Resources | `GET /resources` | read all | Broader X/Twitter intel — tools, bypasses, disclosures |
| Admin · users | `/admin/users` | admin | User management, roles/teams, last-admin guard |
| Admin · sources | `/admin/sources` | admin | Read-only source-health table — **shipped this cycle (v0.13)** |
| Admin · audit | `/admin/audit` | admin | Paginated audit trail with before/after JSON diffs |
| Auth | `/login` `/logout` `/register` | public | Rate-limited (5/5min/IP), constant-time password check, first user auto-admin |
| Profile · Telegram | `/profile/telegram` | read all | Deep-link account linking (30-min token) — **token issuance only, bot listener not wired up yet** |
| Profile · notifications/settings | `/profile/notifications`, `/profile/settings` | read all | Per-event toggles (7 categories); self-service email/team/theme/password |
| API | `/api/health`, `/api/stats`, `/api/cves`, `/api/cve/<id>` | public / read all | `/api/health` is public and unauthenticated, reports `degraded` at ≥3 consecutive source failures; backs the Docker healthcheck |

---

## 8. Platform & deploy

Runs as a 24/7 `Server` daemon with per-source poll intervals from YAML/JSON config, or Docker via `docker-compose` with 10-backup auto-rotation on `deploy.sh`. Production is a single internal host (`172.22.1.4:8081`, gunicorn, admin account `admin:keystone`). No OSS-readiness work is planned — Horus is internal-only.

---

## 9. Engineering health

- **671 tests passing, 0 failing** · **76% coverage** (gate: 70%)
- mypy strict, ruff, pre-commit configured and green on `core`/`pipeline`/`storage` (not yet extended to `horus.web`)
- Timestamps fully migrated off `datetime.utcnow()` to explicit UTC

### Fixed this session

**Test-pollution bug in `load_config`'s env-var override.** `horus/web/__init__.py` builds a module-level Flask `app = create_app()` at import time, which calls `_load_dotenv()` — reading the repo's real `.env` (which sets `HORUS_WEB_PORT=8080`) into `os.environ` as a side effect. `tests/conftest.py` imports `horus.web.queries` at collection time to patch `DB_PATH`, which pulled in that whole import chain and leaked `HORUS_WEB_PORT`/`HORUS_WEB_HOST` into the process env for the rest of the test session. `test_server.py`'s `load_config()` then saw those as a genuine Docker-style override and silently discarded the YAML-configured port.

Confirmed this is test-only pollution, not a production bug: in the real `--server` path, `horus.web` is only ever imported in a separate `gunicorn horus.web:app` subprocess, started *after* `load_config()` has already computed `cfg.web.port` — so the leak path doesn't exist there.

**Fix:** `tests/conftest.py` now snapshots `os.environ` before importing `horus.web.queries` and strips any keys the import silently added, restoring test isolation. No production code changed.

### Known gap

Telegram bot: token issuance/linking UI is fully built (`/profile/telegram`), but the listener that consumes link tokens and dispatches the seven notification-event types isn't wired up yet.

---

## 10. Roadmap

- **v0.13 — Internal Hardening:** source health (shipped), KEV due-date event pipeline (shipped), mypy strict expansion, coverage gate — largely complete this cycle.
- **v0.12 — CTI platform upgrade:** dark-web trust scoring landed (ThreatFox + Hudson Rock via MCP); MalwareBazaar/Hybrid Analysis enrichers, OpenCTI-style dashboard panels, and ATT&CK technique mapping remain pending.
- **Next up — feed quality:** current CVE-keyword matching produces false positives; the next push is raising relevance/precision before adding further intel sources.
- **Longer horizon (v1.0 differentiators):** CVE correlation engine, automated PoC verification, exploitability forecasting beyond the current EPSS-velocity heuristic, STIX/TAXII publishing.

See [roadmap.md](roadmap.md) and `docs/plans/` for full detail.
