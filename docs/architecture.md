# Horus Architecture (v0.8)

```
horus/
├── __init__.py            version
├── __main__.py            `python -m horus` entry
├── cli.py                 argparse + dispatch ONLY (no orchestration)
├── pipeline.py            ★ orchestration — sources → merge → enrich → persist → render
├── server.py              24/7 daemon, supervises gunicorn web child
│
├── config/                static configuration
│   ├── __init__.py        flat re-exports for back-compat
│   ├── paths.py           STATE_DIR, REPORTS_DIR
│   ├── queries.py         GitHub search strings, keyword filters
│   └── tunables.py        HTTP_TIMEOUT, MIN_REPO_STARS, USER_AGENT, ...
│
├── net/                   transport layer (was scattered)
│   ├── http.py            fetch_json + urlopen wrapper
│   ├── auth.py            GitHub token resolution
│   └── xsearch.py         X internal-GraphQL client (Chrome cookies)
│
├── core/                  pure domain — no I/O
│   ├── model.py           CVE / PoC / AffectedProduct dataclasses
│   ├── merge.py           dedup + reputation score + watchlist split
│   ├── vocab.py           attack-tag vocabulary
│   ├── classify.py        CVE → attack tag + product category
│   └── filters.py         is_fresh_poc, extract_cves, ...
│
├── sources/               plugin discovery — one file per source
│   ├── nvd.py             authoritative CVE source
│   ├── github.py          PoC repo discovery
│   ├── x_twitter.py       social signal + github URL discovery
│   └── exploitdb.py       secondary PoC links
│
├── enrichers/             post-merge enrichment plugins
│   ├── epss.py            EPSS scores + DB-wide backfill
│   └── kev.py             CISA KEV flag
│
├── storage/               persistence
│   ├── db.py              schema + migrations + persist_cve/poc/watchlist
│   ├── query.py           CLI --query rendering
│   └── health.py          --health-check report
│
├── render/                outputs
│   ├── report.py          text + markdown
│   ├── graph.py           Cytoscape.js HTML
│   └── persist.py         save report to reports/
│
└── web/                   Flask app
    ├── __init__.py        create_app() + module-level `app` for gunicorn
    ├── __main__.py        `python -m horus.web` dev server
    ├── _render.py         page() helper — rail + version + nav
    ├── queries.py         all SQL read paths (testable, no Flask)
    ├── routes/            one blueprint per section
    │   ├── dashboard.py
    │   ├── triage.py
    │   ├── cves.py
    │   ├── pocs.py
    │   ├── search.py      includes /cve/<id> detail
    │   └── api.py         /api/stats, /api/cve/<id>
    ├── templates/         real Jinja2 files (was inline strings)
    │   ├── base.html
    │   ├── dashboard.html
    │   ├── triage / cves / pocs use list.html
    │   ├── search.html cve_detail.html error.html
    └── static/horus.css   was a 600-line python string

docs/
├── architecture.md        this file
└── plans/v0.8.md          v0.8 design doc

tests/
├── conftest.py            STATE_DIR → tempdir
├── test_pipeline.py       plugin discovery + selection
├── core/test_reputation.py    pins the score formula
├── storage/test_migration.py  idempotent schema + v0.7 → v0.8 ALTER
└── web/test_routes.py     all routes 200, API contract locked
```

## Dependency arrows (one-way)

```
cli.py     ──▶  pipeline.py  ──▶  sources/  enrichers/  storage/  render/
                       │                 │
                       ▼                 ▼
                  net/  config/      net/  config/      config/  core/

server.py  ──▶  pipeline.py  (single source of truth — no fake argv)
web/       ──▶  storage.db   config   (read-only path)
```

`pipeline.py` is the only module that knows about run order. CLI and
server are both thin clients.

## Plugin discovery rules

`pipeline.discover_sources()` / `discover_enrichers()` walk
`horus/sources/` and `horus/enrichers/`. A module is included iff:

1. its name doesn't start with `_`
2. it exports a callable named `run` (sources) or `enrich` (enrichers)

Add a source = one new file under `sources/`. Nothing else changes.

## What lives where (decision rules)

| If the code does this... | Put it here |
|--------------------------|-------------|
| Hits the network | `horus/net/` |
| Pure domain logic with no I/O | `horus/core/` |
| Discovers/produces CVEs or PoCs | `horus/sources/` |
| Post-merge enrichment | `horus/enrichers/` |
| Reads/writes SQLite | `horus/storage/` |
| Builds output artifacts | `horus/render/` |
| Renders HTML | `horus/web/` |
| Orchestrates a full run | `horus/pipeline.py` |
| Argparse / CLI dispatch | `horus/cli.py` |
| Daemon loop, supervises web | `horus/server.py` |
