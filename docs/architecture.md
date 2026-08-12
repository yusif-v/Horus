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
├── plugins/               plugin folders — one folder per plugin
│   ├── sources/           CVE & PoC source plugins
│   │   ├── nvd/           authoritative CVE source
│   │   ├── github/        PoC repo discovery
│   │   ├── gitlab/        PoC repo discovery
│   │   ├── x_twitter/     social signal + github URL discovery
│   │   ├── exploitdb/     secondary PoC links
│   │   ├── codeberg/      PoC repo discovery
│   │   └── news/          security-news RSS feed
│   ├── enrichers/         post-merge enrichment plugins
│   │   ├── epss/          EPSS scores + DB-wide backfill
│   │   ├── kev/           CISA KEV flag
│   │   ├── otx/           AlienVault OTX feed
│   │   └── darkweb/       dark-web intel
│   └── notifications/     post-run notification plugins
│       └── telegram/      per-user Telegram dispatch
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
├── plugins.md             plugin authoring guide
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
cli.py     ──▶  pipeline.py  ──▶  plugins/  storage/  render/
                       │                 │
                       ▼                 ▼
                  net/  config/      net/  config/   config/  core/

server.py  ──▶  pipeline.py  (single source of truth — no fake argv)
web/       ──▶  storage.db   config   (read-only path)
```

`pipeline.py` is the only module that knows about run order. CLI and
server are both thin clients.

## Plugin system

Sources, enrichers, and notifications are all plugins, loaded by a single
`PluginManager` (`horus/plugin_manager.py`). Bundled plugins live in
`horus/plugins/<kind>/<name>/` and external plugins under each `plugin_dirs`
entry (default `~/.config/horus/plugins`); both load identically. A broken
plugin — bad manifest, missing entrypoint, import error — is recorded and
skipped, never aborting a run.

Each plugin folder carries a `plugin.toml` manifest (`[plugin]`
name/type/version/entrypoint/enabled_by_default, `[schedule]`
interval_seconds, `[config]` schema) and an entrypoint `main.py` exporting:

| Kind | Entrypoint export | Contract |
|------|-------------------|----------|
| source | `run(ctx) -> dict` | returns `{"cves":[...], "pocs":[...]}` (+ optional `social_signals`, `x_discovered_urls`) |
| enricher | `enrich(ctx) -> None` | mutates `ctx.cves` / `ctx.pocs` in place |
| notification | `notify(events, ctx)` | `ctx` is a `NotificationContext` (`token`, `users`, `prefs`, `send(channel, message)`) |

The `horus --plugin` CLI manages plugins (`list`, `enable`/`disable`,
`config`, `add`, `remove`, `scaffold`, `validate`); enable/disable/config
persist to horus.yaml's `plugins:` block.

Add a source = create `horus/plugins/sources/<name>/{plugin.toml, main.py}`
(or use `horus --plugin scaffold --plugin-kind source --plugin-name <name>`).
Nothing else changes. Full authoring guide: `docs/plugins.md`.

## What lives where (decision rules)

| If the code does this... | Put it here |
|--------------------------|-------------|
| Hits the network | `horus/net/` |
| Pure domain logic with no I/O | `horus/core/` |
| Discovers/produces CVEs or PoCs | `horus/plugins/sources/<name>/` |
| Post-merge enrichment | `horus/plugins/enrichers/<name>/` |
| Sends notifications | `horus/plugins/notifications/<name>/` |
| Reads/writes SQLite | `horus/storage/` |
| Builds output artifacts | `horus/render/` |
| Renders HTML | `horus/web/` |
| Orchestrates a full run | `horus/pipeline.py` |
| Argparse / CLI dispatch | `horus/cli.py` |
| Daemon loop, supervises web | `horus/server.py` |
