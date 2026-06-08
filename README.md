# Horus

**Version:** 0.8.0

Daily PoC research scanner — or a 24/7 server. Treats NVD as the single source of truth for CVE data; treats GitHub, X/Twitter and Exploit-DB as signals that build a CVE *reputation score*. Enriches with CISA KEV and EPSS. Query any CVE from the local database, or run as a daemon that polls each source on its own interval. Requires Python 3.10+.

## What it does

### Source classification (v0.8)
- **Authoritative** — **NVD only**. CVE ID, description, CVSS, CWE, affected products come from NVD and nowhere else.
- **Signal sources** — never create CVE records. They corroborate what NVD has already published.
  - **GitHub**: PoC/exploit repositories (<30d old, >10 stars, fresh PoC keywords). Confidence: `high` (>100★), `medium` (>10★), `low` otherwise.
  - **X/Twitter** (Chrome-cookie auth, birdnode-compatible): each tweet mentioning a CVE bumps that CVE's `social_mentions` counter; tweets that link to a `github.com` PoC repo feed that URL into the GitHub source for enrichment. **X never produces a PoC record on its own.**
  - **Exploit-DB**: secondary PoC links via the GitLab mirror.
- **Signal-only CVEs** (an ID that only appears in X but not yet in NVD) go to a low-confidence `cve_watchlist` table and are resolved automatically once NVD confirms them.

### Reputation score
A composite 0–10 score replaces the old `exploitability_score`:

```
reputation =
    CVSS  * 0.35                         (0–3.5)
  + EPSS * 10 * 0.25                     (0–2.5)
  + KEV bonus            1.5             (0–1.5)
  + min(social_mentions * 0.15, 1.0)     (0–1.0)
  + min(poc_source_count * 0.5, 1.5)     (0–1.5)
  + ubiquity bonus       1.0             ← nginx, php, wordpress,
                                           openssl, kubernetes, openssh,
                                           apache, mysql, chrome, linux
                                           kernel, …
  Total cap: 10.0
```

The ubiquity bonus reflects what the user asked for in v0.8: a critical CVE in a widely-deployed product (nginx, php, wordpress, openssl, kubernetes, …) outranks the same CVSS on a niche library.

### Other features
- **KEV / EPSS enrichment** — EPSS now backfills all unscored CVEs in the DB, not just the current batch.
- **Classification** — attack tag (rce, sqli, lpe, …) + product category, locked vocabulary.
- **PoC linking** — every PoC's CVE refs are wired into a graph edge.
- **Persistence** — SQLite at `state/horus.db`, idempotent schema + column migrations.
- **Reports** — Markdown + interactive Cytoscape.js graph.
- **Health check** — `--health-check`.
- **CVE query** — `--query CVE-XXXX-XXXX`.
- **24/7 server mode** — `--server`, see below.

## Plugin Architecture

Sources and enrichers are **self-discovering plugins**. Adding a new source = creating ONE file in `horus/sources/` with a `run()` function. No other files change.

```bash
python3 -m horus --list-sources          # show all discovered plugins
python3 -m horus --sources github,nvd    # run only specific sources
python3 -m horus --no-exploitdb          # skip a source (auto-generated flag)
python3 -m horus --skip-kev              # skip an enricher (auto-generated flag)
```

## Usage

```bash
# Run all sources + enrichers
python3 -m horus

# Common options
python3 -m horus --min-cvss 7.0          # NVD: only High/Critical
python3 -m horus --max-results 10         # cap items per source
python3 -m horus --format md             # markdown output
python3 -m horus --quiet                 # suppress progress on stderr
python3 -m horus --no-exploitdb --skip-kev

# Look up a CVE from the database
python3 -m horus --query CVE-2026-11413
python3 -m horus --query 2026-11413      # CVE- prefix auto-added
python3 -m horus --query CVE-2026-11413 --format md

# Keyword search (if exact CVE not found)
python3 -m horus --query log4j

# Database integrity check
python3 -m horus --health-check

# GitHub auth status
python3 -m horus --auth-status
```

### Flags

| Flag | Purpose |
|------|---------|
| `--min-cvss FLOAT` | Drop NVD items below this CVSS base score |
| `--max-results N` | Cap items per source after sorting |
| `--format {text,md}` | Output format (markdown for chat delivery) |
| `--quiet` | Send progress lines to stderr only |
| `--version` | Print version and exit |
| `--list-sources` | List all plugins and exit |
| `--sources A,B` | Run only these sources |
| `--enrichers A,B` | Run only these enrichers |
| `--no-<name>` | Skip a source (auto-generated per source) |
| `--skip-<name>` | Skip an enricher (auto-generated per enricher) |
|| `--query CVE-XXXX-XXXX` | Query a CVE enrichment report from the database |
|| `--health-check` | Run database integrity checks and exit ||
|| `--auth-status` | Show GitHub auth status and exit ||
|| `--no-save` | Skip writing report to disk ||
|| `--no-graph` | Skip writing the interactive graph HTML ||
|| `--backfill-epss` | One-shot: score every unscored CVE in the DB and exit ||
|| `--server` | Run as a 24/7 daemon, polling each source on its own interval (see below) ||
|| `--server-once` | Run a single server poll cycle then exit — handy for cron/testing ||
|| `--config PATH` | YAML/JSON config file for server mode ||

## 24/7 Server Mode (v0.8)

Long-running daemon that polls each source on its own interval and maintains the database. Designed to run as a systemd unit or Docker container; ready to feed into a downstream consumer.

```bash
# Start the daemon with default intervals
python3 -m horus --server

# One poll cycle then exit (useful for cron / testing)
python3 -m horus --server-once

# With a custom config
python3 -m horus --server --config /etc/horus/config.yaml

# Or run the server module directly
python3 -m horus.server --config /etc/horus/config.yaml
python3 -m horus.server --once
```

### Default poll intervals

| Source / Enricher | Interval | Rationale |
|-------------------|----------|-----------|
| `nvd`        | 1 h  | NVD publishes roughly every 2 h |
| `x_twitter`  | 30 m | Social signal moves fastest |
| `github`     | 1 h  | GitHub search API rate limits |
| `exploit_db` | 2 h  | Slower-moving |
| `epss`       | 24 h | EPSS CSV refreshes once a day |
| `kev`        | 24 h | CISA KEV refreshes ~daily |

Every minute the server re-checks which sources are due (i.e. their last-run timestamp is older than their interval) and runs only those. Last-run timestamps live in the SQLite `meta` table, so a restart picks up exactly where it left off.

### Config file (YAML — JSON also accepted)

```yaml
# /etc/horus/config.yaml
poll_intervals:
  nvd: 3600          # seconds — change any of these to suit your feed cadence
  x_twitter: 1800
  github: 3600
  exploit_db: 7200
  epss: 86400
  kev: 86400

sources_enabled:
  nvd: true
  x_twitter: true
  github: true
  exploit_db: false  # turn a source off entirely

check_every_seconds: 60  # how often the loop wakes up to look for due sources

# Web UI — when enabled, the server supervises a gunicorn child for the
# Flask app on :port. Omit / set enabled=false to run pollers only.
web:
  enabled: true
  host: 0.0.0.0
  port: 8080
  workers: 2              # gunicorn sync workers
  allow_dev_fallback: false  # fail fast in prod if gunicorn isn't installed
```

Install the full server stack (Flask + PyYAML + gunicorn) with:

```bash
pip install -e ".[server]"
```

Without `pyyaml` the server still loads JSON config (or falls back to defaults). Without `gunicorn`, the web supervisor falls back to the Flask dev server **only if `allow_dev_fallback: true`** — in production set it to `false` so misconfiguration is loud.

### Running as a systemd service

```ini
# /etc/systemd/system/horus.service
[Unit]
Description=Horus CVE Intelligence Server
After=network.target

[Service]
Type=simple
User=horus
WorkingDirectory=/opt/horus
ExecStart=/opt/horus/.venv/bin/python -m horus.server --config /etc/horus/config.yaml
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
```

`SIGTERM` and `SIGINT` are handled cleanly so `systemctl stop` / `docker stop` shut the loop down between cycles instead of mid-source. The gunicorn child is started in its own process group so the same signal cleanly terminates all workers.

### Docker

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -e ".[server]"
VOLUME ["/data"]
ENV HORUS_DB_PATH=/data/horus.db
EXPOSE 8080
CMD ["python", "-m", "horus", "--server", "--config", "/data/config.yaml"]
```

```bash
docker build -t horus:0.8 .
docker run -d --name horus -p 8080:8080 -v $(pwd)/state:/data horus:0.8
```

### Production checklist

- `web.allow_dev_fallback: false` so a missing gunicorn fails fast instead of starting Flask's single-threaded dev server.
- Front gunicorn with nginx/Caddy if you're exposing publicly — gunicorn's HTTP parser isn't hardened for the open internet.
- Mount `state/` on persistent storage (`state/horus.db` is the source of truth; the JSON files are migration leftovers).
- The `/api/stats` JSON endpoint is suitable as a liveness probe (returns 200 + counts).
- Set a Github token via `GITHUB_TOKEN` env var to get the 5000/hr rate limit instead of 60/hr.

## Web Interface

Horus includes a Flask-based web UI for browsing the database visually.

```bash
# First time: create venv and install dependencies
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[web]"

# Start the server (always activate venv first)
source .venv/bin/activate
python3 -m horus.web              # http://127.0.0.1:8080
python3 -m horus.web --port 8080  # custom port
python3 -m horus.web --host 0.0.0.0 --port 8080  # network-accessible
```

**Pages:**
- `/` — Dashboard: stats, recent CVEs, top PoCs, category breakdown
- `/search?q=CVE-2026-11413` — Search CVEs by ID or keyword
- `/cve/CVE-2026-11413` — Full CVE detail with PoCs, tags, products, related CVEs
- `/cves` — Browse all CVEs, filter by severity/KEV
- `/pocs` — Browse all PoCs, filter by source
- `/api/stats` — JSON API for dashboard stats
- `/api/cve/CVE-2026-11413` — JSON API for CVE detail

Dark theme, responsive design, works on desktop and mobile.

## Query Output

When you look up a CVE with `--query`, Horus returns all enrichment data in a structured report:

```
============================================================
  CVE ENRICHMENT REPORT: CVE-2026-11413
============================================================

  CVSS:     8.8 HIGH
  EPSS:     0.0004 (0.04%)
  KEV:      No
  Exploit:  3.5/10
  Sources:  nvd
  Published: 2026-06-06

  Description:
    A security vulnerability has been detected in JingDong
    JD Cloud Box AX6600...

  Attack tags: buffer-overflow

  CWEs: CWE-119, CWE-121

  Affected products:
    unknown/unknown [cms]

  Linked PoCs (2):
    https://github.com/.../CVE-2026-11413-poc ★42 [github]
    https://x.com/.../status/... [x]

  Related PoCs (mentioned) (3):
    https://x.com/.../status/... [x]

  Related CVEs (5):
    CVE-2026-11414 [CVSS 7.5] (same attack tag)
    CVE-2025-33109 [CVSS 9.8] (same product)
    ...
============================================================
```

**Report sections:**
- CVSS score + severity
- EPSS exploit probability
- CISA KEV status
- Composite exploitability score (0-10)
- Attack tags + CWE IDs
- Affected products with versions
- **Linked PoCs** — formally linked (poc_cve table)
- **Related PoCs** — mention this CVE in description
- **Related CVEs** — same attack tags or same products
- Source tracking + discovery timeline

## Data Sources

| Source | Auth | Cost | Coverage |
|--------|------|------|----------|
| GitHub API | Token optional | Free | New PoC repos |
| NVD API | None | Free | Recent CVEs with CVSS |
| X/Twitter | Chrome cookies | Free | CVE mentions in tweets |
| Exploit-DB | None | Free | Published exploits |
| CISA KEV | None | Free | Known-exploited vulnerabilities |
| EPSS | None | Free | Exploit probability scores |

### X/Twitter authentication

Horus reads your Chrome cookies (auth_token + ct0) to authenticate with X's internal GraphQL API — same approach as birdnode, in pure Python. No API key, no browser required.

Requirements:
- macOS (uses `security` command for keychain access)
- Chrome logged into x.com (Profile 1 tested)
- `cryptography` package: `pip install cryptography`

Override with env vars: `X_AUTH_TOKEN=... X_CT0=... python3 -m horus`

### GitHub authentication

Horus auto-detects a GitHub token in this order — no config needed:

1. `GITHUB_TOKEN` env var
2. `GH_TOKEN` env var
3. `gh auth token` (GitHub CLI keyring)

With a token, the rate limit jumps from 60 → 5000 requests/hour. Check status with:

```bash
python3 -m horus --auth-status
# GitHub auth: OK (token ...Xq7Z, limit 5000/hr)
```

## Health Check

Run `--health-check` to validate database integrity. Ten categories of checks, severity levels (error / warning / info):

| Category | What it catches |
|----------|----------------|
| Schema | Missing tables, columns, indexes |
| CVE data quality | Bad ID format, CVSS out of range, invalid severity, EPSS/KEV out of range, missing timestamps, empty descriptions, future dates, duplicate IDs |
| PoC data quality | Invalid source enum, bad URL format, negative stars/age, missing timestamps, duplicate URLs |
| Referential integrity | Orphan rows in all 7 join tables |
| Enum consistency | Attack tags, products, sources against locked vocabularies |
| Completeness | CVEs without sources, tags, descriptions |
| Stale data | Records not updated in 30+ days |
| Duplicates | Duplicate products, identical CVE descriptions |
| Coverage | EPSS/KEV/CVSS/tag coverage percentages |

```
============================================================
  HORUS DATABASE HEALTH REPORT
============================================================

── Statistics ──────────────────────────────────────────
  total_cves: 45
  cves_with_epss: 45/45 (100%)
  cves_with_kev: 3
  cves_with_attack_tags: 43/45 (95%)
  cves_with_pocs: 12/45 (26%)
  ...

── Warnings (2) ───────────────────────────────
  [WARN] [completeness] 2 CVEs without attack tags
  [WARN] [stale] 5 CVEs not updated in 30+ days

  PASSED with warnings
============================================================
```

## Output

```
=== Daily PoC Research Report — 2026-06-07 ===

[1/6] Running GitHub PoC Repos...
  Found 3 PoCs
[2/6] Running NVD CVE Feed...
  Found 15 CVEs
[3/6] Running X/Twitter (Chrome Auth)...
  Found 5 PoCs
[4/6] Running Exploit-DB...
[5/6] Merging and deduplicating...
  15 unique CVEs, 8 unique PoCs after dedup
[6/6] Persisting to database...

--- Web Application (3 CVEs) ---

  CVE-2026-3143 [CVSS 9.1 CRITICAL] [KEV] [EPSS 87.1%]
    RCE in nginx via crafted HTTP request
    tags: rce
    affects: nginx/nginx 1.24.x, 1.25.x
    PoC: https://github.com/... (558* [github])
    PoC: https://x.com/.../1234 ([x])
    PoC: https://www.exploit-db.com/exploits/52001 ([exploit-db])
    Exploitability: 8.5/10

--- Standalone PoCs (5) ---

  https://github.com/.../CVE-2026-99999-poc (42 3d)
    PoC for zero-day in Apache Tomcat

CVEs: 15 | Standalone PoCs: 5
Report saved -> reports/2026/06/2026-06-07.md
Graph saved  -> reports/2026/06/2026-06-07.graph.html
```

## Project Structure

```
Horus/
├── horus/
│   ├── __init__.py       # Version
│   ├── __main__.py       # `python3 -m horus` entry
│   ├── cli.py            # Plugin orchestrator (generic, never changes)
│   ├── config.py         # Queries, keywords, thresholds, paths
│   ├── core/             # Pure domain — no I/O
│   │   ├── model.py      #   CVE, PoC, AffectedProduct dataclasses
│   │   ├── vocab.py      #   Closed vocabularies (tags, categories)
│   │   ├── classify.py   #   Attack-tag + product-category classifiers
│   │   ├── filters.py    #   PoC relevance + CVE extraction
│   │   ├── merge.py      #   Dedup + PoC↔CVE linking
│   │   └── xsearch.py    #   Chrome cookie auth + X GraphQL client
│   ├── sources/          # Data ingestion plugins (drop-in)
│   │   ├── auth.py       #   GitHub token resolution
│   │   ├── http.py       #   Shared HTTP helper
│   │   ├── github.py     #   GitHub repo search
│   │   ├── nvd.py        #   NVD CVE feed
│   │   ├── exploitdb.py  #   Exploit-DB lookup
│   │   └── x_twitter.py  #   X/Twitter search (Chrome auth)
│   ├── enrichers/        # Enrichment plugins (drop-in)
│   │   ├── kev.py        #   CISA KEV flag
│   │   └── epss.py       #   EPSS scores
│   ├── storage/          # Local persistence (SQLite)
│   │   ├── schema.sql    #   Idempotent DDL
│   │   ├── db.py         #   Schema init, migration, CRUD
│   │   ├── health.py     #   Database integrity checks
│   │   └── query.py      #   CVE query + enrichment report
│   └── render/           # Output formatting
│       ├── report.py     #   Text / markdown renderer
│       ├── persist.py    #   Save markdown report to disk
│       └── graph.py      #   Interactive Cytoscape.js HTML graph
├── state/
│   └── horus.db          # SQLite — all persistent state
├── reports/              # Generated reports + graphs
├── ARCHITECTURE.md       # Plugin architecture documentation
├── README.md
└── CHANGELOG.md
```

## Adding a New Source

Create `horus/sources/my_source.py`:

```python
NAME = "My Source"
DEFAULT_ENABLED = True

def run(known_cve_ids, known_poc_urls, args, **kwargs) -> dict:
    """Fetch new data. Returns {"cves": [CVE, ...], "pocs": [PoC, ...]}."""
    # ... your fetching logic ...
    return {"cves": [...], "pocs": [...]}
```

Done. Horus auto-discovers it. Flag `--no-my_source` is auto-generated.

## Adding a New Enricher

Create `horus/enrichers/my_enricher.py`:

```python
NAME = "My Enricher"
DEFAULT_ENABLED = True

def enrich(cves, pocs, args, **kwargs) -> None:
    """Enrich CVEs/PoCs in-place."""
    for cve in cves:
        cve.my_new_field = "computed_value"
```

Done. Flag `--skip-my_enricher` is auto-generated.

## Interactive Graph

Each run writes `reports/YYYY/MM/YYYY-MM-DD.graph.html`. Open in browser:

```bash
open reports/2026/06/2026-06-07.graph.html   # macOS
```

- **Red circles** — CVEs (size = CVSS)
- **Green diamonds** — PoCs (size = stars)
- **Blue rectangles** — affected products
- **Orange hexagons** — attack tags

Skip with `--no-graph`.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history.

## Cron

Daily execution via Hermes cron job `daily-poc-research` (ID: f68b886451d7).
Results delivered to Telegram.
