# Horus

**Version:** 0.7.0

Daily PoC research scanner. Searches GitHub, NVD, X/Twitter, and Exploit-DB for new vulnerability disclosures with proof-of-concept exploits. Enriches with CISA KEV and EPSS scores. Query any CVE from the local database for a full enrichment report. Requires Python 3.10+.

## What it does

- **GitHub**: Searches for new PoC/exploit repositories (filtered: <30d old, >10 stars, fresh PoC keywords)
- **NVD**: Fetches recently published CVEs with CVSS scores, CWE IDs, and affected vendor/product/version ranges
- **X/Twitter**: Searches for CVE mentions via Chrome cookie authentication (no API key needed) — birdnode-compatible GraphQL client
- **Exploit-DB**: Looks up published exploits for each new CVE found by NVD
- **Enrichment**: CISA KEV (known-exploited flag) + EPSS (exploit probability score) + composite exploitability score
- **Classification**: Tags each CVE with attack type (rce, sql-injection, lpe, …) and product category from a locked vocabulary
- **PoC linking**: All sources that reference known CVE IDs are attached to that CVE
- **Persistence**: SQLite at `state/horus.db` — normalized schema with graph edges
- **Reports**: Markdown + interactive Cytoscape.js graph every run
- **Health check**: Database integrity validation (`--health-check`)
- **CVE query**: Look up any CVE for a full enrichment report (`--query`)

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

## Web Interface

Horus includes a Flask-based web UI for browsing the database visually.

```bash
# Install web dependencies
pip install flask

# Start the server
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
