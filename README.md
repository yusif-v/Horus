# Horus

**Version:** 0.7.0

Daily PoC research scanner. Searches GitHub, NVD, X/Twitter, and Exploit-DB for new vulnerability disclosures with proof-of-concept exploits. Enriches with CISA KEV and EPSS scores. Requires Python 3.10+.

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

## Plugin Architecture

Sources and enrichers are **self-discovering plugins**. Adding a new source = creating ONE file in `horus/sources/` with a `run()` function. No other files change.

```bash
python3 -m horus --list-sources    # show all discovered plugins
python3 -m horus --sources github,nvd  # run only specific sources
python3 -m horus --no-exploitdb    # skip a source (auto-generated flag)
python3 -m horus --skip-kev        # skip an enricher (auto-generated flag)
```

## Usage

```bash
# Run all sources + enrichers
python3 -m horus

# Common options
python3 -m horus --min-cvss 7.0          # NVD: only High/Critical
python3 -m horus --max-results 10         # cap items per source
python3 -m horus --format md             # markdown output (e.g. for Telegram)
python3 -m horus --quiet                 # suppress progress on stderr
python3 -m horus --no-exploitdb --skip-kev  # skip specific plugins
python3 -m horus --list-sources          # list all plugins
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

## Output

```
=== Daily PoC Research Report — 2026-06-07 ===

[1/6] Searching GitHub for new PoC repos...
  Found 9 relevant repos
[2/6] Fetching recent CVEs from NVD...
  Found 15 relevant CVEs
[3/6] Searching X/Twitter for CVE mentions...
  Found 3 relevant tweets
[4/6] Searching Exploit-DB for known CVEs...
  Found 2 Exploit-DB entries
[5/6] Merging and deduplicating findings...
[6/6] Persisting to database...

--- Web Application (3 CVEs) ---
[1] CVE-2026-3143 [CVSS 9.1 CRITICAL] [KEV] [EPSS 0.87]
    Exploit POC for CVE_2026_3143 — RCE in nginx
    ★ 558 stars | GitHub: rootsecdev/cve_2026_31431
    X: @security_researcher (https://x.com/.../status/...)
    EDB: https://www.exploit-db.com/exploits/52001
    Exploitability: 8.5/10

Total: 24 items | CVEs: 15 | PoCs: 9
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
│   │   └── db.py         #   Schema init, migration, CRUD, exploitability scoring
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
