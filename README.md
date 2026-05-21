# Horus

**Version:** 0.5.0

Daily PoC research scanner. Searches GitHub and NVD for new vulnerability disclosures with proof-of-concept exploits.

## What it does

- **GitHub**: Searches for new PoC/exploit repositories (filtered: <30d old, >10 stars, fresh PoC keywords)
- **NVD**: Fetches recently published CVEs with CVSS scores, CWE IDs, and affected vendor/product/version ranges
- **Classification**: Tags each CVE with an attack type (rce, sql-injection, lpe, …) and product category (web-server, database, kernel, …) from a locked vocabulary
- **PoC linking**: GitHub repos that reference known CVE IDs are attached to that CVE; everything else surfaces as a standalone PoC
- **Persistence**: SQLite at `state/horus.db` — normalized schema (CVE, PoC, Product, AttackTag, CWE + join tables for graph edges)
- **Reports**: Markdown (`reports/YYYY/MM/YYYY-MM-DD.md`) and interactive graph (`reports/YYYY/MM/YYYY-MM-DD.graph.html`) written every run
- **Delivery**: Designed to run as a daily cron job, outputs to stdout

## Usage

```bash
# Run manually
python3 -m horus

# Common options
python3 -m horus --min-cvss 7.0          # NVD: only High/Critical
python3 -m horus --max-results 10         # cap items per source
python3 -m horus --format md              # markdown output (e.g. for Telegram)
python3 -m horus --quiet                  # suppress progress on stderr

# Run via cron (daily at 09:00 UTC)
# Cron ID: f68b886451d7
```

### Flags

| Flag | Purpose |
|------|---------|
| `--min-cvss FLOAT` | Drop NVD items below this CVSS base score |
| `--max-results N` | Cap items per source after sorting |
| `--format {text,md}` | Output format (markdown for chat delivery) |
| `--quiet` | Send progress lines to stderr only |
| `--version` | Print version and exit |

Progress messages now go to **stderr**, so `python3 -m horus --format md > report.md` produces clean markdown.

### Interactive graph

Each run writes `reports/YYYY/MM/YYYY-MM-DD.graph.html` — a single self-contained file with Cytoscape.js (loaded via CDN). Open it directly in a browser:

```bash
open reports/2026/05/2026-05-21.graph.html   # macOS
xdg-open reports/2026/05/2026-05-21.graph.html  # Linux
```

- **Red circles** — CVEs (size = CVSS)
- **Green diamonds** — PoCs (size = stars)
- **Blue rectangles** — affected products
- **Orange hexagons** — attack tags

Click any node to highlight its neighborhood and view details. Skip with `--no-graph`.

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
=== Daily PoC Research Report — 2026-05-19 ===

[1/2] Searching GitHub for new PoC repos...
  Found 9 relevant repos
[2/2] Fetching recent CVEs from NVD...
  Found 15 relevant CVEs

--- GitHub Repos (new PoCs) ---
[1] rootsecdev/cve_2026_31431 (558 stars, 19d old)
    https://github.com/rootsecdev/cve_2026_31431
    Exploit POC for CVE_2026_31431

--- Recent CVEs (NVD) ---
[1] CVE-2026-8719 [CVSS: 8.8 HIGH]
    WordPress AI Engine privilege escalation

Total: 24 items | GitHub: 9 | NVD: 15
```

## Data Sources

| Source | Auth | Cost | Coverage |
|--------|------|------|----------|
| GitHub API | None | Free | New PoC repos |
| NVD API | None | Free | Recent CVEs with CVSS |

## Project Structure

```
Horus/
├── horus/
│   ├── __init__.py       # Version
│   ├── __main__.py       # `python3 -m horus` entry
│   ├── cli.py            # Orchestration
│   ├── config.py         # Queries, keywords, thresholds, paths
│   ├── core/             # Pure domain — no I/O
│   │   ├── model.py      #   CVE, PoC, AffectedProduct dataclasses
│   │   ├── vocab.py      #   Closed vocabularies (tags, categories)
│   │   ├── classify.py   #   Attack-tag + product-category classifiers
│   │   ├── filters.py    #   PoC relevance + CVE extraction
│   │   └── merge.py      #   Raw dicts → typed model + PoC↔CVE links
│   ├── sources/          # Data ingestion (network)
│   │   ├── http.py       #   Shared HTTP/JSON helper
│   │   ├── auth.py       #   GitHub token resolution
│   │   ├── github.py     #   GitHub repo search
│   │   └── nvd.py        #   NVD CVE feed (CWE + CPE extraction)
│   ├── storage/          # Local persistence (SQLite)
│   │   ├── schema.sql    #   Idempotent DDL
│   │   └── db.py         #   Schema init, vocab seeding, migration, CRUD
│   └── render/           # Output formatting
│       ├── report.py     #   Text / markdown renderer
│       ├── persist.py    #   Save markdown report to disk
│       └── graph.py      #   Interactive Cytoscape.js HTML graph
├── state/
│   └── horus.db          # SQLite — all persistent state
├── README.md
└── CHANGELOG.md
```

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history.

## Cron

Daily execution via Hermes cron job `daily-poc-research` (ID: f68b886451d7).
Results delivered to Telegram.
