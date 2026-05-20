# Horus

**Version:** 0.3.1

Daily PoC research scanner. Searches GitHub and NVD for new vulnerability disclosures with proof-of-concept exploits.

## What it does

- **GitHub**: Searches for new PoC/exploit repositories (filtered: <30d old, >10 stars, fresh PoC keywords)
- **NVD**: Fetches recently published CVEs with CVSS scores
- **Deduplication**: Tracks seen items in `state/seen_items.json` to avoid reporting duplicates
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
│   ├── filters.py        # PoC relevance + CVE extraction
│   ├── http.py           # Shared HTTP/JSON helper
│   ├── report.py         # Output formatting
│   ├── state.py          # Deduplication state
│   └── sources/
│       ├── github.py     # GitHub repo search
│       └── nvd.py        # NVD CVE feed
├── state/
│   ├── seen_items.json   # Deduplication state
│   └── last_run.json     # Per-source last-run timestamps
├── README.md
└── CHANGELOG.md
```

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history.

## Cron

Daily execution via Hermes cron job `daily-poc-research` (ID: f68b886451d7).
Results delivered to Telegram.
