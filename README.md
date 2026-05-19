# Horus

Daily PoC research scanner. Searches GitHub and NVD for new vulnerability disclosures with proof-of-concept exploits.

## What it does

- **GitHub**: Searches for new PoC/exploit repositories (filtered: <30d old, >10 stars, fresh PoC keywords)
- **NVD**: Fetches recently published CVEs with CVSS scores
- **X/Twitter**: Optional via xurl (requires paid X API access)
- **Deduplication**: Tracks seen items to avoid reporting duplicates
- **Delivery**: Designed to run as a daily cron job, outputs to stdout

## Usage

```bash
# Run manually
python3 horus.py

# Run via cron (daily at 09:00 UTC)
# Cron ID: f68b886451d7
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
| X/Twitter | xurl + API key | Pay-per-use | Early disclosures |

## State

Seen items are stored in `~/.hermes/poc-research/seen_items.json` for deduplication.

## Cron

Daily execution via Hermes cron job `daily-poc-research` (ID: f68b886451d7).
Results delivered to Telegram.
