# Horus v0.8 — Source Purity, Scoring Rework & 24/7 Server Mode

## Overview

Three major changes:
1. **Source purity** — NVD is the ONLY authoritative source for CVE data. X/Twitter is social signal only. GitHub is the ONLY PoC source.
2. **Reputation scoring** — new composite score combining CVSS + EPSS + KEV + social mentions + PoC source count
3. **24/7 server mode** — long-running daemon that polls sources at configurable intervals, ready for production feed

---

## Part 1: Source Classification

### Authoritative sources (produce CVE records)
- `nvd` → CVE ID, description, CVSS, CWE, affected products. This is the ONLY source that creates/updates CVE records.

### Signal sources (produce PoC links + social mentions)
- `github` → PoC repos (actual exploit code). Confidence: high if >100 stars, medium if >10, low otherwise.
- `x-twitter` → Social mentions + GitHub URL discovery. Does NOT create PoC records with source="x". Instead:
  - Each tweet mentioning a CVE increments `social_mentions` on that CVE
  - Each tweet linking to a GitHub PoC repo creates a PoC record with source="github" and `discovered_via="x"`
- `exploit-db` → PoC links (secondary, lower confidence)

---

## Part 2: CVE Model Changes

File: `horus/core/model.py`

Add fields to CVE dataclass:
```python
social_mentions: int = 0          # how many X posts mention this CVE
poc_source_count: int = 0         # how many distinct signal sources have PoCs
reputation_score: float = 0.0     # computed composite (0-10)
confidence: str = "high"          # high=NVD, medium=NVD+signal, low=signal-only
```

Remove `exploitability_score` (replaced by `reputation_score`).

---

## Part 3: Reputation Score Formula

File: `horus/core/merge.py` — new function `compute_reputation_score(cve)`

```
reputation_score =
    CVSS_score * 0.35                    (0-3.5)
  + EPSS * 10 * 0.25                    (0-2.5)
  + KEV_bonus: 1.5 if kev else 0        (0-1.5)
  + min(social_mentions * 0.15, 1.0)    (0-1.0)
  + min(poc_source_count * 0.5, 1.5)    (0-1.5)
  Total cap: 10.0
```

Examples:
- CVSS 9.8 + KEV + EPSS 0.8 + 5 social + 2 PoC sources = 3.43 + 2.0 + 1.5 + 0.75 + 1.0 = **8.68**
- CVSS 7.0 + no KEV + EPSS 0.1 + 0 social + 0 PoC = 2.45 + 0.25 + 0 + 0 + 0 = **2.70**

---

## Part 4: X/Twitter Source Rework

File: `horus/sources/x_twitter.py`

### Current behavior (WRONG):
- Produces PoC records with tweet text as description
- Source labeled "x" or "twitter"
- Broad noisy queries: "CVE-2026", "0day", "zeroday"

### New behavior:
- **Social signal**: Each tweet mentioning a CVE increments `social_mentions`
- **GitHub URL discovery**: If tweet contains a github.com URL that looks like a PoC, create PoC with source="github", discovered_via="x"
- **No source="x" PoCs ever**

### New search queries (targeted, GitHub-focused):
```python
DEFAULT_QUERIES = [
    "CVE-2026 github.com",
    "CVE-2025 github.com",
    "CVE PoC github",
    "CVE exploit github.com",
    "0day github.com PoC",
]
```

### Return format:
```python
return {
    "cves": [],           # X never creates CVEs
    "pocs": github_pocs,  # Only GitHub URLs, source="github"
    "social_signals": [   # New: social mention signals
        {"cve_id": "CVE-2026-XXXX", "tweet_url": "...", "likes": N, "retweets": N},
    ]
}
```

---

## Part 5: GitHub Source Refinement

File: `horus/sources/github.py`

Changes:
- Accept GitHub URLs discovered by X/Twitter (pass via `x_discovered_urls` parameter)
- Add confidence scoring: repos with >100 stars = high, >10 = medium, else low
- Keep existing `is_fresh_poc` filter

---

## Part 6: Merge Layer Rework

File: `horus/core/merge.py`

### `merge_findings()` changes:
- CVEs from NVD are authoritative (confidence="high")
- CVEs discovered ONLY via social signal (no NVD match) go to watchlist table, NOT main index
- Aggregate `social_mentions` from all signal sources
- Count distinct `poc_source_count` per CVE
- Call `compute_reputation_score()` for each CVE

### New function: `compute_reputation_score(cve) -> float`
Implements the formula from Part 3.

### New function: `aggregate_social_signals(cves, social_signals)`
Takes social signal dicts from X source and increments `social_mentions` on matching CVEs.

---

## Part 7: EPSS Enricher Fix

File: `horus/enrichers/epss.py`

### Current: Only enriches CVEs from current run's batch (6.8% coverage)
### Fix: After scoring new CVEs, backfill ALL unscored CVEs in DB

```python
# After scoring new batch:
unscored = conn.execute("SELECT id FROM cve WHERE epss_score IS NULL").fetchall()
# Score them from the same CSV download
```

---

## Part 8: Database Schema Changes

File: `horus/storage/schema.sql`

### cve table — ADD columns:
```sql
ALTER TABLE cve ADD COLUMN social_mentions INTEGER DEFAULT 0;
ALTER TABLE cve ADD COLUMN poc_source_count INTEGER DEFAULT 0;
ALTER TABLE cve ADD COLUMN reputation_score REAL;
ALTER TABLE cve ADD COLUMN confidence TEXT DEFAULT 'high';
```

### cve table — DROP column:
```sql
-- exploitability_score replaced by reputation_score
-- SQLite doesn't support DROP COLUMN directly; recreate table or just leave it
```

### New table: cve_watchlist
```sql
CREATE TABLE IF NOT EXISTS cve_watchlist (
    id              TEXT PRIMARY KEY,
    first_seen      TEXT NOT NULL,
    social_mentions INTEGER DEFAULT 0,
    source          TEXT NOT NULL,     -- which signal source found it
    confidence      TEXT DEFAULT 'low',
    resolved        INTEGER DEFAULT 0  -- 1 when NVD confirms it
);
```

File: `horus/storage/db.py`
- Update `persist_cve()` to handle new fields
- Add `persist_watchlist()` function
- Update `_compute_exploitability()` → `_compute_reputation()`

---

## Part 9: CLI Pipeline Changes

File: `horus/cli.py`

### New pipeline phases:
```
Phase 1: Run NVD (authoritative CVE discovery)
Phase 2: Run X/Twitter (social signals + GitHub URL discovery)
Phase 3: Run GitHub (own queries + X-discovered URLs)
Phase 4: Run Exploit-DB (secondary PoC links)
Phase 5: Merge — aggregate signals, deduplicate, compute reputation
Phase 6: Enrich — EPSS (ALL CVEs), KEV
Phase 7: Persist
Phase 8: Output
```

### New flags:
- `--backfill-epss` — one-time: score all unscored CVEs in DB
- `--server` — run in 24/7 server mode (see Part 11)

---

## Part 10: Web UI Changes

File: `horus/web.py`

### Dashboard updates:
- Threat posture grid: add "Social heat" cell (CVEs with social_mentions > 0)
- Add "Reputation" column to CVE tables
- Triage page: sort by reputation_score by default
- CVE detail: show social_mentions, poc_source_count, confidence badge
- New filter: "High reputation" (reputation_score >= 7)
- Fix version string: "HORUS v0.5" → "HORUS v0.8"

### API updates:
- `/api/stats` — include social_mentions_total, avg_reputation
- `/api/cve/<id>` — include all new fields

---

## Part 11: 24/7 Server Mode (NEW)

New file: `horus/server.py`

### Concept:
Long-running daemon that polls sources at configurable intervals and maintains the database. Designed to run as a systemd service or Docker container.

### Polling intervals (configurable):
```python
POLL_INTERVALS = {
    "nvd": 3600,        # every 1 hour — NVD updates ~2h
    "x_twitter": 1800,  # every 30 min — social moves fast
    "github": 3600,     # every 1 hour — GitHub search API rate limits
    "exploit_db": 7200, # every 2 hours — slow-moving
    "epss": 86400,      # daily — EPSS CSV updates once/day
    "kev": 86400,       # daily — KEV catalog updates ~daily
}
```

### Architecture:
```
horus/server.py
  ├── Server class
  │   ├── __init__(config) — load intervals, init DB
  │   ├── start() — main loop with asyncio or threading
  │   ├── stop() — graceful shutdown
  │   ├── run_source(name) — run a single source + merge + enrich + persist
  │   └── status() — return health info
  ├── Config (dataclass or dict)
  │   ├── poll_intervals: dict
  │   ├── sources_enabled: dict
  │   ├── db_path: Path
  │   └── log_level: str
  └── main() — CLI entry point
```

### Main loop (asyncio-based):
```python
async def run(self):
    while self._running:
        for source_name, interval in self.poll_intervals.items():
            if not self.sources_enabled.get(source_name, True):
                continue
            elapsed = time.time() - self.last_run.get(source_name, 0)
            if elapsed >= interval:
                await self._run_source(source_name)
                self.last_run[source_name] = time.time()
        await asyncio.sleep(60)  # check every minute
```

### Per-source run:
1. Run the source module
2. Merge findings (aggregate signals)
3. Run relevant enrichers (EPSS/KEV only on schedule)
4. Compute reputation scores
5. Persist to DB
6. Log results

### CLI usage:
```bash
# Start server
python3 -m horus.server

# Start with custom config
python3 -m horus.server --config /etc/horus/config.yaml

# Check status
python3 -m horus.server --status

# Run once (single poll cycle, then exit)
python3 -m horus.server --once
```

### Config file format (YAML):
```yaml
# /etc/horus/config.yaml or ~/.config/horus/config.yaml
poll_intervals:
  nvd: 3600
  x_twitter: 1800
  github: 3600
  exploit_db: 7200
  epss: 86400
  kev: 86400

sources_enabled:
  nvd: true
  x_twitter: true
  github: true
  exploit_db: false

database:
  path: /var/lib/horus/horus.db

logging:
  level: INFO
  file: /var/log/horus/server.log

web:
  enabled: true
  host: 0.0.0.0
  port: 8080
```

### Systemd service file (for deployment):
```
# /etc/systemd/system/horus.service
[Unit]
Description=Horus CVE Intelligence Server
After=network.target

[Service]
Type=simple
User=horus
WorkingDirectory=/opt/horus
ExecStart=/opt/horus/.venv/bin/python3 -m horus.server --config /etc/horus/config.yaml
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
```

### Docker support:
```dockerfile
FROM python:3.14-slim
WORKDIR /app
COPY . .
RUN pip install -e ".[web]"
VOLUME ["/data"]
ENV HORUS_DB_PATH=/data/horus.db
EXPOSE 8080
CMD ["python3", "-m", "horus.server", "--config", "/data/config.yaml"]
```

---

## Part 12: Report Renderer Updates

File: `horus/render/report.py`

- Show confidence badge per CVE
- Show social_mentions count
- Show reputation_score
- Group by reputation tier (Critical/High/Medium/Low) instead of just category

---

## Files to Modify (in order):

1. `horus/__init__.py` — bump version to 0.8.0
2. `setup.py` — bump version, add server extras
3. `horus/core/model.py` — add fields, remove exploitability
4. `horus/storage/schema.sql` — add columns, watchlist table
5. `horus/storage/db.py` — persist new fields, backfill EPSS
6. `horus/core/merge.py` — new scoring, signal aggregation
7. `horus/sources/x_twitter.py` — social signal + GitHub URL discovery
8. `horus/sources/github.py` — accept X-discovered URLs
9. `horus/enrichers/epss.py` — backfill all unscored CVEs
10. `horus/cli.py` — new pipeline phases, --backfill-epss, --server flags
11. `horus/web.py` — new UI elements
12. `horus/render/report.py` — new fields in output
13. `horus/server.py` — NEW: 24/7 server mode

## What doesn't change:
- NVD source (already correct — authoritative)
- KEV enricher (already correct)
- Attack tag classification
- Product category classification
- Graph renderer
- API endpoint structure (just gets new fields)

## Verification:
1. `python3 -m horus --backfill-epss` → EPSS coverage >80%
2. `python3 -m horus` → X produces social_mentions, not source="x" PoCs
3. `SELECT id, social_mentions, poc_source_count, reputation_score FROM cve ORDER BY reputation_score DESC LIMIT 10`
4. Web dashboard shows new fields, triage sorts by reputation
5. `python3 -m horus.server --once` → single poll cycle works
6. `python3 -m horus.server` → starts and runs continuously
