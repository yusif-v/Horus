# Horus — Feature Documentation

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Pipeline](#pipeline)
3. [CVE + PoC Discovery](#cve--poc-discovery)
4. [Reputation Scoring](#reputation-scoring)
5. [Weekly Threat Reports](#weekly-threat-reports)
6. [AI-Powered Analysis](#ai-powered-analysis)
7. [CVE Correlation Engine](#cve-correlation-engine)
8. [Automated PoC Verification](#automated-poc-verification)
9. [MITRE ATT&CK Mapping](#mitre-attck-mapping)
10. [EPSS Trend Tracking](#epss-trend-tracking)
11. [CVE-News Intelligence Linking](#cve-news-intelligence-linking)
12. [Web Dashboard](#web-dashboard)
13. [API Reference](#api-reference)
14. [AI News Feed](#ai-news-feed)

---

## Architecture Overview

Horus is a plugin-based CVE + PoC discovery pipeline. Sources and enrichers are self-discovering modules — adding a new one requires only a single file.

```
Sources (plugins)     Enrichers (plugins)     Render
───────────────       ───────────────────      ──────
nvd                   kev                      report (text/md/html)
github                epss                     graph (cytoscape HTML)
codeberg              darkweb                  weekly report
gitlab
exploitdb
x_twitter
news
resource_intelligence
```

**Core principle:** NVD is the single authoritative source for CVE data. All other sources are signal-only — they can never create or mutate CVE records.

---

## Pipeline

Single function `run_pipeline()` orchestrates the entire flow:

1. **CVE sources** (NVD) — authoritative IDs first
2. **PoC sources** (X/Twitter → GitHub/Codeberg → others)
3. **CVE backfill** from PoC references
4. **Merge & dedupe** — reputation scoring, social signal aggregation
5. **Enrich** — KEV, EPSS, dark web trust scoring
6. **Persist** — imminence scoring + SQLite
7. **CVE-news linking** — extract CVEs from RSS, create associations
8. **CVE correlation** — pairwise correlation scoring + cluster detection
9. **PoC verification** — confidence scoring for all PoCs
10. **Render** — text/markdown/HTML report + interactive graph
11. **End-of-run hooks** — Telegram notifications

---

## CVE + PoC Discovery

### Source Classification

| Source | Type | What it provides |
|--------|------|------------------|
| NVD | Authoritative | CVE ID, description, CVSS, CWE, products |
| GitHub | Signal | PoC repositories (confidence from stars) |
| GitLab | Signal | PoC repositories |
| Codeberg | Signal | PoC repositories |
| Exploit-DB | Signal | Exploit links |
| X/Twitter | Signal | Social mentions + discovered URLs |
| News/RSS | Intelligence | Security news articles |
| Resource Intel | Intelligence | Tools, bypasses, advisories |

### Reputation Score (0-10)

```
CVSS × 0.35          (0–3.5)
+ EPSS × 10 × 0.25    (0–2.5)
+ KEV bonus           1.5
+ social mentions     min(mentions × 0.15, 1.0)
+ PoC sources         min(sources × 0.5, 1.5)
+ ubiquity bonus      1.0
= capped at 10.0
```

---

## Weekly Threat Reports

Generated via `--weekly-report`. Produces aggregated weekly intelligence.

**Output formats:** text, markdown, HTML (dark-themed, self-contained)

**Sections:**
- Executive Summary (KPI table with WoW trends)
- Severity Distribution (visual bar chart)
- Top CVEs by Risk Score
- CISA KEV (new + overdue alerts)
- Highest Exploitability (EPSS rankings)
- Most Targeted Vendors
- Attack Technique Distribution
- Security News Highlights
- ThreatFox IOC Summary
- Notable Exploit Publications
- Triage Workflow Status
- Source Health

**Options:**
- `--weekly-format {text,md,html}`
- `--weeks-back N` (configurable lookback)
- `--weekly-output PATH` (save to file)
- `--ai` (AI-augmented)

---

## AI-Powered Analysis

Activated with `--ai` flag. Requires an API key (or local Ollama).

**Providers:**
- OpenAI (GPT-4o)
- Anthropic (Claude)
- Ollama (local, no key needed)

**Config:**
```bash
export HORUS_AI_PROVIDER=openai
export OPENAI_API_KEY=sk-...
```

**Two-pass analysis (single API call):**
1. **Narrative Generation** — executive summary, trend analysis, risk assessment, recommendations
2. **QA Bug Detection** — data anomalies (CVSS/EPSS mismatches, missing KEV dates) + report correctness

**Cost:** ~10K tokens per report (~$0.03-0.06)

---

## CVE Correlation Engine

Finds relationships between CVEs using structured signals + temporal proximity.

**Signals & Weights:**
| Signal | Weight |
|--------|--------|
| Shared PoCs | 4x |
| Shared attack tags | 3x |
| Shared CWE IDs | 3x |
| Shared products | 2x |
| Temporal proximity (≤7d) | 1x |
| Same vendor | 1x |

**Threshold:** score ≥ 3 (stored)

**Clustering:** Greedy agglomerative clustering on correlation graph. Top 50 clusters by size.

**UI:** `/correlations` dashboard + enhanced "Related CVEs" on each CVE page.

---

## Automated PoC Verification

Composite confidence score (0-100, grade A-F) from 6 signals:

| Signal | Max Points |
|--------|------------|
| CVE presence in description | 40 |
| Repository freshness | 20 |
| Star count | 15 |
| URL/repo quality | 10 |
| Description quality | 10 |
| NVD cross-reference | 5 |

**Grades:** A (80+), B (60+), C (40+), D (20+), F (<20)

**API:** `GET /api/poc/<url>/verify`

---

## MITRE ATT&CK Mapping

22 attack tags mapped to MITRE ATT&CK technique IDs.

**Examples:**
| Tag | ATT&CK Techniques |
|-----|-------------------|
| rce | T1190, T1059 |
| lpe | T1068 |
| xss | T1059.007, T1189 |
| sql-injection | T1190 |
| auth-bypass | T1078, T1556 |
| supply-chain | T1195 |

**Persistence:** `cve_attack_technique` table (per-CVE)
**API:** `GET /api/cve/<id>/attack-techniques`, `GET /api/attack-techniques`

---

## EPSS Trend Tracking

Track EPSS score changes over time.

**CVE-level:**
- EPSS history chart (Chart.js line)
- Velocity badge (▲ rising / ▼ falling / → stable)
- Days above 50% threshold counter

**Global dashboard (`/epss-trends`):**
- Top movers table (sorted by absolute velocity)
- Threshold alerts (CVEs crossing 50% EPSS)
- Summary stats (rising/falling/stable counts)

**API:** `GET /api/cve/<id>/epss-trend`, `GET /api/epss-trends`

---

## CVE-News Intelligence Linking

Extract CVE IDs from RSS news articles and link them to CVE records.

**Extraction:** Regex `CVE-\d{4}-\d{4,}` on article title + summary
**Context detection:**
- Exploit status: active / poC / patched / unknown (keyword-based)
- Severity mention: critical / high / medium / low

**Active search:** For critical CVEs (CVSS 9+/KEV), re-scan RSS feeds for coverage

**UI:** "Intelligence Sources" panel on CVE page (latest 10 articles)
**API:** `GET /api/cve/<id>/sources`

---

## Web Dashboard

Flask app with 13 blueprints, RBAC, CSRF protection, audit logging.

**Pages:**
| Route | Access | Purpose |
|-------|--------|---------|
| `/` | read all | KPI dashboard with Chart.js |
| `/cves` | read all | Filterable CVE table |
| `/cves/<id>` | read all | CVE dossier |
| `/pocs` | read all | Exploit index |
| `/vendors` | read all | Vendor exposure |
| `/search` | read all | Keyword lookup |
| `/triage` | write | Action queue |
| `/watchlist` | team | Per-team pins |
| `/news` | read all | Classified RSS news |
| `/posts` | read all | AI-curated news feed |
| `/resources` | read all | Security intelligence |
| `/correlations` | read all | CVE correlation clusters |
| `/epss-trends` | read all | EPSS movers dashboard |
| `/admin` | admin | Users, sources, audit |

**Access levels:** read all (any logged-in user) · write (analyst/admin) · admin · team (red/blue)

---

## API Reference

| Endpoint | Description |
|----------|-------------|
| `GET /api/health` | Public health check |
| `GET /api/stats` | Aggregate statistics |
| `GET /api/cves` | CVE list (paginated, filterable) |
| `GET /api/cve/<id>` | CVE detail |
| `GET /api/cve/<id>/sources` | Linked news articles |
| `GET /api/cve/<id>/epss-trend` | EPSS history + velocity |
| `GET /api/cve/<id>/correlations` | Related CVEs |
| `GET /api/cve/<id>/attack-techniques` | ATT&CK mappings |
| `GET /api/poc/<url>/verify` | PoC verification score |
| `GET /api/epss-trends` | Global EPSS movers |
| `GET /api/clusters` | Correlation clusters |
| `GET /api/clusters/<id>` | Cluster members |
| `GET /api/attack-techniques` | All techniques with counts |

---

## AI News Feed

New articles from the RSS news source are scored for importance by the AI. Articles scoring at or above `news_feed.threshold` become **posts** on a new `/posts` feed page — an AI-curated, ranked read of the security-news intake.

**Flow:**
1. RSS articles land in `news_article` via the news source plugin
2. `horus/news_feed` scores every new article 0–100 (one batched AI call per cycle)
3. Each scored article is persisted (never re-scored); `ai_score >= threshold` → post

**Triggers:**
- Automatic: server pipeline end-hook after each full cycle
- Manual/backfill: `horus --news-feed` CLI command (prints `scored N, posted M`)

**Config (`horus.yaml`):**
```yaml
news_feed:
  enabled: true
  threshold: 80            # min ai_score to become a post
  max_articles_per_run: 50 # token-cost bound per cycle
```

**`/posts` page (read all):** AI headline, score badge, AI rationale, source, original link, posted_at. Paginated like `/news`; read-only (no moderation in v1).
