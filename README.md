# Horus

**Version:** 0.16.0

CVE + PoC discovery pipeline with reputation scoring, weekly threat reports, AI-powered analysis, and MITRE ATT&CK mapping. Runs as a one-shot CLI or 24/7 server.

## Quick Start

```bash
pip install -e .
python3 -m horus                      # run once
python3 -m horus --server             # 24/7 daemon
python3 -m horus --weekly-report      # generate weekly threat report
```

## Features

### CVE + PoC Discovery
- **NVD** (authoritative) + **GitHub, GitLab, Codeberg, Exploit-DB, X/Twitter** (signal sources)
- **Reputation scoring** (0-10): CVSS + EPSS + KEV + social mentions + PoC availability
- **Weekly reports**: text, markdown, or HTML with executive summary, top CVEs, KEV, EPSS trends, vendor breakdown

### AI-Powered Analysis (`--ai`)
- LLM-generated executive summary, trend analysis, risk assessment, recommendations
- Automated QA bug detection (data anomalies + report correctness)
- Providers: OpenAI, Anthropic, Ollama (local)

### CVE Correlation Engine
- Pairwise correlation from shared tags, CWEs, products, PoCs, temporal proximity
- Attack cluster detection (campaign grouping)
- Dashboard at `/correlations`

### Automated PoC Verification
- Composite confidence score (0-100, grade A-F) from 6 signals
- CVE presence, repo freshness, stars, URL quality, description, NVD cross-ref

### MITRE ATT&CK Mapping
- 22 attack tags mapped to ATT&CK technique IDs (T1059, T1190, T1068, etc.)
- Per-CVE technique persistence + API

### EPSS Trend Tracking
- CVE-level EPSS history charts (Chart.js)
- Velocity badges, days-above-threshold counters
- Global movers dashboard at `/epss-trends`

### Web Dashboard
- Flask UI with RBAC (viewer/analyst/admin), audit logging, CSRF protection
- CVE index, vendor exposure, triage queue, watchlist, news feed
- Telegram notification support

## CLI Reference

| Command | Description |
|---------|-------------|
| `python3 -m horus` | Run pipeline once |
| `python3 -m horus --server` | 24/7 daemon |
| `python3 -m horus --weekly-report` | Generate weekly report |
| `python3 -m horus --weekly-format html` | HTML output |
| `python3 -m horus --ai` | AI-augmented report |
| `python3 -m horus --query CVE-2026-1234` | CVE enrichment report |
| `python3 -m horus --export-json DIR` | Static JSON export |
| `python3 -m horus --health-check` | Database health check |
| `python3 -m horus --backfill-epss` | Score all unscored CVEs |

## Configuration

Config via `horus.yaml` or environment variables. See `docs/architecture.md` for full architecture.

## License

Internal tool — not for external distribution.
