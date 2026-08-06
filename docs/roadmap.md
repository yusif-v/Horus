# Horus — Roadmap

*Last updated: 2026-08-07*

## v0.15.0 — Current Release

| # | Feature | Status |
|---|---------|--------|
| 1 | Weekly threat reports (text/md/html) | shipped |
| 2 | AI-powered analysis (OpenAI, Anthropic, Ollama) | shipped |
| 3 | CVE correlation engine | shipped |
| 4 | Automated PoC verification | shipped |
| 5 | MITRE ATT&CK technique mapping | shipped |
| 6 | EPSS trend tracking | shipped |
| 7 | CVE-news intelligence linking | shipped |

## v0.14.0 — Previous Release

| # | Feature | Status |
|---|---------|--------|
| 1 | Weekly threat reports | shipped |
| 2 | AI-powered analysis | shipped |
| 3 | Dark web trust scoring (ThreatFox + Hudson Rock) | shipped |
| 4 | Source health observability | shipped |
| 5 | KEV due-date event pipeline | shipped |

---

## Next Up

| # | Feature | Status |
|---|---------|--------|
| 1 | Telegram bot listener — wire token UI to notification dispatch | partial — token UI built, listener not connected |
| 2 | CVE dedup via description similarity (TF-IDF) | not started |
| 3 | CVSS vector parsing & attack prerequisites | not started |
| 4 | STIX/TAXII publishing | not started |
| 5 | Offline-first graph rendering (bundle Cytoscape, export GEXF/GraphML/DOT) | not started |

## Long Horizon

| # | Feature | Notes |
|---|---------|-------|
| 1 | Attack graph generator | Per-CVE prereq chains, Mermaid/Graphviz |
| 2 | Patch detection | Monitor GitHub commits, vendor RSS for fix dates |
| 3 | X/Twitter sentiment & urgency scoring | Classify mentions as in-the-wild/weaponized/research/noise |
