# Horus — Roadmap & Ideas

*Consolidates the former `IDEA.md` and `IDEA_EXTENDED.md`. Active version work lives in `docs/plans/`. Open issues live in `docs/issues.md`.*

*Last updated: 2026-06-12*

---

## What Horus is today (v0.9-dev)

Daily PoC research scanner with plugin architecture, 5 sources (NVD, GitHub, X/Twitter, Exploit-DB, GitLab), 2 enrichers (KEV, EPSS), SQLite persistence, reputation scoring, watchlist, 24/7 server mode, web dashboard, CVE query reports.

**Strengths:** plugin sources, source-purity model (NVD authoritative, others signals), reputation scoring, watchlist for pre-NVD signals, server mode with per-source intervals, web UI, X auth via Chrome cookies, path-traversal hardening.

**Gap:** it collects but doesn't correlate, prioritize, predict, or act. That's the differentiation opportunity.

---

## v0.8.x — Quick wins (some landed, some pending)

| # | Feature | Status |
|---|---------|--------|
| 1 | EPSS trend tracking (score velocity, days-above-threshold) | partial — scores stored, no history table |
| 2 | X/Twitter sentiment & urgency scoring (in-wild / weaponized / research / noise) | partial — mentions counted, not classified |
| 3 | CVE dedup via description similarity (TF-IDF) | not started |
| 4 | CVSS vector parsing & attack prerequisites | not started |
| 5 | Offline-first graph rendering (bundle Cytoscape, export GEXF/GraphML/DOT) | not started |

---

## v0.9.0 — High-impact, builds on existing foundation

| # | Feature | Notes |
|---|---------|-------|
| 6 | **CVE correlation engine** | Clusters by tag+time, shared PoCs, CWE chains, text similarity. New `cve_chains` table. No OSS tool does this. |
| 7 | **Automated PoC verification** | Confidence score per PoC: grep source for CVE ID, commit freshness, NVD cross-ref |
| 8 | **Attack graph generator** | Per-CVE prereq chains, render as Mermaid/Graphviz |
| 9 | **Vendor exposure dashboard** | Weighted CVSS×EPSS per vendor, trend, patch velocity |
| 10 | **Patch detection** | Monitor GitHub commit msgs, kernel git, vendor RSS for fix dates |

Also tracked operationally in `docs/plans/v0.9.x.md`: coverage lift, mypy expansion, supply chain.

---

## v1.0.0 — Unique differentiators

| # | Feature | Hook |
|---|---------|------|
| 11 | STIX/TAXII + MISP + Slack/Telegram + email digest feeds | Become a publisher, not just a collector |
| 12 | Natural-language CVE search | "Show me critical RCE in web servers last week" |
| 13 | Temporal exploitability forecasting | Predict days-to-exploitation, not just probability |
| 14 | Shodan/Censys cross-reference | CVSS 7.0 × 50k exposed > CVSS 9.0 × 50 |
| 15 | MITRE ATT&CK technique mapping | tag → technique ID for SIEM/SOAR |
| 16 | Auto CVE → Metasploit module mapping | Scrape `rapid7/metasploit-framework` |
| 17 | CVE changelog / diff tracking | Snapshot CVE state per run, surface CVSS re-scores |
| 18 | Personalized risk profile (YAML) | "Top 10 CVEs for MY stack this week" |
| 19 | Malware / campaign correlation | Which CVEs cluster in APT activity |
| 20 | Exploit-DB code pattern extraction | Pull PoC code, structure: targets, prereqs, vector, impact |

---

## Extended ideas (from former `IDEA_EXTENDED.md`)

### A. Data sources to add
NVD API v2 rate-limit hardening · SQLite FTS5 full-text CVE index · Vendor RSS (Apache, nginx, MSRC, Oracle, Cisco, Chrome, Mozilla, Debian, Ubuntu, RedHat) · CVE references monitor · Bug tracker monitoring (Apache JIRA, Bugzilla, Chromium, kernel BZ, GH advisories) · Public paste sites (Pastebin, gists, snippets).

### B. Enrichment & analysis
CVSS v3.1 vector decomposition · CWE chain analysis · affected-version range parser · exploitability prerequisites matrix · temporal/decay risk scoring · cross-vendor dependency impact (OpenSSL → 23 products).

### C. Reporting & output
Jinja report templates (pentest / management / IR / compliance) · differential reports · executive briefing generator · IOC extraction from PoCs · detection-rule generation (Snort/Suricata/YARA/Sigma/SPL).

### D. Integrations
Webhooks (Slack/Telegram/Teams/PagerDuty) · MISP auto-publish · TheHive/Cortex case creation · Splunk/Elastic feeds · Ansible/Puppet remediation playbooks.

### E. Personas served
Pentester · SOC analyst · vuln manager · threat-intel analyst · CISO · red team · bug bounty hunter · academic researcher. Each persona's workflow detailed in source notes.

### F. Product directions
HaaS multi-tenant SaaS · lightweight endpoint agent · browser extension (NVD/GitHub/Twitter enrichment) · CI/CD scanner with SBOM · mobile dashboard.

### G. ML opportunities
Exploitability prediction (XGBoost/logreg) · CVSS score prediction · vendor patch-velocity (Cox PH) · description clustering (TF-IDF + KMeans) · PoC quality classifier · NL search (SBERT + cosine).

### H. Compliance & governance
Compliance framework mapping (PCI/HIPAA/SOC2/ISO27001/NIST 800-53) · SLA tracking per severity · risk-acceptance workflow · vulnerability metrics dashboard (MTTD/MTTR).

### I. Collaboration
CVE annotation/notes · multi-user triage workflow · shared watchlists per team · per-CVE discussion threads.

### J. Cross-domain framing
"Vulnerability weather report" · "CVE stock market" (investment over time) · per-org "security health score" · CVE "genetics" (families with shared root cause) · "ecosystem map" (products → CVEs → PoCs → exploits → campaigns → APTs).

### K. Cross-cutting infra ideas
- **Async pipeline** — `asyncio`-driven sources, cut 2.5min → ~30s
- **Incremental updates** — track per-run deltas, "what changed since yesterday"
- **Plugin lifecycle hooks** — `on_run_start`, `on_cve_persisted`, `on_run_end` for notification plugins
- **Configuration profiles** — `--profile personal|pentest|research`
- **Retry/backoff everywhere** — consistent across sources (partial today)
- **Source dedup via content hash** — same PoC found via different URLs
- **CVE aging model** — per-vendor expected patch delay
- **Exploit chain feasibility score** — product of individual exploitability scores
- **Sleeper detection** — dormant CVEs that suddenly get PoCs / social mentions
- **KEV due-date tracking** — federal-agency-style deadline prioritization
- **Multi-language PoC detection** — Chinese, Russian repos (common for APT-related work)

---

## Competitive positioning

| Capability | Horus | NVD | Shodan | Metasploit | Recorded Future |
|---|---|---|---|---|---|
| CVE collection | ✓ | ✓ | — | — | ✓ |
| PoC discovery | ✓ | — | — | ✓ | ✓ |
| X/Twitter intel | ✓ | — | — | — | ✓ |
| EPSS + KEV enrichment | ✓ | — | — | — | ✓ |
| Plugin architecture | ✓ | — | — | ✓ | — |
| 24/7 server + web | ✓ | — | partial | — | ✓ |
| **Correlation / verification / forecasting / ATT&CK / Metasploit / STIX / exposure** | planned | — | partial (exposure) | partial (msf) | ✓ |

Differentiation path: **correlation, verification, and prediction** in an OSS tool.

---

## Web UI roadmap

**v0.9** (spec in `docs/plans/web-v0.9.md`):
- Clickable tag/category/severity filters on dashboard (combinable, preserved in pagination)
- News feed — RSS (BleepingComputer, THN, SecurityWeek, CISA) + vendor advisories + X intel; deduped by URL/title/CVE; urgency classification

**v1.0:** real-time WebSocket updates · personalized feed (watchlist-driven) · auto news→CVE linking · global threat-level indicator.
