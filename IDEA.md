# Horus — Feature Ideas & Roadmap

## Current State Summary

Horus v0.7.0 is a daily PoC research scanner with plugin architecture, 4 sources (NVD, GitHub, X/Twitter, Exploit-DB), 2 enrichers (KEV, EPSS), SQLite persistence, health checks, and CVE query reports. It collects, enriches, deduplicates, and reports on vulnerability data.

What it does NOT do yet: correlate, prioritize, predict, exploit, or act. That's where the opportunity is.

---

## Tier 1 — High Impact, Builds on Existing Foundation

### 1. CVE Correlation Engine
**Problem:** CVEs are stored flat. Real-world attacks chain multiple CVEs together.
**Solution:** Build a correlation graph that clusters CVEs by:
- Shared attack tags + temporal proximity (same product, same week)
- Shared PoCs (one exploit targets multiple CVEs)
- CWE chains (e.g., CWE-22 → CWE-94: path traversal leading to RCE)
- Text similarity of descriptions (TF-IDF or embedding-based)

Output: "CVE-2026-11413 → CVE-2026-11414 → CVE-2026-11415 form a 3-stage attack chain targeting JD Cloud Box"
**Uniqueness:** No existing tool (Shuffle, Metasploit, even commercial correlators for EMBER)
**Implementation:** `enrichers/correlation.py` that runs after merge, builds `cve_chains` table.

---

### 2. Automated PoC Verification
**Problem:** PoC repos exist but may be fake, non-functional, or the CVE ID in the name is wrong.
**Solution:** For each PoC repo, verify by:
- Check if the repo actually references the CVE (grep source code for CVE ID)
- Clone and run static analysis: does the code contain exploit patterns?
- Check commit freshness (commits within 7 days of CVE publication = high confidence)
- Cross-reference: does NVD/Exploit-DB confirm this CVE has a known PoC?

Output: Confidence score per PoC (0.0–1.0) displayed in reports.
**Uniqueness:** Nobody does automated PoC verification. Shodan/Censys find exposed services but don't validate exploits.
**Implementation:** Confidence scores stored in `poc.confidence` column, calculated in `enrichers/poc_verify.py`.

---

### 3. EPSS Trend Tracking
**Problem:** EPSS scores change daily. A CVE with rising EPSS is more urgent than one with a static score.
**Solution:** Store EPSS history per CVE (date, score, percentile). Track:
- Score velocity (rising/falling)
- Days since first above threshold (e.g., >0.5)
- Acceleration (second derivative)

Output alert: "CVE-2026-11413 EPSS rose 40% in 3 days — active exploitation likely increasing"
**Uniqueness:** FIRST.org shows current scores but no trend analysis.
**Implementation:** New table `cve_epss_history(cve_id, date, epss_score, percentile)`, updated daily by epss enricher.

---

### 4. Exploit-DB Code Pattern Extraction
**Problem:** PoCs are URLs. The actual exploit code is not analyzed.
**Solution:** Pull Exploit-DB code, extract:
- Targeted versions
- Required preconditions
- Attack vector (local/remote, auth required)
- Impact type (RCE, LPE, DoS, info-disclosure)

Each Exploit-DB PoC becomes a structured card, not just a link.
**Uniqueness:** Shodan monitors for vulnerable services. Nobody reverse-engineers PoC code to extract structured metadata.
**Implementation:** Parse `files_exploit.csv` + `files_exploit_context.json` from GitLab mirror. New table `exploit_meta`.

---

### 5. X/Twitter Sentiment & Urgency Scoring
**Problem:** A tweet saying "CVE-2026-XXXX is being exploited in the wild" is more urgent than "interesting CVE-2026-XXXX writeup."
**Solution:** Classify tweets mentioning CVEs:
- **In-the-wild:** "exploited", "active attacks", "under exploit", "wormable"
- **Weaponized:** "PoC released", "Metasploit module", "0day"
- **Research:** "analysis", "writeup", "technical deep dive"
- **Noise:** "CVE of the day", generic mentions

Output: Each X-sourced PoC gets an urgency score. High-urgency items reported first.
**Uniqueness:** CISA KEV is reactive. This provides real-time threat signal from social media.
**Implementation:** Keyword classifier in `sources/x_twitter.py`, urgency stored in `poc.urgency` column.

---

## Tier 2 — Unique Differentiators

### 6. Attack Graph Generator
**Problem:** Security teams need to understand how multiple CVEs combine into attack paths.
**Solution:** Generate per-CVE attack prerequisite chains:
```
CVE-2026-XXXX (auth-bypass) → CVE-2026-YYY (file upload) → CVE-2026-ZZZZ (RCE)
```
Using attack tag transitions (auth-bypass → file upload → RCE is a common pattern).
Output: Graphviz DOT or Mermaid diagram in the query report.
**Uniqueness:** Attack path modeling exists in tools like Cynevus (theoretical) but is not automated from real CVE data.
**Implementation:** `enrichers/attack_graph.py`, new table `cve_attack_paths`.

---

### 7. Vendor Exposure Dashboard
**Problem:** "Which of my vendors have the most critical CVEs this month?"
**Solution:** Group CVEs by vendor, calculate:
- Vendor risk score (weighted sum of CVSS × EPSS)
- Vendor exposure trend (rising/falling month-over-month)
- Vendor patch velocity (how fast do they publish fixes after CVE disclosure)

Output: Vendor risk rankings in query report and weekly summary.
**Uniqueness:** NIST NVD gives raw counts. No tool computes vendor risk scores automatically.
**Implementation:** `storage/query.py` extension for vendor-level aggregation, `render/report.py` vendor section.

---

### 8. CVE Deduplication via Description Similarity
**Problem:** Some CVEs are effectively the same vulnerability reported differently. Example: CVE-2026-11413 and CVE-2026-11414 may affect the same product/component.
**Solution:** Compute description similarity between CVEs using TF-IDF. Flag pairs above threshold (0.7+) as "likely related." Useful for:
- Avoiding duplicate work
- Finding umbrella CVEs vs. specific instances
- Discovering split CVEs (one vuln assigned multiple IDs)

**Implementation:** `enrichers/similarity.py`, new table `cve_similarity(cve_id_a, cve_id_b, score)`.

---

### 9. Patch Detection & Tracking
**Problem:** A CVE being published is only half the story. When is it patched?
**Solution:** Monitor:
- GitHub commit messages mentioning the CVE (search `repo:owner/repo "CVE-2026-XXXX"`)
- Linux kernel git (git.kernel.org) for CVE fixes
- Vendor security advisories (RSS feeds from major vendors)

Store first-known-patch date. Report: "CVE-2026-XXXX published 2026-06-01, patched 2026-06-05 (4 day window)"
**Uniqueness:** CVE/NVD track disclosure dates. Nobody tracks patch timelines automatically.
**Implementation:** `sources/patch_monitor.py`, new table `cve_patch(cve_id, patch_date, source_url, confidence)`.

---

### 10. Vulnerability Intel Feed Aggregator
**Problem:** Horus is a collector. It should also be a publisher.
**Solution:** Generate machine-readable intel feeds from the Horus database:
- STIX/TAXII feed for SIEM integration
- MISP events for threat intel platforms
- RSS feed for human consumption
- Slack/Telegram webhook alerts for critical CVEs (CVSS > 9.0 + KEV)
- Email digest with configurable filters

Output: Configurable feeds. Horus becomes a CVE intel platform, not just a scanner.
**Uniqueness:** NVD provides raw data. Commercial tools (Recorded Future, Mandiant) do enrichment. Horus can be the open-source bridge.
**Implementation:** `render/feed.py` (STIX, RSS, MISP), webhook plugins.

---

## Tier 3 — Advanced / Differentiated

### 11. Natural Language CVE Search
**Problem:** `--query` requires exact CVE ID. Users should be able to ask "Show me critical RCE in web servers from the past week."
**Solution:** Parse natural language queries:
- "RCE in nginx last week" → filter by tag=rce, product=nginx, published>7d
- "critical CVEs with PoCs" → cvss>9.0, has_poc=true
- "Log4j-like vulnerabilities" → similar to CVE-2021-44228 by tag+product+score

**Implementation:** Query parser in `storage/query.py`, extend `--query` to accept NL.

---

### 12. Temporal Exploitability Forecasting
**Problem:** Not all CVEs get exploited at the same rate. Some are exploited within hours, others never.
**Solution:** Build a simple model (logistic regression or gradient boosted trees) trained on historical CVE features:
- CVSS vector components (attack vector, complexity, privileges required)
- EPSS score
- Vendor (some vendors get targeted more)
- Attack type (RCE > XSS in exploitability)
- Description keywords ("wormable", "default config", "no auth required")

Output: Predicted days-to-exploitation for each new CVE. High-risk CVEs flagged.
**Uniqueness:** EPSS gives probability. This gives time-to-exploitation — a different and more actionable metric.
**Implementation:** `enrichers/predict.py`, model trained on historical KEV + EPSS data.

---

### 13. Cross-Reference with Shodan/Censys
**Problem:** A CVE is more critical if there are internet-facing services running the vulnerable version.
**Solution:** For each CVE with affected products:
- Query Shodan API for affected services (`product:"Apache" version:"2.4.49"`)
- Query Censys for certificate/host data
- Report: "CVE-2026-XXXX affects Product v1.2. 12,000 instances detected on Shodan."

Output: Severely changes prioritization. A CVSS 7.0 with 50,000 exposed instances > CVSS 9.0 with 50.
**Uniqueness:** Shodan/Censys find services but don't correlate with new CVEs automatically. This bridges that gap.
**Implementation:** `enrichers/exposure.py`, Shodan/Censys API integration.

---

### 14. MITRE ATT&CK Mapping
**Problem:** CVEs map to CWEs but not to ATT&CK techniques. Attackers think in ATT&CK.
**Solution:** Map attack tags to ATT&CK techniques:
- rce → T1059 (Command and Scripting Interpreter)
- sql-injection → T1190 (Exploit Public-Facing Application)
- lpe → T1068 (Exploitation for Privilege Escalation)
- auth-bypass → T1078 (Valid Accounts)

Output: Each CVE query report includes ATT&CK technique IDs. Enables direct integration with SIEM/SOAR.
**Implementation:** Mapping table in `core/vocab.py`, report renderer enhancement.

---

### 15. Automated CVE-to-Metasploit Module Mapping
**Problem:** Metasploit has thousands of modules. Matching CVEs to modules is manual.
**Solution:** Scrape Metasploit module metadata (from `rapid7/metasploit-framework` GitHub repo):
- Module path, CVE references, target platforms
- Match CVE IDs from Horus DB to Metasploit modules
- Report: "CVE-2026-XXXX → exploit/linux/http/product_rce (Metasploit)"

Output: Direct actionable path from CVE discovery to exploitation.
**Implementation:** `enrichers/metasploit.py`, weekly scrape of metasploit-framework repo.

---

### 16. CVE Changelog / Diff Tracking
**Problem:** CVE records get updated by NVD (description changes, CVSS re-scored, references added). These changes matter.
**Solution:** Store snapshots of CVE data on each run. Track changes:
- CVSS score changed from 7.5 → 9.1 (urgency spike)
- New references added (PoC published post-disclosure)
- Description expanded (more attack details known)

Output: Per-CVE changelog in query report. "2026-06-05: CVSS re-scored from 7.5 to 9.1. 3 new PoC references added."
**Implementation:** `cve_snapshots` table, diff logic in `storage/db.py`.

---

### 17. Personalized Risk Profile
**Problem:** Different teams care about different things. A web app team doesn't care about kernel CVEs.
**Solution:** Configurable risk profile (YAML or CLI args):
```yaml
risk_profile:
  vendors: ["apache", "nginx", "microsoft", "google"]
  categories: ["web-server", "framework", "browser"]
  min_cvss: 7.0
  require_poc: false
  notify_kev: true
```
Filter and rank CVEs by the profile. "Top 10 CVEs for MY infrastructure this week."
**Implementation:** Config in `config.py`, filtering in `render/report.py`.

---

### 18. Malware/Campaign CVE Correlation
**Problem:** Threat actors use specific CVE sets. Knowing which CVEs are used together reveals campaigns.
**Solution:** Correlate CVEs from:
- Malware analysis reports (grep writeups for CVE mentions)
- Threat intel feeds (RSS from malware traffic analysis, etc.)
- MITRE ATT&CK software entries

Output: "CVE-2026-XXXX is used by APT29 in conjunction with CVE-2026-YYYY"
**Implementation:** `sources/threat_intel.py`, correlation in `enrichers/campaign.py`.

---

### 19. CVSS Vector Parsing & Attack Prerequisites
**Problem:** CVSS score alone doesn't tell you the attack requirements. A CVSS 9.1 requiring physical access is less urgent than CVSS 8.0 over network with no auth.
**Solution:** Parse CVSS vector string (if available from NVD):
- AV:N (network) > AV:A (adjacent) > AV:L (local) > AV:P (physical)
- PR:N (no privileges) > PR:L > PR:H
- UI:N (no user interaction) > UI:R

Store parsed prerequisites. Report attack requirements clearly.
**Implementation:** `core/cvss.py` parser, extend `cve` table with parsed vector columns.

---

### 20. Offline-First Graph Rendering
**Problem:** The Cytoscape.js graph loads from CDN. Doesn't work offline.
**Solution:** Bundle Cytoscape.js in the package, or generate static SVG with networkx + matplotlib. Also export to:
- GEXF (for Gephi)
- GraphML (for yEd)
- DOT (for Graphviz)

Output: Fully offline interactive graph + exportable formats.
**Implementation:** Vendor Cytoscape.js or switch to `pyvis` (bundles vis.js).

---

## Architecture Improvements

### A. Async Pipeline
Run all sources concurrently with `asyncio`. Current sequential execution means 4 sources × 30s avg = 2 min minimum. Async could cut to ~30s total.

### B. Incremental Updates
Track which CVEs/PoCs were updated in each run. Enable "show me what changed since yesterday" queries. Currently all reports are full snapshots.

### C. Plugin Hooks System
Add lifecycle hooks for plugins:
- `on_run_start()` — before pipeline
- `on_cve_persisted(cve)` — after each CVE is saved
- `on_run_end(report)` — after pipeline complete

Enables plugins like Slack notification, webhook dispatch, etc. without modifying core.

### D. Configuration Profiles
Support multiple named profiles for different use cases:
- `horus --profile personal` — your infrastructure vendors
- `horus --profile pentest` — focus on exploitable, with PoCs
- `horus --profile research` — all CVEs, verbose output

### E. Retry & Backoff
Every HTTP call should have exponential backoff with retries. Currently a transient network error kills the source silently.

### F. Source Deduplication via Content Hash
For PoCs, hash the description + URL domain. Detect when the same PoC is found by multiple sources but with slightly different URLs or descriptions.

### G. NVD API v2 Pagination
NVD API returns max 50 results per page. On busy days (100+ CVEs), data is lost. Implement proper pagination.

---

## Competitive Positioning

| Feature | Horus | NVD | Shodan | Metasploit | Recorded Future |
|---------|-------|-----|--------|------------|-----------------|
| CVE collection | ✓ | ✓ | — | — | ✓ |
| PoC discovery | ✓ | — | — | ✓ | ✓ |
| X/Twitter intel | ✓ | — | — | — | ✓ |
| EPSS enrichment | ✓ | — | — | — | ✓ |
| KEV enrichment | ✓ | — | — | — | ✓ |
| Plugin architecture | ✓ | — | — | ✓ | — |
| Health checks | ✓ | — | — | — | — |
| CVE query reports | ✓ | partial | — | — | ✓ |
| **CVE correlation** | planned | — | — | — | ✓ |
| **PoC verification** | planned | — | — | — | — |
| **EPSS trends** | planned | — | — | — | — |
| **Attack path modeling** | planned | — | — | — | — |
| **Vendor risk scoring** | planned | — | — | — | ✓ |
| **Patch tracking** | planned | — | — | — | — |
| **Exposure detection** | planned | — | ✓ | — | ✓ |
| **NL queries** | planned | — | — | — | — |
| **Exploit forecasting** | planned | — | — | — | — |

The path to differentiation: **correlation, verification, and prediction**. Nobody else combines these in an open-source tool.
