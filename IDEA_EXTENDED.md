# Horus — Extended Features & Use Cases

*Brainstorm document: features, use cases, and product directions not in the original IDEA.md*
*Date: 2026-06-11*

---

## A. New Data Sources

### A1. NVD API v2 Full Coverage
**Current:** NVD source exists but may not handle all edge cases.
**Gap:** NVD API v2 has rate limits (5 req/30s without key, 50 with key). Need proper pagination, retry, and rate-limit handling.
**Impact:** Ensures no CVEs are missed on high-volume days (100+ CVEs).

### A2. Full-Text CVE Description Index
**Current:** CVE descriptions are stored but not indexed for search.
**Gap:** SQLite FTS5 index on descriptions would enable fast keyword search across all historical CVEs.
**Use case:** "Find all CVEs mentioning 'deserialization' in Apache Commons" — instant results from local DB.

### A3. Vendor Security Advisory RSS Feeds
**Current:** No vendor-specific advisory monitoring.
**Sources to add:**
- Apache Security (https://security.apache.org/)
- nginx Security Advisories
- Microsoft Security Response Center (MSRC)
- Oracle Critical Patch Updates
- Cisco PSIRT
- Google Chrome Releases
- Mozilla Foundation Security Advisories
- Debian Security Tracker
- Ubuntu CVE Tracker
- Red Hat Errata

**Use case:** "Alert me when nginx publishes a new security advisory" — before NVD even has the CVE.

### A4. CVE References Monitor
**Current:** NVD references are stored but not actively monitored.
**Gap:** Many CVE references point to vendor advisories, bug trackers, and commit logs. These often contain patch details, workarounds, and exploitation hints before PoCs appear.
**Implementation:** Parse `cve_reference` table, fetch and classify each URL (vendor advisory, commit, bug report, blog post).

### A5. Bug Tracker Monitoring
**Current:** No bug tracker integration.
**Sources:**
- Apache JIRA (issues.apache.org)
- Mozilla Bugzilla
- Chromium Issues
- Linux Kernel Bugzilla
- GitHub Security Advisories (github.com/advisories)

**Use case:** "Monitor Apache JIRA for new security issues" — catch CVEs before they're officially assigned.

### A6. Dark Web / Paste Site Monitoring (Ethical)
**Current:** No dark web integration.
**Ethical approach:** Monitor public paste sites that are accessible without authentication:
- Pastebin API (public pastes)
- GitHub Gists (public)
- GitLab Snippets (public)

**Use case:** "Alert me when a PoC for a KEV CVE appears on Pastebin" — early warning of weaponization.

---

## B. Enrichment & Analysis

### B1. CVSS v3.1 Vector Decomposition
**Current:** CVSS score is stored as a float. The vector string is not parsed.
**Gap:** A CVSS 9.1 requiring physical access is less urgent than CVSS 8.0 over network with no auth.
**Solution:** Parse CVSS vector string into components:
- Attack Vector (AV): N/A/L/P
- Attack Complexity (AC): L/H
- Privileges Required (PR): N/L/H
- User Interaction (UI): N/R
- Scope (S): U/C
- CIA Impact (C/I/A): N/L/H

**Use case:** Filter by "network exploitable, no auth, no user interaction" — the truly critical ones.

### B2. CWE Chain Analysis
**Current:** CWE IDs are stored but not analyzed for chains.
**Gap:** Real attacks chain CWEs. CWE-22 (path traversal) → CWE-94 (code injection) → RCE.
**Solution:** Build a CWE transition graph from historical CVE data. Identify common chains.
**Use case:** "This CVE has CWE-22. Historically, 40% of CWE-22 CWEs in this product class chain to RCE within 30 days."

### B3. Affected Version Range Analysis
**Current:** Affected versions are stored as text strings.
**Gap:** "Versions 1.0 to 2.0" and "Versions 1.5 to 3.0" overlap but this isn't computed.
**Solution:** Parse version ranges, compute overlap, identify unpatched version ranges.
**Use case:** "You're running version 1.8. CVE-2026-XXXX affects 1.0-2.0. You're vulnerable."

### B4. Exploitability Prerequisites Matrix
**Current:** No structured prerequisites data.
**Solution:** For each CVE, compute an exploitability matrix:
```
Prerequisites:
- Network accessible: Yes/No
- Authentication required: Yes/No
- User interaction required: Yes/No
- Privileges needed: None/Local/Admin
- Product version: Specific range
- Configuration: Default/Specific config
```
**Use case:** "Show me all CVEs that are network-exploitable with no auth against default configs."

### B5. Temporal Risk Scoring
**Current:** Reputation score is static (computed at ingestion).
**Gap:** Risk changes over time. A CVE with a new PoC today is more dangerous than the same CVE 6 months ago with no PoC.
**Solution:** Add time-decay and time-boost factors:
- New PoC published this week: +2.0
- EPSS score doubled in 7 days: +1.5
- KEV added: +3.0
- No new activity in 90 days: -1.0

**Use case:** "What's newly dangerous this week?" — not just new CVEs, but newly weaponized old ones.

### B6. Cross-Vendor Impact Analysis
**Current:** Products are categorized but cross-vendor impact isn't computed.
**Gap:** A vulnerability in OpenSSL affects nginx, Apache, Node.js, Python, and 50+ other products.
**Solution:** Build a dependency graph. When a library CVE is found, automatically flag all dependent products.
**Use case:** "CVE-2026-XXXX affects OpenSSL 3.x. This impacts 23 products in your vendor list."

---

## C. Reporting & Output

### C1. Configurable Report Templates
**Current:** Report format is hardcoded (text/md).
**Gap:** Different consumers need different formats.
**Solution:** Jinja2 report templates:
- `report_pentest.md` — focuses on exploitable CVEs with PoCs
- `report_management.md` — high-level risk summary with vendor rankings
- `report_ir.md` — incident response format with IOCs and detection guidance
- `report_compliance.md` — compliance-focused (PCI-DSS, HIPAA mappings)

### C2. Differential Reports
**Current:** Reports are full snapshots.
**Gap:** "What changed since yesterday?" requires comparing two full reports.
**Solution:** Store report hashes per CVE. Generate delta reports:
- New CVEs since last run
- CVEs with changed CVSS scores
- CVEs with new PoCs
- CVEs added to KEV
- CVEs with rising EPSS

**Use case:** Daily digest email showing only what changed, not the full database.

### C3. CVE Briefing Generator
**Current:** Query reports show raw data.
**Gap:** Security teams need executive-ready briefings.
**Solution:** Generate structured briefings:
```
CVE-2026-XXXX — Executive Briefing
Severity: Critical (CVSS 9.8)
Product: ProductName v1.0-v2.0
Impact: Remote code execution, no authentication required
Exploitation: Public PoC available on GitHub (150 stars)
KEV: Yes — CISA confirmed active exploitation
EPSS: 0.95 (95% probability of exploitation within 30 days)
Recommended Action: Patch to v2.1 immediately
Workaround: Disable feature X until patch is applied
```

### C4. IOC Extraction from PoCs
**Current:** PoCs are stored as URLs.
**Gap:** PoCs contain IOCs (IPs, domains, file hashes, YARA rules) that could be extracted.
**Solution:** Clone PoC repos, extract:
- IP addresses and domains (C2 servers, test targets)
- File hashes (malware samples, exploit payloads)
- YARA rules (if present)
- Snort/Suricata rules (if present)

**Use case:** "Extract all IOCs from PoCs for CVE-2026-XXXX" — feed directly into SIEM.

### C5. Detection Rule Generation
**Current:** No detection guidance.
**Solution:** For each CVE, generate:
- Snort/Suricata rules (based on known exploit patterns)
- YARA rules (based on PoC code patterns)
- Sigma rules (for log-based detection)
- Splunk SPL queries

**Use case:** "Generate detection rules for all new KEV CVEs this week" — deploy to SOC immediately.

---

## D. Integration & Automation

### D1. Webhook Dispatch System
**Current:** No outbound integrations.
**Solution:** Configurable webhooks for events:
- New KEV CVE → Slack/Telegram/Teams
- New PoC for watched vendor → PagerDuty
- EPSS spike → Email
- CVSS re-score → SIEM

### D2. MISP Integration
**Current:** No threat intel platform integration.
**Solution:** Auto-publish CVE events to MISP:
- Create MISP events for new high-severity CVEs
- Add PoC URLs, IOCs, and detection rules as attributes
- Tag with ATT&CK techniques

### D3. TheHive/Cortex Integration
**Current:** No SOAR integration.
**Solution:** Create TheHive cases for critical CVEs:
- Auto-create case for CVSS > 9.0 + KEV
- Populate with CVE details, PoCs, and IOCs
- Link to Cortex analyzers for automated enrichment

### D4. Splunk/Elastic SIEM Feed
**Current:** No SIEM integration.
**Solution:** Generate SIEM-compatible feeds:
- Splunk lookup CSV (CVE → severity → PoC count → EPSS)
- Elastic Security detection rules
- OpenIOC format for legacy systems

### D5. Ansible/Puppet Remediation Playbooks
**Current:** No remediation guidance.
**Solution:** For common CVE types, generate remediation playbooks:
- "Update nginx to 1.24.0" → Ansible playbook
- "Disable vulnerable feature X" → Config snippet
- "Apply vendor patch" → Step-by-step guide

---

## E. Use Cases by Persona

### E1. Penetration Tester
**Needs:** Find exploitable CVEs for engagements.
**Features used:**
- PoC verification (is the exploit real?)
- Exploitability prerequisites (can I actually use this?)
- Metasploit mapping (is there a module?)
- Attack graph (can I chain this with other CVEs?)
- Detection rules (how do I avoid being caught?)

**Workflow:**
1. Run Horus weekly scan
2. Filter: has_poc=true, exploitability=high, product in target scope
3. Review attack graphs for chain opportunities
4. Export Metasploit module list
5. Generate detection rules for red team OPSEC

### E2. SOC Analyst
**Needs:** Know what's being exploited right now.
**Features used:**
- KEV monitoring (what's actively exploited?)
- EPSS trends (what's about to be exploited?)
- IOC extraction (what do I look for?)
- Detection rules (how do I detect it?)
- Differential reports (what changed today?)

**Workflow:**
1. Horus runs every 30 minutes in server mode
2. SOC checks web dashboard triage view
3. New KEV CVE → immediate alert to Slack
4. Download detection rules for new CVEs
5. Check IOC feed for threat hunting

### E3. Vulnerability Manager
**Needs:** Prioritize patching across the organization.
**Features used:**
- Vendor exposure dashboard (which vendors are most affected?)
- Risk scoring (what's the actual risk to us?)
- Patch tracking (is it patched yet?)
- Remediation playbooks (how do I fix it?)
- Compliance mapping (what regulations require patching?)

**Workflow:**
1. Horus runs daily with risk profile configured
2. Weekly report: top 10 CVEs for our infrastructure
3. Track patch status per CVE
4. Generate compliance report for auditors
5. Alert on new CVEs affecting critical vendors

### E4. Threat Intelligence Analyst
**Needs:** Understand the threat landscape.
**Features used:**
- CVE correlation (what CVEs are used together?)
- Campaign correlation (which APT uses which CVEs?)
- Temporal forecasting (what's about to be exploited?)
- Dark web monitoring (are PoCs leaking?)
- STIX/TAXII feeds (share intel with partners)

**Workflow:**
1. Horus runs continuously, building historical data
2. Weekly: review correlation engine output
3. Identify new attack chains
4. Publish STIX feed to ISAC
5. Track campaign CVE usage patterns

### E5. CISO / Security Leadership
**Needs:** Risk overview and compliance status.
**Features used:**
- Executive briefing generator
- Vendor risk rankings
- Compliance dashboard
- Trend analysis (are we getting better or worse?)
- Board-ready reports

**Workflow:**
1. Monthly: generate executive briefing
2. Quarterly: vendor risk assessment
3. Annual: compliance audit support
4. Ad-hoc: "What's our exposure to Log4j-type events?"

### E6. Red Team Operator
**Needs:** Find and chain exploits for engagements.
**Features used:**
- Attack graph generator
- Exploit chain feasibility scoring
- PoC verification
- Metasploit mapping
- Detection rule generation (for OPSEC)

**Workflow:**
1. Pre-engagement: run Horus with target scope
2. Identify high-value CVE chains
3. Verify PoCs work in lab
4. Generate detection rules to avoid
5. Post-engagement: update Horus with new findings

### E7. Bug Bounty Hunter
**Needs:** Find new vulnerabilities before others.
**Features used:**
- Sleeper CVE detection (dormant CVEs getting new PoCs)
- Vendor advisory monitoring (new advisories = new targets)
- Version range analysis (is the target running vulnerable version?)
- Exploitability scoring (which CVEs are actually exploitable?)

**Workflow:**
1. Horus monitors vendor advisories in real-time
2. New advisory → immediate notification
3. Check if target scope is affected
4. Review PoCs for exploitation guidance
5. Generate proof-of-concept if none exists

### E8. Academic Researcher
**Needs:** Analyze vulnerability trends and patterns.
**Features used:**
- Full historical database
- CWE chain analysis
- Temporal analysis
- Vendor patch velocity
- Export to CSV/JSON for analysis

**Workflow:**
1. Export Horus database monthly
2. Analyze trends (are CVEs increasing? which types?)
3. Study vendor patch velocity
4. Research CWE chains
5. Publish findings

---

## F. Product Directions

### F1. Horus as a Service (HaaS)
**Concept:** Multi-tenant SaaS version of Horus.
- Each tenant configures their vendor list and risk profile
- Centralized scanning, per-tenant reporting
- API access for integrations
- Team collaboration features

### F2. Horus Agent (Lightweight Scanner)
**Concept:** Lightweight agent that runs on endpoints.
- Scans local software versions
- Compares against Horus CVE database
- Reports vulnerable software to central server
- No network scanning — purely local version detection

### F3. Horus Browser Extension
**Concept:** Browser extension for security researchers.
- When viewing a CVE on NVD, show Horus enrichment
- When viewing a GitHub repo, check if it's a known PoC
- When viewing a tweet, check if it mentions known CVEs
- One-click "Add to watchlist"

### F4. Horus CLI for CI/CD
**Concept:** Integrate Horus into CI/CD pipelines.
- Scan container images for known CVEs
- Fail builds if critical CVEs are found
- Generate SBOM (Software Bill of Materials)
- Track CVEs across deployments

### F5. Horus Mobile App
**Concept:** Mobile dashboard for on-the-go monitoring.
- Push notifications for critical CVEs
- Triage view for quick review
- One-tap "investigate" to open full report
- Dark mode (obviously)

---

## G. Data Science & ML Opportunities

### G1. CVE Exploitability Prediction
**Features:** CVSS vector, EPSS, vendor, attack type, description keywords, product category
**Target:** Will this CVE have a public PoC within 30 days?
**Model:** Gradient boosted trees (XGBoost) or logistic regression
**Training data:** Historical CVEs with known PoC status

### G2. CVSS Score Prediction
**Features:** CWE IDs, attack tags, product category, vendor, description text
**Target:** What will the CVSS score be?
**Model:** Regression on historical CVE scoring patterns
**Use case:** Predict severity before NVD scores the CVE

### G3. Vendor Patch Velocity Prediction
**Features:** Vendor, product, CVE severity, CWE type, historical patch times
**Target:** How many days until this vendor patches this CVE?
**Model:** Survival analysis (Cox proportional hazards)
**Use case:** "This vendor typically patches critical CVEs in 14 days. This CVE is 10 days old. Expect patch in 4 days."

### G4. CVE Description Clustering
**Features:** CVE description text
**Target:** Group similar CVEs together
**Model:** TF-IDF + K-means or DBSCAN
**Use case:** Identify vulnerability trends (e.g., "deserialization CVEs in Java frameworks are increasing")

### G5. PoC Quality Scoring
**Features:** Stars, age, commit frequency, code complexity, CVE reference accuracy
**Target:** Is this PoC high-quality and functional?
**Model:** Binary classifier trained on manually labeled PoCs
**Use case:** Filter out fake/low-quality PoCs from reports

### G6. Natural Language CVE Search
**Features:** User query text
**Target:** Relevant CVEs from the database
**Model:** Sentence embeddings (SBERT) + cosine similarity
**Use case:** "Show me critical RCE vulnerabilities in web servers from the past month"

---

## H. Compliance & Governance

### H1. Compliance Framework Mapping
**Concept:** Map CVEs to compliance frameworks:
- PCI-DSS: Requirement 6.2 (patch critical vulnerabilities within 30 days)
- HIPAA: Security Rule (risk assessment and mitigation)
- SOC 2: CC6.1 (logical and physical access controls)
- ISO 27001: A.12.6.1 (technical vulnerability management)
- NIST 800-53: SI-2 (flaw remediation)

**Use case:** "Which of our unpatched CVEs put us out of compliance with PCI-DSS?"

### H2. SLA Tracking
**Concept:** Track patch SLAs per vendor and CVE severity.
- Critical (CVSS > 9.0): 7-day SLA
- High (CVSS 7.0-9.0): 30-day SLA
- Medium (CVSS 4.0-7.0): 90-day Slope
- Low (CVSS < 4.0): 180-day SLA

**Use case:** "We have 12 CVEs past their patch SLA. 3 are critical."

### H3. Risk Acceptance Workflow
**Concept:** Track risk acceptance decisions for CVEs.
- CVE identified → risk assessed → accepted/rejected → remediation planned → verified
- Full audit trail for compliance

### H4. Vulnerability Metrics Dashboard
**Concept:** Track key metrics over time:
- Mean time to detect (MTTD)
- Mean time to remediate (MTTR)
- CVEs by severity over time
- Patch compliance rate
- Vendor risk trends

---

## I. Collaboration Features

### I1. CVE Annotation & Notes
**Concept:** Allow users to add notes to CVEs.
- "We're not affected — running version 2.1"
- "Patch scheduled for next maintenance window"
- "Compensating control: WAF rule #1234"

### I2. Team Triage Workflow
**Concept:** Multi-user triage workflow.
- Analyst reviews CVE → assigns priority → assigns to team member → tracks resolution
- Status: New → In Review → Accepted → Remediated → Verified

### I3. CVE Watchlist Sharing
**Concept:** Share watchlists across teams.
- "Web team watchlist" — CVEs affecting web servers
- "Infrastructure watchlist" — CVEs affecting network devices
- "Cloud team watchlist" — CVEs affecting cloud services

### I4. CVE Discussion Threads
**Concept:** Per-CVE discussion threads.
- "Has anyone tested this PoC?"
- "Our environment is not affected because..."
- "Patch available from vendor, testing now"

---

## I. Ideas from Other Domains

### I1. CVE "Weather Report"
**Concept:** Daily summary of the "vulnerability weather."
- "Today's forecast: 12 new CVEs, 3 critical, 1 KEV addition, EPSS spike on 2 CVEs"
- Like a weather report but for security

### I2. CVE "Stock Market"
**Concept:** Track "investment" in CVEs over time.
- "CVE-2026-XXXX: 5 new PoCs this week, EPSS up 40%, social mentions up 200%"
- "CVE-2026-YYYY: No new activity, EPSS declining, likely not being exploited"

### I3. CVE "Health Score"
**Concept:** Overall security posture score.
- Based on: number of unpatched CVEs, severity distribution, patch velocity, KEV count
- "Your security health score: 72/100 (down from 78 last month)"

### I4. CVE "Genetics"
**Concept:** Track CVE "families" — CVEs that share common ancestry.
- Same root cause, different manifestations
- "This CVE is part of the 'Java deserialization' family — 47 related CVEs since 2020"

### I5. CVE "Ecosystem Map"
**Concept:** Visualize the vulnerability ecosystem.
- Products → CVEs → PoCs → Exploits → Campaigns → APT groups
- Interactive graph showing relationships

---

*This is a brainstorm document. Not all ideas are equally valuable. Prioritize based on user needs and implementation effort.*
