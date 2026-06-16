# Horus Web UI — Comprehensive Feature & Filter List

## Philosophy

Every number, badge, chart element, and section title on every page should be
**clickable** and lead to a filtered view. The dashboard is a drill-down
machine: overview → category → filtered list → detail. No dead ends.

---

## 1. Dashboard (Overview) — `/`

### Current sections and what each element should do

#### Posture cells (top 4 boxes)
| Element | Click target |
|---------|-------------|
| "Actionable now" number | → `/triage` (already works) |
| "KEV" count inside cell | → `/cves?kev=1` |
| "EPSS≥0.5 with PoC" count | → `/triage?lens=imminent` |
| "Weaponized" number | → `/triage?lens=weaponized` |
| "CVSS≥9 with public PoC" count | → `/triage?lens=weaponized` |
| "Imminent (EPSS≥0.5)" number | → `/triage?lens=imminent` |
| "PoCs linked" number | → `/pocs` |
| "across N CVEs" count | → `/cves?has_poc=1` |

#### KEV table
| Element | Click target |
|---------|-------------|
| Each CVE row | → `/cve/<id>` (already works) |
| "View all →" link | → `/triage?lens=kev` (already works) |
| Section heading "Known exploited" | → `/cves?kev=1` |

#### Severity mix (bar chart)
| Element | Click target |
|---------|-------------|
| Each severity bar (CRITICAL, HIGH, MEDIUM, LOW) | → `/cves?severity=<SEVERITY>` |
| "N indexed" count | → `/cves` |

#### Exploit probability (EPSS buckets)
| Element | Click target |
|---------|-------------|
| "Very High (≥0.5)" bar | → `/cves?epss_min=0.5` |
| "High (0.1-0.5)" bar | → `/cves?epss_min=0.1&epss_max=0.5` |
| "Medium (0.01-0.1)" bar | → `/cves?epss_min=0.01&epss_max=0.1` |
| "Low (<0.01)" bar | → `/cves?epss_max=0.01` |
| "N scored" count | → `/cves?has_epss=1` |

#### Highest EPSS table
| Element | Click target |
|---------|-------------|
| Each CVE row | → `/cve/<id>` (already works) |
| "All by EPSS →" link | → `/cves?sort=epss` (already works) |

#### Recent ingest table
| Element | Click target |
|---------|-------------|
| Each CVE row | → `/cve/<id>` (already works) |
| Section heading | → `/cves?sort=date&window=week` |

#### Top PoCs table
| Element | Click target |
|---------|-------------|
| Each PoC URL | → opens in new tab (already works) |
| Each source badge | → `/pocs?source=<source>` |
| Section heading | → `/pocs` |

#### Attack surface (tag cloud)
| Element | Click target |
|---------|-------------|
| Each attack tag badge | → `/cves?tag=<tag>` |
| Section heading | → `/cves` |

#### Publication tempo (monthly bar chart)
| Element | Click target |
|---------|-------------|
| Each month bar | → `/cves?window=month&month=<YYYY-MM>` |
| Section heading | → `/cves?sort=date` |

#### PoC sources (bar chart)
| Element | Click target |
|---------|-------------|
| Each source bar (github, exploit-db, etc.) | → `/pocs?source=<source>` |
| "N artifacts" count | → `/pocs` |

#### Affected product categories (tag cloud)
| Element | Click target |
|---------|-------------|
| Each category badge | → `/cves?category=<category>` |
| Section heading | → `/cves` |

### New dashboard sections to add

- **Watchlist matches** — show count of CVEs matching team watchlist, click → `/cves?watchlist=1`
- **Social heat** — CVEs with social mentions, click → `/cves?has_social=1`
- **Reputation leaders** — top 10 by reputation score, click → `/cves?sort=exploit`

---

## 2. CVE List — `/cves`

### Current filters (already work)
- Severity chip group: All / Critical / High / Medium / Low
- KEV toggle chip
- Sort: CVSS / EPSS / Exploitability / Newest
- Window: Last 24h / Last week / Last month / All time
- Pagination

### New filters to add

#### Filter bar additions
| Filter | Type | URL param |
|--------|------|-----------|
| Has PoC | toggle chip | `has_poc=1` |
| Has EPSS | toggle chip | `has_epss=1` |
| Has social mentions | toggle chip | `has_social=1` |
| EPSS range | dropdown | `epss_min=0.5` |
| CVSS range | dropdown | `cvss_min=9` |
| Attack tag | multi-select dropdown | `tag=rce&tag=privilege-escalation` |
| Product category | dropdown | `category=web-server` |
| Vendor | searchable dropdown | `vendor=nginx` |
| Watchlist match | toggle chip | `watchlist=1` |
| Source | dropdown | `source=nvd` |
| Has CWE | toggle chip | `has_cwe=1` |
| Reputation range | dropdown | `reputation_min=7` |

#### Sort additions
| Sort | URL param |
|------|-----------|
| By reputation | `sort=exploit` (already exists) |
| By social mentions | `sort=social` |
| By PoC count | `sort=poc_count` |
| By published date | `sort=date` (already exists) |

#### Quick filter chips (below the main filter bar)
- "Critical + PoC" → `/cves?severity=CRITICAL&has_poc=1`
- "KEV only" → `/cves?kev=1` (already exists)
- "EPSS ≥ 0.5" → `/cves?epss_min=0.5`
- "Weaponized" → `/cves?cvss_min=9&has_poc=1`
- "Social buzz" → `/cves?has_social=1&sort=social`
- "Watchlist hits" → `/cves?watchlist=1`

#### Table column additions
- Reputation score column (sortable)
- Social mentions count (sortable)
- PoC count (sortable)
- Source tags

---

## 3. CVE Detail — `/cve/<id>`

### Current sections
- Hero: CVSS, EPSS, Reputation gauges
- Badges: severity, KEV, IMMINENT, PoC count, attack tags
- CWE classification
- Affected products (vendor → product → versions → category)
- Exploits / PoC list
- Social posts / X mentions
- Related vulnerabilities

### New interactive elements

| Element | Click target |
|---------|-------------|
| Each attack tag badge | → `/cves?tag=<tag>` |
| Each CWE badge | → `/cves?cwe=<cwe_id>` |
| Each affected product category badge | → `/cves?category=<category>` |
| Each affected vendor name | → `/cves?vendor=<vendor>` |
| "N products across M vendors" count | → `/cves?vendor=<vendor>` |
| Each related CVE row | → `/cve/<id>` (already works) |
| Related CVE relation badge | → `/cves?tag=<shared_tag>` |
| Each social post author @handle | → `https://x.com/<handle>` (already works) |
| Each social post URL | → opens tweet (already works) |

### New sections to add

- **EPSS history** — sparkline showing EPSS score over time (requires new `epss_history` table)
- **CVSS vector breakdown** — parsed vector string showing AV/AC/PR/UI/S/C/I/A
- **Exploit chain feasibility** — if related CVEs exist, show combined risk
- **Detection links** — links to Nuclei templates, Sigma rules, YARA rules on GitHub

---

## 4. Triage Queue — `/triage`

### Current filters
- Lens: All actionable / KEV only / Imminent / Weaponized
- Dismissed: Hide / Show

### New filters to add

| Filter | Type | URL param |
|--------|------|-----------|
| Status | multi-select | `status=new&status=working` |
| Assigned to | dropdown | `assigned=<user_id>` |
| Unassigned | toggle chip | `unassigned=1` |
| Team | dropdown | `team=red` |
| Has note | toggle chip | `has_note=1` |
| Age | dropdown | `triage_age=7d` |

#### Quick filter chips
- "My queue" → `/triage?assigned=me`
- "Unassigned" → `/triage?unassigned=1`
- "Stale (>7d)" → `/triage?triage_age=7d`
- "Needs review" → `/triage?status=new`

#### Table additions
- Triage age column (days since status change)
- Team column
- Last updated timestamp

---

## 5. PoC List — `/pocs`

### Current filters
- Source filter
- Sort: Newest / Stars

### New filters to add

| Filter | Type | URL param |
|--------|------|-----------|
| Has CVE link | toggle chip | `linked=1` |
| Star range | dropdown | `stars_min=100` |
| Age range | dropdown | `age_max=30` |
| CVE severity | dropdown | `cve_severity=CRITICAL` |
| Source URL domain | dropdown | `domain=github.com` |

#### Quick filter chips
- "Linked to CVEs" → `/pocs?linked=1`
- "Popular (>100 stars)" → `/pocs?stars_min=100`
- "Fresh (<30d)" → `/pocs?age_max=30`
- "Critical CVEs" → `/pocs?cve_severity=CRITICAL`

---

## 6. Security Resources — `/resources`

### Current filters
- Type: poc / exploit / tool / technique / advisory / bypass / disclosure
- Source: x_twitter / github / gitlab / pastebin / web
- Sort: Newest / Engagement / Stars

### New filters to add

| Filter | Type | URL param |
|--------|------|-----------|
| Has CVE ref | toggle chip | `has_cve=1` |
| CVE ID search | text input | `cve=CVE-2026-0001` |
| Tag | multi-select | `tag=windows&tag=rce` |
| Engagement range | dropdown | `engagement_min=50` |
| Author | searchable dropdown | `author=<screen_name>` |

#### Quick filter chips
- "With CVE refs" → `/resources?has_cve=1`
- "High engagement" → `/resources?engagement_min=50`
- "PoCs only" → `/resources?type=poc`
- "Tools only" → `/resources?type=tool`

---

## 7. Watchlist — `/watchlist`

### Current functionality
- Add vendor/product pins
- View matching CVEs
- Delete pins

### New features

| Feature | Description |
|---------|-------------|
| Edit pin | Change product, note, team |
| Pin categories | Tag pins (e.g. "production", "critical-infra") |
| Match history | Show when each pin first matched, last matched |
| Bulk import | Paste list of vendors, bulk add |
| Export | Download watchlist as CSV/YAML |
| Pin priority | Mark pins as critical/high/medium/low |
| Notification per pin | Override global prefs for specific pins |

---

## 8. Search — `/search`

### Current behavior
- Text search across CVE ID and description
- Redirects to dashboard if empty

### New features

| Feature | Description |
|---------|-------------|
| Advanced search syntax | `cvss:>9 kev:true tag:rce` |
| Search history | Recent searches in session |
| Saved searches | Bookmark filter combinations |
| Search suggestions | Autocomplete CVE IDs, vendors, products |
| Full-text search | SQLite FTS5 across descriptions |

---

## 9. Global UI Features

### Filter state management
- **URL-driven filters** — all filters reflected in URL (already partially done)
- **Filter persistence** — remember last filter state per page in sessionStorage
- **Clear all filters** — one button to reset
- **Filter summary bar** — show active filters as removable chips
- **Share filter URL** — copy link to clipboard

### Keyboard shortcuts
| Key | Action |
|-----|--------|
| `/` | Focus search |
| `g` then `d` | Go to dashboard |
| `g` then `c` | Go to CVEs |
| `g` then `t` | Go to triage |
| `g` then `p` | Go to PoCs |
| `g` then `r` | Go to resources |
| `g` then `w` | Go to watchlist |
| `Esc` | Close modals, clear focus |
| `j` / `k` | Next / prev row in focused table |
| `Enter` | Open focused row |

### Table features
- **Column show/hide** — toggle columns per table
- **Column reorder** — drag to reorder
- **Sticky headers** — headers stay visible on scroll
- **Row selection** — checkbox select multiple rows for bulk actions
- **Bulk triage** — select multiple CVEs, set status/assignee
- **Export** — download current view as CSV/JSON
- **Column sorting** — click any column header to sort

### Visual features
- **Dark mode** — already default
- **Compact mode** — denser table rows
- **Severity color left border** — already exists on some tables
- **Relative timestamps** — "2d ago" instead of "2026-06-13"
- **Sparkline mini-charts** — EPSS trend, CVSS distribution
- **Empty states** — helpful messages when filters return nothing
- **Loading states** — skeleton loaders for slow queries

---

## 10. New Pages

### Vendor Exposure Dashboard — `/vendors`
- List all vendors with CVE counts, avg CVSS, avg EPSS
- Click vendor → `/cves?vendor=<vendor>`
- Sort by: CVE count, avg CVSS, avg EPSS, watchlist status
- Filter by: category, watchlist status

### Attack Surface Map — `/attack-surface`
- Visual matrix: attack tags × product categories
- Cell size = number of CVEs
- Click cell → `/cves?tag=<tag>&category=<category>`
- Filter by: severity, KEV, EPSS

### CVE Chains — `/chains`
- Group related CVEs (shared tags, products, temporal proximity)
- Show chain risk score (combined reputation)
- Click chain → filtered CVE list

### Reports — `/reports`
- List generated reports (already saved to `reports/`)
- Filter by: date range, format
- Download links

### Notifications — `/notifications`
- In-app notification feed (complement Telegram)
- Show last N events that matched user prefs
- Mark as read, dismiss
- Link to relevant CVE

---

## Implementation Priority

### Phase 1 — Clickable dashboard (highest impact)
1. Make all dashboard numbers/badges clickable with correct filter URLs
2. Add quick filter chips to CVE list page
3. Add attack tag, category, vendor filters to CVE list
4. Add has_poc, has_epss, has_social toggles to CVE list

### Phase 2 — Enhanced detail pages
5. Make CVE detail tags/categories/vendors clickable
6. Add triage filters (status, assigned, unassigned, stale)
7. Add PoC filters (linked, stars, age, severity)
8. Add resource filters (has_cve, engagement, author)

### Phase 3 — Table enhancements
9. Column sorting on all tables
10. Export to CSV
11. Relative timestamps
12. Filter state in URL + clear all button

### Phase 4 — New pages
13. Vendor exposure dashboard
14. Attack surface map
15. In-app notifications feed
16. Keyboard shortcuts
