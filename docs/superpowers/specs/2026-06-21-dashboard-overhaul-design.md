# Dashboard Overhaul — Design Spec

> **Date:** 2026-06-21
> **Goal:** Redesign the Horus dashboard to match CVE-Intel's superior UX while keeping Horus's unique features (reputation scoring, multi-source, watchlist, RBAC).

---

## 1. Problems with Current Dashboard

1. **KPI cards show "0"** — The 4 posture cells (Actionable, Weaponized, Imminent, PoCs linked) show 0 because `actionable`, `weaponized`, `imminent`, `linked_pocs`, `cves_with_pocs` are computed from the full DB but the stats query doesn't filter by time window. With only 83 CVEs from the last week and no KEV/EPSS enrichment yet, these are legitimately 0 — but it looks broken.

2. **Redundant sections** — Severity mix (bar chart) repeats what the donut chart already shows. EPSS buckets (bar chart) repeats what the EPSS donut shows. Publication tempo is a tiny bar chart that could be part of the trend line.

3. **No live activity feed** — CVE-Intel has a "Live Cyber News" feed on the dashboard. Horus has news but it's on a separate page.

4. **No search on dashboard** — CVE-Intel has a prominent search bar. Horus has it in the nav but not dashboard-centric.

5. **Tables are too long** — "Recent ingest" shows 10 rows, pushing everything else down. CVE-Intel shows 5 with a "View all" link.

6. **No year selector** — CVE-Intel has a year timeline sidebar. Horus has no way to filter dashboard by year.

7. **No NVD detail panel** — CVE-Intel has a slide-out panel showing CVSS vector, CWE, EPSS, description when you click a CVE. Horus requires navigating to a separate page.

8. **Chart.js charts are basic** — The current charts are functional but not as polished as CVE-Intel's (no gradients, no animations, no interactivity).

---

## 2. Target Layout (Top to Bottom)

### 2.1 Hero Section (keep, enhance)
- **4 KPI cards** — but fix the data: show counts for the selected time window (default: last 7 days), not all-time. Add a time window selector (24h / 7d / 30d / all).
- **Search bar** — prominent, centered, with placeholder "Search CVEs, repos, keywords..."
- **Year selector** — horizontal pill buttons (2026, 2025, 2024, ...) above the KPI cards

### 2.2 Charts Section (redesign)
- **Left: Severity donut** — keep, add click-to-filter
- **Right: Publication trend line** — keep, add gradient fill
- **Remove** the redundant severity mix bar chart and EPSS bar chart (they duplicate the donut charts)

### 2.3 Live Activity Feed (new)
- **Right sidebar or bottom section** — Live cyber news feed with tier badges (Tier 4 = red/pulsing, Tier 3 = blue, etc.)
- Show 5 most recent articles with source, time ago, tier badge
- "View all →" link to /news

### 2.4 CVE Table (redesign)
- **Compact table** — 5 rows (not 10), with "View all →" link
- **Columns**: CVE ID | Type (RCE/LPE/DoS badge) | CVSS | EPSS | KEV | Published | Stars
- **Clickable rows** — click opens a slide-out detail panel (like CVE-Intel's right panel)
- **Detail panel shows**: CVSS score + vector, CWE links, EPSS bar, description, linked PoCs, "View full →" link

### 2.5 Filters (new)
- **Dropdown filters** above the table: Severity | KEV | EPSS band | Type | Clear
- Same as CVE-Intel's filter row

### 2.6 Bottom Stats (keep, compact)
- **3 columns**: Attack surface tags | Publication tempo | PoC sources
- Compact, no redundant charts

---

## 3. Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| KPI cards show time-windowed stats | Fix the "0" problem — show counts for selected window, not all-time |
| Remove duplicate bar charts | Donut charts already show severity/EPSS distribution |
| Add live news feed | CVE-Intel's dashboard feels alive; Horus news is buried on a separate page |
| Slide-out detail panel | Avoid page navigation for quick CVE inspection |
| 5-row table with "View all" | Less scrolling, faster page load |
| Year selector | CVE-Intel's most-used feature — jump between years instantly |
| Keep Horus-unique features | Reputation score, watchlist, RBAC, Telegram — these are Horus advantages |

---

## 4. Files to Modify

1. `horus/storage/db.py` — Add `cvss_vector TEXT` column to `cve` table via migration
2. `horus/sources/nvd.py` — Extract and store CVSS vector from NVD API response
3. `horus/web/templates/dashboard.html` — Complete rewrite of the dashboard template
4. `horus/web/static/horus.css` — New styles for slide-out panel, year selector, compact table
5. `horus/web/static/dashboard-charts.js` — Enhanced charts with gradients, animations, click-to-filter
6. `horus/web/queries.py` — Add `get_stats(window='7d')` time-windowed stats, make `recent_cves` limit configurable, add `get_cve_exploit_types()` helper
7. `horus/web/routes/dashboard.py` — Add window/year parameters
8. `horus/web/templates/cve_detail.html` — Add slide-out panel markup

## 5. Data Model Changes

### New column: `cve.cvss_vector`
- Type: TEXT
- Source: NVD API `metrics.cvssMetricV31[0].cvssData.vectorString`
- Migration: Add via `_migrate_columns()` pattern
- Used in: slide-out detail panel, CVE detail page

### Time-window filtering in `get_stats()`
- Add `window` parameter: `'24h'`, `'7d'`, `'30d'`, `'all'` (default)
- SQL: `published_at >= date('now', '-7 days')`
- Composable with existing `year` parameter
- Affects all KPI counts and breakdowns

### CVE table "Type" column
- `exploit_type` is on PoC, not CVE. A CVE can have multiple PoCs with different types.
- Solution: Show the most frequent exploit_type among linked PoCs
- New query: `get_cve_exploit_types(cve_id)` → returns list of types
- Display: Show the most common type as a badge, or "Multi" if >1 type

---

## 5. Success Criteria

1. KPI cards show non-zero counts for the selected time window
2. Dashboard has year selector (2026, 2025, 2024, ...)
3. Live news feed visible on dashboard with tier badges
4. CVE table is compact (5 rows) with "View all" link
5. Clicking a CVE row opens a slide-out detail panel with CVSS, CWE, EPSS, description, PoCs
6. Filter dropdowns work (Severity, KEV, EPSS band, Type)
7. Charts have gradients and smooth animations
8. No redundant sections (remove duplicate bar charts)
9. All existing tests pass
10. `ruff check` and `ruff format` clean
