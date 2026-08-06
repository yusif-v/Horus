# EPSS Trend Tracking Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task.

**Goal:** Add EPSS trend visualization (CVE-level + global dashboard) using existing epss_history data.

**Architecture:** Query functions in `horus/web/queries.py` read `epss_history` table, compute velocity/trend. Two API endpoints. CVE dossier gets Chart.js sparkline panel. New global dashboard page at `/epss-trends`.

**Tech Stack:** Python 3.10+, SQLite, Flask, Chart.js (already loaded)

## Global Constraints

- Python 3.10+ compatibility
- Follow existing Horus patterns: ruff, mypy, TDD
- No schema changes (uses existing `epss_history` table)
- Test coverage gate: 70%

---

### Task 1: Query functions

**Files:**
- Modify: `horus/web/queries.py`
- Test: `tests/web/test_queries_epss.py`

- [ ] **Step 1: Write failing tests**

Test `epss_trend()`, `epss_movers()`, `epss_threshold_alerts()` with in-memory DB.

- [ ] **Step 2: Implement query functions**

```python
def epss_trend(cve_id: str) -> dict:
    """Get EPSS history + computed trend for a CVE."""
    # Query epss_history for last 30 days
    # Compute velocity from last 2 points
    # Determine trend: rising (>0.005), falling (<-0.005), stable
    # Count days above 0.50 threshold
    # Return {cve_id, current_score, velocity, trend, days_above_50pct, history}

def epss_movers(days: int = 7, limit: int = 20) -> list[dict]:
    """Top EPSS velocity changes in last N days."""
    # For each CVE with history in period, compute velocity
    # Sort by absolute velocity DESC
    # Return [{cve_id, current_score, previous_score, velocity, trend, cvss_score, kev}]

def epss_threshold_alerts(days: int = 7) -> list[dict]:
    """CVEs that crossed 50% EPSS in last N days."""
    # Find CVEs where score was < 0.50 before and >= 0.50 after
    # Return [{cve_id, crossed_at, direction}]
```

- [ ] **Step 3: Run tests and commit**

Commit: `feat(queries): add EPSS trend query functions`

---

### Task 2: API endpoints

**Files:**
- Modify: `horus/web/routes/api.py`
- Test: `tests/web/test_api_epss.py`

- [ ] **Step 1: Add `GET /api/cve/<id>/epss-trend`**

Returns `epss_trend()` data as JSON.

- [ ] **Step 2: Add `GET /api/epss-trends`**

Returns movers + threshold alerts as JSON.

- [ ] **Step 3: Write and run tests**

Commit: `feat(api): add EPSS trend endpoints`

---

### Task 3: CVE dossier panel

**Files:**
- Modify: `horus/web/routes/cves.py`
- Modify: `horus/web/templates/cve_detail.html`

- [ ] **Step 1: Add EPSS trend data to CVE detail route**

Pass `epss_trend(cve_id)` result to template.

- [ ] **Step 2: Add "EPSS Trend" panel to template**

Chart.js line chart + velocity badge + days-above-threshold counter.

- [ ] **Step 3: Write and run tests**

Commit: `feat(ui): add EPSS trend panel to CVE page`

---

### Task 4: Global dashboard page

**Files:**
- Create: `horus/web/routes/epss_trends.py`
- Create: `horus/web/templates/epss_trends.html`
- Test: `tests/web/test_epss_trends_page.py`

- [ ] **Step 1: Create route**

`GET /epss-trends` → renders dashboard with movers table + alerts.

- [ ] **Step 2: Create template**

Top movers table + threshold alerts + summary stats.

- [ ] **Step 3: Register blueprint in web app**

- [ ] **Step 4: Add nav link**

Add "EPSS Trends" to main navigation.

- [ ] **Step 5: Write and run tests**

Commit: `feat(ui): add EPSS trends dashboard page`

---

### Task 5: Full verification

**Files:** None new

- [ ] **Step 1: Run full suite** → ≥ 70% coverage
- [ ] **Step 2: Lint + typecheck**
- [ ] **Step 3: Commit fixes if needed**
