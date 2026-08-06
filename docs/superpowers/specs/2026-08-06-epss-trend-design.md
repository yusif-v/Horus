# EPSS Trend Tracking — Design Spec

*Created 2026-08-06, for Horus v0.14.x*

## Purpose

Track EPSS (Exploit Prediction Scoring System) score changes over time, surface velocity/trends, and alert on threshold crossings. Analysts can see which CVEs are rapidly becoming more exploitable.

## Current State

- `epss_history` table exists with `cve_id, score, recorded_at` (one row per CVE per day)
- `append_epss_history()` records daily scores during pipeline backfill
- `epss_velocity()` in `core/forecast.py` computes Δscore/day between two most recent points
- `imminence_score` and `imminence_bucket` already stored on each CVE

**Gap:** No UI or API to view trends. No threshold alerts. No global movers view.

## Components

### 1. CVE-Level EPSS Trend

**API:** `GET /api/cve/<id>/epss-trend`
- Returns: current score, velocity, trend direction, days-above-threshold, history (last 30 days)

**CVE Dossier Panel:** "EPSS Trend" section
- Current score badge + velocity (▲/▼/→)
- Days above 50% threshold
- Chart.js line chart (30-day history)

### 2. Global Movers Dashboard

**Page:** `/epss-trends`
**API:** `GET /api/epss-trends?days=7&limit=20`

- Top movers table (sorted by absolute velocity)
- Threshold alerts (CVEs crossing 50% EPSS in last N days)
- Summary stats (rising/falling/stable counts)

### 3. Data Layer

**Functions in `horus/web/queries.py`:**
```python
def epss_trend(cve_id: str) -> dict:
    """EPSS history + velocity + days-above-threshold for one CVE."""

def epss_movers(days: int = 7, limit: int = 20) -> list[dict]:
    """Top EPSS velocity changes in last N days."""

def epss_threshold_alerts(days: int = 7) -> list[dict]:
    """CVEs that crossed 50% EPSS threshold in last N days."""
```

## Data Flow

```
Pipeline (existing):
  EPSS enricher → score CVEs → append_epss_history()

API request → queries.py → epss_history table → compute velocity/trend

Velocity formula (existing):
  (score_new - score_old) / days_between

Trend direction:
  velocity > 0.005 → rising
  velocity < -0.005 → falling
  otherwise → stable

Days above threshold:
  COUNT(history rows WHERE score >= 0.50)
```

## UI

- Chart.js line chart on CVE dossier (already loaded on other pages)
- New nav link "EPSS Trends" → global dashboard page
- Top movers table with CVE link, CVSS, KEV badge, velocity arrow
- Threshold alerts section with date crossed

## Error Handling

| Scenario | Behavior |
|----------|----------|
| No EPSS history for CVE | Return empty history, velocity 0, trend "stable" |
| Only one history point | Velocity 0 (insufficient data) |
| CVE not found | 404 |

## Testing

- Unit tests for `epss_trend()`, `epss_movers()`, `epss_threshold_alerts()`
- API endpoint tests (success, empty, 404)
- Page render tests

## Migration

No schema changes needed. Uses existing `epss_history` table.
