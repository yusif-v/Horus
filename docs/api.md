# Horus JSON API Reference

Stable endpoints for external consumers and health monitoring.

## Authentication

All endpoints except `/api/health` require authentication via session cookie. Session is
established through `/login` (POST with username/password). Successful APIs return 401
for unauthenticated requests.

## Endpoints

### GET `/api/health`

Public health check endpoint (no auth required).

**Response shape:**

```json
{
  "status": "ok" | "degraded",
  "db": true,
  "sources": {
    "source_name": {
      "status": "ok" | "error" | "skipped",
      "last_run": "2026-06-30T08:41:22Z" | null,
      "consecutive_failures": 0
    },
    ...
  }
}
```

- `status`: `ok` if all enabled sources succeeded; `degraded` if any enabled source has
  `consecutive_failures >= 3`.
- `db`: `true` if database is accessible; `false` with 503 status if not.
- `sources`: Per-source health snapshot from the `source_health` table.

**Example:**

```json
{
  "status": "ok",
  "db": true,
  "sources": {
    "nvd": {"status": "ok", "last_run": "2026-06-30T08:41:22Z", "consecutive_failures": 0},
    "github": {"status": "ok", "last_run": "2026-06-30T08:41:00Z", "consecutive_failures": 0},
    "news": {"status": "skipped", "last_run": null, "consecutive_failures": 0}
  }
}
```

---

### GET `/api/stats`

Dashboard statistics and counts. Requires read role.

**Query parameters:**

| Param | Type | Description |
|-------|------|-------------|
| `year` | int | Filter CVEs by publication year (e.g., `?year=2026`) |

**Response shape:**

```json
{
  "cve_count": 1250,
  "poc_count": 420,
  "kev_count": 23,
  "with_epss": 890,
  "linked_pocs": 156,
  "cves_with_pocs": 78,
  "avg_epss": 0.12,
  "avg_reputation": 6.2,
  "social_heat": 12,
  "social_mentions_total": 45,
  "watchlist_count": 3,
  "severity_breakdown": [{"cvss_severity": "HIGH", "cnt": 15}, ...],
  "epss_buckets": [{"bucket": "Medium (0.01-0.1)", "cnt": 45}, ...],
  "sources": [{"source": "github", "cnt": 200}, ...],
  "categories": [{"category": "operating-system", "cnt": 120}, ...],
  "top_tags": [{"tag": "rce", "cnt": 15}, ...],
  "recent_cves": [{"id": "CVE-2026-1234", "cvss_score": 9.8, ...}, ...],
  "high_trust_count": 45,
  "threatfox_hits": 12,
  "stealer_compromised_count": 3
}
```

---

### GET `/api/cves`

List CVEs with pagination. Requires read role.

**Query parameters:**

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `year` | int | — | Filter by publication year |
| `page` | int | 1 | Page number |
| `per_page` | int | 20 | Items per page (1-100) |

**Response shape:**

```json
{
  "results": [
    {"id": "CVE-2026-1234", "cvss_score": 9.8, "cvss_severity": "CRITICAL", ...},
    ...
  ],
  "total": 1250,
  "page": 1,
  "per_page": 20
}
```

---

### GET `/api/cve/<cve_id>`

Detailed view for a single CVE. Requires read role.

**Response shape:**

```json
{
  "cve": {
    "id": "CVE-2026-1234",
    "description": "SQL injection in example app",
    "cvss_score": 9.8,
    "cvss_severity": "CRITICAL",
    "epss_score": 0.75,
    "kev": 1,
    "kev_due_date": "2026-07-15",
    "published_at": "2026-01-05T00:00:00Z",
    "trust_score": 85.0,
    "threatfox_ioc_count": 5,
    "stealer_hits": 0,
    ...
  },
  "tags": ["sqli"],
  "cwes": ["CWE-89"],
  "products": [{"vendor": "example", "product": "app", ...}],
  "sources": ["nvd"],
  "linked_pocs": [{"url": "...", "source": "github", ...}],
  "social_posts": [...],
  "related_cves": [...]
}
```

**Status codes:**

- `200` on success
- `404` if CVE not found
- `401` if not authenticated
- `500` on server error
