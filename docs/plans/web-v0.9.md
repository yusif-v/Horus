# Horus Web v0.9 — Dashboard Filters & News Feed

*Planned for v0.9.x*
*Date: 2026-06-11*

---

## Feature 1: Clickable Tag Filters on Dashboard

### Problem
The "Attack surface" section on the dashboard shows tag counts (XSS · 152, BUFFER-OVERFLOW · 120, etc.) but they're not clickable. Users have to navigate to a separate page or use search to find CVEs by tag.

### Solution
Make every tag in the "Attack surface" section clickable. Clicking a tag navigates to a filtered CVE list showing only CVEs with that attack tag.

### Implementation

#### 1. New route: `/cves?tag=<tag_name>`
Add a `tag` query parameter to the existing CVE list route (`/cves`).

**File:** `horus/web/routes/cves.py`
```python
@bp.route("/cves")
def cves():
    page = safe_int(request.args.get("page", "1"))
    tag_filter = request.args.get("tag")          # NEW
    source_filter = request.args.get("source")    # existing
    sort = request.args.get("sort", "cvss")       # existing

    # Build WHERE clause dynamically
    where_clauses = []
    params = []

    if tag_filter:
        where_clauses.append(
            "c.id IN (SELECT cve_id FROM cve_attack_tag WHERE tag = ?)"
        )
        params.append(tag_filter)

    if source_filter:
        where_clauses.append(
            "c.id IN (SELECT cve_id FROM poc_cve WHERE poc_url IN "
            "(SELECT url FROM poc WHERE source = ?))"
        )
        params.append(source_filter)

    where = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""

    # ... existing query logic with dynamic where clause
```

#### 2. New route: `/cves?category=<category_name>`
Same pattern but for product categories (web-server, database, kernel, etc.).

```python
if category_filter:
    where_clauses.append(
        "c.id IN (SELECT cve_id FROM cve_product WHERE product_id IN "
        "(SELECT id FROM product WHERE category = ?))"
    )
    params.append(category_filter)
```

#### 3. New route: `/cves?severity=<severity>`
Filter by CVSS severity (Critical, High, Medium, Low).

```python
if severity_filter:
    where_clauses.append("c.cvss_severity = ?")
    params.append(severity_filter)
```

#### 4. Dashboard template updates
**File:** `horus/web/templates/dashboard.html`

Change the tag cloud section from static badges to clickable links:

```html
<!-- BEFORE (static) -->
<span class="badge badge-tag {% if tag.cnt > max_tag * 0.6 %}large{% endif %}">
    {{ tag.tag }} · {{ tag.cnt }}
</span>

<!-- AFTER (clickable) -->
<a href="/cves?tag={{ tag.tag }}"
   class="badge badge-tag {% if tag.cnt > max_tag * 0.6 %}large{% endif %}"
   title="Show all {{ tag.tag }} CVEs">
    {{ tag.tag }} · {{ tag.cnt }}
</a>
```

Same for the "Affected product categories" section:

```html
<!-- BEFORE -->
<span class="badge badge-tag {% if cat.cnt > 50 %}large{% endif %}">
    {{ cat.category }} · {{ cat.cnt }}
</span>

<!-- AFTER -->
<a href="/cves?category={{ cat.category }}"
   class="badge badge-tag {% if cat.cnt > 50 %}large{% endif %}"
   title="Show all {{ cat.category }} CVEs">
    {{ cat.category }} · {{ cat.cnt }}
</a>
```

#### 5. Filter chips on the CVE list page
When a filter is active, show a removable chip at the top of the list:

```html
{% if tag_filter %}
<div class="filter-chip">
    Tag: {{ tag_filter }}
    <a href="/cves" class="remove" title="Clear filter">×</a>
</div>
{% endif %}
```

#### 6. Combined filters
Filters should be combinable: `/cves?tag=rce&severity=Critical&sort=epss`

The URL should preserve all active filters when navigating pages:
```
/cves?tag=rce&severity=Critical&page=2
```

### Files to modify:
| File | Change |
|------|--------|
| `horus/web/routes/cves.py` | Add `tag`, `category`, `severity` query params to existing route |
| `horus/web/templates/dashboard.html` | Make tags and categories clickable links |
| `horus/web/templates/list.html` | Add filter chips, preserve filters in pagination |
| `horus/web/static/horus.css` | Add `.filter-chip` styles, `.badge-tag:hover` styles |
| `horus/web/queries.py` | Add `fetch_cves_by_tag()`, `fetch_cves_by_category()` |

### API endpoint (for future AJAX):
```
GET /api/cves?tag=rce&severity=Critical&page=1&per_page=20
→ { "cves": [...], "total": 152, "page": 1, "filters": {"tag": "rce", "severity": "Critical"} }
```

---

## Feature 2: News Feed on Dashboard

### Problem
The dashboard shows CVE data but no contextual news. Security analysts need to know *why* a CVE matters — is it being exploited in the wild? Is there a new PoC? Did a vendor release an advisory?

### Solution
Add a "Latest intelligence" section to the dashboard showing recent news items from X/Twitter and other sources. Each news item links to the related CVE(s).

### Data Model

#### New table: `news_item`
```sql
CREATE TABLE IF NOT EXISTS news_item (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT UNIQUE NOT NULL,
    title TEXT,
    source TEXT NOT NULL,           -- 'x_twitter', 'rss', 'vendor_advisory', 'github'
    summary TEXT,                   -- extracted or generated summary
    published_at TEXT,              -- ISO 8601
    first_seen TEXT DEFAULT (datetime('now')),
    cve_refs TEXT,                  -- JSON array of CVE IDs mentioned
    source_name TEXT,               -- e.g., '@username' for X, 'Reuters' for RSS
    urgency TEXT DEFAULT 'normal',  -- 'critical', 'high', 'normal', 'low'
    is_duplicate INTEGER DEFAULT 0  -- 1 if deduplicated
);

CREATE INDEX IF NOT EXISTS idx_news_published ON news_item(published_at DESC);
CREATE INDEX IF NOT EXISTS idx_news_source ON news_item(source);
CREATE INDEX IF NOT EXISTS idx_news_urgency ON news_item(urgency);
```

### Sources

#### 1. X/Twitter (existing data)
The `cve_social_post` table already stores tweets mentioning CVEs. The news feed can surface the most relevant ones:
- Tweets with high engagement (likes + retweets)
- Tweets classified as "in-the-wild" or "weaponized" (from urgency scoring)
- Tweets from known security researchers

**Query:**
```sql
SELECT cs.url, cs.screen_name, cs.likes, cs.retweets, cs.replies,
       cs.views, cs.first_seen, c.id as cve_id, c.cvss_score
FROM cve_social_post cs
JOIN cve c ON c.id = cs.cve_id
WHERE cs.first_seen >= datetime('now', '-7 days')
ORDER BY (COALESCE(cs.likes, 0) + COALESCE(cs.retweets, 0) * 3) DESC
LIMIT 20
```

#### 2. RSS Feeds (new source)
Monitor security news RSS feeds:
- Reuters Technology News
- BleepingComputer
- The Hacker News
- SecurityWeek
- CISA Alerts
- US-CERT Alerts

**New file:** `horus/sources/rss_news.py`
```python
RSS_FEEDS = [
    {"url": "https://www.bleepcomputer.com/feed/", "name": "BleepingComputer"},
    {"url": "https://thehackernews.com/feeds/posts/default", "name": "The Hacker News"},
    {"url": "https://www.securityweek.com/feed/", "name": "SecurityWeek"},
    {"url": "https://www.cisa.gov/cybersecurity-advisories.xml", "name": "CISA"},
]

def run(ctx) -> dict:
    """Fetch RSS feeds, extract news items, deduplicate."""
    items = []
    for feed in RSS_FEEDS:
        try:
            parsed = feedparser.parse(feed["url"])
            for entry in parsed.entries[:10]:
                # Extract CVE references from title + summary
                cve_ids = extract_cve_refs(entry.title + " " + entry.get("summary", ""))
                items.append({
                    "url": entry.link,
                    "title": entry.title,
                    "source": "rss",
                    "source_name": feed["name"],
                    "summary": entry.get("summary", "")[:300],
                    "published_at": entry.get("published", ""),
                    "cve_refs": cve_ids,
                })
        except Exception:
            continue
    return {"news_items": items}
```

#### 3. Vendor Advisories (new source)
Monitor vendor security advisory RSS feeds:
- Apache Security
- nginx Security Advisories
- Microsoft MSRC
- Oracle CPU
- Cisco PSIRT

**New file:** `horus/sources/vendor_advisory.py`

#### 4. GitHub Releases (new source)
Monitor security-related GitHub releases:
- `rapid7/metasploit-framework` (new exploit modules)
- `nmap/nmap` (new NSE scripts)
- Known security tool repos

### Deduplication Strategy

News items are deduplicated by:
1. **URL exact match** — same URL from different sources
2. **Title similarity** — TF-IDF cosine similarity > 0.85
3. **CVE overlap** — same set of CVE IDs + published within 1 hour

```python
def is_duplicate(conn, title, url, cve_refs) -> bool:
    # URL match
    if conn.execute("SELECT 1 FROM news_item WHERE url = ?", (url,)).fetchone():
        return True

    # Title similarity (simple approach: normalized title match)
    normalized = normalize_title(title)
    existing = conn.execute(
        "SELECT title FROM news_item WHERE first_seen >= datetime('now', '-7 days')"
    ).fetchall()
    for row in existing:
        if title_similarity(normalized, normalize_title(row[0])) > 0.85:
            return True

    return False
```

### Dashboard Integration

#### New section in dashboard.html
```html
{% if news_items %}
<div class="section">
  <div class="section-head">
    <h2>Latest <em>intelligence</em></h2>
    <span class="count">{{ news_items|length }} items · 7d</span>
    <div class="actions"><a href="/news">View all →</a></div>
  </div>
  <div class="panel">
    <div class="panel-body">
      <div class="news-feed">
      {% for item in news_items %}
        <div class="news-item urgency-{{ item.urgency }}">
          <div class="news-meta">
            <span class="badge badge-source">{{ item.source_name }}</span>
            <span class="news-time">{{ item.published_at[:10] if item.published_at else '—' }}</span>
            {% if item.urgency == 'critical' %}
              <span class="badge badge-critical">CRITICAL</span>
            {% elif item.urgency == 'high' %}
              <span class="badge badge-high">HIGH</span>
            {% endif %}
          </div>
          <div class="news-title">
            <a href="{{ item.url }}" target="_blank">{{ item.title }}</a>
          </div>
          {% if item.summary %}
          <div class="news-summary">{{ item.summary[:200] }}</div>
          {% endif %}
          {% if item.cve_refs %}
          <div class="news-cves">
            {% for cve in item.cve_refs[:5] %}
              <a href="/cve/{{ cve }}" class="badge badge-cve">{{ cve }}</a>
            {% endfor %}
            {% if item.cve_refs|length > 5 %}
              <span class="badge badge-more">+{{ item.cve_refs|length - 5 }}</span>
            {% endif %}
          </div>
          {% endif %}
        </div>
      {% endfor %}
      </div>
    </div>
  </div>
</div>
{% endif %}
```

#### Urgency Classification
News items are classified by urgency:
- **Critical:** Contains keywords like "actively exploited", "in the wild", "wormable", "zero-day"
- **High:** Contains "PoC released", "Metasploit module", "KEV added"
- **Normal:** Security advisories, analysis writeups
- **Low:** General security news, non-technical

### New Route: `/news`
Full news feed page with filtering:
- `/news` — all news, last 7 days
- `/news?source=x_twitter` — X/Twitter only
- `/news?urgency=critical` — critical only
- `/news?cve=CVE-2026-XXXX` — news mentioning specific CVE

### API Endpoint:
```
GET /api/news?limit=20&source=x_twitter&urgency=critical
→ { "items": [...], "total": 45 }
```

### Files to create/modify:
| File | Change |
|------|--------|
| `horus/storage/schema.sql` | Add `news_item` table |
| `horus/sources/rss_news.py` | NEW — RSS feed source |
| `horus/sources/vendor_advisory.py` | NEW — vendor advisory source |
| `horus/web/routes/news.py` | NEW — `/news` route |
| `horus/web/routes/cves.py` | Add `tag`, `category`, `severency` filters |
| `horus/web/routes/dashboard.py` | Add news items to stats query |
| `horus/web/queries.py` | Add `get_news()`, `get_cves_by_tag()`, `get_cves_by_category()` |
| `horus/web/templates/dashboard.html` | Make tags clickable, add news section |
| `horus/web/templates/list.html` | Add filter chips, preserve filters |
| `horus/web/templates/news.html` | NEW — full news feed page |
| `horus/web/static/horus.css` | Add news feed styles, filter chip styles, hover states |

### Server Mode Integration
In server mode, news sources run on their own intervals:
- X/Twitter: every 30 min (existing)
- RSS feeds: every 15 min
- Vendor advisories: every hour
- GitHub releases: every 2 hours

### Deduplication Rules
1. Same URL → skip
2. Title similarity > 0.85 → skip
3. Same CVE refs + within 1 hour → merge (keep the one with more detail)
4. Retweets of same content → skip (check for "RT @" prefix)

---

## Combined Filter + News UX

The two features work together:

1. User sees "XSS · 152" on dashboard → clicks it
2. Goes to `/cves?tag=xss` — sees all XSS CVEs
3. Sees news items at top: "New XSS PoC released for Chrome" → clicks
4. Goes to `/cve/CVE-2026-XXXX` — sees full CVE detail with linked PoCs
5. Clicks PoC link → goes to GitHub repo

This creates a **discovery loop**: dashboard → filter → news → CVE → PoC → action.

---

## Future Enhancements (v1.0)

### Real-time Updates via WebSocket
- Dashboard auto-updates when new CVEs arrive
- News feed pushes new items without refresh
- Filter counts update live

### Personalized News Feed
- User configures watched vendors/categories
- News feed prioritizes items matching watchlist
- "Your vendors" section shows only relevant news

### News → CVE Auto-Linking
- When a news item mentions a CVE, auto-link it in the database
- Creates `news_cve_link` table for many-to-many relationship
- Enables "show all news for CVE-2026-XXXX" on CVE detail page

### Threat Level Indicator
- Overall "threat level" based on recent news volume and urgency
- Green/Yellow/Orange/Red indicator on dashboard
- Based on: # of critical news items in 24h, KEV additions, EPSS spikes
