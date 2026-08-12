"""PoC source — GitLab repository search.

Searches GitLab for new PoC/exploit repositories.
No authentication required for public API (500 req/hr rate limit).

GitLab search works best with single keywords — multi-word phrases
tend to return 0 results. We use targeted single-word queries.

Confidence scoring matches GitHub:
  - high:   >100 stars
  - medium: >10 stars
  - low:    otherwise
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from urllib.parse import quote as url_quote

from horus.config import MAX_REPO_AGE_DAYS, MIN_REPO_STARS
from horus.core.filters import extract_cves, is_fresh_poc
from horus.net.http import fetch_json

NAME = "GitLab PoC Repos"
DEFAULT_ENABLED = True
KIND = "poc"

# Single-keyword queries — GitLab search handles these well.
# Multi-word phrases (e.g. "CVE-2026 exploit poc") return 0 results.
SEARCH_TERMS = [
    "CVE-2026",
    "CVE-2025",
    "exploit",
    "poc",
    "0day",
    "rce",
    "vulnerability",
    "CVE",
]


def _confidence_for_stars(stars: int | None) -> str:
    if stars is None:
        return "low"
    if stars > 100:
        return "high"
    if stars > 10:
        return "medium"
    return "low"


def run(ctx) -> dict:
    """Search GitLab for new PoC repos. Returns {"cves": [], "pocs": [dict]}."""
    results = []
    base = "https://gitlab.com/api/v4/projects"

    for term in SEARCH_TERMS:
        params = f"?search={url_quote(term)}&order_by=created_at&sort=desc&per_page=15"
        try:
            data = fetch_json(f"{base}{params}")
        except Exception as e:
            print(f"  [WARN] GitLab search failed for '{term}': {e}", file=sys.stderr)
            continue

        for item in data:
            if not isinstance(item, dict):
                continue

            web_url = item.get("web_url", "")
            name = item.get("name") or item.get("path") or ""
            description = item.get("description") or ""
            created_at = item.get("created_at", "")
            stars = item.get("star_count", 0)
            namespace = item.get("namespace", {})
            full_path = namespace.get("full_path", "") if isinstance(namespace, dict) else ""
            repo_slug = f"{full_path}/{name}" if full_path else name

            if not web_url or web_url in ctx.known_poc_urls:
                continue

            try:
                created = datetime.strptime(created_at, "%Y-%m-%dT%H:%M:%S.%fZ")
                age_days = (datetime.now(timezone.utc).replace(tzinfo=None) - created).days
            except (ValueError, TypeError):
                try:
                    created = datetime.strptime(created_at, "%Y-%m-%dT%H:%M:%SZ")
                    age_days = (datetime.now(timezone.utc).replace(tzinfo=None) - created).days
                except (ValueError, TypeError):
                    age_days = None

            if age_days is not None and age_days > MAX_REPO_AGE_DAYS:
                continue
            if stars < MIN_REPO_STARS:
                continue

            combined = f"{repo_slug} {description}"
            if not is_fresh_poc(combined):
                continue

            ctx.known_poc_urls.add(web_url)
            results.append(
                {
                    "source": "gitlab",
                    "repo": repo_slug,
                    "url": web_url,
                    "description": description[:300],
                    "cves": extract_cves(combined),
                    "stars": stars,
                    "created": created_at[:10] if created_at else "",
                    "age_days": age_days,
                    "confidence": _confidence_for_stars(stars),
                }
            )

    results.sort(key=lambda x: x.get("stars", 0), reverse=True)
    if ctx.max_results is not None:
        results = results[: ctx.max_results]

    from horus.core.merge import poc_from_gitlab

    pocs = [poc_from_gitlab(r) for r in results]
    return {"cves": [], "pocs": pocs}
