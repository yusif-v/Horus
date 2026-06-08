"""PoC source — GitHub repository search.

Searches GitHub for new PoC/exploit repositories.
"""

from __future__ import annotations
import sys
import urllib.parse
from datetime import datetime

from ..config import GITHUB_QUERIES, MAX_REPO_AGE_DAYS, MIN_REPO_STARS
from ..core.filters import extract_cves, is_fresh_poc
from .auth import github_token
from .http import fetch_json


NAME = "GitHub PoC Repos"
DEFAULT_ENABLED = True


def run(
    known_cve_ids: set[str],
    known_poc_urls: set[str],
    args,
    **kwargs,
) -> dict:
    """Search GitHub for new PoC repos. Returns {"cves": [], "pocs": [dict]}."""
    results = []
    token = github_token()
    auth_headers = {"Authorization": f"Bearer {token}"} if token else None

    for query in GITHUB_QUERIES:
        encoded = urllib.parse.quote(query)
        search_url = (
            f"https://api.github.com/search/repositories"
            f"?q={encoded}&sort=created&order=desc&per_page=15"
        )

        try:
            data = fetch_json(search_url, accept="application/vnd.github.v3+json", headers=auth_headers)
        except Exception as e:
            print(f"  [WARN] GitHub search failed for '{query}': {e}", file=sys.stderr)
            continue

        for item in data.get("items", []):
            html_url = item.get("html_url", "")
            description = item.get("description") or ""
            created_at = item.get("created_at", "")
            stars = item.get("stargazers_count", 0)

            if not html_url or html_url in known_poc_urls:
                continue

            try:
                created = datetime.strptime(created_at, "%Y-%m-%dT%H:%M:%SZ")
                age_days = (datetime.utcnow() - created).days
            except ValueError:
                age_days = None

            if age_days is not None and age_days > MAX_REPO_AGE_DAYS:
                continue
            if stars < MIN_REPO_STARS:
                continue

            combined = f'{item.get("full_name", "")} {description}'
            if not is_fresh_poc(combined):
                continue

            known_poc_urls.add(html_url)
            results.append({
                "source": "GitHub",
                "repo": item.get("full_name", ""),
                "url": html_url,
                "description": description[:300],
                "cves": extract_cves(combined),
                "stars": stars,
                "created": created_at[:10] if created_at else "",
                "age_days": age_days,
            })

    results.sort(key=lambda x: x.get("stars", 0), reverse=True)
    if args.max_results is not None:
        results = results[: args.max_results]

    from ..core.merge import poc_from_github
    pocs = [poc_from_github(r) for r in results]
    return {"cves": [], "pocs": pocs}
