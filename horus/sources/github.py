"""PoC source — GitHub repository search.

Searches GitHub for new PoC/exploit repositories.
Also accepts GitHub URLs discovered by X/Twitter for enrichment.

Confidence scoring:
  - high:   >100 stars
  - medium: >10 stars
  - low:    otherwise
"""

from __future__ import annotations
import sys
import urllib.parse
from datetime import datetime

from ..config import GITHUB_QUERIES, MAX_REPO_AGE_DAYS, MIN_REPO_STARS
from ..core.filters import extract_cves, is_fresh_poc
from ..net.auth import github_token
from ..net.http import fetch_json


NAME = "GitHub PoC Repos"
DEFAULT_ENABLED = True


def _confidence_for_stars(stars: int | None) -> str:
    """Return confidence level based on star count."""
    if stars is None:
        return "low"
    if stars > 100:
        return "high"
    if stars > 10:
        return "medium"
    return "low"


def run(
    known_cve_ids: set[str],
    known_poc_urls: set[str],
    args,
    x_discovered_urls: list[str] | None = None,
    **kwargs,
) -> dict:
    """Search GitHub for new PoC repos. Returns {"cves": [], "pocs": [dict]}.

    Args:
        x_discovered_urls: GitHub URLs discovered by X/Twitter source.
            These are fetched for metadata enrichment and added as PoCs
            with source="github" and discovered_via="x".
    """
    results = []
    token = github_token()
    auth_headers = {"Authorization": f"Bearer {token}"} if token else None

    # Process X-discovered URLs first
    if x_discovered_urls:
        for gh_url in x_discovered_urls:
            if gh_url in known_poc_urls:
                continue
            # Extract owner/repo from URL
            parts = gh_url.rstrip("/").split("/")
            if len(parts) < 5:
                continue
            owner, repo = parts[3], parts[4]
            # Reject path-traversal-ish or empty segments before forming the API URL.
            if not owner or not repo or owner in (".", "..") or repo in (".", ".."):
                continue
            api_url = f"https://api.github.com/repos/{urllib.parse.quote(owner, safe='')}/{urllib.parse.quote(repo, safe='')}"
            try:
                data = fetch_json(api_url, accept="application/vnd.github.v3+json", headers=auth_headers)
            except Exception as e:
                print(f"  [WARN] GitHub enrichment failed for '{gh_url}': {e}", file=sys.stderr)
                # Still add it as a basic PoC even if enrichment fails
                known_poc_urls.add(gh_url)
                results.append({
                    "source": "github",
                    "repo": f"{owner}/{repo}",
                    "url": gh_url,
                    "description": "",
                    "cves": [],
                    "stars": None,
                    "created": "",
                    "age_days": None,
                    "discovered_via": "x",
                    "confidence": "low",
                })
                continue

            html_url = data.get("html_url", gh_url)
            description = data.get("description") or ""
            created_at = data.get("created_at", "")
            stars = data.get("stargazers_count", 0)

            try:
                created = datetime.strptime(created_at, "%Y-%m-%dT%H:%M:%SZ")
                age_days = (datetime.utcnow() - created).days
            except ValueError:
                age_days = None

            if age_days is not None and age_days > MAX_REPO_AGE_DAYS:
                continue
            if stars < MIN_REPO_STARS:
                continue

            combined = f'{data.get("full_name", "")} {description}'
            cves = extract_cves(combined)

            known_poc_urls.add(html_url)
            results.append({
                "source": "github",
                "repo": data.get("full_name", ""),
                "url": html_url,
                "description": description[:300],
                "cves": cves,
                "stars": stars,
                "created": created_at[:10] if created_at else "",
                "age_days": age_days,
                "discovered_via": "x",
                "confidence": _confidence_for_stars(stars),
            })

    # Standard GitHub search queries
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
                "source": "github",
                "repo": item.get("full_name", ""),
                "url": html_url,
                "description": description[:300],
                "cves": extract_cves(combined),
                "stars": stars,
                "created": created_at[:10] if created_at else "",
                "age_days": age_days,
                "confidence": _confidence_for_stars(stars),
            })

    results.sort(key=lambda x: x.get("stars", 0), reverse=True)
    if args.max_results is not None:
        results = results[: args.max_results]

    from ..core.merge import poc_from_github
    pocs = [poc_from_github(r) for r in results]
    return {"cves": [], "pocs": pocs}
