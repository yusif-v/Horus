"""PoC source — Codeberg repository search.

Searches Codeberg for new PoC/exploit repositories.
Also accepts Codeberg URLs discovered by X/Twitter for enrichment.

Confidence scoring:
  - high:   >100 stars
  - medium: >10 stars
  - low:    otherwise
"""

from __future__ import annotations

import sys
import urllib.parse
from datetime import datetime, timezone

from ..config import CODEBERG_QUERIES, MAX_REPO_AGE_DAYS, MIN_REPO_STARS
from ..core.filters import extract_cves, is_fresh_poc
from ..net.auth import codeberg_token
from ..net.http import fetch_json

NAME = "Codeberg PoC Repos"
DEFAULT_ENABLED = True
KIND = "poc"
CONSUMES = ["x_discovered_urls"]  # enriched in the same pass


def _confidence_for_stars(stars: int | None) -> str:
    """Return confidence level based on star count."""
    if stars is None:
        return "low"
    if stars > 100:
        return "high"
    if stars > 10:
        return "medium"
    return "low"


def _extract_owner_repo_from_url(url: str) -> tuple[str, str] | None:
    """Extract owner and repo name from Codeberg URL."""
    parts = url.rstrip("/").split("/")
    if len(parts) < 5:
        return None
    owner, repo = parts[3], parts[4]
    if not owner or not repo or owner in (".", "..") or repo in (".", ".."):
        return None
    return owner, repo


def run(ctx) -> dict:
    """Search Codeberg for new PoC repos. Returns {"cves": [], "pocs": [dict]}

    Also enriches any Codeberg URLs `ctx.x_discovered_urls` (surfaced by
    x_twitter earlier in this cycle) — these get full repo metadata
    and are tagged with `discovered_via="x"`.
    """
    results = []
    token = codeberg_token()
    auth_headers = {"Authorization": f"Bearer {token}"} if token else None

    # Process X-discovered URLs first
    if ctx.x_discovered_urls:
        for codeberg_url in ctx.x_discovered_urls:
            # Skip non-Codeberg URLs
            if "codeberg.org" not in codeberg_url:
                continue

            if codeberg_url in ctx.known_poc_urls:
                continue

            # Extract owner/repo from URL
            owner_repo = _extract_owner_repo_from_url(codeberg_url)
            if not owner_repo:
                continue

            owner, repo = owner_repo
            api_url = f"https://codeberg.org/api/v1/repos/{urllib.parse.quote(owner, safe='')}/{urllib.parse.quote(repo, safe='')}"

            try:
                data = fetch_json(api_url, accept="application/json", headers=auth_headers)
            except Exception as e:
                print(
                    f"  [WARN] Codeberg enrichment failed for '{codeberg_url}': {e}",
                    file=sys.stderr,
                )
                # Still add it as a basic PoC even if enrichment fails
                ctx.known_poc_urls.add(codeberg_url)
                results.append(
                    {
                        "source": "codeberg",
                        "repo": f"{owner}/{repo}",
                        "url": codeberg_url,
                        "description": "",
                        "cves": [],
                        "stars": None,
                        "created": "",
                        "age_days": None,
                        "discovered_via": "x",
                        "confidence": "low",
                    }
                )
                continue

            html_url = data.get("html_url", codeberg_url)
            description = data.get("description") or ""
            created_at = data.get("created_at", "")
            stars = data.get("stars_count", 0)  # Codeberg uses stars_count

            try:
                created = datetime.strptime(created_at, "%Y-%m-%dT%H:%M:%SZ")
                age_days = (datetime.now(timezone.utc).replace(tzinfo=None) - created).days
            except (ValueError, TypeError):
                age_days = None

            if age_days is not None and age_days > MAX_REPO_AGE_DAYS:
                continue
            if stars < MIN_REPO_STARS:
                continue

            combined = f"{data.get('full_name', '')} {description}"
            cves = extract_cves(combined)

            ctx.known_poc_urls.add(html_url)
            results.append(
                {
                    "source": "codeberg",
                    "repo": data.get("full_name", ""),
                    "url": html_url,
                    "description": description[:300],
                    "cves": cves,
                    "stars": stars,
                    "created": created_at[:10] if created_at else "",
                    "repo_created_at": created_at,
                    "discovered_via": "x",
                    "confidence": _confidence_for_stars(stars),
                }
            )

    # Standard Codeberg search queries
    for query in CODEBERG_QUERIES:
        encoded = urllib.parse.quote(query)
        search_url = (
            f"https://codeberg.org/api/v1/repos/search?q={encoded}&sort=created&order=desc&limit=15"
        )

        try:
            data = fetch_json(search_url, accept="application/json", headers=auth_headers)
        except Exception as e:
            print(f"  [WARN] Codeberg search failed for '{query}': {e}", file=sys.stderr)
            continue

        for item in data.get("data", []):  # Codeberg API returns data array
            html_url = item.get("html_url", "")
            description = item.get("description") or ""
            created_at = item.get("created_at", "")
            stars = item.get("stars_count", 0)

            if not html_url or html_url in ctx.known_poc_urls:
                continue

            try:
                created = datetime.strptime(created_at, "%Y-%m-%dT%H:%M:%SZ")
                age_days = (datetime.now(timezone.utc).replace(tzinfo=None) - created).days
            except (ValueError, TypeError):
                age_days = None

            if age_days is not None and age_days > MAX_REPO_AGE_DAYS:
                continue
            if stars < MIN_REPO_STARS:
                continue

            combined = f"{item.get('full_name', '')} {description}"
            if not is_fresh_poc(combined):
                continue

            ctx.known_poc_urls.add(html_url)
            results.append(
                {
                    "source": "codeberg",
                    "repo": item.get("full_name", ""),
                    "url": html_url,
                    "description": description[:300],
                    "cves": extract_cves(combined),
                    "stars": stars,
                    "created": created_at[:10] if created_at else "",
                    "repo_created_at": created_at,
                    "confidence": _confidence_for_stars(stars),
                }
            )

    # No re-sorting here — web query handles ordering (newest first by default)
    if ctx.max_results is not None:
        results = results[: ctx.max_results]

    from ..core.merge import poc_from_codeberg

    pocs = [poc_from_codeberg(r) for r in results]
    return {"cves": [], "pocs": pocs}
