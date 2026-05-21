"""GitHub repo search source."""

import sys
import urllib.parse
from datetime import datetime

from ..config import GITHUB_QUERIES, MAX_REPO_AGE_DAYS, MIN_REPO_STARS
from ..core.filters import extract_cves, is_fresh_poc
from .auth import github_token
from .http import fetch_json


def _repo_age_days(created_at: str) -> int | None:
    if not created_at:
        return None
    try:
        created = datetime.strptime(created_at, '%Y-%m-%dT%H:%M:%SZ')
        return (datetime.utcnow() - created).days
    except ValueError:
        return None


def search_github(
    seen: set[str],
    max_results: int | None = None,
) -> list[dict]:
    """Search GitHub for new PoC/exploit repositories.

    Mutates `seen` to include newly-reported keys.
    """
    results: list[dict] = []
    token = github_token()
    auth_headers = {'Authorization': f'Bearer {token}'} if token else None

    for query in GITHUB_QUERIES:
        encoded = urllib.parse.quote(query)
        url = (
            f'https://api.github.com/search/repositories'
            f'?q={encoded}&sort=created&order=desc&per_page=15'
        )

        try:
            data = fetch_json(
                url,
                accept='application/vnd.github.v3+json',
                headers=auth_headers,
            )
        except Exception as e:
            print(f'  [WARN] GitHub search failed for "{query}": {e}', file=sys.stderr)
            continue

        for item in data.get('items', []):
            repo_name = item.get('full_name', '')
            description = item.get('description') or ''
            created_at = item.get('created_at', '')
            stars = item.get('stargazers_count', 0)

            age_days = _repo_age_days(created_at)
            if age_days is not None and age_days > MAX_REPO_AGE_DAYS:
                continue
            if stars < MIN_REPO_STARS:
                continue

            combined = f'{repo_name} {description}'
            if not is_fresh_poc(combined):
                continue

            key = f'github:{repo_name}'
            if key in seen:
                continue
            seen.add(key)

            results.append({
                'source': 'GitHub',
                'repo': repo_name,
                'url': item.get('html_url', ''),
                'description': description[:300],
                'cves': extract_cves(combined),
                'stars': stars,
                'created': created_at[:10] if created_at else '',
                'age_days': age_days or 0,
            })

    results.sort(key=lambda x: x.get('stars', 0), reverse=True)
    if max_results is not None:
        results = results[:max_results]
    return results
