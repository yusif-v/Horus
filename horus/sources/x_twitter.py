"""X/Twitter PoC source — birdnode-compatible Chrome cookie search.

Uses Chrome cookies (auth_token + ct0) to authenticate with X's internal
GraphQL API. Searches for CVE mentions in tweets.

Falls back to dynamically discovered query IDs if known ones expire.
"""

from __future__ import annotations

import sys

from ..core.filters import extract_cves

# Reuse the standalone xsearch module for auth + API
from ..core.xsearch import XSearch, XSearchError, XAuthError


NAME = "X/Twitter (Chrome Auth)"
DEFAULT_ENABLED = True

# Default search queries for CVE hunting
DEFAULT_QUERIES = [
    "CVE-2026",
    "CVE-2025",
    "CVE PoC",
    "CVE exploit",
    "0day",
    "zeroday",
    "0-day",
]


def run(
    known_cve_ids: set[str],
    known_poc_urls: set[str],
    args,
    **kwargs,
) -> dict:
    """Search X for CVE mentions. Returns {"cves": [], "pocs": [dict]}."""
    try:
        xs = XSearch()
    except XAuthError as e:
        print(f"  [WARN] X auth failed: {e}", file=sys.stderr)
        return {"cves": [], "pocs": []}

    all_results = []
    seen_urls: set[str] = set()

    for query in DEFAULT_QUERIES:
        try:
            tweets = xs.search(query, max_results=10, product="Latest")
        except XSearchError as e:
            print(f"  [WARN] X search failed for '{query}': {e}", file=sys.stderr)
            continue

        for tweet in tweets:
            url = tweet.get("url", "")
            if url in seen_urls or url in known_poc_urls:
                continue

            cves = extract_cves(tweet.get("text", ""))
            if not cves:
                continue

            seen_urls.add(url)
            known_poc_urls.add(url)
            all_results.append({
                "url": url,
                "source": "x",
                "description": tweet.get("text", "")[:300],
                "cves": cves,
                "stars": tweet.get("likes", 0),
                "age_days": 0,
                "screen_name": tweet.get("screenName", ""),
                "author": tweet.get("author", ""),
                "followers_count": tweet.get("followersCount", 0),
                "created_at": tweet.get("createdAt", ""),
                "likes": tweet.get("likes", 0),
                "retweets": tweet.get("retweets", 0),
                "replies": tweet.get("replies", 0),
                "views": tweet.get("views", 0),
            })

    if not all_results:
        print("  [WARN] X/Twitter: no CVE mentions found", file=sys.stderr)

    if args.max_results is not None:
        all_results = all_results[: args.max_results]

    from ..core.merge import poc_from_x
    pocs = [poc_from_x(r) for r in all_results]
    return {"cves": [], "pocs": pocs}
