"""X/Twitter source — social signal + GitHub URL discovery.

Uses Chrome cookies (auth_token + ct0) to authenticate with X's internal
GraphQL API. Searches for CVE mentions in tweets.

X/Twitter NEVER creates PoC records. Instead:
  - Each tweet mentioning a CVE increments social_mentions on that CVE
  - Each tweet linking to a GitHub PoC repo creates a PoC record with
    source="github" and discovered_via="x"

Falls back to dynamically discovered query IDs if known ones expire.
"""

from __future__ import annotations

import re
import sys

from ..core.filters import extract_cves

# Reuse the standalone xsearch module for auth + API
from ..core.xsearch import XSearch, XSearchError, XAuthError


NAME = "X/Twitter (Chrome Auth)"
DEFAULT_ENABLED = True

# Targeted search queries — GitHub-focused, no broad noise
DEFAULT_QUERIES = [
    "CVE-2026 github.com",
    "CVE-2025 github.com",
    "CVE PoC github",
    "CVE exploit github.com",
    "0day github.com PoC",
]

# Regex to extract GitHub repo URLs from tweet text
_GITHUB_URL_RE = re.compile(
    r'https?://github\.com/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+',
    re.IGNORECASE,
)


def run(
    known_cve_ids: set[str],
    known_poc_urls: set[str],
    args,
    **kwargs,
) -> dict:
    """Search X for CVE mentions.

    Returns:
        {
            "cves": [],            # X never creates CVEs
            "pocs": github_pocs,   # Only GitHub URLs, source="github"
            "social_signals": [    # Social mention signals
                {"cve_id": "CVE-2026-XXXX", "tweet_url": "...", "likes": N, "retweets": N},
            ]
        }
    """
    try:
        xs = XSearch()
    except XAuthError as e:
        print(f"  [WARN] X auth failed: {e}", file=sys.stderr)
        return {"cves": [], "pocs": [], "social_signals": []}

    social_signals = []
    github_poc_urls = {}  # url -> {cves, tweet_meta}
    seen_tweet_urls: set[str] = set()

    for query in DEFAULT_QUERIES:
        try:
            tweets = xs.search(query, max_results=10, product="Latest")
        except XSearchError as e:
            print(f"  [WARN] X search failed for '{query}': {e}", file=sys.stderr)
            continue

        for tweet in tweets:
            tweet_url = tweet.get("url", "")
            text = tweet.get("text", "")

            if not text or tweet_url in seen_tweet_urls:
                continue
            seen_tweet_urls.add(tweet_url)

            cves = extract_cves(text)
            if not cves:
                continue

            # Social signal: each tweet mentioning a CVE is a signal
            for cve_id in cves:
                social_signals.append({
                    "cve_id": cve_id,
                    "tweet_url": tweet_url,
                    "likes": tweet.get("likes", 0),
                    "retweets": tweet.get("retweets", 0),
                    "replies": tweet.get("replies", 0),
                    "views": tweet.get("views", 0),
                    "screen_name": tweet.get("screenName", ""),
                })

            # GitHub URL discovery: extract GitHub repo URLs from tweet
            gh_urls = _GITHUB_URL_RE.findall(text)
            for gh_url in gh_urls:
                # Normalize: strip trailing paths beyond repo slug
                # e.g. https://github.com/user/repo/blob/... -> https://github.com/user/repo
                parts = gh_url.rstrip("/").split("/")
                if len(parts) >= 5:
                    gh_url = "/".join(parts[:5])
                if gh_url in known_poc_urls or gh_url in github_poc_urls:
                    continue
                github_poc_urls[gh_url] = {
                    "url": gh_url,
                    "source": "github",
                    "discovered_via": "x",
                    "cves": cves,
                    "stars": None,
                    "age_days": None,
                    "description": text[:300],
                    "tweet_url": tweet_url,
                }

    if not social_signals and not github_poc_urls:
        print("  [WARN] X/Twitter: no CVE mentions found", file=sys.stderr)

    # Build PoC dicts from discovered GitHub URLs
    poc_dicts = list(github_poc_urls.values())

    if args.max_results is not None:
        poc_dicts = poc_dicts[: args.max_results]

    from ..core.merge import poc_from_github
    pocs = [poc_from_github(r) for r in poc_dicts]
    return {
        "cves": [],
        "pocs": pocs,
        "social_signals": social_signals,
        "x_discovered_urls": [p["url"] for p in poc_dicts],
    }
