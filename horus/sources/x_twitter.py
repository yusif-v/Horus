"""X/Twitter source — social signal + URL discovery.

Searches X for security-relevant posts and extracts any useful URLs.
Resolves shortened URLs (t.co) to their final destination for proper
classification of the resource type.
"""

from __future__ import annotations

import sys
from urllib.parse import urlparse

from horus.core.filters import extract_cves
from horus.core.url_extractor import UrlType, extract_urls
from horus.net.xsearch import XAuthError, XSearch, XSearchError
from horus.sources.url_resolve import classify_destination_domain, resolve_urls_batch

NAME = "X/Twitter (Chrome Auth)"
DEFAULT_ENABLED = True
KIND = "poc"
PROVIDES = ["x_discovered_urls"]  # github source picks these up
SOCIAL_SOURCE_NAME = "x_twitter"  # tagged on watchlist entries

# Targeted search queries — broad PoC discovery
DEFAULT_QUERIES = [
    "CVE-2026 github.com",
    "CVE-2025 github.com",
    "CVE-2026 gitlab.com",
    "CVE-2025 gitlab.com",
    "CVE PoC github",
    "CVE exploit github.com",
    "CVE exploit gitlab.com",
    "0day github.com PoC",
    "0day gitlab.com PoC",
    "CVE-2026 pastebin",
    "CVE-2026 gist.github",
    "CVE exploit pastebin",
    "CVE PoC gist",
    "CVE-2026 PoC",
    "CVE-2025 PoC",
    "CVE exploit code",
    "security exploit repo",
    "CVE-2026 disclosure",
    "CVE-2025 disclosure",
    "hackerone CVE-2026",
    "hackerone CVE-2025",
]


def run(ctx) -> dict:
    """Search X for CVE mentions and extract URLs.

    Resolves t.co URLs to their final destination for proper classification.
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
                social_signals.append(
                    {
                        "cve_id": cve_id,
                        "tweet_url": tweet_url,
                        "likes": tweet.get("likes", 0),
                        "retweets": tweet.get("retweets", 0),
                        "replies": tweet.get("replies", 0),
                        "views": tweet.get("views", 0),
                        "screen_name": tweet.get("screenName", ""),
                        "source": SOCIAL_SOURCE_NAME,
                    }
                )

            # URL discovery: extract all categorized URLs from tweet text
            extracted_urls = extract_urls(text)

            # Batch-resolve t.co URLs to their final destination
            tco_urls = [e.url for e in extracted_urls if _is_short_url(e.url)]
            resolved_map: dict[str, str | None] = {}
            if tco_urls:
                resolved_map = resolve_urls_batch(tco_urls, max_workers=5, timeout=3)

            for extracted in extracted_urls:
                url = extracted.canonical_url

                # Resolve shortened URLs and classify by final destination
                if _is_short_url(url):
                    resolved = resolved_map.get(url)
                    if resolved:
                        dest_source, _ = classify_destination_domain(resolved)
                        url = resolved
                        source = dest_source
                    else:
                        continue  # Could not resolve, skip
                else:
                    source = _source_for_url_type(extracted.url_type)

                if url in ctx.known_poc_urls or url in github_poc_urls:
                    continue

                github_poc_urls[url] = {
                    "url": url,
                    "source": source,
                    "discovered_via": "x",
                    "cves": cves,
                    "stars": None,
                    "age_days": None,
                    "description": text[:300],
                    "tweet_url": tweet_url,
                    "url_type": extracted.url_type.value,
                    "repo_created_at": None,
                }

    if not social_signals and not github_poc_urls:
        print("  [WARN] X/Twitter: no CVE mentions found", file=sys.stderr)

    # Build PoC dicts from discovered URLs
    poc_dicts = list(github_poc_urls.values())

    if ctx.max_results is not None:
        poc_dicts = poc_dicts[: ctx.max_results]

    from ..core.merge import poc_from_github

    pocs = [poc_from_github(r) for r in poc_dicts]
    return {
        "cves": [],
        "pocs": pocs,
        "social_signals": social_signals,
        "x_discovered_urls": [p["url"] for p in poc_dicts],
    }


def _is_short_url(url: str) -> bool:
    """Check if a URL is a known shortener."""
    host = (urlparse(url).hostname or "").lower()
    return host in (
        "t.co",
        "bit.ly",
        "tinyurl.com",
        "goo.gl",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "dlvr.it",
    )


def _source_for_url_type(url_type: UrlType) -> str:
    """Map URL type to PoC source name."""
    mapping = {
        UrlType.GITHUB_REPO: "github",
        UrlType.GITHUB_GIST: "github",
        UrlType.GITHUB_RAW: "github",
        UrlType.GITLAB_REPO: "gitlab",
        UrlType.GITLAB_SNIPPET: "gitlab",
        UrlType.PASTEBIN: "pastebin",
        UrlType.HACKERONE: "hackerone",
        UrlType.BUGCROWD: "bugcrowd",
        UrlType.GENERIC: "web",
    }
    return mapping.get(url_type, "web")
