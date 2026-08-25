"""URL resolution utilities for classifying discovered resources.

Resolves shortened URLs (t.co, bit.ly, etc.) to their final destination
so we can properly classify the resource type.
"""

from __future__ import annotations

import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse


def resolve_url(url: str, timeout: int = 5) -> str | None:
    """Resolve a shortened URL to its final destination.
    Returns the final URL or None if resolution fails.
    """
    try:
        req = urllib.request.Request(url, method="HEAD")
        req.add_header("User-Agent", "Mozilla/5.0 (compatible; Horus)")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return str(resp.url)
    except Exception:
        return None


def resolve_urls_batch(
    urls: list[str], max_workers: int = 10, timeout: int = 3
) -> dict[str, str | None]:
    """Resolve multiple URLs concurrently. Returns {original_url: final_url}."""
    results: dict[str, str | None] = {}
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(resolve_url, url, timeout): url for url in urls}
        for future in as_completed(futures):
            original = futures[future]
            try:
                results[original] = future.result()
            except Exception:
                results[original] = None
    return results


def classify_destination_domain(url: str) -> tuple[str, str]:
    """Classify a resolved URL by its destination domain.

    Returns (source, resource_type) tuple.
    """
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()

    # Code repositories → PoC
    if "github.com" in host:
        return ("github", "poc")
    if "gitlab.com" in host:
        return ("gitlab", "poc")
    if "pastebin.com" in host:
        return ("pastebin", "poc")
    if "exploit-db.com" in host:
        return ("exploit-db", "poc")
    if "gist.github.com" in host:
        return ("github", "poc")

    # Code snippet sharing
    if "gist.github" in host or "dotnetfiddle" in host or "jsfiddle" in host or "codepen" in host:
        return ("web", "poc")

    # Vulnerability databases / advisories
    if any(
        d in host
        for d in (
            "nvd.nist.gov",
            "cve.mitre.org",
            "vulmon.com",
            "vuldb.com",
            "securityfocus.com",
            "osv.dev",
            "cvedetails.com",
        )
    ):
        return ("web", "advisory")

    # Security blogs, writeups, analysis
    if any(
        d in host
        for d in (
            "blog",
            "medium.com",
            "dev.to",
            "hackernoon",
            "substack.com",
            "ghost.io",
            "wp-content",
        )
    ):
        return ("web", "advisory")

    # Vendor advisories
    if any(
        d in host
        for d in (
            "msrc.microsoft.com",
            "advisory",
            "security.googleblog",
            "apache.org/security",
            "ubuntu.com/security",
            "debian.org/security",
            "redhat.com/security",
        )
    ):
        return ("web", "advisory")

    # InfoQ, The Hacker News, etc.
    if any(
        d in host
        for d in (
            "thehackernews.com",
            "bleepingcomputer.com",
            "zdnet.com",
            "threatpost.com",
            "securityweek.com",
            "arstechnica.com",
            "infoq.com",
            "darkreading.com",
            "scmagazine.com",
            "krebsonsecurity.com",
            "schneier.com",
            "wired.com/security",
            "threataft.com",
            "crowdstrike.com/blog",
            "mandiant.com/resources",
            "googleprojectzero.blogspot",
        )
    ):
        return ("web", "advisory")

    # Default: web resource (could be tool, advisory, or other)
    return ("web", "advisory")
