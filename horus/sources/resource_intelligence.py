"""X/Twitter source — broad security resource intelligence.

Searches X for security-relevant posts and extracts any useful URLs:
exploit tools, bypass techniques, vulnerability disclosures, PoCs, etc.

Unlike x_twitter (which only finds CVE-linked GitHub repos), this source
casts a wide net for any security resource mentioned on social media.
Resolves shortened URLs (t.co) to their final destination for proper
classification.
"""

from __future__ import annotations

import sys
import urllib.request
from urllib.parse import urlparse

from ..core.filters import extract_cves
from ..core.url_extractor import UrlType, extract_urls
from ..net.xsearch import XAuthError, XSearch, XSearchError

NAME = "Security Resource Intelligence (X/Twitter)"
DEFAULT_ENABLED = True
KIND = "resource"

# Broad security discovery queries
DEFAULT_QUERIES = [
    "exploit tool github",
    "proof of concept github",
    "0day exploit released",
    "CVE exploit code",
    "poc github released",
    "bypass technique security",
    "attack technique disclosed",
    "exploit technique github",
    "security bypass tool",
    "vulnerability disclosed",
    "security advisory",
    "0day disclosed",
    "exploit released",
    "red team tool github",
    "pentest tool released",
    "hacking tool github",
    "exploit framework",
    "CVE-2026 github",
    "CVE-2025 github",
    "CVE poc released",
    "CVE exploit github",
    "exploit pastebin",
    "poc gist.github",
]

# Keywords for resource type classification
_TYPE_KEYWORDS = {
    "poc": ["poc", "proof of concept", "proof-of-concept"],
    "exploit": ["exploit", "exploit code", "exploit tool", "exploit framework"],
    "bypass": ["bypass", "bypass technique", "bypass security", "evasion"],
    "tool": ["tool", "toolkit", "framework", "red team", "pentest"],
    "technique": ["technique", "attack technique", "exploit technique", "method"],
    "advisory": ["advisory", "security advisory", "vulnerability disclosed"],
    "disclosure": [
        "disclosure",
        "full disclosure",
        "0day disclosed",
        "disclosed",
        "bug bounty report",
    ],
}

# Keywords for tag extraction
_TAG_KEYWORDS = [
    "rce",
    "lpe",
    "privilege escalation",
    "xss",
    "sql injection",
    "sqli",
    "csrf",
    "ssrf",
    "xxe",
    "command injection",
    "file inclusion",
    "buffer overflow",
    "use-after-free",
    "heap overflow",
    "sandbox escape",
    "kernel",
    "windows",
    "linux",
    "macos",
    "android",
    "ios",
    "chrome",
    "firefox",
    "safari",
    "edge",
    "bitlocker",
    "tpm",
    "secure boot",
    "uefi",
    "bios",
    "active directory",
    "kerberos",
    "ntlm",
    "ldap",
    "docker",
    "kubernetes",
    "container escape",
    "wifi",
    "bluetooth",
    "nfc",
    "phishing",
    "social engineering",
    "physical access",
    "reverse shell",
    "backdoor",
    "rootkit",
    "keylogger",
    "ransomware",
    "spyware",
    "trojan",
    "worm",
    "firmware",
    "hardware",
    "iot",
    "embedded",
    "cryptography",
    "encryption",
    "hash",
    "password",
    "firewall",
    "ids",
    "ips",
    "waf",
    "edr",
    "av",
    "api",
    "oauth",
    "jwt",
    "saml",
    "sso",
    "cloud",
    "aws",
    "azure",
    "gcp",
    "serverless",
    "supply chain",
    "dependency",
    "package",
    "library",
]


def _classify_resource_type(text: str, url_type: UrlType) -> str:
    """Determine resource type from tweet text and URL type."""
    text_lower = text.lower()
    if url_type in (UrlType.GITHUB_GIST, UrlType.PASTEBIN):
        if any(kw in text_lower for kw in _TYPE_KEYWORDS["poc"]):
            return "poc"
        if any(kw in text_lower for kw in _TYPE_KEYWORDS["exploit"]):
            return "exploit"
        return "poc"
    for rtype, keywords in _TYPE_KEYWORDS.items():
        if any(kw in text_lower for kw in keywords):
            return rtype
    if url_type == UrlType.GITHUB_REPO:
        return "tool"
    if url_type in (UrlType.HACKERONE, UrlType.BUGCROWD):
        return "disclosure"
    return "tool"


def _extract_tags(text: str) -> list[str]:
    """Extract security tags from tweet text."""
    text_lower = text.lower()
    tags = []
    for tag in _TAG_KEYWORDS:
        if tag in text_lower:
            tags.append(tag)
    return tags[:10]


def _parse_tweet_date(date_str: str | None) -> str | None:
    """Parse X/Twitter date format to ISO 8601.
    Twitter format: 'Thu Jun 11 07:04:39 +0000 2026'
    """
    if not date_str:
        return None
    try:
        from datetime import datetime

        dt = datetime.strptime(date_str, "%a %b %d %H:%M:%S %z %Y")
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, TypeError):
        return None


def _source_for_url_type(url_type: UrlType) -> str:
    """Map URL type to resource source name."""
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


def resolve_url(url: str, timeout: int = 5) -> str | None:
    """Resolve a shortened URL to its final destination."""
    try:
        req = urllib.request.Request(url, method="HEAD")
        req.add_header("User-Agent", "Mozilla/5.0 (compatible; Horus)")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.url
    except Exception:
        return None


def run(ctx) -> dict:
    """Search X for security-relevant posts and extract resources."""
    try:
        xs = XSearch()
    except XAuthError as e:
        print(f"  [WARN] X auth failed: {e}", file=sys.stderr)
        return {"resources": []}

    resources = []
    seen_urls: set[str] = set()

    for query in DEFAULT_QUERIES:
        try:
            tweets = xs.search(query, max_results=10, product="Latest")
        except XSearchError as e:
            print(f"  [WARN] X search failed for '{query}': {e}", file=sys.stderr)
            continue

        for tweet in tweets:
            tweet_url = tweet.get("url", "")
            text = tweet.get("text", "")

            if not text or not tweet_url:
                continue

            cves = extract_cves(text)
            if not cves:
                continue

            extracted_urls = extract_urls(text)

            # Batch-resolve t.co URLs
            tco_urls = [e.url for e in extracted_urls if _is_short_url(e.url)]
            resolved_map: dict[str, str | None] = {}
            if tco_urls:
                resolved_map = _resolve_batch(tco_urls)

            for extracted in extracted_urls:
                url = extracted.canonical_url

                # Resolve short URLs and classify by final destination
                if _is_short_url(url):
                    resolved = resolved_map.get(url)
                    if resolved:
                        dest_source, dest_type = _classify_destination(resolved)
                        url = resolved
                        source = dest_source
                    else:
                        continue  # Could not resolve, skip
                else:
                    source = _source_for_url_type(extracted.url_type)
                    dest_type = _classify_resource_type(text, extracted.url_type)

                if url in ctx.known_poc_urls or url in seen_urls:
                    continue
                if hasattr(ctx, "known_resource_urls") and url in ctx.known_resource_urls:
                    continue

                seen_urls.add(url)

                likes = tweet.get("likes", 0) or 0
                retweets = tweet.get("retweets", 0) or 0
                replies = tweet.get("replies", 0) or 0
                engagement = likes + retweets * 3 + replies
                tweet_date = _parse_tweet_date(tweet.get("createdAt"))

                resources.append(
                    {
                        "url": url,
                        "resource_type": dest_type,
                        "title": text[:100] if text else None,
                        "description": text[:500] if text else None,
                        "source": source,
                        "source_url": tweet_url,
                        "source_author": tweet.get("screenName"),
                        "engagement_score": engagement,
                        "tags": _extract_tags(text),
                        "cve_refs": cves,
                        "stars": None,
                        "repo_created_at": None,
                        "tweet_created_at": tweet_date,
                    }
                )

    if not resources:
        print("  [INFO] Security Resource Intelligence: no new resources found", file=sys.stderr)

    return {"resources": resources}


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


def _resolve_batch(
    urls: list[str], max_workers: int = 5, timeout: int = 3
) -> dict[str, str | None]:
    """Resolve multiple URLs concurrently."""
    from concurrent.futures import ThreadPoolExecutor, as_completed

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


def _classify_destination(url: str) -> tuple[str, str]:
    """Classify a resolved URL by its destination domain. Returns (source, resource_type)."""
    host = (urlparse(url).hostname or "").lower()

    if "github.com" in host:
        return ("github", "poc")
    if "gitlab.com" in host:
        return ("gitlab", "poc")
    if "pastebin.com" in host:
        return ("pastebin", "poc")
    if "exploit-db.com" in host:
        return ("exploit-db", "poc")
    if "vulmon.com" in host or "cvedetails.com" in host or "nvd.nist.gov" in host:
        return ("web", "advisory")
    if any(
        d in host
        for d in (
            "thehackernews.com",
            "bleepingcomputer.com",
            "darkreading.com",
            "threatpost.com",
            "securityweek.com",
            "krebsonsecurity.com",
        )
    ):
        return ("web", "advisory")

    return ("web", "advisory")
