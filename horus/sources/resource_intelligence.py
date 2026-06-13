"""X/Twitter source — broad security resource intelligence.

Searches X for security-relevant posts and extracts any useful URLs:
exploit tools, bypass techniques, vulnerability disclosures, PoCs, etc.

Unlike x_twitter (which only finds CVE-linked GitHub repos), this source
casts a wide net for any security resource mentioned on social media.
"""

from __future__ import annotations

import sys

from ..core.filters import extract_cves
from ..core.url_extractor import UrlType, extract_urls

# Reuse the standalone xsearch module for auth + API
from ..net.xsearch import XAuthError, XSearch, XSearchError

NAME = "Security Resource Intelligence (X/Twitter)"
DEFAULT_ENABLED = True
KIND = "resource"

# Broad security discovery queries
DEFAULT_QUERIES = [
    # Exploit & PoC
    "exploit tool github",
    "proof of concept github",
    "0day exploit released",
    "CVE exploit code",
    "poc github released",
    # Bypass & technique
    "bypass technique security",
    "attack technique disclosed",
    "exploit technique github",
    "security bypass tool",
    # Disclosure & advisory
    "vulnerability disclosed",
    "security advisory",
    "0day disclosed",
    "exploit released",
    # Red team / tools
    "red team tool github",
    "pentest tool released",
    "hacking tool github",
    "exploit framework",
    # CVE mentions with resources
    "CVE-2026 github",
    "CVE-2025 github",
    "CVE poc released",
    "CVE exploit github",
    # Pastebin / gist
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

    # Check URL type first
    if url_type in (UrlType.GITHUB_GIST, UrlType.PASTEBIN):
        # Gists and pastebins are often PoCs or exploit code
        if any(kw in text_lower for kw in _TYPE_KEYWORDS["poc"]):
            return "poc"
        if any(kw in text_lower for kw in _TYPE_KEYWORDS["exploit"]):
            return "exploit"
        return "poc"  # Default for gists/pastebins

    # Check text keywords
    for rtype, keywords in _TYPE_KEYWORDS.items():
        if any(kw in text_lower for kw in keywords):
            return rtype

    # Default based on URL type
    if url_type == UrlType.GITHUB_REPO:
        return "tool"
    if url_type in (UrlType.HACKERONE, UrlType.BUGCROWD):
        return "disclosure"

    return "tool"  # Generic fallback


def _extract_tags(text: str) -> list[str]:
    """Extract security tags from tweet text."""
    text_lower = text.lower()
    tags = []
    for tag in _TAG_KEYWORDS:
        if tag in text_lower:
            tags.append(tag)
    return tags[:10]  # Max 10 tags


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


def run(ctx) -> dict:
    """Search X for security-relevant posts and extract resources.

    Returns:
        {
            "resources": [dict],  # Discovered security resources
        }
    """
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

            # Extract all URLs from the tweet
            extracted_urls = extract_urls(text)

            # Also extract CVE references from the text
            cves = extract_cves(text)

            for extracted in extracted_urls:
                url = extracted.canonical_url

                # Skip if already seen or already in our DBs
                if url in seen_urls:
                    continue
                if url in ctx.known_poc_urls:
                    continue

                # Check if URL is already in security_resource table
                # (handled by known_resource_urls in ctx if available)
                if hasattr(ctx, "known_resource_urls") and url in ctx.known_resource_urls:
                    continue

                seen_urls.add(url)

                # Classify the resource
                resource_type = _classify_resource_type(text, extracted.url_type)
                tags = _extract_tags(text)
                source = _source_for_url_type(extracted.url_type)

                # Calculate engagement score
                likes = tweet.get("likes", 0) or 0
                retweets = tweet.get("retweets", 0) or 0
                replies = tweet.get("replies", 0) or 0
                engagement = likes + retweets * 3 + replies

                resources.append(
                    {
                        "url": url,
                        "resource_type": resource_type,
                        "title": text[:100] if text else None,
                        "description": text[:500] if text else None,
                        "source": source,
                        "source_url": tweet_url,
                        "source_author": tweet.get("screenName"),
                        "engagement_score": engagement,
                        "tags": tags,
                        "cve_refs": cves,
                        "stars": None,
                        "repo_created_at": None,
                    }
                )

    if not resources:
        print("  [INFO] Security Resource Intelligence: no new resources found", file=sys.stderr)

    return {"resources": resources}
