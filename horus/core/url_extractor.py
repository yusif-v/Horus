"""URL extraction utilities for PoC discovery.

Categorizes discovered URLs by source type for appropriate handling:
- github_repo: github.com/user/repo
- github_gist: gist.github.com/...
- gitlab_repo: gitlab.com/user/repo
- pastebin: pastebin.com/...
- raw_file: Direct file URLs (raw.githubusercontent.com, etc.)
- generic: Any other HTTP(S) URL that might contain PoC material
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlparse


class UrlType(Enum):
    GITHUB_REPO = "github_repo"
    GITHUB_GIST = "github_gist"
    GITHUB_RAW = "github_raw"
    GITLAB_REPO = "gitlab_repo"
    GITLAB_SNIPPET = "gitlab_snippet"
    CODEBERG_REPO = "codeberg_repo"
    PASTEBIN = "pastebin"
    HACKERONE = "hackerone"
    BUGCROWD = "bugcrowd"
    GENERIC = "generic"


@dataclass
class ExtractedUrl:
    url: str
    url_type: UrlType
    canonical_url: str
    cves: list[str] = field(default_factory=list)


# ── URL type patterns ─────────────────────────────────────────────────────────

# GitHub: github.com/user/repo — capture only first 2 path segments
# Negative lookahead: don't match if followed by / and more path content
_GITHUB_REPO_RE = re.compile(
    r"https?://(?:www\.)?github\.com/"
    r"[A-Za-z0-9._-]+/[A-Za-z0-9._-]+"
    r"(?![A-Za-z0-9._/-])",
    re.IGNORECASE,
)

# GitHub Gist
_GITHUB_GIST_RE = re.compile(
    r"https?://gist\.github\.com/[A-Za-z0-9._-]+/[A-Za-z0-9]+",
    re.IGNORECASE,
)

# GitHub raw file URLs
_GITHUB_RAW_RE = re.compile(
    r"https?://raw\.githubusercontent\.com/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+/",
    re.IGNORECASE,
)

# GitLab: gitlab.com/user/repo — match exactly 2 path segments
_GITLAB_REPO_RE = re.compile(
    r"https?://(?:www\.)?gitlab\.com/"
    r"[A-Za-z0-9._-]+/[A-Za-z0-9._-]+"
    r"(?:[/?\#]|$)",
    re.IGNORECASE,
)

# GitLab snippets
_GITLAB_SNIPPET_RE = re.compile(
    r"https?://(?:www\.)?gitlab\.com/-/snippets/\d+",
    re.IGNORECASE,
)

# Codeberg: codeberg.org/user/repo
_CODEBERG_REPO_RE = re.compile(
    r"https?://(?:www\.)?codeberg\.org/"
    r"[A-Za-z0-9._-]+/[A-Za-z0-9._-]+"
    r"(?![A-Za-z0-9._-])",
    re.IGNORECASE,
)

# Pastebin
_PASTEBIN_RE = re.compile(
    r"https?://(?:www\.)?pastebin\.com/(?:raw/)?[A-Za-z0-9]+",
    re.IGNORECASE,
)

# HackerOne disclosures
_HACKERONE_RE = re.compile(
    r"https?://hackerone\.com/reports/\d+",
    re.IGNORECASE,
)

# Bugcrowd disclosures
_BUGCROWD_RE = re.compile(
    r"https?://bugcrowd\.com/disclosures?/\d+",
    re.IGNORECASE,
)

# Generic URL (catch-all for any remaining http(s) URLs)
_GENERIC_URL_RE = re.compile(
    r"https?://[^\s<>\)\]\}\'\"]+",
    re.IGNORECASE,
)

# Ordered list of (pattern, url_type) — first match wins
_URL_PATTERNS: list[tuple[re.Pattern[str], UrlType]] = [
    (_GITHUB_GIST_RE, UrlType.GITHUB_GIST),
    (_GITHUB_RAW_RE, UrlType.GITHUB_RAW),
    (_GITHUB_REPO_RE, UrlType.GITHUB_REPO),
    (_GITLAB_SNIPPET_RE, UrlType.GITLAB_SNIPPET),
    (_GITLAB_REPO_RE, UrlType.GITLAB_REPO),
    (_CODEBERG_REPO_RE, UrlType.CODEBERG_REPO),
    (_PASTEBIN_RE, UrlType.PASTEBIN),
    (_HACKERONE_RE, UrlType.HACKERONE),
    (_BUGCROWD_RE, UrlType.BUGCROWD),
]


def normalize_url(url: str) -> str:
    """Normalize a URL: strip trailing punctuation, fragments, query params for dedup."""
    url = url.rstrip(".,;:!?)\"'>")
    # Strip fragment
    if "#" in url:
        url = url[: url.index("#")]
    return url


def canonicalize_url(url: str, url_type: UrlType) -> str:
    """Return a canonical form of the URL for deduplication.

    For GitHub/GitLab repos, strip to just the repo path.
    For gists/snippets, strip to the ID.
    For pastebin, strip to the paste ID.
    """
    parsed = urlparse(url)
    path = parsed.path.strip("/")

    if url_type == UrlType.GITHUB_REPO:
        # github.com/user/repo -> keep only first 2 path segments
        parts = path.split("/")
        if len(parts) >= 2:
            return f"https://github.com/{parts[0]}/{parts[1]}"

    elif url_type == UrlType.GITHUB_GIST:
        # gist.github.com/user/gist_id -> keep only gist ID
        parts = path.split("/")
        if len(parts) >= 2:
            return f"https://gist.github.com/{parts[-2]}/{parts[-1]}"

    elif url_type == UrlType.GITHUB_RAW:
        # raw.githubusercontent.com/user/repo/branch/path -> user/repo
        parts = path.split("/")
        if len(parts) >= 3:
            return f"https://github.com/{parts[0]}/{parts[1]}"

    elif url_type == UrlType.GITLAB_REPO:
        # gitlab.com/user/repo -> keep only first 2 path segments
        parts = path.split("/")
        if len(parts) >= 2:
            return f"https://gitlab.com/{parts[0]}/{parts[1]}"

    elif url_type == UrlType.CODEBERG_REPO:
        # codeberg.org/user/repo -> keep only first 2 path segments
        parts = path.split("/")
        if len(parts) >= 2:
            return f"https://codeberg.org/{parts[0]}/{parts[1]}"

    elif url_type == UrlType.PASTEBIN:
        # pastebin.com/raw/XXX or pastebin.com/XXX -> pastebin.com/XXX
        parts = path.split("/")
        paste_id = parts[-1] if parts else path
        return f"https://pastebin.com/{paste_id}"

    return url


def extract_urls(text: str) -> list[ExtractedUrl]:
    """Extract and categorize all URLs from text.

    Returns a list of ExtractedUrl objects with type classification.
    Deduplicates by canonical URL (first occurrence wins).
    """
    seen_canonical: dict[str, ExtractedUrl] = {}
    results: list[ExtractedUrl] = []

    # First pass: match known patterns in priority order
    for pattern, url_type in _URL_PATTERNS:
        for match in pattern.finditer(text):
            raw_url = normalize_url(match.group(0))
            canonical = canonicalize_url(raw_url, url_type)
            if canonical not in seen_canonical:
                extracted = ExtractedUrl(
                    url=raw_url,
                    url_type=url_type,
                    canonical_url=canonical,
                )
                seen_canonical[canonical] = extracted
                results.append(extracted)

    # Second pass: catch any remaining generic URLs that weren't matched
    for match in _GENERIC_URL_RE.finditer(text):
        raw_url = normalize_url(match.group(0))
        # Skip if this URL (or a substring) was already matched by a specific pattern
        already_matched = False
        for existing in results:
            if raw_url.startswith(existing.url) or existing.url.startswith(raw_url):
                already_matched = True
                break
        if not already_matched:
            canonical = raw_url
            if canonical not in seen_canonical:
                extracted = ExtractedUrl(
                    url=raw_url,
                    url_type=UrlType.GENERIC,
                    canonical_url=canonical,
                )
                seen_canonical[canonical] = extracted
                results.append(extracted)

    return results


def extract_urls_by_type(text: str, url_type: UrlType) -> list[str]:
    """Extract only URLs of a specific type from text."""
    return [u.url for u in extract_urls(text) if u.url_type == url_type]
