r"""IOC (Indicators of Compromise) extraction and scanning module.

Extracts threat indicators from raw text using regex patterns:
- IPv4 addresses (excluding private ranges)
- Domains (valid FQDNs, excluding common CDNs)
- URLs (http/https)
- File hashes (MD5, SHA1, SHA256)
- Email addresses
- CVE IDs
- Registry paths (HKLM\, HKCU\)
- File paths (C:\, /etc/, /var/)

Usage:
    from horus.core.ioc_extractor import extract_iocs, extract_iocs_from_news
    indicators = extract_iocs(some_text)
"""

from __future__ import annotations

import ipaddress
import logging
import re
import sqlite3
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Common CDN domains to exclude from IOC_DOMAIN results
CDN_DOMAINS: set[str] = {
    "cloudflare.com",
    "akamai.com",
    "akamaiedge.net",
    "fastly.net",
    "amazonaws.com",
    "azureedge.net",
    "cloudfront.net",
    "googleapis.com",
    "google.com",
    "youtube.com",
    "facebook.com",
    "twitter.com",
    "x.com",
    "linkedin.com",
    "github.com",
    "githubusercontent.com",
    "gitlab.com",
    "stackoverflow.com",
    "wikipedia.org",
    "mozilla.org",
    "apple.com",
    "microsoft.com",
    "office.com",
    "windows.net",
    "office365.com",
    "sharepoint.com",
    "outlook.com",
    "live.com",
    "msn.com",
    "bing.com",
    "fonts.googleapis.com",
    "ajax.googleapis.com",
    "cdnjs.cloudflare.com",
    "unpkg.com",
    "jsdelivr.net",
    "bootstrapcdn.com",
}

# Regex patterns
RE_IPV4 = re.compile(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?![\d.])")
RE_DOMAIN = re.compile(
    r"(?<![\w.-])((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,})(?![\w.-])"
)
RE_URL = re.compile(r"https?://[^\s<>\"\')}\]]+", re.IGNORECASE)
RE_MD5 = re.compile(r"(?<![a-fA-F0-9])([a-fA-F0-9]{32})(?![a-fA-F0-9])")
RE_SHA1 = re.compile(r"(?<![a-fA-F0-9])([a-fA-F0-9]{40})(?![a-fA-F0-9])")
RE_SHA256 = re.compile(r"(?<![a-fA-F0-9])([a-fA-F0-9]{64})(?![a-fA-F0-9])")
RE_EMAIL = re.compile(r"(?<![\w.-])([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(?![\w.-])")
RE_CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
RE_REGISTRY = re.compile(r"((?:HKLM|HKCU|HKCR|HKU|HKCC)[\\/](?:[A-Za-z0-9_\-]+\\)*[A-Za-z0-9_\-]+)")
RE_FILEPATH_WIN = re.compile(r"([A-Z]:\\[^\s:<>\"\|\n\r]+)")
RE_FILEPATH_NIX = re.compile(
    r"((?:\/(?:etc|var|usr|opt|home|root|tmp|bin|sbin|lib|boot|dev|proc|sys|srv|mnt|media|run|snap)\/[^\s:<>\"\|\n\r]+))"
)


def _is_private_ip(ip_str: str) -> bool:
    """Check if an IP address is private/link-local."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved
    except ValueError:
        return True


def _is_valid_ip(ip_str: str) -> bool:
    """Validate IPv4 octets are in range 0-255."""
    parts = ip_str.split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        try:
            val = int(p)
            if val < 0 or val > 255:
                return False
        except ValueError:
            return False
    return True


def _is_cdn_domain(domain: str) -> bool:
    """Check if domain is a known CDN or common non-malicious domain."""
    lower = domain.lower()
    return any(lower == cdn or lower.endswith("." + cdn) for cdn in CDN_DOMAINS)


def extract_iocs(text: str) -> dict[str, list[str]]:
    """Extract all IOC types from a text block.

    Args:
        text: Raw text to scan.

    Returns:
        Dict mapping IOC type to sorted list of unique values.
    """
    if not text:
        return {
            "ips": [],
            "domains": [],
            "urls": [],
            "hashes": [],
            "emails": [],
            "cves": [],
            "paths": [],
            "registry": [],
        }

    # Extract IPs (exclude private)
    ips: set[str] = set()
    for m in RE_IPV4.finditer(text):
        ip = m.group(1)
        if _is_valid_ip(ip) and not _is_private_ip(ip):
            ips.add(ip)

    # Extract domains (exclude CDNs)
    domains: set[str] = set()
    for m in RE_DOMAIN.finditer(text):
        d = m.group(1).lower()
        if not _is_cdn_domain(d):
            domains.add(d)

    # Extract URLs
    urls: set[str] = set()
    for m in RE_URL.finditer(text):
        url = m.group(0)
        # Trim trailing punctuation
        while url and url[-1] in ".,;:!?)":
            url = url[:-1]
        urls.add(url)

    # Extract hashes (prefer longer hashes to avoid overlap)
    sha256s = {m.group(1).lower() for m in RE_SHA256.finditer(text)}
    sha1s = {
        m.group(1).lower() for m in RE_SHA1.finditer(text) if m.group(1).lower() not in sha256s
    }
    md5s = {
        m.group(1).lower()
        for m in RE_MD5.finditer(text)
        if m.group(1).lower() not in sha256s and m.group(1).lower() not in sha1s
    }

    hashes: list[str] = sorted(sha256s) + sorted(sha1s) + sorted(md5s)

    # Extract emails
    emails: set[str] = set()
    for m in RE_EMAIL.finditer(text):
        email = m.group(1).lower()
        if not email.endswith((".png", ".jpg", ".gif", ".svg", ".css", ".js")):
            emails.add(email)

    # Extract CVEs
    cves = {m.group(0).upper() for m in RE_CVE.finditer(text)}

    # Extract registry paths
    registry: set[str] = set()
    for m in RE_REGISTRY.finditer(text):
        registry.add(m.group(1))

    # Extract file paths
    paths: set[str] = set()
    for m in RE_FILEPATH_WIN.finditer(text):
        paths.add(m.group(1))
    for m in RE_FILEPATH_NIX.finditer(text):
        paths.add(m.group(1))

    return {
        "ips": sorted(ips),
        "domains": sorted(domains),
        "urls": sorted(urls),
        "hashes": hashes,
        "emails": sorted(emails),
        "cves": sorted(cves),
        "paths": sorted(paths),
        "registry": sorted(registry),
    }


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def extract_iocs_from_news(conn: sqlite3.Connection) -> int:
    """Scan all news articles for IOCs, store in ioc_indicator table.

    Args:
        conn: SQLite connection.

    Returns:
        Count of new IOC indicators stored.
    """
    now = _utc_now_iso()
    rows = conn.execute(
        "SELECT id, title, summary FROM news_article WHERE summary IS NOT NULL OR title IS NOT NULL"
    ).fetchall()

    inserted = 0
    for row in rows:
        article_id, title, summary = row
        text = f"{title or ''} {summary or ''}"
        iocs = extract_iocs(text)
        source_url = f"news:{article_id}"

        for ip in iocs["ips"]:
            inserted += _insert_ioc(conn, "ip", ip, "news", source_url, now)
        for domain in iocs["domains"]:
            inserted += _insert_ioc(conn, "domain", domain, "news", source_url, now)
        for url in iocs["urls"]:
            inserted += _insert_ioc(conn, "url", url, "news", source_url, now)
        for h in iocs["hashes"]:
            htype = _hash_type(h)
            inserted += _insert_ioc(conn, htype, h, "news", source_url, now)
        for email in iocs["emails"]:
            inserted += _insert_ioc(conn, "email", email, "news", source_url, now)
        for cve in iocs["cves"]:
            inserted += _insert_ioc(conn, "cve", cve, "news", source_url, now, cve_id=cve)
        for path in iocs["paths"]:
            inserted += _insert_ioc(conn, "path", path, "news", source_url, now)
        for reg in iocs["registry"]:
            inserted += _insert_ioc(conn, "registry", reg, "news", source_url, now)

    conn.commit()
    return inserted


def extract_iocs_from_resources(conn: sqlite3.Connection) -> int:
    """Scan security resources for IOCs, store in ioc_indicator table.

    Args:
        conn: SQLite connection.

    Returns:
        Count of new IOC indicators stored.
    """
    now = _utc_now_iso()
    rows = conn.execute(
        "SELECT url, title, description, tags FROM security_resource WHERE description IS NOT NULL OR title IS NOT NULL"
    ).fetchall()

    inserted = 0
    for row in rows:
        url, title, description, tags = row
        text = f"{title or ''} {description or ''} {tags or ''}"
        iocs = extract_iocs(text)

        for ip in iocs["ips"]:
            inserted += _insert_ioc(conn, "ip", ip, "resource", url, now)
        for domain in iocs["domains"]:
            inserted += _insert_ioc(conn, "domain", domain, "resource", url, now)
        for u in iocs["urls"]:
            inserted += _insert_ioc(conn, "url", u, "resource", url, now)
        for h in iocs["hashes"]:
            htype = _hash_type(h)
            inserted += _insert_ioc(conn, htype, h, "resource", url, now)
        for email in iocs["emails"]:
            inserted += _insert_ioc(conn, "email", email, "resource", url, now)
        for cve in iocs["cves"]:
            inserted += _insert_ioc(conn, "cve", cve, "resource", url, now, cve_id=cve)
        for path in iocs["paths"]:
            inserted += _insert_ioc(conn, "path", path, "resource", url, now)
        for reg in iocs["registry"]:
            inserted += _insert_ioc(conn, "registry", reg, "resource", url, now)

    conn.commit()
    return inserted


def _hash_type(value: str) -> str:
    """Determine hash type by length."""
    if len(value) == 32:
        return "hash_md5"
    if len(value) == 40:
        return "hash_sha1"
    if len(value) == 64:
        return "hash_sha256"
    return "hash_sha256"


def _insert_ioc(
    conn: sqlite3.Connection,
    ioc_type: str,
    ioc_value: str,
    source: str,
    source_ref: str,
    now: str,
    cve_id: str | None = None,
) -> int:
    """Insert a single IOC, returning 1 if new, 0 if duplicate."""
    # Truncate overly long values
    if len(ioc_value) > 500:
        ioc_value = ioc_value[:500]
    try:
        conn.execute(
            """INSERT INTO ioc_indicator (ioc_type, ioc_value, source, source_ref, cve_id, first_seen, last_seen)
               VALUES (?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(ioc_type, ioc_value, source) DO UPDATE SET last_seen = excluded.last_seen""",
            (ioc_type, ioc_value, source, source_ref, cve_id, now, now),
        )
        return 1
    except sqlite3.Error as e:
        logger.debug("IOC insert error: %s", e)
        return 0
