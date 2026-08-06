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

# Common CDN/source domains to exclude from IOC_DOMAIN results
CDN_DOMAINS: set[str] = {
    # CDNs & cloud
    "cloudflare.com",
    "akamai.com",
    "akamaiedge.net",
    "fastly.net",
    "amazonaws.com",
    "azureedge.net",
    "cloudfront.net",
    "googleapis.com",
    # Social & search
    "google.com",
    "youtube.com",
    "facebook.com",
    "twitter.com",
    "x.com",
    "linkedin.com",
    "bing.com",
    "msn.com",
    "reddit.com",
    # Dev platforms
    "github.com",
    "githubusercontent.com",
    "gitlab.com",
    "stackoverflow.com",
    "npmjs.com",
    "pypi.org",
    "maven.org",
    # Reference & documentation
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
    # Security advisory sources (reference, not IOCs)
    "cisa.gov",
    "cve.org",
    "nvd.nist.gov",
    "mitre.org",
    "se.com",
    "cert.org",
    "us-cert.gov",
    "ncsc.gov.uk",
    "cisa.gov.au",
    # URL shorteners
    "t.co",
    "bit.ly",
    "goo.gl",
    "ow.ly",
    "tinyurl.com",
    # Common CDNs
    "fonts.googleapis.com",
    "ajax.googleapis.com",
    "cdnjs.cloudflare.com",
    "unpkg.com",
    "jsdelivr.net",
    "bootstrapcdn.net",
}

# File extensions that look like TLDs but aren't domains
FILE_EXTENSIONS: frozenset[str] = frozenset(
    {
        "json",
        "xml",
        "pdf",
        "txt",
        "csv",
        "html",
        "htm",
        "jsp",
        "asp",
        "aspx",
        "php",
        "py",
        "js",
        "css",
        "md",
        "yaml",
        "yml",
        "toml",
        "cfg",
        "conf",
        "ini",
        "log",
        "bak",
        "zip",
        "tar",
        "gz",
        "rar",
        "exe",
        "dll",
        "sys",
        "bin",
        "img",
        "iso",
        "dmg",
        "deb",
        "rpm",
    }
)

# Known valid TLDs (subset — excludes file extensions)
VALID_TLDS: frozenset[str] = frozenset(
    {
        "com",
        "org",
        "net",
        "edu",
        "gov",
        "mil",
        "int",
        "io",
        "co",
        "us",
        "uk",
        "de",
        "fr",
        "jp",
        "cn",
        "ru",
        "br",
        "in",
        "au",
        "ca",
        "it",
        "nl",
        "se",
        "no",
        "fi",
        "dk",
        "es",
        "pt",
        "ch",
        "at",
        "be",
        "ie",
        "nz",
        "za",
        "mx",
        "ar",
        "cl",
        "co.uk",
        "com.au",
        "co.in",
        "com.br",
        "co.jp",
        "com.cn",
        "or.jp",
        "go.jp",
        "ac.uk",
        "info",
        "biz",
        "name",
        "pro",
        "aero",
        "museum",
        "coop",
        "travel",
        "jobs",
        "mobi",
        "tel",
        "cat",
        "asia",
        "xxx",
        "post",
        "onion",
        # Country codes that could be confused with file extensions
        "pl",
        "cz",
        "hu",
        "ro",
        "bg",
        "hr",
        "sk",
        "si",
        "lt",
        "lv",
        "ee",
        "ua",
        "by",
        "md",
        "am",
        "ge",
        "az",
        "kz",
        "uz",
        "kg",
        "tj",
        "tm",
        "kr",
        "tw",
        "hk",
        "sg",
        "th",
        "vn",
        "my",
        "ph",
        "id",
        "bd",
        "pk",
        "lk",
        "np",
        "mm",
        "kh",
        "la",
        "bn",
        "mo",
        "mn",
        "kp",
        "ae",
        "sa",
        "qa",
        "kw",
        "bh",
        "om",
        "jo",
        "lb",
        "sy",
        "iq",
        "ir",
        "il",
        "ps",
        "tr",
        "cy",
        "mt",
        "gr",
        "eg",
        "ng",
        "ke",
        "tz",
        "ug",
        "gh",
        "cm",
        "ci",
        "sn",
        "ml",
        "bf",
        "ne",
        "td",
        "sd",
        "et",
        "so",
        "cd",
        "cg",
        "ga",
        "gq",
        "st",
        "ao",
        "mz",
        "zw",
        "bw",
        "na",
        "sz",
        "mg",
        "mu",
        "sc",
        "km",
        "dj",
        "er",
        "cf",
        "gw",
        "lr",
        "sl",
        "gn",
        "bj",
        "tg",
        "cv",
        "gm",
        "mr",
        "bi",
        "rw",
        "ss",
        "ma",
        "tn",
        "dz",
        "ly",
        "eh",
    }
)

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


def _is_valid_domain(domain: str) -> bool:
    """Check if a string is a real domain, not a filename with file extension."""
    lower = domain.lower()
    parts = lower.split(".")
    tld = parts[-1]
    # Reject if TLD is a known file extension
    if tld in FILE_EXTENSIONS:
        return False
    # Reject if TLD is not a known valid TLD
    if tld not in VALID_TLDS:
        return False
    # Reject single-character domains (likely false positives)
    if len(parts) == 2 and len(parts[0]) <= 2:
        return False
    # Reject domains ending in common filename patterns
    return not lower.endswith((".json", ".xml", ".pdf", ".txt", ".csv", ".html", ".htm"))


def _is_reference_url(url: str) -> bool:
    """Check if URL is a reference/documentation link, not an IOC."""
    lower = url.lower()
    # GitHub repos, documentation, advisory pages
    reference_paths = [
        "/blob/",
        "/tree/",
        "/develop/",
        "/docs/",
        "/wiki/",
        "/advisories/",
        "/bulletins/",
        "/alerts/",
        "/analysis/",
        "/csaf_files/",
        "/cve/",
        "/detail/",
    ]
    if any(p in lower for p in reference_paths):
        return True
    # Reference domains
    reference_domains = [
        "cisa.gov",
        "github.com",
        "nvd.nist.gov",
        "mitre.org",
        "cve.org",
        "se.com",
        "cert.org",
        "us-cert.gov",
    ]
    return any(d in lower for d in reference_domains)


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

    # Extract domains (exclude CDNs, file names, invalid TLDs)
    domains: set[str] = set()
    for m in RE_DOMAIN.finditer(text):
        d = m.group(1).lower()
        if not _is_cdn_domain(d) and _is_valid_domain(d):
            domains.add(d)

    # Extract URLs (exclude reference/documentation links)
    urls: set[str] = set()
    for m in RE_URL.finditer(text):
        url = m.group(0)
        # Trim trailing punctuation
        while url and url[-1] in ".,;:!?)":
            url = url[:-1]
        if not _is_reference_url(url):
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
        # Link all IOCs to CVEs mentioned in the same article
        article_cves = iocs["cves"]

        for ip in iocs["ips"]:
            for cve in article_cves:
                inserted += _insert_ioc(conn, "ip", ip, "news", source_url, now, cve_id=cve)
        for domain in iocs["domains"]:
            for cve in article_cves:
                inserted += _insert_ioc(conn, "domain", domain, "news", source_url, now, cve_id=cve)
        for url in iocs["urls"]:
            for cve in article_cves:
                inserted += _insert_ioc(conn, "url", url, "news", source_url, now, cve_id=cve)
        for h in iocs["hashes"]:
            htype = _hash_type(h)
            for cve in article_cves:
                inserted += _insert_ioc(conn, htype, h, "news", source_url, now, cve_id=cve)
        for email in iocs["emails"]:
            for cve in article_cves:
                inserted += _insert_ioc(conn, "email", email, "news", source_url, now, cve_id=cve)
        for cve in iocs["cves"]:
            inserted += _insert_ioc(conn, "cve", cve, "news", source_url, now, cve_id=cve)
        for path in iocs["paths"]:
            for cve in article_cves:
                inserted += _insert_ioc(conn, "path", path, "news", source_url, now, cve_id=cve)
        for reg in iocs["registry"]:
            for cve in article_cves:
                inserted += _insert_ioc(conn, "registry", reg, "news", source_url, now, cve_id=cve)

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
        resource_cves = iocs["cves"]

        for ip in iocs["ips"]:
            for cve in resource_cves:
                inserted += _insert_ioc(conn, "ip", ip, "resource", url, now, cve_id=cve)
        for domain in iocs["domains"]:
            for cve in resource_cves:
                inserted += _insert_ioc(conn, "domain", domain, "resource", url, now, cve_id=cve)
        for u in iocs["urls"]:
            for cve in resource_cves:
                inserted += _insert_ioc(conn, "url", u, "resource", url, now, cve_id=cve)
        for h in iocs["hashes"]:
            htype = _hash_type(h)
            for cve in resource_cves:
                inserted += _insert_ioc(conn, htype, h, "resource", url, now, cve_id=cve)
        for email in iocs["emails"]:
            for cve in resource_cves:
                inserted += _insert_ioc(conn, "email", email, "resource", url, now, cve_id=cve)
        for cve in iocs["cves"]:
            inserted += _insert_ioc(conn, "cve", cve, "resource", url, now, cve_id=cve)
        for path in iocs["paths"]:
            for cve in resource_cves:
                inserted += _insert_ioc(conn, "path", path, "resource", url, now, cve_id=cve)
        for reg in iocs["registry"]:
            for cve in resource_cves:
                inserted += _insert_ioc(conn, "registry", reg, "resource", url, now, cve_id=cve)

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
