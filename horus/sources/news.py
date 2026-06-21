"""News/RSS feed source — fetches and classifies security news articles.

Persists directly to the news_article table (not through the resource pipeline).
"""

from __future__ import annotations

import time
from datetime import datetime, timezone

import feedparser

from ..storage import db

NAME = "News/RSS Feed"
DEFAULT_ENABLED = True
KIND = "news"

# Feed configurations: key → (url, default_tier)
FEEDS: dict[str, tuple[str, int]] = {
    "cisa": (
        "https://www.cisa.gov/cybersecurity-advisories/all.xml",
        4,
    ),
    "hacker_news": (
        "https://feeds.feedburner.com/TheHackersNews",
        3,
    ),
    "bleepingcomputer": (
        "https://www.bleepingcomputer.com/feed/",
        3,
    ),
    "packet_storm": (
        "https://packetstormsecurity.com/feed.xml",
        2,
    ),
    "exploit_db": (
        "https://www.exploit-db.com/rss.xml",
        2,
    ),
    "nvd": (
        "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml",
        1,
    ),
}

# Tier 1 keywords — critical sources / KEV
_TIER1_KEYWORDS = ("cisa", "kev", "known exploited", "0-day", "zero-day", "actively exploited")
# Tier 2 keywords — CVE / exploit / RCE
_TIER2_KEYWORDS = (
    "cve-",
    "rce",
    "remote code",
    "exploit",
    "vulnerability",
    "xss",
    "sqli",
    "sql injection",
    "buffer overflow",
    "privilege escalation",
    "arbitrary code",
)
# Tier 3 keywords — general security news
_TIER3_KEYWORDS = (
    "patch",
    "security update",
    "breach",
    "ransomware",
    "malware",
    "phishing",
    "threat",
    "advisory",
    "cve",
    "vuln",
    "exploitable",
)


def _classify_tier(title: str, summary: str) -> int:
    """Keyword-based tier override. Returns tier 1-4 (lower = more important).

    Checks title + summary against keyword lists in priority order.
    If no keywords match, returns 4 (lowest priority / noise).
    """
    text = f"{title} {summary}".lower()
    for kw in _TIER1_KEYWORDS:
        if kw in text:
            return 1
    for kw in _TIER2_KEYWORDS:
        if kw in text:
            return 2
    for kw in _TIER3_KEYWORDS:
        if kw in text:
            return 3
    return 4


def _parse_published(entry) -> str | None:
    """Extract ISO-8601 date from a feedparser entry, or None."""
    if hasattr(entry, "published_parsed") and entry.published_parsed:
        try:
            dt = datetime.fromtimestamp(time.mktime(entry.published_parsed), tz=timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except (OverflowError, OSError, ValueError):
            pass
    if hasattr(entry, "updated_parsed") and entry.updated_parsed:
        try:
            dt = datetime.fromtimestamp(time.mktime(entry.updated_parsed), tz=timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except (OverflowError, OSError, ValueError):
            pass
    return None


def run(ctx) -> dict:
    """Fetch RSS feeds, classify tiers, persist to news_article table.

    Returns {{}} (empty dict) — articles are persisted directly,
    not through the resource pipeline.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    with db.connect() as conn:
        known_urls = {row[0] for row in conn.execute("SELECT url FROM news_article")}

    for feed_key, (feed_url, _default_tier) in FEEDS.items():
        try:
            parsed = feedparser.parse(feed_url)
        except Exception:
            continue

        for entry in parsed.entries:
            url = getattr(entry, "link", "")
            if not url or url in known_urls:
                continue
            known_urls.add(url)

            title = getattr(entry, "title", "")[:500]
            summary = getattr(entry, "summary", "")[:1000]
            published_at = _parse_published(entry)

            tier = _classify_tier(title, summary)

            with db.connect() as conn:
                conn.execute(
                    """INSERT OR IGNORE INTO news_article
                       (title, url, source, tier, summary, published_at, first_seen)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (title, url, feed_key, tier, summary, published_at, now),
                )

    return {}
