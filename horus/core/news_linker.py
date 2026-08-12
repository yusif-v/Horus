"""CVE-news linking — extract and associate CVEs from news article text."""

from __future__ import annotations

import json
import re
import sqlite3
from datetime import datetime, timezone
from typing import Any

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

_EXPLOIT_ACTIVE = ("actively exploited", "in the wild", "active exploitation", "under attack")
_EXPLOIT_POC = ("proof of concept", "poc available", "demonstrated", "reproduced")
_EXPLOIT_PATCHED = (
    "patch",
    "patched",
    "fix available",
    "update available",
    "mitigated",
    "resolved",
)

_SEVERITY_KEYWORDS = {
    "critical": "critical",
    "high": "high",
    "severe": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "minor": "low",
}


def extract_cves_from_text(text: str) -> list[str]:
    """Extract CVE IDs from text, uppercase, deduplicated, in order of appearance."""
    seen: set[str] = set()
    result: list[str] = []
    for match in CVE_PATTERN.finditer(text):
        cve = match.group(0).upper()
        if cve not in seen:
            seen.add(cve)
            result.append(cve)
    return result


def extract_snippet(text: str, cve_id: str, window: int = 150) -> str:
    """Extract ±window chars around the CVE mention."""
    idx = text.upper().find(cve_id.upper())
    if idx == -1:
        return ""
    start = max(0, idx - window)
    end = min(len(text), idx + len(cve_id) + window)
    return text[start:end].strip()


def detect_context(text: str) -> dict[str, str]:
    """Detect exploitation status and severity mention from text."""
    lowered = text.lower()
    status = "unknown"
    for kw in _EXPLOIT_ACTIVE:
        if kw in lowered:
            status = "active"
            break
    else:
        for kw in _EXPLOIT_POC:
            if kw in lowered:
                status = "poC"
                break
        else:
            for kw in _EXPLOIT_PATCHED:
                if kw in lowered:
                    status = "patched"
                    break

    severity = "unknown"
    for kw, val in _SEVERITY_KEYWORDS.items():
        if kw in lowered:
            severity = val
            break

    return {"exploit_status": status, "severity_mention": severity}


def extract_links_from_article(article: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract CVE links from a news article record."""
    text = f"{article.get('title', '')} {article.get('summary', '')}"
    cves = extract_cves_from_text(text)
    if not cves:
        return []
    context = detect_context(text)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return [
        {
            "cve_id": cve,
            "snippet": extract_snippet(text, cve),
            "context": context,
            "linked_at": now,
        }
        for cve in cves
    ]


def link_cves_to_news(conn: sqlite3.Connection, *, since_days: int = 7) -> dict[str, int]:
    """Run CVE-news linking pass. Returns {"linked": N, "articles_scanned": M}."""
    linked = 0
    articles_scanned = 0

    # Retroactive: scan all unlinked articles
    unlinked = conn.execute(
        """
        SELECT id, title, summary FROM news_article
        WHERE id NOT IN (SELECT article_id FROM news_article_cve)
        """
    ).fetchall()

    # Get all known CVE IDs for matching
    known_cves = {row[0] for row in conn.execute("SELECT id FROM cve")}

    for article in unlinked:
        articles_scanned += 1
        article_record = {"title": article[1], "summary": article[2]}
        for link in extract_links_from_article(article_record):
            cve_id = link["cve_id"]
            if cve_id not in known_cves:
                continue
            cur = conn.execute(
                """INSERT OR IGNORE INTO news_article_cve
                   (article_id, cve_id, snippet, context, linked_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (
                    article[0],
                    cve_id,
                    link["snippet"],
                    json.dumps(link["context"]),
                    link["linked_at"],
                ),
            )
            if cur.rowcount > 0:
                linked += 1

    # Active search: critical CVEs from last N days
    critical_cves = conn.execute(
        """
        SELECT id FROM cve
        WHERE (cvss_score >= 9.0 OR kev = 1)
          AND first_seen >= datetime('now', ?)
        """,
        (f"-{since_days} days",),
    ).fetchall()

    if critical_cves:
        # Re-scan all RSS feeds for critical CVE coverage
        try:
            from horus.plugins.sources.news.main import FEEDS
        except ImportError:
            FEEDS = {}
        try:
            import feedparser
        except ImportError:
            feedparser = None
        if feedparser and FEEDS:
            critical_ids = [row[0] for row in critical_cves]
            for feed_key, (feed_url, _) in FEEDS.items():
                try:
                    parsed = feedparser.parse(feed_url)
                except Exception:
                    continue
                for entry in parsed.entries:
                    text = f"{getattr(entry, 'title', '')} {getattr(entry, 'summary', '')}"
                    for cve_id in critical_ids:
                        if cve_id.upper() in text.upper():
                            url = getattr(entry, "link", "")
                            if not url:
                                continue
                            existing = conn.execute(
                                "SELECT id FROM news_article WHERE url = ?", (url,)
                            ).fetchone()
                            if not existing:
                                conn.execute(
                                    """INSERT OR IGNORE INTO news_article
                                       (title, url, source, tier, summary, first_seen)
                                       VALUES (?, ?, ?, 3, ?, ?)""",
                                    (
                                        getattr(entry, "title", "")[:500],
                                        url,
                                        feed_key,
                                        getattr(entry, "summary", "")[:1000],
                                        datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                                    ),
                                )
                                existing = conn.execute(
                                    "SELECT id FROM news_article WHERE url = ?", (url,)
                                ).fetchone()
                            if existing:
                                snippet = extract_snippet(text, cve_id)
                                context = detect_context(text)
                                now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                                conn.execute(
                                    """INSERT OR IGNORE INTO news_article_cve
                                       (article_id, cve_id, snippet, context, linked_at)
                                       VALUES (?, ?, ?, ?, ?)""",
                                    (existing[0], cve_id, snippet, str(context), now),
                                )

    conn.commit()
    return {"linked": linked, "articles_scanned": articles_scanned}
