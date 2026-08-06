"""CVE-news linking — extract and associate CVEs from news article text."""

from __future__ import annotations

import re
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
