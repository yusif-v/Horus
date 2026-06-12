"""Text filters: PoC relevance check and CVE extraction."""

from __future__ import annotations

import re

from ..config import FRESH_POC_KEYWORDS, LOW_VALUE_KEYWORDS

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def is_fresh_poc(text: str) -> bool:
    """True if text looks like a real PoC, not a CVE list/archive.

    Relaxed: accepts repos that contain a CVE ID even if they don't
    match the keyword list, since many PoC repos only have the CVE
    in their name/description without explicit keywords.
    """
    text_lower = text.lower()
    if any(kw in text_lower for kw in LOW_VALUE_KEYWORDS):
        return False
    if any(kw in text_lower for kw in FRESH_POC_KEYWORDS):
        return True
    # Accept if text contains a CVE ID pattern (many PoCs are named
    # only with the CVE number and don't include keyword text)
    return _CVE_RE.search(text) is not None


def extract_cves(text: str) -> list[str]:
    return sorted({m.upper() for m in _CVE_RE.findall(text)})
