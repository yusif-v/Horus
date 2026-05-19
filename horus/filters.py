"""Text filters: PoC relevance check and CVE extraction."""

import re

from .config import FRESH_POC_KEYWORDS, LOW_VALUE_KEYWORDS

_CVE_RE = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)


def is_fresh_poc(text: str) -> bool:
    """True if text looks like a real PoC, not a CVE list/archive."""
    text_lower = text.lower()
    if any(kw in text_lower for kw in LOW_VALUE_KEYWORDS):
        return False
    return any(kw in text_lower for kw in FRESH_POC_KEYWORDS)


def extract_cves(text: str) -> list[str]:
    return sorted({m.upper() for m in _CVE_RE.findall(text)})
