"""Classifiers for attack tags and product categories.

Both classifiers return values drawn strictly from the closed vocabularies
in `horus.vocab`. Anything outside the vocab is dropped.
"""

from __future__ import annotations

from .vocab import (
    ATTACK_TAGS,
    CWE_TO_TAG,
    KEYWORD_TO_TAG,
    PRODUCT_TO_CATEGORY,
)


def classify_attack_tags(description: str, cwe_ids: list[str] | None = None) -> list[str]:
    """Return a sorted, de-duplicated list of attack tags.

    CWE mappings take priority; description keywords fill in the gaps.
    """
    tags: set[str] = set()

    for cwe in cwe_ids or []:
        tag = CWE_TO_TAG.get(cwe.upper())
        if tag and tag in ATTACK_TAGS:
            tags.add(tag)

    # Pad with spaces so short tokens like " rce " match on word boundary.
    text = f" {description.lower()} "
    for needle, tag in KEYWORD_TO_TAG.items():
        if needle in text and tag in ATTACK_TAGS:
            tags.add(tag)

    return sorted(tags)


def classify_product_category(*texts: str) -> str:
    """Return a single category from PRODUCT_CATEGORIES, or 'unknown'."""
    haystack = " ".join(t.lower() for t in texts if t)
    for needle, category in PRODUCT_TO_CATEGORY.items():
        if needle in haystack:
            return category
    return "unknown"


def classify_exploit_type(text: str) -> str:
    """Return an exploit type label from text.

    Keyword-based classifier that inspects the combined description / repo
    text for known exploit-type signals.  Priority order matters — the first
    match wins — so more specific patterns should appear before generic ones.

    Returns one of: RCE, LPE, Inject, DoS, Bypass, PoC, or "Exploit" as
    the default fallback.
    """
    hay = f" {text.lower()} "

    # Ordered so the most specific / highest-signal patterns match first.
    rules: list[tuple[list[str], str]] = [
        # RCE
        (
            [
                "rce",
                "remote code execution",
                "code execution",
                "command injection",
                "cmd injection",
            ],
            "RCE",
        ),
        # LPE
        (
            [
                "lpe",
                "privilege escalation",
                "privesc",
                "local privilege",
                "root exploit",
            ],
            "LPE",
        ),
        # Injection
        (
            [
                "sqli",
                "sql injection",
                "xss",
                "cross-site",
                "ssti",
                "template injection",
                "xxe",
                "xml injection",
            ],
            "Inject",
        ),
        # DoS
        (
            [
                " dos ",
                "denial of service",
                "flood",
                "crash",
                "blue screen",
                "bsod",
            ],
            "DoS",
        ),
        # Bypass
        (
            [
                "bypass",
                "auth bypass",
                "authentication bypass",
                "waf bypass",
            ],
            "Bypass",
        ),
        # PoC (generic — keep last before default)
        (
            [
                "proof of concept",
                "writeup",
            ],
            "PoC",
        ),
    ]

    for needles, label in rules:
        for needle in needles:
            if needle in hay:
                return label

    return "Exploit"
