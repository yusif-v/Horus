"""News source tests: tier classification, parsing."""

from __future__ import annotations

from horus.sources.news import _classify_tier


def test_classify_tier_high_priority_keywords():
    assert _classify_tier("CISA adds new KEV", "summary") == 1
    assert _classify_tier("Known exploited 0-day", "text") == 1
    assert _classify_tier("Zero-day attack", "") == 1


def test_classify_tier_medium_priority():
    assert _classify_tier("CVE-2026-1234 RCE", "summary") == 2
    assert _classify_tier("Remote code execution", "text") == 2
    assert _classify_tier("SQL injection found", "") == 2
    assert _classify_tier("XSS vulnerability", "") == 2


def test_classify_tier_low_priority():
    assert _classify_tier("Security patch released", "") == 3
    assert _classify_tier("Ransomware attack reported", "") == 3
    assert _classify_tier("Malware campaign", "") == 3


def test_classify_tier_no_match_returns_four():
    assert _classify_tier("random news title", "") == 4
    assert _classify_tier("", "no keywords here") == 4
