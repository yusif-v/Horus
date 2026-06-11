"""CVE extraction and PoC freshness filter."""

from __future__ import annotations

from horus.core.filters import extract_cves, is_fresh_poc


def test_extract_cves_finds_ids_anywhere():
    text = "Exploit for CVE-2026-12345 affecting cve-2024-9999."
    assert extract_cves(text) == ["CVE-2024-9999", "CVE-2026-12345"]


def test_extract_cves_uppercases_and_deduplicates():
    text = "cve-2026-9999 cve-2026-9999 CVE-2026-9999"
    assert extract_cves(text) == ["CVE-2026-9999"]


def test_extract_cves_no_match_returns_empty():
    assert extract_cves("no cve here, just text") == []


def test_extract_cves_requires_4plus_digits_in_id_suffix():
    # Real NVD ids have ≥4 digits in the suffix; "CVE-2026-12" should not match.
    assert "CVE-2026-12" not in extract_cves("CVE-2026-12 should not match")


def test_is_fresh_poc_accepts_real_exploit_text():
    assert is_fresh_poc("Proof-of-concept exploit for RCE in nginx") is True


def test_is_fresh_poc_rejects_low_value_archive():
    # "awesome-list" style aggregator repos are explicitly filtered.
    assert is_fresh_poc("awesome list of CVEs collected over the years") is False
