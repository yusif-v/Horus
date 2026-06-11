"""Attack-tag and product-category classifiers."""

from __future__ import annotations

from horus.core.classify import classify_attack_tags, classify_product_category


def test_cwe_drives_tag_selection():
    # CWE-89 → sql-injection (deterministic, no keyword needed)
    assert "sql-injection" in classify_attack_tags("", cwe_ids=["CWE-89"])


def test_keyword_fallback_when_no_cwe():
    tags = classify_attack_tags("remote code execution in the server")
    assert "rce" in tags


def test_cwe_and_keyword_union():
    tags = classify_attack_tags(
        "remote code execution and SQL injection chained",
        cwe_ids=["CWE-22"],
    )
    assert {"rce", "sql-injection", "path-traversal"}.issubset(set(tags))


def test_unknown_cwe_is_dropped():
    # Unknown CWE in vocab → no tag from CWE path
    assert classify_attack_tags("", cwe_ids=["CWE-99999"]) == []


def test_tags_are_sorted_and_deduplicated():
    tags = classify_attack_tags("RCE rce rce RCE", cwe_ids=["CWE-94", "CWE-434"])
    assert tags == sorted(set(tags))


def test_product_category_matches_known_vendor():
    assert classify_product_category("nginx", "nginx") == "web-server"


def test_product_category_unknown_when_no_match():
    assert classify_product_category("foo", "bar") == "unknown"


def test_product_category_searches_all_passed_texts():
    # The vendor field is empty; the description carries the signal.
    assert classify_product_category("", "Apache HTTP Server vulnerability") == "web-server"
