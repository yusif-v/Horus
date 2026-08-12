"""NVD single-CVE fetch + parse."""

from __future__ import annotations

import io
import json
from contextlib import contextmanager
from datetime import datetime

from horus.core import nvd_fetch

# ── fetch_cve_by_id ──────────────────────────────────────────────────────


def _patch_urlopen(monkeypatch, payload: dict | None = None, *, raise_exc=None):
    @contextmanager
    def fake_open(req, timeout=0):
        if raise_exc is not None:
            raise raise_exc
        yield io.BytesIO(json.dumps(payload or {}).encode())

    monkeypatch.setattr(nvd_fetch.urllib.request, "urlopen", fake_open)


def test_fetch_by_id_returns_cve_payload(monkeypatch):
    _patch_urlopen(
        monkeypatch,
        {"vulnerabilities": [{"cve": {"id": "CVE-2026-1111", "descriptions": []}}]},
    )
    result = nvd_fetch.fetch_cve_by_id("cve-2026-1111")
    assert result == {"id": "CVE-2026-1111", "descriptions": []}


def test_fetch_by_id_unknown_cve_returns_none(monkeypatch):
    _patch_urlopen(monkeypatch, {"vulnerabilities": []})
    assert nvd_fetch.fetch_cve_by_id("CVE-9999-9999") is None


def test_fetch_by_id_network_error_returns_none(monkeypatch):
    _patch_urlopen(monkeypatch, raise_exc=RuntimeError("timeout"))
    assert nvd_fetch.fetch_cve_by_id("CVE-2026-1111") is None


# ── parse_nvd_cve ────────────────────────────────────────────────────────


def test_parse_full_cve_record():
    raw = {
        "id": "CVE-2026-1111",
        "descriptions": [
            {"lang": "en", "value": "RCE via auth bypass in Apache httpd."},
            {"lang": "es", "value": "ignored"},
        ],
        "metrics": {
            "cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "critical"}}]
        },
        "weaknesses": [
            {"description": [{"lang": "en", "value": "CWE-287"}]},
            {"description": [{"lang": "en", "value": "CWE-78"}]},
        ],
        "published": "2026-06-01T12:00:00.000Z",
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:apache:httpd:2.4.59:*:*:*:*:*:*:*",
                            }
                        ]
                    }
                ]
            }
        ],
    }
    parsed = nvd_fetch.parse_nvd_cve(raw)
    assert parsed["cve"] == "CVE-2026-1111"
    assert parsed["cvss_score"] == 9.8
    assert parsed["severity"] == "CRITICAL"
    assert parsed["cwe_ids"] == ["CWE-287", "CWE-78"]
    assert isinstance(parsed["published_at"], datetime)
    assert any(a["vendor"] == "apache" and a["product"] == "httpd" for a in parsed["affected"])


def test_parse_missing_id_returns_none():
    assert nvd_fetch.parse_nvd_cve({"descriptions": []}) is None


def test_parse_falls_back_to_cvss_v2_with_synthetic_severity():
    raw = {
        "id": "CVE-2010-0001",
        "descriptions": [{"lang": "en", "value": "old"}],
        "metrics": {"cvssMetricV2": [{"cvssData": {"baseScore": 7.5}}]},
    }
    parsed = nvd_fetch.parse_nvd_cve(raw)
    assert parsed["cvss_score"] == 7.5
    assert parsed["severity"] == "HIGH"


def test_parse_v2_medium_threshold():
    raw = {
        "id": "CVE-X",
        "descriptions": [{"lang": "en", "value": "x"}],
        "metrics": {"cvssMetricV2": [{"cvssData": {"baseScore": 5.0}}]},
    }
    assert nvd_fetch.parse_nvd_cve(raw)["severity"] == "MEDIUM"


def test_parse_v2_low_threshold():
    raw = {
        "id": "CVE-X",
        "descriptions": [{"lang": "en", "value": "x"}],
        "metrics": {"cvssMetricV2": [{"cvssData": {"baseScore": 2.0}}]},
    }
    assert nvd_fetch.parse_nvd_cve(raw)["severity"] == "LOW"


def test_parse_no_metrics_yields_none_score():
    raw = {
        "id": "CVE-NONE",
        "descriptions": [{"lang": "en", "value": "x"}],
        "metrics": {},
    }
    parsed = nvd_fetch.parse_nvd_cve(raw)
    assert parsed["cvss_score"] is None
    assert parsed["severity"] is None


def test_parse_skips_wildcard_vendors_in_affected():
    raw = {
        "id": "CVE-W",
        "descriptions": [{"lang": "en", "value": "x"}],
        "metrics": {},
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:*:*:*:*:*:*:*:*:*:*",
                            }
                        ]
                    }
                ]
            }
        ],
    }
    parsed = nvd_fetch.parse_nvd_cve(raw)
    assert parsed["affected"] == []


def test_parse_skips_non_vulnerable_cpe_matches():
    raw = {
        "id": "CVE-NV",
        "descriptions": [{"lang": "en", "value": "x"}],
        "metrics": {},
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "vulnerable": False,
                                "criteria": "cpe:2.3:a:apache:httpd:1.0:*:*:*:*:*:*:*",
                            }
                        ]
                    }
                ]
            }
        ],
    }
    assert nvd_fetch.parse_nvd_cve(raw)["affected"] == []


def test_parse_falls_back_to_non_english_description():
    raw = {
        "id": "CVE-LANG",
        "descriptions": [{"lang": "fr", "value": "description française"}],
        "metrics": {},
    }
    assert "française" in nvd_fetch.parse_nvd_cve(raw)["description"]
