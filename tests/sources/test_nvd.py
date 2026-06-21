"""NVD source — CVE feed parsing against canned API responses."""

from __future__ import annotations

from datetime import datetime

from horus.core.context import SourceContext
from horus.sources import nvd


def _vuln(
    cve_id: str,
    description: str,
    *,
    cvss: float = 9.8,
    severity: str = "CRITICAL",
    published: str = "2026-06-01T00:00:00.000",
    cwes: list[str] | None = None,
) -> dict:
    weaknesses = []
    if cwes:
        weaknesses = [{"description": [{"lang": "en", "value": c}]} for c in cwes]
    return {
        "cve": {
            "id": cve_id,
            "descriptions": [{"lang": "en", "value": description}],
            "metrics": {
                "cvssMetricV31": [{"cvssData": {"baseScore": cvss, "baseSeverity": severity}}]
            },
            "published": published,
            "weaknesses": weaknesses,
            "configurations": [],
        }
    }


def _patch(monkeypatch, payload: dict):
    """Patch fetch_json to return `payload` on first call, empty after."""
    calls = {"n": 0}

    def fake_fetch(url):
        calls["n"] += 1
        if calls["n"] == 1:
            return payload
        return {"totalResults": payload.get("totalResults", 0), "vulnerabilities": []}

    monkeypatch.setattr(nvd, "fetch_json", fake_fetch)
    return calls


def test_parses_vulnerabilities(monkeypatch):
    payload = {
        "totalResults": 2,
        "vulnerabilities": [
            _vuln("CVE-2026-1111", "Critical RCE in Apache", cvss=9.8, cwes=["CWE-78"]),
            _vuln("CVE-2026-2222", "SQLi in WordPress plugin", cvss=7.5, severity="HIGH"),
        ],
    }
    _patch(monkeypatch, payload)

    result = nvd.run(SourceContext(max_results=10))

    assert result["pocs"] == []
    cves = result["cves"]
    assert len(cves) == 2
    # Sorted by score desc
    assert cves[0].id == "CVE-2026-1111"
    assert cves[0].cvss_score == 9.8
    assert cves[0].cvss_severity == "CRITICAL"
    assert "CWE-78" in cves[0].cwe_ids


def test_filters_below_min_cvss(monkeypatch):
    payload = {
        "totalResults": 2,
        "vulnerabilities": [
            _vuln("CVE-2026-AAAA", "low-severity issue", cvss=3.1, severity="LOW"),
            _vuln("CVE-2026-BBBB", "critical RCE", cvss=9.5, severity="CRITICAL"),
        ],
    }
    _patch(monkeypatch, payload)

    result = nvd.run(SourceContext(min_cvss=7.0))
    ids = [c.id for c in result["cves"]]
    assert ids == ["CVE-2026-BBBB"]


def test_skips_known_cve_ids(monkeypatch):
    payload = {
        "totalResults": 1,
        "vulnerabilities": [_vuln("CVE-2026-DUPE", "already seen")],
    }
    _patch(monkeypatch, payload)

    ctx = SourceContext(known_cve_ids={"CVE-2026-DUPE"})
    result = nvd.run(ctx)
    assert result["cves"] == []


def test_fetch_failure_yields_empty(monkeypatch):
    def boom(_url):
        raise RuntimeError("503")

    monkeypatch.setattr(nvd, "fetch_json", boom)
    result = nvd.run(SourceContext())
    assert result == {"cves": [], "pocs": []}


def test_extract_cwes_dedups_and_sorts():
    weaknesses = [
        {"description": [{"value": "CWE-79"}, {"value": "CWE-89"}]},
        {"description": [{"value": "CWE-79"}]},  # dupe
        {"description": [{"value": "NOT-A-CWE"}]},  # ignored
    ]
    assert nvd._extract_cwes(weaknesses) == ["CWE-79", "CWE-89"]


def test_extract_cvss_prefers_v31():
    metrics = {
        "cvssMetricV31": [
            {
                "cvssData": {
                    "baseScore": 9.8,
                    "baseSeverity": "CRITICAL",
                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                }
            }
        ],
        "cvssMetricV2": [{"cvssData": {"baseScore": 5.0, "baseSeverity": "MEDIUM"}}],
    }
    score, sev, vec = nvd._extract_cvss(metrics)
    assert score == 9.8
    assert sev == "CRITICAL"
    assert vec == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def test_extract_cvss_missing_returns_none():
    assert nvd._extract_cvss({}) == (None, None, None)


def test_resolve_start_no_last_run_uses_default_lookback():
    now = datetime(2026, 6, 13, 12, 0, 0)
    start = nvd._resolve_start(now, None)
    assert (now - start).days >= 1


def test_resolve_start_respects_last_run_with_overlap():
    now = datetime(2026, 6, 13, 12, 0, 0)
    start = nvd._resolve_start(now, "2026-06-13T08:00:00Z")
    # 6h overlap before last_run
    assert start == datetime(2026, 6, 13, 2, 0, 0)


def test_resolve_start_floors_at_max_lookback():
    now = datetime(2026, 6, 13, 12, 0, 0)
    # last_run far in the past — should floor to NVD_MAX_LOOKBACK_DAYS
    start = nvd._resolve_start(now, "2020-01-01T00:00:00Z")
    assert (now - start).days <= nvd.NVD_MAX_LOOKBACK_DAYS


def test_source_metadata():
    assert nvd.NAME == "NVD CVE Feed"
    assert nvd.KIND == "cve"
    assert nvd.DEFAULT_ENABLED is True
