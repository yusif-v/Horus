"""OTX enricher tests — mock HTTP responses, test IOC-CVE linking."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from horus.core.context import EnricherContext
from horus.core.model import CVE
from horus.core.otx_client import (
    extract_cves_from_pulse,
    get_all_pulse_iocs,
    get_recent_pulses,
    parse_indicator_type,
)

# ─── Fixtures ──────────────────────────────────────────────────────────────


def _cve(cve_id: str) -> CVE:
    return CVE(
        id=cve_id,
        description="Test vulnerability",
        cvss_score=7.5,
        published_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )


def _mock_response(payload: dict, status_code: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = payload
    resp.raise_for_status = MagicMock()
    if status_code >= 400:
        from requests import HTTPError

        resp.raise_for_status.side_effect = HTTPError("mock error")
    return resp


def _sample_pulse() -> dict:
    return {
        "id": "65f8a1b234c8d90001a2b3c4",
        "name": "LockBit 3.0 CVE-2026-1234 Campaign",
        "description": (
            "Active exploitation of CVE-2026-1234 and CVE-2026-5678 "
            "by LockBit 3.0 ransomware group."
        ),
        "tags": ["CVE-2026-1234", "ransomware", "lockbit"],
        "malware_families": ["LockBit"],
        "indicators": [
            {
                "type": "IPv4",
                "indicator": "198.51.100.42",
                "id": 1,
                "role": "",
                "title": "C2 server",
            },
            {
                "type": "domain",
                "indicator": "evil.example.com",
                "id": 2,
                "role": "",
                "title": "malware host",
            },
            {
                "type": "FileHash-SHA256",
                "indicator": "aabbccdd" * 8,
                "id": 3,
                "role": "",
                "title": "payload hash",
            },
            {
                "type": "URL",
                "indicator": "http://evil.example.com/payload.exe",
                "id": 4,
                "role": "",
                "title": "download URL",
            },
        ],
        "TLP": "green",
        "modified": "2026-08-07T12:00:00.000Z",
        "author_name": "test_user",
        "created": "2026-08-07T10:00:00.000Z",
    }


def _sample_pulses_response() -> dict:
    return {
        "count": 1,
        "next": None,
        "previous": None,
        "results": [_sample_pulse()],
    }


# ─── parse_indicator_type ──────────────────────────────────────────────────


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("IPv4", "ip"),
        ("IPv6", "ip"),
        ("domain", "domain"),
        ("hostname", "domain"),
        ("URL", "url"),
        ("FileHash-MD5", "hash_md5"),
        ("FileHash-SHA1", "hash_sha1"),
        ("FileHash-SHA256", "hash_sha256"),
        ("email", "email"),
        ("CVE", "cve"),
        ("filepath", "path"),
        ("registry", "registry"),
        ("unknown_type", "unknown_type"),
    ],
)
def test_parse_indicator_type(raw, expected):
    assert parse_indicator_type(raw) == expected


# ─── extract_cves_from_pulse ───────────────────────────────────────────────


def test_extract_cves_from_tags():
    pulse = {"tags": ["CVE-2026-1234", "ransomware"], "name": "", "description": ""}
    cves = extract_cves_from_pulse(pulse)
    assert cves == ["CVE-2026-1234"]


def test_extract_cves_from_description():
    pulse = {
        "tags": [],
        "name": "Test",
        "description": "Exploits CVE-2026-5678 and CVE-2026-9999 in the wild.",
    }
    cves = extract_cves_from_pulse(pulse)
    assert "CVE-2026-5678" in cves
    assert "CVE-2026-9999" in cves


def test_extract_cves_from_name():
    pulse = {
        "tags": [],
        "name": "Campaign CVE-2026-0001",
        "description": "",
    }
    cves = extract_cves_from_pulse(pulse)
    assert cves == ["CVE-2026-0001"]


def test_extract_cves_deduplicates():
    pulse = {
        "tags": ["CVE-2026-1234"],
        "name": "CVE-2026-1234 Campaign",
        "description": "Details on CVE-2026-1234",
    }
    cves = extract_cves_from_pulse(pulse)
    assert cves == ["CVE-2026-1234"]


def test_extract_cves_empty():
    pulse = {"tags": [], "name": "", "description": ""}
    assert extract_cves_from_pulse(pulse) == []


def test_extract_cves_lowercase_normalized():
    pulse = {
        "tags": [],
        "name": "",
        "description": "exploiting cve-2026-4321",
    }
    cves = extract_cves_from_pulse(pulse)
    assert cves == ["CVE-2026-4321"]


# ─── get_recent_pulses ──────────────────────────────────────────────────────


def test_get_recent_pulses_success():
    mock_resp = _mock_response(_sample_pulses_response())
    with patch("horus.core.otx_client.requests.get", return_value=mock_resp) as get:
        pulses = get_recent_pulses(5)

    assert len(pulses) == 1
    assert pulses[0]["id"] == "65f8a1b234c8d90001a2b3c4"

    # Verify correct API call
    get.assert_called_once()
    call_kwargs = get.call_args
    assert "pulses/subscribed" in call_kwargs[0][0]
    headers = call_kwargs[1]["headers"]
    assert "X-OTX-API-KEY" in headers


def test_get_recent_pulses_empty():
    mock_resp = _mock_response({"count": 0, "results": []})
    with patch("horus.core.otx_client.requests.get", return_value=mock_resp):
        pulses = get_recent_pulses(5)
    assert pulses == []


def test_get_recent_pulses_network_failure():
    import requests

    with patch(
        "horus.core.otx_client.requests.get",
        side_effect=requests.ConnectionError("network down"),
    ):
        pulses = get_recent_pulses(5)
    assert pulses == []


def test_get_recent_pulses_null_response():
    mock_resp = _mock_response(None)
    mock_resp.json.side_effect = ValueError("no JSON")
    with patch("horus.core.otx_client.requests.get", return_value=mock_resp):
        pulses = get_recent_pulses(5)
    assert pulses == []


# ─── get_all_pulse_iocs ────────────────────────────────────────────────────


def test_get_all_pulse_iocs():
    pulse = _sample_pulse()
    iocs = get_all_pulse_iocs(pulse)

    assert len(iocs) == 4

    # Verify indicator types are parsed correctly
    values_by_type = {ioc["ioc_type"]: ioc["ioc_value"] for ioc in iocs}
    assert "198.51.100.42" in values_by_type["ip"]
    assert "evil.example.com" in values_by_type["domain"]
    assert "aabbccdd" * 8 in values_by_type["hash_sha256"]
    assert "http://evil.example.com/payload.exe" in values_by_type["url"]


def test_get_all_pulse_iocs_empty():
    assert get_all_pulse_iocs({"indicators": []}) == []


def test_get_all_pulse_iocs_skips_invalid():
    pulse = {
        "indicators": [
            {"type": "IPv4", "indicator": "1.2.3.4"},
            {"type": "domain"},  # missing indicator
            "not a dict",
        ]
    }
    iocs = get_all_pulse_iocs(pulse)
    assert len(iocs) == 1
    assert iocs[0]["ioc_value"] == "1.2.3.4"


def test_get_all_pulse_iocs_deduplicates():
    pulse = {
        "indicators": [
            {"type": "IPv4", "indicator": "1.2.3.4"},
            {"type": "IPv4", "indicator": "1.2.3.4"},
        ]
    }
    iocs = get_all_pulse_iocs(pulse)
    assert len(iocs) == 1


# ─── Enricher integration ──────────────────────────────────────────────────


def test_enricher_sets_otx_count():
    """Enricher should set otx_ioc_count when OTX returns pulses with CVEs."""
    cve = _cve("CVE-2026-1234")
    ctx = EnricherContext(cves=[cve], pocs=[])

    with patch(
        "horus.plugins.enrichers.otx.main.get_recent_pulses", return_value=[_sample_pulse()]
    ):
        from horus.plugins.enrichers.otx import main as otx

        otx.enrich(ctx)

    assert ctx.cves[0].otx_ioc_count == 4
    assert ctx.cves[0].trust_otx == 8.0  # 4 * 2
    assert ctx.cves[0].trust_score >= 8.0


def test_enricher_no_pulses():
    """Enricher should leave counts at 0 when no pulses found."""
    cve = _cve("CVE-2026-0001")
    ctx = EnricherContext(cves=[cve], pocs=[])

    with patch("horus.plugins.enrichers.otx.main.get_recent_pulses", return_value=[]):
        from horus.plugins.enrichers.otx import main as otx

        otx.enrich(ctx)

    assert ctx.cves[0].otx_ioc_count == 0
    assert ctx.cves[0].trust_otx == 0.0


def test_enricher_pulse_no_cves():
    """Enricher should skip pulses with no CVE references."""
    cve = _cve("CVE-2026-0001")
    ctx = EnricherContext(cves=[cve], pocs=[])

    pulse = {
        "id": "abc123",
        "name": "Generic malware",
        "description": "No CVE mentioned",
        "tags": ["malware"],
        "indicators": [{"type": "IPv4", "indicator": "1.2.3.4"}],
    }

    with patch("horus.plugins.enrichers.otx.main.get_recent_pulses", return_value=[pulse]):
        from horus.plugins.enrichers.otx import main as otx

        otx.enrich(ctx)

    assert ctx.cves[0].otx_ioc_count == 0


# ─── IOC persistence ──────────────────────────────────────────────────────


@pytest.fixture
def tmp_db(tmp_path):
    """Create a temp DB with the full schema."""
    import horus.storage.db as db_mod

    db_mod.DB_PATH = tmp_path / "test.db"
    conn = sqlite3.connect(str(db_mod.DB_PATH))
    schema_path = db_mod.SCHEMA_PATH
    conn.executescript(schema_path.read_text())
    # Insert a CVE to satisfy FK
    conn.execute(
        "INSERT INTO cve (id, description, first_seen, last_seen) VALUES (?, ?, ?, ?)",
        ("CVE-2026-1234", "test", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"),
    )
    conn.commit()
    yield conn
    conn.close()


def test_persist_otx_iocs(tmp_db):
    iocs = [
        {
            "ioc_value": "198.51.100.42",
            "ioc_type": "ip",
            "otx_type": "IPv4",
        },
        {
            "ioc_value": "evil.example.com",
            "ioc_type": "domain",
            "otx_type": "domain",
        },
    ]

    from horus.plugins.enrichers.otx.main import _persist_otx_iocs

    count = _persist_otx_iocs(tmp_db, "CVE-2026-1234", "pulse123", iocs)
    assert count == 2

    rows = tmp_db.execute(
        "SELECT ioc_value, ioc_type, source, cve_id FROM ioc_indicator WHERE cve_id = ?",
        ("CVE-2026-1234",),
    ).fetchall()
    assert len(rows) == 2
    values = {r[0] for r in rows}
    assert "198.51.100.42" in values
    assert "evil.example.com" in values
    assert all(r[2] == "otx" for r in rows)


def test_persist_empty_iocs(tmp_db):
    from horus.plugins.enrichers.otx.main import _persist_otx_iocs

    count = _persist_otx_iocs(tmp_db, "CVE-2026-1234", "pulse123", [])
    assert count == 0


def test_persist_skips_invalid_iocs(tmp_db):
    iocs = [
        {"ioc_value": "", "ioc_type": "ip"},  # empty value
        {"ioc_type": "domain"},  # missing value
    ]
    from horus.plugins.enrichers.otx.main import _persist_otx_iocs

    count = _persist_otx_iocs(tmp_db, "CVE-2026-1234", "pulse123", iocs)
    assert count == 0


def test_persist_upsert_no_duplicate(tmp_db):
    ioc = {
        "ioc_value": "198.51.100.42",
        "ioc_type": "ip",
        "otx_type": "IPv4",
    }
    from horus.plugins.enrichers.otx.main import _persist_otx_iocs

    _persist_otx_iocs(tmp_db, "CVE-2026-1234", "pulse123", [ioc])
    _persist_otx_iocs(tmp_db, "CVE-2026-1234", "pulse123", [ioc])

    rows = tmp_db.execute(
        "SELECT COUNT(*) FROM ioc_indicator WHERE ioc_value = ?",
        ("198.51.100.42",),
    ).fetchone()
    assert rows[0] == 1
