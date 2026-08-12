"""ThreatFox enricher tests — mock HTTP responses, test IOC persistence."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from horus.core.context import EnricherContext
from horus.core.model import CVE, AffectedProduct
from horus.core.threatfox import (
    _extract_iocs,
    _map_ioc_type,
    get_recent_iocs,
    search_c2,
    search_ioc,
)
from horus.plugins.enrichers.darkweb import main as darkweb

# ─── Fixtures ──────────────────────────────────────────────────────────────


def _cve(cve_id: str, affected: list[AffectedProduct] | None = None) -> CVE:
    return CVE(
        id=cve_id,
        description="Test vulnerability",
        cvss_score=7.5,
        published_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        affected=affected or [],
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


def _sample_threatfox_response() -> dict:
    return {
        "query_status": "ok",
        "data": [
            {
                "id": "12345",
                "ioc": "198.51.100.42",
                "ioc_type": "ip_address",
                "threat_type": "botnet_cc",
                "malware": "Cobalt Strike",
                "malware_printable": "Cobalt Strike",
                "first_seen": "2026-08-01 12:00:00",
                "last_seen": "2026-08-05 12:00:00",
                "confidence_level": 90,
                "reference": "https://example.com/report",
                "tags": ["cobalt-strike", "c2"],
            },
            {
                "id": "12346",
                "ioc": "evil.example.com",
                "ioc_type": "domain",
                "threat_type": "malware_distribution",
                "malware": "Emotet",
                "malware_printable": "Emotet",
                "first_seen": "2026-08-02 08:00:00",
                "last_seen": "2026-08-06 14:00:00",
                "confidence_level": 75,
                "reference": "",
                "tags": ["emotet"],
            },
        ],
    }


# ─── search_ioc ────────────────────────────────────────────────────────────


def test_search_ioc_success():
    mock_resp = _mock_response(_sample_threatfox_response())
    with patch("horus.core.threatfox.requests.post", return_value=mock_resp) as post:
        result = search_ioc("198.51.100.42")

    assert len(result) == 2
    assert result[0]["ioc_value"] == "198.51.100.42"
    assert result[0]["ioc_type"] == "ip"
    assert result[1]["ioc_value"] == "evil.example.com"
    assert result[1]["ioc_type"] == "domain"

    # Verify correct API call
    post.assert_called_once()
    call_kwargs = post.call_args
    assert call_kwargs[0][0] == "https://threatfox-api.abuse.ch/api/v1/"
    body = call_kwargs[1]["json"]
    assert body["query"] == "search_ioc"
    assert body["search_term"] == "198.51.100.42"
    headers = call_kwargs[1]["headers"]
    assert "Auth-Key" in headers


def test_search_ioc_empty_response():
    mock_resp = _mock_response({"query_status": "ok", "data": []})
    with patch("horus.core.threatfox.requests.post", return_value=mock_resp):
        result = search_ioc("1.2.3.4")
    assert result == []


def test_search_ioc_api_error():
    mock_resp = _mock_response({"query_status": "error", "data": None})
    with patch("horus.core.threatfox.requests.post", return_value=mock_resp):
        result = search_ioc("1.2.3.4")
    assert result == []


def test_search_ioc_network_failure():
    import requests

    with patch(
        "horus.core.threatfox.requests.post",
        side_effect=requests.ConnectionError("network down"),
    ):
        result = search_ioc("1.2.3.4")
    assert result == []


# ─── search_c2 ─────────────────────────────────────────────────────────────


def test_search_c2_success():
    mock_resp = _mock_response(_sample_threatfox_response())
    with patch("horus.core.threatfox.requests.post", return_value=mock_resp) as post:
        result = search_c2("example.com")

    assert len(result) == 2
    body = post.call_args[1]["json"]
    assert body["query"] == "search_ioc"
    assert body["search_term"] == "example.com"
    assert body["exact_match"] is True


def test_search_c2_empty():
    mock_resp = _mock_response({"query_status": "ok", "data": []})
    with patch("horus.core.threatfox.requests.post", return_value=mock_resp):
        result = search_c2("clean.example.com")
    assert result == []


# ─── get_recent_iocs ───────────────────────────────────────────────────────


def test_get_recent_iocs_success():
    mock_resp = _mock_response(_sample_threatfox_response())
    with patch("horus.core.threatfox.requests.post", return_value=mock_resp) as post:
        result = get_recent_iocs(7)

    assert len(result) == 2
    body = post.call_args[1]["json"]
    assert body["query"] == "get_iocs"
    assert body["days"] == 7


def test_get_recent_iocs_default_days():
    mock_resp = _mock_response({"query_status": "ok", "data": []})
    with patch("horus.core.threatfox.requests.post", return_value=mock_resp) as post:
        get_recent_iocs()
    body = post.call_args[1]["json"]
    assert body["days"] == 7


def test_get_recent_iocs_failure():
    import requests

    with patch(
        "horus.core.threatfox.requests.post",
        side_effect=requests.Timeout("timeout"),
    ):
        result = get_recent_iocs(3)
    assert result == []


# ─── _extract_iocs ────────────────────────────────────────────────────────


def test_extract_iocs_empty():
    assert _extract_iocs([]) == []
    assert _extract_iocs(None) == []  # type: ignore[arg-type]


def test_extract_iocs_skips_invalid():
    data = [
        {"ioc": "1.2.3.4", "ioc_type": "ip_address"},
        {"ioc_type": "domain"},  # missing ioc
        "not a dict",
    ]
    result = _extract_iocs(data)
    assert len(result) == 1
    assert result[0]["ioc_value"] == "1.2.3.4"


# ─── _map_ioc_type ────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("ip_address", "ip"),
        ("domain", "domain"),
        ("url", "url"),
        ("md5_hash", "hash_md5"),
        ("sha1_hash", "hash_sha1"),
        ("sha256_hash", "hash_sha256"),
        ("unknown_type", "unknown_type"),
    ],
)
def test_map_ioc_type(raw, expected):
    assert _map_ioc_type(raw) == expected


# ─── Enricher integration ──────────────────────────────────────────────────


def test_enricher_sets_threatfox_count():
    """Enricher should set threatfox_ioc_count when ThreatFox returns IOCs."""
    cve = _cve("CVE-2026-9999")
    ctx = EnricherContext(cves=[cve], pocs=[])

    with (
        patch.object(
            darkweb,
            "search_ioc",
            return_value=[
                {"ioc_value": "1.2.3.4", "ioc_type": "ip"},
                {"ioc_value": "evil.com", "ioc_type": "domain"},
            ],
        ),
        patch.object(darkweb, "search_c2", return_value=[]),
    ):
        darkweb.enrich(ctx)

    assert ctx.cves[0].threatfox_ioc_count == 2
    assert ctx.cves[0].trust_threatfox == 4.0  # 2 * 2
    assert ctx.cves[0].trust_score > 10.0


def test_enricher_no_iocs():
    """Enricher should leave counts at 0 when no IOCs found."""
    cve = _cve("CVE-2026-0001")
    ctx = EnricherContext(cves=[cve], pocs=[])

    with (
        patch.object(darkweb, "search_ioc", return_value=[]),
        patch.object(darkweb, "search_c2", return_value=[]),
    ):
        darkweb.enrich(ctx)

    assert ctx.cves[0].threatfox_ioc_count == 0


def test_enricher_with_affected_products():
    """Enricher should search C2 for each affected vendor domain."""
    cve = _cve(
        "CVE-2026-1234",
        affected=[AffectedProduct(vendor="Acme", product="Widget")],
    )
    ctx = EnricherContext(cves=[cve], pocs=[])

    def fake_search_ioc(term):
        return []

    def fake_search_c2(infra):
        if "acme.com" in infra:
            return [{"ioc_value": "5.6.7.8", "ioc_type": "ip"}]
        return []

    with (
        patch.object(darkweb, "search_ioc", side_effect=fake_search_ioc),
        patch.object(darkweb, "search_c2", side_effect=fake_search_c2),
    ):
        darkweb.enrich(ctx)

    assert ctx.cves[0].threatfox_ioc_count == 1


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
        ("CVE-2026-9999", "test", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"),
    )
    conn.commit()
    yield conn
    conn.close()


def test_persist_threatfox_iocs(tmp_db):
    iocs = [
        {
            "ioc_value": "1.2.3.4",
            "ioc_type": "ip",
            "threat_type": "botnet_cc",
            "first_seen": "2026-08-01T12:00:00Z",
            "last_seen": "2026-08-05T12:00:00Z",
            "reference": "https://example.com",
        },
        {
            "ioc_value": "evil.com",
            "ioc_type": "domain",
            "threat_type": "malware_distribution",
            "first_seen": "2026-08-02T08:00:00Z",
            "last_seen": "2026-08-06T14:00:00Z",
            "reference": "",
        },
    ]

    count = darkweb.persist_threatfox_iocs(tmp_db, "CVE-2026-9999", iocs)
    assert count == 2

    # Verify cve_threatfox_ioc rows
    rows = tmp_db.execute(
        "SELECT ioc_value, ioc_type FROM cve_threatfox_ioc WHERE cve_id = ?",
        ("CVE-2026-9999",),
    ).fetchall()
    assert len(rows) == 2
    values = {r[0] for r in rows}
    assert "1.2.3.4" in values
    assert "evil.com" in values

    # Verify ioc_indicator rows
    ioc_rows = tmp_db.execute(
        "SELECT ioc_value, source FROM ioc_indicator WHERE cve_id = ?",
        ("CVE-2026-9999",),
    ).fetchall()
    assert len(ioc_rows) == 2
    assert all(r[1] == "threatfox" for r in ioc_rows)


def test_persist_empty_iocs(tmp_db):
    count = darkweb.persist_threatfox_iocs(tmp_db, "CVE-2026-9999", [])
    assert count == 0


def test_persist_skips_invalid_iocs(tmp_db):
    iocs = [
        {"ioc_value": "", "ioc_type": "ip"},  # empty value
        {"ioc_type": "domain"},  # missing value
    ]
    count = darkweb.persist_threatfox_iocs(tmp_db, "CVE-2026-9999", iocs)
    assert count == 0


def test_persist_upsert_no_duplicate(tmp_db):
    ioc = {
        "ioc_value": "1.2.3.4",
        "ioc_type": "ip",
        "threat_type": "botnet_cc",
        "first_seen": "2026-08-01T12:00:00Z",
        "last_seen": "2026-08-05T12:00:00Z",
        "reference": "",
    }
    darkweb.persist_threatfox_iocs(tmp_db, "CVE-2026-9999", [ioc])
    darkweb.persist_threatfox_iocs(tmp_db, "CVE-2026-9999", [ioc])

    rows = tmp_db.execute(
        "SELECT COUNT(*) FROM cve_threatfox_ioc WHERE cve_id = ?",
        ("CVE-2026-9999",),
    ).fetchone()
    assert rows[0] == 1  # still 1, not duplicated
