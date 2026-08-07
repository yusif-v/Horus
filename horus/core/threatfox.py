"""ThreatFox API client — direct HTTP calls to abuse.ch.

https://threatfox.abuse.ch/api/

All queries are POST-only with JSON body. Authentication uses the
``Auth-Key`` HTTP header.

Supported queries:
- get_iocs: recent IOCs
- search_ioc: search for a specific IOC
- search_hash: search by file hash
- taginfo: IOCs by tag
- malwareinfo: IOCs by malware family
"""

from __future__ import annotations

import logging
import os
from typing import Any

import requests

API_URL = "https://threatfox-api.abuse.ch/api/v1/"
API_KEY = os.environ.get(
    "HORUS_THREATFOX_API_KEY",
    "5c31475de44c048c0d17cc8b254d10133e2f190f66952d29",
)

log = logging.getLogger(__name__)


def _headers() -> dict[str, str]:
    """Return authentication + content-type headers."""
    return {
        "Content-Type": "application/json",
        "Auth-Key": API_KEY,
    }


def _post(payload: dict[str, Any]) -> dict[str, Any] | None:
    """Send a POST to ThreatFox and return the parsed response dict.

    Returns None on any network / parse error so callers can degrade
    gracefully.
    """
    try:
        resp = requests.post(
            API_URL,
            json=payload,
            headers=_headers(),
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()  # type: ignore[no-any-return]
    except requests.RequestException as e:
        log.warning("ThreatFox request failed: %s", e)
        return None
    except (ValueError, KeyError) as e:
        log.warning("ThreatFox response parse error: %s", e)
        return None


def _extract_iocs(data: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    """Normalise ThreatFox response ``data`` into a flat list of IOC dicts."""
    if not data:
        return []
    out: list[dict[str, Any]] = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        ioc_value = entry.get("ioc", "")
        if not ioc_value:
            continue
        ioc_type_raw = entry.get("ioc_type", "")
        ioc_type = _map_ioc_type(ioc_type_raw)
        out.append(
            {
                "ioc_value": ioc_value,
                "ioc_type": ioc_type,
                "threat_type": entry.get("threat_type", ""),
                "malware": entry.get("malware_printable", entry.get("malware", "")),
                "first_seen": entry.get("first_seen", ""),
                "last_seen": entry.get("last_seen", ""),
                "confidence": entry.get("confidence_level", 0),
                "reference": entry.get("reference", ""),
                "tags": entry.get("tags", []),
                "raw": entry,
            }
        )
    return out


def _map_ioc_type(raw: str) -> str:
    """Map ThreatFox ioc_type strings to Horus ioc_indicator values."""
    mapping = {
        "ip_address": "ip",
        "ip:port": "ip",
        "domain": "domain",
        "url": "url",
        "md5_hash": "hash_md5",
        "sha1_hash": "hash_sha1",
        "sha256_hash": "hash_sha256",
    }
    return mapping.get(raw, raw)


def search_ioc(ioc_value: str, exact: bool = False) -> list[dict[str, Any]]:
    """Search ThreatFox for a specific IOC value.

    Returns a list of normalised IOC dicts (may be empty).
    """
    result = _post(
        {
            "query": "search_ioc",
            "search_term": ioc_value,
            "exact_match": exact,
        }
    )
    if not result:
        return []
    status = result.get("query_status", "")
    if status != "ok":
        log.warning("ThreatFox search_ioc returned status=%s", status)
        return []
    return _extract_iocs(result.get("data", []))


def search_hash(file_hash: str) -> list[dict[str, Any]]:
    """Search ThreatFox for IOCs matching an MD5 or SHA256 hash."""
    result = _post({"query": "search_hash", "hash": file_hash})
    if not result:
        return []
    status = result.get("query_status", "")
    if status != "ok":
        log.warning("ThreatFox search_hash returned status=%s", status)
        return []
    return _extract_iocs(result.get("data", []))


def search_c2(infrastructure: str) -> list[dict[str, Any]]:
    """Search for C2 infrastructure matching an IP or domain.

    Uses ``search_ioc`` with exact match against the IP or domain.
    """
    return search_ioc(infrastructure, exact=True)


def get_recent_iocs(days: int = 7) -> list[dict[str, Any]]:
    """Fetch IOCs added to ThreatFox in the last ``days`` days (max 7)."""
    days = min(max(days, 1), 7)  # clamp to API limits
    result = _post({"query": "get_iocs", "days": days})
    if not result:
        return []
    status = result.get("query_status", "")
    if status != "ok":
        log.warning("ThreatFox get_iocs returned status=%s", status)
        return []
    return _extract_iocs(result.get("data", []))


def search_by_tag(tag: str, limit: int = 100) -> list[dict[str, Any]]:
    """Search for IOCs tagged with ``tag`` (e.g. "CobaltStrike")."""
    result = _post({"query": "taginfo", "tag": tag, "limit": limit})
    if not result:
        return []
    status = result.get("query_status", "")
    if status != "ok":
        log.warning("ThreatFox taginfo returned status=%s", status)
        return []
    return _extract_iocs(result.get("data", []))


def search_by_malware(malware: str, limit: int = 100) -> list[dict[str, Any]]:
    """Search for IOCs associated with a malware family."""
    result = _post(
        {
            "query": "malwareinfo",
            "malware": malware,
            "limit": limit,
        }
    )
    if not result:
        return []
    status = result.get("query_status", "")
    if status != "ok":
        log.warning("ThreatFox malwareinfo returned status=%s", status)
        return []
    return _extract_iocs(result.get("data", []))


def search_by_cve(cve_id: str) -> list[dict[str, Any]]:
    """Search for IOCs that reference a CVE in tags or reference fields.

    ThreatFox has no native CVE search, so we use ``search_ioc`` with
    the CVE string and filter results that mention the CVE.
    """
    direct = search_ioc(cve_id)
    # Filter to entries that actually mention the CVE in tags or reference
    matched = [
        ioc
        for ioc in direct
        if cve_id.lower() in " ".join(ioc.get("tags") or []).lower()
        or cve_id.lower() in (ioc.get("reference") or "").lower()
    ]
    return matched if matched else direct
