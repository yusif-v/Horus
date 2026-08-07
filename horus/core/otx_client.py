"""AlienVault OTX (Open Threat Exchange) API client.

https://otx.alienvault.com/api/v1/

Provides IOC-to-CVE linkage by fetching subscribed pulses and
extracting indicators with their associated CVE references.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any

import requests

BASE_URL = "https://otx.alienvault.com/api/v1/"
API_KEY = os.environ.get(
    "HORUS_OTX_API_KEY",
    "7afea1a468f99ced8a0436a191f43c0be29e55a68c4e0cbece2192a132cb7155",
)

log = logging.getLogger(__name__)

_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def _headers() -> dict[str, str]:
    return {"X-OTX-API-KEY": API_KEY, "Accept": "application/json"}


def _get(path: str, params: dict[str, Any] | None = None) -> dict[str, Any] | None:
    """Send a GET to OTX and return the parsed response dict.

    Returns None on any network / parse error so callers can degrade
    gracefully.
    """
    url = BASE_URL + path.lstrip("/")
    try:
        resp = requests.get(url, headers=_headers(), params=params, timeout=30)
        resp.raise_for_status()
        return resp.json()  # type: ignore[no-any-return]
    except requests.RequestException as e:
        log.warning("OTX request failed: %s", e)
        return None
    except (ValueError, KeyError) as e:
        log.warning("OTX response parse error: %s", e)
        return None


def get_recent_pulses(limit: int = 50) -> list[dict[str, Any]]:
    """Fetch recent subscribed pulses with IOCs."""
    data = _get("pulses/subscribed", params={"limit": limit, "page": 1})
    if not data:
        return []
    return data.get("results", [])  # type: ignore[no-any-return]


def get_pulse_indicators(pulse_id: str) -> list[dict[str, Any]]:
    """Get all indicators from a pulse."""
    data = _get(f"pulses/{pulse_id}")
    if not data:
        return []
    return data.get("indicators", [])  # type: ignore[no-any-return]


def extract_cves_from_pulse(pulse: dict[str, Any]) -> list[str]:
    """Extract CVE IDs from pulse tags, description, and name."""
    text_parts: list[str] = []
    text_parts.extend(pulse.get("tags", []) or [])
    text_parts.append(pulse.get("description", "") or "")
    text_parts.append(pulse.get("name", "") or "")

    text = " ".join(text_parts)
    cves = _CVE_PATTERN.findall(text)
    seen: set[str] = set()
    unique: list[str] = []
    for cve in cves:
        upper = cve.upper()
        if upper not in seen:
            seen.add(upper)
            unique.append(upper)
    return unique


def parse_indicator_type(otx_type: str) -> str:
    """Convert OTX indicator type to Horus type."""
    mapping = {
        "IPv4": "ip",
        "IPv6": "ip",
        "domain": "domain",
        "hostname": "domain",
        "URL": "url",
        "FileHash-MD5": "hash_md5",
        "FileHash-SHA1": "hash_sha1",
        "FileHash-SHA256": "hash_sha256",
        "email": "email",
        "CVE": "cve",
        "filepath": "path",
        "registry": "registry",
    }
    return mapping.get(otx_type, otx_type.lower())


def get_all_pulse_iocs(pulse: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract and normalize all IOCs from a pulse.

    Returns list of dicts with keys: ioc_value, ioc_type, otx_type, role.
    """
    indicators = pulse.get("indicators", []) or []
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    for ind in indicators:
        if not isinstance(ind, dict):
            continue
        value = ind.get("indicator", "")
        otx_type = ind.get("type", "")
        if not value or not otx_type:
            continue
        horus_type = parse_indicator_type(otx_type)
        key = (horus_type, value)
        if key in seen:
            continue
        seen.add(key)
        out.append(
            {
                "ioc_value": value,
                "ioc_type": horus_type,
                "otx_type": otx_type,
                "role": ind.get("role", ""),
                "title": ind.get("title", ""),
                "id": ind.get("id"),
            }
        )
    return out
