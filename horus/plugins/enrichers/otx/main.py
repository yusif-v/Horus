"""Enricher — AlienVault OTX (Open Threat Exchange) IOC-CVE linking.

Fetches recent OTX pulses and stores IOC-to-CVE relationships in the
ioc_indicator table. This provides real-world threat intelligence
linking indicators to specific vulnerabilities.

Source: AlienVault OTX (https://otx.alienvault.com)
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from horus.core.otx_client import (
    extract_cves_from_pulse,
    get_all_pulse_iocs,
    get_recent_pulses,
)

if TYPE_CHECKING:
    from horus.core.context import EnricherContext

log = logging.getLogger(__name__)

NAME = "AlienVault OTX"
DEFAULT_ENABLED = True


def _persist_otx_iocs(
    conn: Any,
    cve_id: str,
    pulse_id: str,
    iocs: list[dict[str, Any]],
) -> int:
    """Store OTX IOCs in ioc_indicator with CVE linkage.

    Returns the number of new rows inserted.
    """
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    inserted = 0

    for ioc in iocs:
        ioc_value = ioc.get("ioc_value", "")
        if not ioc_value:
            continue
        ioc_type = ioc.get("ioc_type", "unknown")

        try:
            conn.execute(
                """INSERT INTO ioc_indicator
                       (ioc_type, ioc_value, source, source_ref,
                        cve_id, first_seen, last_seen)
                   VALUES (?, ?, 'otx', ?, ?, ?, ?)
                   ON CONFLICT(ioc_type, ioc_value, source) DO UPDATE SET
                       last_seen = excluded.last_seen,
                       cve_id = COALESCE(excluded.cve_id, ioc_indicator.cve_id),
                       source_ref = COALESCE(excluded.source_ref, ioc_indicator.source_ref)
                """,
                (
                    ioc_type,
                    ioc_value,
                    pulse_id,
                    cve_id,
                    now,
                    now,
                ),
            )
            inserted += 1
        except Exception:
            pass

    return inserted


def enrich(ctx: EnricherContext) -> None:
    """Fetch OTX pulses and link IOCs to CVEs. Mutates CVEs in-place.

    For each OTX pulse:
    - Extract CVEs from tags/name/description
    - Extract all IOCs (IPs, domains, hashes, URLs)
    - Link each IOC to each CVE mentioned in the pulse
    - Persist to ioc_indicator table

    Sets otx_ioc_count and trust_otx on CVEs with OTX-sourced IOCs.
    """
    from horus.storage.db import connect

    try:
        pulses = get_recent_pulses(limit=50)
    except Exception as e:
        log.warning("OTX pulse fetch failed: %s", e)
        return

    if not pulses:
        return

    cve_ioc_counts: dict[str, int] = {}
    total_iocs = 0
    total_cve_links = 0

    with connect() as conn:
        for pulse in pulses:
            pulse_id = pulse.get("id", "")
            if not pulse_id:
                continue

            cves = extract_cves_from_pulse(pulse)
            if not cves:
                continue

            iocs = get_all_pulse_iocs(pulse)
            if not iocs:
                continue

            for cve in cves:
                total_iocs += _persist_otx_iocs(conn, cve, pulse_id, iocs)
                cve_ioc_counts[cve] = cve_ioc_counts.get(cve, 0) + len(iocs)
                total_cve_links += 1

    # Update CVE trust scores for known CVEs
    for cve in ctx.cves:
        count = cve_ioc_counts.get(cve.id.upper(), 0)
        if count > 0:
            cve.otx_ioc_count = count
            if not hasattr(cve, "trust_otx"):
                cve.trust_otx = 0.0
            cve.trust_otx = min(count * 2.0, 25.0)
            cve.trust_score = getattr(cve, "trust_score", 0) + cve.trust_otx

    if total_iocs:
        log.info(
            "OTX: %d IOCs with CVE links from %d pulses (%d CVE associations)",
            total_iocs,
            len(pulses),
            total_cve_links,
        )
