"""Enricher — Dark web threat intelligence via direct HTTP APIs.

Fetches ThreatFox IOCs for CVEs using the ThreatFox REST API.
Hudson Rock and MalwareBazaar enrichments are stubbed for future
direct-API integration.

Sources:
- ThreatFox (abuse.ch) — IOC search by IP/domain/hash/URL
- Hudson Rock (stub) — stealer log search by domain/email/IP
- MalwareBazaar (stub) — malware sample lookup by hash

All are optional enrichments. Missing API keys skip gracefully.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from horus.core.threatfox import search_c2, search_ioc

if TYPE_CHECKING:
    from horus.core.context import EnricherContext

log = logging.getLogger(__name__)

NAME = "Dark web intel"
DEFAULT_ENABLED = True


def _search_threatfox_for_cve(cve_id: str, affected: list[Any]) -> list[dict]:
    """Search ThreatFox for IOCs related to a CVE.

    Searches by:
    1. The CVE ID directly (mentions in tags/reference)
    2. Each affected product's vendor domain

    Returns list of normalised IOC dicts.
    """
    iocs: list[dict] = []
    seen_values: set[str] = set()

    # Search by CVE ID
    for ioc in search_ioc(cve_id):
        val = ioc.get("ioc_value", "")
        if val and val not in seen_values:
            seen_values.add(val)
            iocs.append(ioc)

    # Search by vendor/product domains
    for prod in affected:
        vendor = getattr(prod, "vendor", "") or ""
        if not vendor:
            continue
        domain = f"{vendor.lower()}.com"
        for ioc in search_c2(domain):
            val = ioc.get("ioc_value", "")
            if val and val not in seen_values:
                seen_values.add(val)
                iocs.append(ioc)

    return iocs


def _check_stealer_for_vendor(vendor: str, product: str) -> int:
    """Check Hudson Rock stealer logs for vendor.product.com domain.

    Stub — Hudson Rock direct API not yet integrated.
    Returns 0 until direct API is available.
    """
    return 0


def _compute_trust_score(cve: Any) -> float:
    """Compute trust score based on intel findings. Max 100."""
    score = 10.0  # Baseline: NVD confirmed (trust_nvd)

    # ThreatFox IOCs: each IOC adds confidence
    ioc_count = getattr(cve, "threatfox_ioc_count", 0)
    score += min(ioc_count * 2, 30)  # Cap at 30 from IOCs

    # Stealer logs: strong indicator of active exploitation
    stealer_hits = getattr(cve, "stealer_hits", 0)
    score += min(stealer_hits * 0.5, 20)  # Cap at 20 from stealer

    # KEV adds 20 (already reflected in reputation, add to trust)
    if getattr(cve, "kev", 0) == 1:
        score += 20

    # EPSS > 0.5 indicates exploitation activity
    epss = getattr(cve, "epss_score", 0)
    if epss and epss > 0.5:
        score += 15
    elif epss and epss > 0.1:
        score += 10

    return min(score, 100.0)


def enrich(ctx: EnricherContext) -> None:
    """Enrich CVEs with dark web intelligence. Mutates in-place.

    Adds fields:
    - threatfox_ioc_count: number of ThreatFox IOCs found
    - stealer_hits: compromised machines for vendor domains
    - trust_score: aggregate trust score 0-100
    - trust_threatfox, trust_nvd, trust_hudsonrock: trust breakdown
    """
    cves = ctx.cves

    for cve in cves:
        # Initialize trust fields (defaults in model, but ensure explicit)
        if not hasattr(cve, "threatfox_ioc_count"):
            cve.threatfox_ioc_count = 0
        if not hasattr(cve, "stealer_hits"):
            cve.stealer_hits = 0

        affected = getattr(cve, "affected", [])

        # ThreatFox: search for IOCs related to this CVE
        iocs = _search_threatfox_for_cve(cve.id, affected)
        ioc_count = len(iocs)
        if ioc_count > 0:
            cve.threatfox_ioc_count = ioc_count
            if not hasattr(cve, "trust_threatfox"):
                cve.trust_threatfox = 0
            cve.trust_threatfox = min(ioc_count * 2, 30)

        # Hudson Rock: check each affected product for stealer logs
        for prod in affected:
            if prod.vendor and prod.product:
                hits = _check_stealer_for_vendor(prod.vendor, prod.product)
                if hits > 0:
                    cve.stealer_hits += hits
                    if not hasattr(cve, "trust_hudsonrock"):
                        cve.trust_hudsonrock = 0
                    cve.trust_hudsonrock += min(hits * 0.5, 20)

        # Compute aggregate trust score
        cve.trust_score = _compute_trust_score(cve)

        if cve.threatfox_ioc_count or cve.stealer_hits:
            log.info(
                "Dark web: %s - %d IOCs, %d stealer hits, trust=%.0f",
                cve.id,
                cve.threatfox_ioc_count,
                cve.stealer_hits,
                cve.trust_score,
            )


def persist_threatfox_iocs(
    conn: Any,
    cve_id: str,
    iocs: list[dict[str, Any]],
) -> int:
    """Store ThreatFox IOCs in ``cve_threatfox_ioc`` and ``ioc_indicator``.

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
        threat_type = ioc.get("threat_type", "")
        first_seen = ioc.get("first_seen") or now
        last_seen = ioc.get("last_seen") or now

        # Upsert into cve_threatfox_ioc
        conn.execute(
            """INSERT INTO cve_threatfox_ioc
                   (cve_id, ioc_type, ioc_value, threat_type,
                    first_seen, last_seen)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(cve_id, ioc_value) DO UPDATE SET
                   last_seen = excluded.last_seen,
                   threat_type = excluded.threat_type
            """,
            (cve_id, ioc_type, ioc_value, threat_type, first_seen, last_seen),
        )

        # Also populate ioc_indicator for weekly reports
        try:
            conn.execute(
                """INSERT INTO ioc_indicator
                       (ioc_type, ioc_value, source, source_ref,
                        cve_id, first_seen, last_seen)
                   VALUES (?, ?, 'threatfox', ?, ?, ?, ?)
                   ON CONFLICT(ioc_type, ioc_value, source) DO UPDATE SET
                       last_seen = excluded.last_seen,
                       cve_id = COALESCE(excluded.cve_id, ioc_indicator.cve_id)
                """,
                (
                    ioc_type,
                    ioc_value,
                    ioc.get("reference", ""),
                    cve_id,
                    first_seen,
                    last_seen,
                ),
            )
            inserted += 1
        except Exception:
            # ioc_indicator may not exist in very old DBs — skip gracefully
            pass

    return inserted
