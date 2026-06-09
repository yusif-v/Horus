"""Enricher — CISA Known Exploited Vulnerabilities (KEV).

Fetches the CISA KEV catalog and marks matching CVEs.
"""

from __future__ import annotations

import sys

from ..net.http import fetch_json


NAME = "CISA KEV"
DEFAULT_ENABLED = True

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def enrich(ctx) -> None:
    """Mark CVEs that appear in the CISA KEV catalog. Mutates CVEs in-place."""
    cves = ctx.cves

    try:
        data = fetch_json(KEV_URL)
    except Exception as e:
        print(f"  [WARN] CISA KEV fetch failed: {e}", file=sys.stderr)
        return

    kev_ids = {entry.get("cveID", "").upper() for entry in data.get("vulnerabilities", [])}

    count = 0
    for cve in cves:
        if cve.id.upper() in kev_ids:
            cve.kev = 1
            count += 1

    if count:
        print(f"  KEV: {count} CVEs marked as known-exploited", file=sys.stderr)
