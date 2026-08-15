"""Enricher — CISA Known Exploited Vulnerabilities (KEV).

Fetches the CISA KEV catalog and marks matching CVEs.
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

from horus.net.http import fetch_json

if TYPE_CHECKING:
    from horus.core.context import EnricherContext

NAME = "CISA KEV"
DEFAULT_ENABLED = True

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def enrich(ctx: EnricherContext) -> None:
    """Mark CVEs that appear in the CISA KEV catalog. Mutates CVEs in-place.

    Also captures dueDate into cve.kev_due_date for overdue/due-soon tracking.
    """
    cves = ctx.cves

    try:
        data = fetch_json(KEV_URL)
    except Exception as e:
        print(f"  [WARN] CISA KEV fetch failed: {e}", file=sys.stderr)
        return

    # Build lookup: CVE ID -> dueDate
    kev_data: dict[str, str | None] = {}
    for entry in data.get("vulnerabilities", []):
        cve_id = entry.get("cveID", "").upper()
        due_date = entry.get("dueDate")
        if cve_id:
            kev_data[cve_id] = due_date

    count = 0
    for cve in cves:
        if cve.id.upper() in kev_data:
            cve.kev = 1
            cve.kev_due_date = kev_data[cve.id.upper()]
            count += 1

    if count:
        print(f"  KEV: {count} CVEs marked as known-exploited", file=sys.stderr)
