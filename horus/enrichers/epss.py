"""Enricher — EPSS (Exploit Prediction Scoring System).

Fetches EPSS scores from FIRST.org and enriches CVEs.
"""

from __future__ import annotations

from ..sources.http import fetch_json


NAME = "EPSS Scores"
DEFAULT_ENABLED = True

EPSS_API_URL = "https://api.first.org/epss/v2/"
EPSS_BATCH_SIZE = 15


def enrich(cves, pocs, args, **kwargs) -> None:
    """Enrich CVEs with EPSS scores. Mutates CVEs in-place."""
    cve_ids = [c.id for c in cves if c.id]
    if not cve_ids:
        return

    scores: dict[str, float] = {}
    for i in range(0, len(cve_ids), EPSS_BATCH_SIZE):
        batch = cve_ids[i : i + EPSS_BATCH_SIZE]
        url = f"{EPSS_API_URL}?cve={','.join(batch)}"
        try:
            data = fetch_json(url)
        except Exception as e:
            print(f"  [WARN] EPSS fetch failed: {e}", file=__import__("sys").stderr)
            continue
        for entry in data.get("data", []):
            cve = entry.get("cve", "").upper()
            epss = entry.get("epss")
            if cve and epss is not None:
                try:
                    scores[cve] = float(epss)
                except (ValueError, TypeError):
                    pass

    count = 0
    for cve in cves:
        if cve.id in scores:
            cve.epss_score = scores[cve.id]
            count += 1

    if count:
        print(f"  EPSS: {count} CVEs enriched", file=__import__("sys").stderr)
