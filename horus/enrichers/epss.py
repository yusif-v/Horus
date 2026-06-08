"""Enricher — EPSS (Exploit Prediction Scoring System).

Fetches EPSS scores from the daily CSV dump and enriches CVEs.
The CSV is ~5MB compressed, downloaded once per run.
"""

from __future__ import annotations

import gzip
import io
import sys
import urllib.request


NAME = "EPSS Scores"
DEFAULT_ENABLED = True

# EPSS daily CSV dump (compressed, ~5MB)
EPSS_CSV_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"


def enrich(cves, pocs, args, **kwargs) -> None:
    """Enrich CVEs with EPSS scores. Mutates CVEs in-place."""
    cve_ids = {c.id.upper() for c in cves if c.id}
    if not cve_ids:
        return

    # Download the CSV dump
    try:
        req = urllib.request.Request(EPSS_CSV_URL, headers={
            "User-Agent": "Horus-PoC-Scanner/0.7",
        })
        with urllib.request.urlopen(req, timeout=60) as resp:
            raw = resp.read()
    except Exception as e:
        print(f"  [WARN] EPSS: cannot download CSV: {e}", file=sys.stderr)
        return

    # Decompress and parse
    try:
        csv_text = gzip.decompress(raw).decode("utf-8", errors="replace")
    except Exception:
        # Maybe it's not compressed
        csv_text = raw.decode("utf-8", errors="replace")

    # Build score lookup: cve_id -> epss_score
    scores: dict[str, float] = {}
    for line in csv_text.splitlines():
        # CSV format: cve,epss,percentile
        # Skip header lines starting with #
        if line.startswith("#") or not line.strip():
            continue
        parts = line.split(",", 2)
        if len(parts) >= 2:
            cve = parts[0].strip().upper()
            try:
                epss = float(parts[1].strip())
                scores[cve] = epss
            except ValueError:
                continue

    count = 0
    for cve in cves:
        if cve.id.upper() in scores:
            cve.epss_score = scores[cve.id.upper()]
            count += 1

    if count:
        print(f"  EPSS: {count}/{len(cves)} CVEs enriched", file=sys.stderr)
