"""Enricher — EPSS (Exploit Prediction Scoring System).

Fetches EPSS scores from the daily CSV dump and enriches CVEs.
The CSV is ~5MB compressed, downloaded once per run.

After scoring new CVEs, backfills ALL unscored CVEs in the database
to ensure comprehensive coverage.
"""

from __future__ import annotations

import gzip
import sys
import urllib.request

from ..storage.db import append_epss_history

NAME = "EPSS Scores"
DEFAULT_ENABLED = True

# EPSS daily CSV dump (compressed, ~5MB)
EPSS_CSV_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"


def _download_epss_scores() -> dict[str, float]:
    """Download and parse the EPSS CSV. Returns {cve_id: epss_score}."""
    try:
        req = urllib.request.Request(
            EPSS_CSV_URL,
            headers={
                "User-Agent": "Horus-PoC-Scanner/0.8",
            },
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            raw = resp.read()
    except Exception as e:
        print(f"  [WARN] EPSS: cannot download CSV: {e}", file=sys.stderr)
        return {}

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

    return scores


def enrich(ctx) -> None:
    """Enrich CVEs with EPSS scores. Mutates CVEs in-place.

    After scoring the current batch, backfills ALL unscored CVEs
    in the database from the same CSV download.
    """
    cves = ctx.cves
    scores = _download_epss_scores()
    if not scores:
        return

    # Score the current batch of CVE objects
    count = 0
    for cve in cves:
        if cve.id.upper() in scores:
            cve.epss_score = scores[cve.id.upper()]
            count += 1

    if count:
        print(f"  EPSS: {count}/{len(cves)} CVEs enriched (current batch)", file=sys.stderr)

    # Backfill: score ALL previously-unscored CVEs already in the DB.
    from ..storage import db as _db

    try:
        with _db.connect() as conn:
            _backfill_db(conn, scores)
    except Exception as e:
        print(f"  [WARN] EPSS backfill skipped: {e}", file=sys.stderr)


def _backfill_db(conn, scores: dict[str, float]) -> int:
    """Backfill EPSS scores + append history for all known CVEs."""
    all_cves = conn.execute("SELECT id, epss_score FROM cve").fetchall()
    updated = 0
    for cve_id, current in all_cves:
        cve_upper = cve_id.upper()
        if cve_upper not in scores:
            continue
        new_score = scores[cve_upper]
        if current is None:
            conn.execute("UPDATE cve SET epss_score = ? WHERE id = ?", (new_score, cve_id))
            updated += 1
        append_epss_history(conn, cve_id, new_score)
    if updated:
        print(f"  EPSS backfill: {updated} unscored CVEs updated", file=sys.stderr)
    return updated


def backfill_all(conn) -> int:
    """One-time backfill: score ALL unscored CVEs in the DB.

    This is the entry point for the --backfill-epss CLI flag.
    Returns the number of CVEs updated.
    """
    scores = _download_epss_scores()
    if not scores:
        return 0
    return _backfill_db(conn, scores)
