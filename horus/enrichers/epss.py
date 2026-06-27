"""Enricher — EPSS (Exploit Prediction Scoring System).

Fetches EPSS scores from the daily CSV dump and enriches CVEs.
The CSV is ~5MB compressed, downloaded once per run.

After scoring new CVEs, backfills ALL unscored CVEs in the database
to ensure comprehensive coverage.
"""

from __future__ import annotations

import gzip
import hashlib
import logging
import urllib.request

from ..storage.db import append_epss_history

logger = logging.getLogger(__name__)

NAME = "EPSS Scores"
DEFAULT_ENABLED = True

# EPSS daily CSV dump (compressed, ~5MB)
EPSS_CSV_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
EPSS_CHECKSUM_URL = EPSS_CSV_URL + ".sha256"


def _verify_checksum(raw: bytes, expected_hex: str) -> bool:
    """Verify SHA256 checksum of downloaded data. Returns True if valid."""
    actual = hashlib.sha256(raw).hexdigest()
    return actual == expected_hex.strip().lower()


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
        logger.warning("EPSS: cannot download CSV: %s", e)
        return {}

    # Checksum verification (non-blocking)
    try:
        checksum_req = urllib.request.Request(
            EPSS_CHECKSUM_URL,
            headers={
                "User-Agent": "Horus-PoC-Scanner/0.8",
            },
        )
        with urllib.request.urlopen(checksum_req, timeout=10) as checksum_resp:
            expected_hex = checksum_resp.read().decode("ascii").strip()
        if _verify_checksum(raw, expected_hex):
            logger.debug("EPSS: checksum verification passed")
        else:
            logger.warning("EPSS: checksum mismatch — data may be corrupted, proceeding anyway")
    except Exception as e:
        logger.debug("EPSS: checksum endpoint unreachable: %s", e)

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
        logger.info("EPSS: %d/%d CVEs enriched (current batch)", count, len(cves))

    # Backfill: score ALL previously-unscored CVEs already in the DB.
    from ..storage import db as _db

    try:
        with _db.connect() as conn:
            _backfill_db(conn, scores)
    except Exception as e:
        logger.warning("EPSS backfill skipped: %s", e)


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
        logger.info("EPSS backfill: %d unscored CVEs updated", updated)
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
