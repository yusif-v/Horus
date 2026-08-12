"""One-shot data backfills for rows persisted before later fixes landed.

Triggered by `horus --backfill={products,poc_cve,all}`.

- `products` walks every `product` row and applies the NVD vendor /
  product alias tables that ship with the current code. Old rows like
  `apache_software_foundation` collapse into `apache`; the cve_product
  join is re-pointed at the canonical product row, and the duplicate
  is deleted. Category is recomputed from the normalized name.

- `poc_cve` walks every stored PoC and re-runs `extract_cves` over the
  URL + description. Each extracted CVE-id that matches a stored CVE
  gets a `poc_cve` link. Closes the gap from the v0.9.0 fix where
  URL-scan only caught newly discovered PoCs.

Both backfills are idempotent — running twice is a no-op on the second
pass.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from ..core.classify import classify_product_category
from ..core.filters import extract_cves
from ..core.normalize import _normalize_product, _normalize_vendor
from . import db


@dataclass
class BackfillResult:
    products_normalized: int = 0
    products_merged: int = 0
    poc_cve_links_added: int = 0
    pocs_scanned: int = 0

    def summary(self) -> str:
        return (
            f"products: {self.products_normalized} normalized, "
            f"{self.products_merged} merged into canonical rows; "
            f"poc_cve: {self.poc_cve_links_added} links added "
            f"across {self.pocs_scanned} PoCs"
        )


def backfill_products(conn: sqlite3.Connection) -> tuple[int, int]:
    """Re-normalize vendor/product on every `product` row.

    Returns (normalized_in_place, merged_into_existing).
    """
    rows = conn.execute("SELECT id, vendor, product, category FROM product").fetchall()

    normalized_count = 0
    merged_count = 0

    for pid, vendor, product, _category in rows:
        new_vendor = _normalize_vendor(vendor)
        new_product = _normalize_product(product, new_vendor)
        if new_vendor == vendor and new_product == product:
            continue

        # Does a canonical row already exist?
        existing = conn.execute(
            "SELECT id FROM product WHERE vendor = ? AND product = ? AND id != ?",
            (new_vendor, new_product, pid),
        ).fetchone()

        new_category = classify_product_category(new_vendor, new_product)

        if existing:
            canonical_id = int(existing[0])
            # Re-point every cve_product row, dropping any that would
            # collide with an existing (cve_id, canonical_id) link.
            conn.execute(
                """UPDATE OR IGNORE cve_product
                   SET product_id = ?
                   WHERE product_id = ?""",
                (canonical_id, pid),
            )
            # Any rows that hit the unique conflict are still pointing
            # at the old pid — drop them, the canonical link already exists.
            conn.execute("DELETE FROM cve_product WHERE product_id = ?", (pid,))
            conn.execute("DELETE FROM product WHERE id = ?", (pid,))
            merged_count += 1
        else:
            conn.execute(
                "UPDATE product SET vendor = ?, product = ?, category = ? WHERE id = ?",
                (new_vendor, new_product, new_category, pid),
            )
            normalized_count += 1

    return normalized_count, merged_count


def backfill_poc_cve(conn: sqlite3.Connection) -> tuple[int, int]:
    """Scan every PoC's url + description for CVE refs and link to stored CVEs.

    Returns (links_added, pocs_scanned).
    """
    rows = conn.execute("SELECT url, description FROM poc").fetchall()
    known_cves = {row[0] for row in conn.execute("SELECT id FROM cve")}

    links_added = 0
    for url, description in rows:
        text = f"{url} {description or ''}"
        for cve_id in extract_cves(text):
            if cve_id.upper() not in known_cves:
                continue
            cur = conn.execute(
                "INSERT OR IGNORE INTO poc_cve (poc_url, cve_id) VALUES (?, ?)",
                (url, cve_id.upper()),
            )
            if cur.rowcount > 0:
                links_added += 1

    return links_added, len(rows)


def run_backfill(which: str) -> BackfillResult:
    """Entry point. `which` is 'products', 'poc_cve', or 'all'."""
    if which not in {"products", "poc_cve", "all"}:
        raise ValueError(f"unknown backfill target: {which!r}")

    db.initialize()
    result = BackfillResult()

    with db.connect() as conn:
        if which in ("products", "all"):
            normalized, merged = backfill_products(conn)
            result.products_normalized = normalized
            result.products_merged = merged

        if which in ("poc_cve", "all"):
            links, scanned = backfill_poc_cve(conn)
            result.poc_cve_links_added = links
            result.pocs_scanned = scanned

    return result
