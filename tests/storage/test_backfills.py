"""Data backfills: product normalization + poc_cve link recovery."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

import pytest

from horus.storage import backfills, db


@pytest.fixture()
def fresh_db_path(tmp_path, monkeypatch):
    path = tmp_path / "horus.db"
    monkeypatch.setattr(db, "DB_PATH", path)
    db.initialize()
    return path


@pytest.fixture()
def conn(fresh_db_path):
    c = sqlite3.connect(fresh_db_path)
    c.execute("PRAGMA foreign_keys = ON")
    yield c
    c.close()


def _now() -> str:
    return datetime.now(timezone.utc).replace(tzinfo=None).isoformat()


def _add_cve(conn, cve_id: str):
    conn.execute(
        "INSERT INTO cve (id, description, first_seen, last_seen) VALUES (?, ?, ?, ?)",
        (cve_id, "x", _now(), _now()),
    )


def _add_product(conn, vendor: str, product: str, category: str = "unknown") -> int:
    cur = conn.execute(
        "INSERT INTO product (vendor, product, category) VALUES (?, ?, ?)",
        (vendor, product, category),
    )
    return int(cur.lastrowid)


def _add_poc(conn, url: str, description: str = ""):
    conn.execute(
        "INSERT INTO poc (url, source, description, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)",
        (url, "github", description, _now(), _now()),
    )


# ── backfill_products ────────────────────────────────────────────────────


def test_backfill_products_normalizes_in_place_when_no_canonical_exists(conn):
    pid = _add_product(conn, "apache_software_foundation", "httpd", "unknown")
    conn.commit()

    normalized, merged = backfills.backfill_products(conn)
    conn.commit()

    assert normalized == 1
    assert merged == 0
    row = conn.execute("SELECT vendor, product FROM product WHERE id = ?", (pid,)).fetchone()
    assert row == ("apache", "httpd")


def test_backfill_products_merges_into_existing_canonical(conn):
    """Duplicate row collapses; cve_product rows re-point to the canonical id."""
    canonical_id = _add_product(conn, "apache", "httpd")
    legacy_id = _add_product(conn, "apache_software_foundation", "httpd")

    _add_cve(conn, "CVE-2026-1111")
    conn.execute(
        "INSERT INTO cve_product (cve_id, product_id, versions) VALUES (?, ?, NULL)",
        ("CVE-2026-1111", legacy_id),
    )
    conn.commit()

    _, merged = backfills.backfill_products(conn)
    conn.commit()

    assert merged == 1
    # Legacy row gone
    assert conn.execute("SELECT 1 FROM product WHERE id = ?", (legacy_id,)).fetchone() is None
    # cve_product now points at canonical
    row = conn.execute(
        "SELECT product_id FROM cve_product WHERE cve_id = ?", ("CVE-2026-1111",)
    ).fetchone()
    assert row[0] == canonical_id


def test_backfill_products_merges_drops_collision_rows(conn):
    """When both legacy and canonical link to the same CVE, drop the duplicate link."""
    canonical_id = _add_product(conn, "apache", "httpd")
    legacy_id = _add_product(conn, "apache_software_foundation", "httpd")

    _add_cve(conn, "CVE-2026-AAAA")
    # Both rows already exist for the same CVE
    conn.execute(
        "INSERT INTO cve_product (cve_id, product_id, versions) VALUES (?, ?, NULL)",
        ("CVE-2026-AAAA", canonical_id),
    )
    conn.execute(
        "INSERT INTO cve_product (cve_id, product_id, versions) VALUES (?, ?, NULL)",
        ("CVE-2026-AAAA", legacy_id),
    )
    conn.commit()

    backfills.backfill_products(conn)
    conn.commit()

    rows = conn.execute(
        "SELECT product_id FROM cve_product WHERE cve_id = ?", ("CVE-2026-AAAA",)
    ).fetchall()
    assert rows == [(canonical_id,)]


def test_backfill_products_idempotent(conn):
    _add_product(conn, "apache_software_foundation", "httpd")
    conn.commit()

    backfills.backfill_products(conn)
    conn.commit()
    second_normalized, second_merged = backfills.backfill_products(conn)

    assert (second_normalized, second_merged) == (0, 0)


def test_backfill_products_skips_already_canonical(conn):
    _add_product(conn, "apache", "httpd")
    _add_product(conn, "nginx", "nginx")
    conn.commit()

    normalized, merged = backfills.backfill_products(conn)
    assert (normalized, merged) == (0, 0)


# ── backfill_poc_cve ─────────────────────────────────────────────────────


def test_backfill_poc_cve_links_from_url(conn):
    _add_cve(conn, "CVE-2026-1111")
    _add_poc(conn, "https://github.com/u/CVE-2026-1111-poc")
    conn.commit()

    links, scanned = backfills.backfill_poc_cve(conn)
    conn.commit()

    assert links == 1
    assert scanned == 1
    row = conn.execute("SELECT cve_id FROM poc_cve").fetchone()
    assert row[0] == "CVE-2026-1111"


def test_backfill_poc_cve_links_from_description(conn):
    _add_cve(conn, "CVE-2026-2222")
    _add_poc(
        conn,
        "https://github.com/u/exploit",
        description="Exploits CVE-2026-2222 in Apache",
    )
    conn.commit()

    links, _ = backfills.backfill_poc_cve(conn)
    conn.commit()

    assert links == 1


def test_backfill_poc_cve_skips_unknown_cves(conn):
    """A PoC ref to a CVE not in our DB must NOT link (FK would fail)."""
    _add_poc(conn, "https://github.com/u/CVE-9999-9999-poc")
    conn.commit()

    links, _ = backfills.backfill_poc_cve(conn)
    conn.commit()

    assert links == 0
    assert conn.execute("SELECT COUNT(*) FROM poc_cve").fetchone()[0] == 0


def test_backfill_poc_cve_idempotent(conn):
    _add_cve(conn, "CVE-2026-1111")
    _add_poc(conn, "https://github.com/u/CVE-2026-1111-poc")
    conn.commit()

    backfills.backfill_poc_cve(conn)
    conn.commit()
    second_links, _ = backfills.backfill_poc_cve(conn)

    assert second_links == 0


def test_backfill_poc_cve_extracts_multiple_refs(conn):
    _add_cve(conn, "CVE-2026-1111")
    _add_cve(conn, "CVE-2026-2222")
    _add_poc(
        conn,
        "https://github.com/u/multi-poc",
        description="Affects CVE-2026-1111 and CVE-2026-2222",
    )
    conn.commit()

    links, _ = backfills.backfill_poc_cve(conn)
    conn.commit()

    assert links == 2


# ── run_backfill (entry point) ───────────────────────────────────────────


def test_run_backfill_rejects_unknown_target():
    with pytest.raises(ValueError):
        backfills.run_backfill("nonsense")


def test_run_backfill_all_runs_both(fresh_db_path):
    """`all` should hit products + poc_cve and report both counts."""
    raw = sqlite3.connect(fresh_db_path)
    _add_product(raw, "apache_software_foundation", "httpd")
    _add_cve(raw, "CVE-2026-1111")
    _add_poc(raw, "https://github.com/u/CVE-2026-1111-poc")
    raw.commit()
    raw.close()

    result = backfills.run_backfill("all")

    assert result.products_normalized == 1
    assert result.poc_cve_links_added == 1
    assert result.pocs_scanned == 1
    assert "products:" in result.summary()
    assert "poc_cve:" in result.summary()


def test_run_backfill_products_only(fresh_db_path):
    raw = sqlite3.connect(fresh_db_path)
    _add_product(raw, "apache_software_foundation", "httpd")
    _add_poc(raw, "https://github.com/u/CVE-2026-1111-poc")  # would be linked if poc_cve ran
    raw.commit()
    raw.close()

    result = backfills.run_backfill("products")
    assert result.products_normalized == 1
    # poc_cve branch must not have run
    assert result.pocs_scanned == 0
