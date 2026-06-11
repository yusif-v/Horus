"""Round-trip persistence: CVE + PoC + link + watchlist + social posts."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from horus.core.model import CVE, AffectedProduct, PoC
from horus.storage import db


@pytest.fixture()
def conn(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "horus.db")
    db.initialize()
    with db.connect() as c:
        yield c


def _cve(**overrides) -> CVE:
    base = dict(
        id="CVE-2026-0001",
        description="Test CVE for round-trip.",
        cvss_score=9.1,
        cvss_severity="CRITICAL",
        published_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        attack_tags=["rce"],
        cwe_ids=["CWE-94"],
        affected=[AffectedProduct(vendor="nginx", product="nginx", versions=["1.0"])],
        sources=["nvd"],
        epss_score=0.5,
        kev=0,
    )
    base.update(overrides)
    return CVE(**base)


def test_persist_cve_round_trip(conn):
    db.persist_cve(conn, _cve())
    row = conn.execute(
        "SELECT id, cvss_score, cvss_severity FROM cve WHERE id = ?", ("CVE-2026-0001",)
    ).fetchone()
    assert tuple(row) == ("CVE-2026-0001", 9.1, "CRITICAL")
    # Attack tag, CWE link, product, and source were all written.
    assert (
        conn.execute(
            "SELECT COUNT(*) FROM cve_attack_tag WHERE cve_id = ?", ("CVE-2026-0001",)
        ).fetchone()[0]
        == 1
    )
    assert (
        conn.execute(
            "SELECT COUNT(*) FROM cve_cwe WHERE cve_id = ?", ("CVE-2026-0001",)
        ).fetchone()[0]
        == 1
    )
    assert (
        conn.execute(
            "SELECT COUNT(*) FROM cve_product WHERE cve_id = ?", ("CVE-2026-0001",)
        ).fetchone()[0]
        == 1
    )
    assert (
        conn.execute(
            "SELECT source FROM cve_source WHERE cve_id = ?", ("CVE-2026-0001",)
        ).fetchone()[0]
        == "nvd"
    )


def test_persist_cve_is_upsert(conn):
    db.persist_cve(conn, _cve(cvss_score=7.0))
    db.persist_cve(conn, _cve(cvss_score=9.0, kev=1))
    row = conn.execute(
        "SELECT cvss_score, kev FROM cve WHERE id = ?", ("CVE-2026-0001",)
    ).fetchone()
    # COALESCE keeps the latest score, MAX preserves the higher kev flag.
    assert tuple(row) == (9.0, 1)


def test_persist_cve_computes_reputation(conn):
    db.persist_cve(conn, _cve(kev=1, epss_score=0.9))
    score = conn.execute(
        "SELECT reputation_score FROM cve WHERE id = ?", ("CVE-2026-0001",)
    ).fetchone()[0]
    assert score is not None and score > 0


def test_persist_poc_and_link(conn):
    db.persist_cve(conn, _cve())
    db.persist_poc(
        conn,
        PoC(url="https://example.com/x", source="github", stars=10, age_days=1, description="poc"),
    )
    assert db.link_poc_to_cve(conn, "https://example.com/x", "CVE-2026-0001") is True
    n = conn.execute("SELECT COUNT(*) FROM poc_cve").fetchone()[0]
    assert n == 1


def test_link_poc_skips_unknown_cve(conn):
    db.persist_poc(conn, PoC(url="https://example.com/x", source="github"))
    # CVE does not exist — link must be skipped without raising.
    assert db.link_poc_to_cve(conn, "https://example.com/x", "CVE-1999-0001") is False
    assert conn.execute("SELECT COUNT(*) FROM poc_cve").fetchone()[0] == 0


def test_watchlist_and_resolution(conn):
    db.persist_watchlist(conn, "CVE-2026-0099", source="x_twitter", social_mentions=3)
    row = conn.execute(
        "SELECT social_mentions, resolved FROM cve_watchlist WHERE id = ?",
        ("CVE-2026-0099",),
    ).fetchone()
    assert tuple(row) == (3, 0)
    # Re-insert accumulates mentions and clears resolved.
    db.persist_watchlist(conn, "CVE-2026-0099", source="x_twitter", social_mentions=2)
    assert (
        conn.execute(
            "SELECT social_mentions FROM cve_watchlist WHERE id = ?", ("CVE-2026-0099",)
        ).fetchone()[0]
        == 5
    )
    db.resolve_watchlist(conn, "CVE-2026-0099")
    assert (
        conn.execute(
            "SELECT resolved FROM cve_watchlist WHERE id = ?", ("CVE-2026-0099",)
        ).fetchone()[0]
        == 1
    )


def test_persist_social_posts_skips_unknown_cves(conn):
    db.persist_cve(conn, _cve())
    signals = [
        {"cve_id": "CVE-2026-0001", "tweet_url": "https://x.com/a/1", "likes": 5},
        {"cve_id": "CVE-2099-9999", "tweet_url": "https://x.com/b/2", "likes": 9},
    ]
    written = db.persist_social_posts(conn, signals, known_cve_ids={"CVE-2026-0001"})
    assert written == 1
    rows = [tuple(r) for r in conn.execute("SELECT cve_id, likes FROM cve_social_post").fetchall()]
    assert rows == [("CVE-2026-0001", 5)]


def test_mark_and_get_last_run_round_trip(conn):
    assert db.get_last_run(conn, "nvd") is None
    db.mark_run(conn, "nvd")
    assert db.get_last_run(conn, "nvd") is not None


def test_list_known_ids(conn):
    db.persist_cve(conn, _cve())
    db.persist_poc(conn, PoC(url="https://example.com/x", source="github"))
    assert "CVE-2026-0001" in db.list_known_cve_ids(conn)
    assert "https://example.com/x" in db.list_known_poc_urls(conn)
