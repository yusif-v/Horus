"""CVE correlation engine tests."""

from __future__ import annotations

from datetime import date, timedelta

from horus.core import correlation
from horus.storage import db


def _days_ago(n: int) -> str:
    return (date.today() - timedelta(days=n)).isoformat()


def _seed_cve(conn, cve_id, published_at, tags=None, cwes=None, products=None, pocs=None):
    conn.execute(
        "INSERT OR REPLACE INTO cve (id, description, published_at, first_seen, last_seen)"
        " VALUES (?, ?, ?, ?, ?)",
        (cve_id, f"desc {cve_id}", published_at, published_at, published_at),
    )
    for tag in tags or []:
        conn.execute("INSERT OR IGNORE INTO attack_tag (name) VALUES (?)", (tag,))
        conn.execute(
            "INSERT OR IGNORE INTO cve_attack_tag (cve_id, tag) VALUES (?, ?)",
            (cve_id, tag),
        )
    for cwe_id in cwes or []:
        conn.execute("INSERT OR IGNORE INTO cwe (id) VALUES (?)", (cwe_id,))
        conn.execute(
            "INSERT OR IGNORE INTO cve_cwe (cve_id, cwe_id) VALUES (?, ?)",
            (cve_id, cwe_id),
        )
    for vendor, product in products or []:
        conn.execute(
            "INSERT OR IGNORE INTO product (vendor, product, category) VALUES (?, ?, 'generic')",
            (vendor, product),
        )
        row = conn.execute(
            "SELECT id FROM product WHERE vendor = ? AND product = ?",
            (vendor, product),
        ).fetchone()
        conn.execute(
            "INSERT OR IGNORE INTO cve_product (cve_id, product_id) VALUES (?, ?)",
            (cve_id, row[0]),
        )
    for poc_url in pocs or []:
        conn.execute(
            "INSERT OR IGNORE INTO poc (url, source, first_seen, last_seen) VALUES (?, ?, ?, ?)",
            (poc_url, "github", "2026-01-01", "2026-01-01"),
        )
        conn.execute(
            "INSERT OR IGNORE INTO poc_cve (poc_url, cve_id) VALUES (?, ?)",
            (poc_url, cve_id),
        )


def test_signals_weights():
    assert correlation.SIGNALS["shared_poc"] == 4
    assert correlation.SIGNALS["shared_tag"] == 3
    assert correlation.SIGNALS["shared_cwe"] == 3
    assert correlation.SIGNALS["shared_product"] == 2
    assert correlation.SIGNALS["shared_tag"] == 3


def test_compute_pair_score_shared_poc():
    score, reasons = correlation._compute_pair_score(
        set(),
        set(),
        set(),
        set(),
        set(),
        set(),
        {"https://github.com/poc1"},
        {"https://github.com/poc1"},
        "2026-01-01",
        "2026-06-01",
        set(),
        set(),
    )
    assert score == 4
    assert "shared_poc" in reasons


def test_compute_pair_score_shared_tag_and_cwe():
    score, reasons = correlation._compute_pair_score(
        {"rce"},
        {"rce"},
        {"CWE-120"},
        {"CWE-120"},
        set(),
        set(),
        set(),
        set(),
        "2026-01-01",
        "2026-06-01",
        set(),
        set(),
    )
    assert score == 6
    assert "shared_tag" in reasons
    assert "shared_cwe" in reasons


def test_compute_pair_score_temporal_proximity():
    score, reasons = correlation._compute_pair_score(
        set(),
        set(),
        set(),
        set(),
        set(),
        set(),
        set(),
        set(),
        _days_ago(5),
        _days_ago(10),
        set(),
        set(),
    )
    assert score == 1
    assert "temporal_proximity" in reasons


def test_compute_pair_score_no_match():
    score, reasons = correlation._compute_pair_score(
        set(),
        set(),
        set(),
        set(),
        set(),
        set(),
        set(),
        set(),
        "2026-01-01",
        "2026-06-01",
        set(),
        set(),
    )
    assert score == 0
    assert reasons == ""


def test_compute_pair_score_same_vendor():
    score, reasons = correlation._compute_pair_score(
        set(),
        set(),
        set(),
        set(),
        set(),
        set(),
        set(),
        set(),
        "2026-01-01",
        "2026-06-01",
        {"microsoft"},
        {"microsoft"},
    )
    assert score == 1
    assert "same_vendor" in reasons


def test_compute_pair_score_combined_signals():
    score, reasons = correlation._compute_pair_score(
        {"rce"},
        {"rce"},
        {"CWE-120"},
        {"CWE-120"},
        {1},
        {1},
        set(),
        set(),
        _days_ago(3),
        _days_ago(5),
        {"cisco"},
        {"cisco"},
    )
    assert score == 3 + 3 + 2 + 1 + 1
    for s in ("shared_tag", "shared_cwe", "shared_product", "temporal_proximity", "same_vendor"):
        assert s in reasons


def test_compute_correlations_above_threshold():
    db.initialize()
    with db.connect() as conn:
        conn.execute("DELETE FROM cve")
        conn.execute("DELETE FROM poc_cve")
        conn.execute("DELETE FROM poc")
        conn.execute("DELETE FROM cve_attack_tag")
        conn.execute("DELETE FROM cve_cwe")
        conn.execute("DELETE FROM cve_product")
        conn.execute("DELETE FROM product")

        _seed_cve(
            conn,
            "CVE-2026-1001",
            _days_ago(5),
            tags={"rce"},
            cwes={"CWE-120"},
            products=[("cisco", "ios")],
            pocs=["https://github.com/exploit1"],
        )
        _seed_cve(
            conn,
            "CVE-2026-1002",
            _days_ago(7),
            tags={"rce"},
            cwes={"CWE-120"},
            products=[("cisco", "ios")],
            pocs=["https://github.com/exploit1"],
        )
        conn.commit()

        count = correlation.compute_correlations(conn, days=30, threshold=3.0)
        assert count == 1

        row = conn.execute(
            "SELECT score, reasons FROM cve_correlation"
            " WHERE ((cve_id = ? AND related_id = ?) OR (cve_id = ? AND related_id = ?))",
            ("CVE-2026-1001", "CVE-2026-1002", "CVE-2026-1002", "CVE-2026-1001"),
        ).fetchone()
        assert row is not None
        assert row[0] >= 3.0
        assert "shared_poc" in row[1]


def test_compute_correlations_below_threshold_filtered():
    db.initialize()
    with db.connect() as conn:
        conn.execute("DELETE FROM cve")
        conn.execute("DELETE FROM poc_cve")
        conn.execute("DELETE FROM poc")
        conn.execute("DELETE FROM cve_attack_tag")

        _seed_cve(conn, "CVE-2026-2001", _days_ago(5), tags={"xss"})
        _seed_cve(conn, "CVE-2026-2002", _days_ago(8), tags={"rce"})
        conn.commit()

        count = correlation.compute_correlations(conn, days=30, threshold=3.0)
        assert count == 0


def test_build_clusters_creates_cluster():
    db.initialize()
    with db.connect() as conn:
        conn.execute("DELETE FROM cve")
        conn.execute("DELETE FROM poc_cve")
        conn.execute("DELETE FROM poc")
        conn.execute("DELETE FROM cve_attack_tag")
        conn.execute("DELETE FROM cve_cwe")
        conn.execute("DELETE FROM cve_product")
        conn.execute("DELETE FROM product")
        conn.execute("DELETE FROM cve_correlation")
        conn.execute("DELETE FROM cve_cluster_member")
        conn.execute("DELETE FROM cve_cluster")

        _seed_cve(
            conn,
            "CVE-2026-3001",
            _days_ago(5),
            tags={"rce"},
            products=[("cisco", "ios")],
            pocs=["https://github.com/poc1"],
        )
        _seed_cve(
            conn,
            "CVE-2026-3002",
            _days_ago(6),
            tags={"rce"},
            products=[("cisco", "ios")],
            pocs=["https://github.com/poc1"],
        )
        conn.commit()

        correlation.compute_correlations(conn, days=30, threshold=3.0)
        n_clusters = correlation.build_clusters(conn, max_clusters=50)
        assert n_clusters == 1

        cluster = conn.execute("SELECT cve_count FROM cve_cluster").fetchone()
        assert cluster[0] == 2


def test_build_clusters_no_correlations():
    db.initialize()
    with db.connect() as conn:
        conn.execute("DELETE FROM cve_correlation")
        conn.execute("DELETE FROM cve_cluster_member")
        conn.execute("DELETE FROM cve_cluster")

        n_clusters = correlation.build_clusters(conn, max_clusters=50)
        assert n_clusters == 0


def test_compute_correlations_clears_previous():
    db.initialize()
    with db.connect() as conn:
        conn.execute("DELETE FROM cve")
        conn.execute("DELETE FROM poc_cve")
        conn.execute("DELETE FROM poc")
        conn.execute("DELETE FROM cve_attack_tag")
        conn.execute("DELETE FROM cve_cwe")
        conn.execute("DELETE FROM cve_product")
        conn.execute("DELETE FROM product")

        _seed_cve(
            conn,
            "CVE-2026-4001",
            _days_ago(5),
            tags={"rce"},
            pocs=["https://github.com/p1"],
        )
        _seed_cve(
            conn,
            "CVE-2026-4002",
            _days_ago(7),
            tags={"rce"},
            pocs=["https://github.com/p1"],
        )
        conn.commit()

        correlation.compute_correlations(conn, days=30, threshold=3.0)
        first_count = conn.execute("SELECT COUNT(*) FROM cve_correlation").fetchone()[0]
        assert first_count == 1

        conn.execute("DELETE FROM cve_attack_tag WHERE cve_id = 'CVE-2026-4002'")
        conn.execute("DELETE FROM poc_cve WHERE cve_id = 'CVE-2026-4002'")
        conn.commit()
        correlation.compute_correlations(conn, days=30, threshold=3.0)
        second_count = conn.execute("SELECT COUNT(*) FROM cve_correlation").fetchone()[0]
        assert second_count == 0


def test_compute_correlations_only_recent_cves():
    db.initialize()
    with db.connect() as conn:
        conn.execute("DELETE FROM cve")
        conn.execute("DELETE FROM poc_cve")
        conn.execute("DELETE FROM poc")
        conn.execute("DELETE FROM cve_attack_tag")

        _seed_cve(conn, "CVE-2025-9001", "2025-01-01", tags={"rce"})
        _seed_cve(conn, "CVE-2025-9002", "2025-01-02", tags={"rce"})
        conn.commit()

        count = correlation.compute_correlations(conn, days=30, threshold=3.0)
        assert count == 0


def test_build_clusters_respects_max_clusters():
    db.initialize()
    with db.connect() as conn:
        conn.execute("DELETE FROM cve")
        conn.execute("DELETE FROM poc_cve")
        conn.execute("DELETE FROM poc")
        conn.execute("DELETE FROM cve_attack_tag")
        conn.execute("DELETE FROM cve_correlation")
        conn.execute("DELETE FROM cve_cluster_member")
        conn.execute("DELETE FROM cve_cluster")

        for i in range(6):
            grp = i // 3
            _seed_cve(
                conn,
                f"CVE-2026-7{i:03d}",
                _days_ago(i + 1),
                tags={f"tag{grp}"},
                pocs=[f"https://github.com/g{grp}"],
            )
        conn.commit()

        correlation.compute_correlations(conn, days=30, threshold=3.0)
        n_clusters = correlation.build_clusters(conn, max_clusters=5)
        assert n_clusters == 2
