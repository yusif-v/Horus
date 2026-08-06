from horus.storage import db


def _conn():
    db.initialize()
    return db.connect()


def test_upsert_ok_sets_status_and_counts_and_zero_failures():
    with _conn() as conn:
        db.upsert_source_health(conn, "nvd", status="ok", cve_count=12, poc_count=3)
        rows = db.get_source_health(conn)
    row = next(r for r in rows if r["source_name"] == "nvd")
    assert row["last_status"] == "ok"
    assert row["cve_count"] == 12
    assert row["poc_count"] == 3
    assert row["consecutive_failures"] == 0
    assert row["last_run_at"] is not None


def test_consecutive_failures_increment_then_reset():
    with _conn() as conn:
        db.upsert_source_health(conn, "github", status="error", error="boom")
        db.upsert_source_health(conn, "github", status="error", error="boom again")
        mid = next(r for r in db.get_source_health(conn) if r["source_name"] == "github")
        assert mid["consecutive_failures"] == 2
        assert mid["last_error"] == "boom again"
        db.upsert_source_health(conn, "github", status="ok", cve_count=1)
        after = next(r for r in db.get_source_health(conn) if r["source_name"] == "github")
        assert after["consecutive_failures"] == 0
        assert after["last_error"] is None


def test_skipped_preserves_prior_last_run_at():
    with _conn() as conn:
        db.upsert_source_health(conn, "news", status="ok", cve_count=5)
        prior = next(r for r in db.get_source_health(conn) if r["source_name"] == "news")
        db.upsert_source_health(conn, "news", status="skipped")
        after = next(r for r in db.get_source_health(conn) if r["source_name"] == "news")
    assert after["last_status"] == "skipped"
    assert after["last_run_at"] == prior["last_run_at"]
    assert after["consecutive_failures"] == 0
