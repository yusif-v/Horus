from horus.storage import db


def test_records_ok_error_and_skipped(monkeypatch):
    """A failing source records error+failure; an enabled-but-not-run source is skipped."""
    db.initialize()
    with db.connect() as conn:
        # Simulate a cycle's outcome map: nvd ok, github failed.
        results = {
            "nvd": {"cves": 4, "pocs": 0},
            "github": {"cves": 0, "pocs": 0, "error": "rate limited"},
        }
        ran = set(results)
        all_sources = {"nvd", "github", "news"}  # news discovered but disabled
        # This mirrors the persist-phase loop added in pipeline.py:
        for name, r in results.items():
            status = "error" if "error" in r else "ok"
            db.upsert_source_health(
                conn,
                name,
                status=status,
                error=r.get("error"),
                cve_count=r.get("cves", 0),
                poc_count=r.get("pocs", 0),
            )
        for name in all_sources - ran:
            db.upsert_source_health(conn, name, status="skipped")
        rows = {r["source_name"]: r for r in db.get_source_health(conn)}
    assert rows["nvd"]["last_status"] == "ok" and rows["nvd"]["cve_count"] == 4
    assert rows["github"]["last_status"] == "error" and rows["github"]["consecutive_failures"] == 1
    assert rows["news"]["last_status"] == "skipped"
