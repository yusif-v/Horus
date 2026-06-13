"""Health-check entrypoint + per-check coverage on a seeded test DB."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from horus.storage import db, health


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


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(tzinfo=None).isoformat()


def _insert_cve(
    conn,
    cve_id="CVE-2026-1111",
    *,
    cvss=9.8,
    severity="CRITICAL",
    epss=0.5,
    kev=0,
    description="An RCE",
    published_at=None,
    first_seen=None,
    last_seen=None,
):
    now = _now_iso()
    conn.execute(
        "INSERT INTO cve (id, description, cvss_score, cvss_severity, published_at,"
        " epss_score, kev, first_seen, last_seen)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            cve_id,
            description,
            cvss,
            severity,
            published_at,
            epss,
            kev,
            first_seen if first_seen is not None else now,
            last_seen if last_seen is not None else now,
        ),
    )


def _insert_poc(
    conn,
    url="https://github.com/u/exploit",
    *,
    source="github",
    stars=10,
    age_days=5,
    first_seen=None,
    last_seen=None,
):
    now = _now_iso()
    conn.execute(
        "INSERT INTO poc (url, source, stars, age_days, first_seen, last_seen)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (
            url,
            source,
            stars,
            age_days,
            first_seen if first_seen is not None else now,
            last_seen if last_seen is not None else now,
        ),
    )


def test_missing_database_reports_error(tmp_path):
    report = health.run_health_check(db_path=str(tmp_path / "nope.db"))
    assert report.passed is False
    assert any(i.category == "database" for i in report.issues)


def test_fresh_database_schema_passes(fresh_db_path):
    report = health.run_health_check(db_path=str(fresh_db_path))
    schema_errors = [i for i in report.issues if i.category == "schema" and i.severity == "error"]
    assert schema_errors == [], "fresh schema should not produce schema errors"


def test_report_aggregates_issues_by_severity():
    r = health.HealthReport()
    r.error("schema", "boom")
    r.warning("data", "soft issue")
    r.info("stats", "fyi")
    assert r.passed is False
    assert sum(1 for i in r.issues if i.severity == "error") == 1
    assert sum(1 for i in r.issues if i.severity == "warning") == 1
    assert sum(1 for i in r.issues if i.severity == "info") == 1


# ── HealthReport / HealthIssue ───────────────────────────────────────────


def test_health_issue_default_details_empty():
    issue = health.HealthIssue(severity="error", category="x", message="y")
    assert issue.details == []


def test_warning_and_info_do_not_flip_passed():
    r = health.HealthReport()
    r.warning("data", "soft")
    r.info("stats", "fyi")
    assert r.passed is True


def test_print_renders_all_sections(capsys):
    r = health.HealthReport()
    r.stats["total_cves"] = 5
    r.error("schema", "missing table", details=["t1", "t2", "t3", "t4", "t5", "t6"])
    r.warning("data", "soft", details=["a", "b", "c", "d"])
    r.info("stats", "informational")
    r.print()
    out = capsys.readouterr().out
    assert "HORUS DATABASE HEALTH REPORT" in out
    assert "total_cves" in out
    assert "Errors (1)" in out
    assert "Warnings (1)" in out
    assert "Info (1)" in out
    assert "FAILED" in out
    # details truncation
    assert "... and 1 more" in out  # 6 error details, prints 5 + 1 truncated


def test_print_passed_with_warnings_shows_warning_status(capsys):
    r = health.HealthReport()
    r.warning("data", "soft warning")
    r.print()
    out = capsys.readouterr().out
    assert "PASSED with warnings" in out


def test_print_clean_report_says_passed(capsys):
    health.HealthReport().print()
    out = capsys.readouterr().out
    assert "PASSED — all checks OK" in out


# ── _check_cve_data_quality ──────────────────────────────────────────────


def test_cve_quality_empty_db_emits_info(conn):
    report = health.HealthReport()
    health._check_cve_data_quality(conn, report)
    assert any(i.category == "cve_data" and i.severity == "info" for i in report.issues)


def test_cve_quality_flags_invalid_id_format(conn):
    _insert_cve(conn, cve_id="NOT-A-CVE-FORMAT")
    conn.commit()
    report = health.HealthReport()
    health._check_cve_data_quality(conn, report)
    msgs = [i.message for i in report.issues if i.severity == "error"]
    assert any("invalid ID format" in m for m in msgs)


def test_cve_quality_flags_cvss_out_of_range(conn):
    _insert_cve(conn, cve_id="CVE-2026-2222", cvss=11.5)
    conn.commit()
    report = health.HealthReport()
    health._check_cve_data_quality(conn, report)
    assert any("CVSS out of range" in i.message for i in report.issues)


def test_cve_quality_flags_invalid_severity(conn):
    _insert_cve(conn, cve_id="CVE-2026-3333", severity="EXTREME")
    conn.commit()
    report = health.HealthReport()
    health._check_cve_data_quality(conn, report)
    assert any("invalid severity" in i.message for i in report.issues)


def test_cve_quality_flags_epss_out_of_range(conn):
    _insert_cve(conn, cve_id="CVE-2026-4444", epss=1.7)
    conn.commit()
    report = health.HealthReport()
    health._check_cve_data_quality(conn, report)
    assert any("EPSS out of range" in i.message for i in report.issues)


def test_cve_quality_flags_invalid_kev_value(conn):
    _insert_cve(conn, cve_id="CVE-2026-5555", kev=7)
    conn.commit()
    report = health.HealthReport()
    health._check_cve_data_quality(conn, report)
    assert any("invalid KEV value" in i.message for i in report.issues)


def test_cve_quality_warns_on_empty_description(conn):
    _insert_cve(conn, cve_id="CVE-2026-6666", description="")
    conn.commit()
    report = health.HealthReport()
    health._check_cve_data_quality(conn, report)
    assert any("empty description" in i.message and i.severity == "warning" for i in report.issues)


def test_cve_quality_warns_on_future_published_at(conn):
    future = (datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(days=30)).isoformat()
    _insert_cve(conn, cve_id="CVE-2026-7777", published_at=future)
    conn.commit()
    report = health.HealthReport()
    health._check_cve_data_quality(conn, report)
    assert any("future published_at" in i.message for i in report.issues)


def test_cve_quality_stats_populated(conn):
    _insert_cve(conn, cve_id="CVE-2026-8888", epss=0.5, kev=1)
    conn.commit()
    report = health.HealthReport()
    health._check_cve_data_quality(conn, report)
    assert report.stats["total_cves"] == 1
    assert report.stats["cves_with_kev"] == 1
    assert "100%" in str(report.stats["cves_with_epss"])


# ── _check_poc_data_quality ──────────────────────────────────────────────


def test_poc_quality_empty_db_emits_info(conn):
    report = health.HealthReport()
    health._check_poc_data_quality(conn, report)
    assert any(i.category == "poc_data" and i.severity == "info" for i in report.issues)


def test_poc_quality_flags_invalid_source(conn):
    _insert_poc(conn, url="https://example.com/x", source="weird-source")
    conn.commit()
    report = health.HealthReport()
    health._check_poc_data_quality(conn, report)
    assert any("invalid source" in i.message for i in report.issues)


def test_poc_quality_flags_invalid_url(conn):
    _insert_poc(conn, url="not-a-url")
    conn.commit()
    report = health.HealthReport()
    health._check_poc_data_quality(conn, report)
    assert any("invalid URL" in i.message for i in report.issues)


def test_poc_quality_warns_on_negative_stars(conn):
    _insert_poc(conn, url="https://github.com/u/neg", stars=-5)
    conn.commit()
    report = health.HealthReport()
    health._check_poc_data_quality(conn, report)
    assert any("negative stars" in i.message for i in report.issues)


def test_poc_quality_warns_on_negative_age(conn):
    _insert_poc(conn, url="https://github.com/u/neg-age", age_days=-3)
    conn.commit()
    report = health.HealthReport()
    health._check_poc_data_quality(conn, report)
    assert any("negative age_days" in i.message for i in report.issues)


def test_poc_quality_stats_break_down_by_source(conn):
    _insert_poc(conn, url="https://github.com/u/a", source="github")
    _insert_poc(conn, url="https://gitlab.com/u/b", source="gitlab")
    conn.commit()
    report = health.HealthReport()
    health._check_poc_data_quality(conn, report)
    assert report.stats.get("pocs_source_github") == 1
    assert report.stats.get("pocs_source_gitlab") == 1
    assert report.stats["total_pocs"] == 2


# ── _check_referential_integrity ─────────────────────────────────────────


def test_referential_clean_db_has_no_orphan_errors(conn):
    report = health.HealthReport()
    health._check_referential_integrity(conn, report)
    assert [i for i in report.issues if i.severity == "error"] == []


def test_referential_flags_orphan_poc_cve_link(fresh_db_path):
    """A poc_cve row pointing at a poc_url that doesn't exist in poc."""
    # FK must be disabled BEFORE the row is inserted; do it on a fresh
    # connection (PRAGMA only affects the connection it runs on).
    fk_off = sqlite3.connect(fresh_db_path)
    fk_off.execute("PRAGMA foreign_keys = OFF")
    fk_off.execute(
        "INSERT INTO cve (id, description, first_seen, last_seen)"
        " VALUES ('CVE-2026-AAAA', 'x', ?, ?)",
        (_now_iso(), _now_iso()),
    )
    fk_off.execute(
        "INSERT INTO poc_cve (poc_url, cve_id) VALUES (?, ?)",
        ("https://orphan.example/poc", "CVE-2026-AAAA"),
    )
    fk_off.commit()
    fk_off.close()

    check_conn = sqlite3.connect(fresh_db_path)
    report = health.HealthReport()
    health._check_referential_integrity(check_conn, report)
    check_conn.close()
    assert any("poc_cve" in i.message and "PoCs" in i.message for i in report.issues)


# ── _check_enum_consistency ──────────────────────────────────────────────


def test_enum_flags_unknown_poc_source(conn):
    _insert_poc(conn, url="https://example.com/x", source="ghost-source")
    conn.commit()
    report = health.HealthReport()
    health._check_enum_consistency(conn, report)
    assert any("PoC sources" in i.message for i in report.issues)


# ── _check_cve_completeness ──────────────────────────────────────────────


def test_completeness_flags_cve_without_source(conn):
    _insert_cve(conn, cve_id="CVE-2026-NOSRC")
    conn.commit()
    report = health.HealthReport()
    health._check_cve_completeness(conn, report)
    assert any("without any source entry" in i.message for i in report.issues)


def test_completeness_warns_on_missing_attack_tags(conn):
    _insert_cve(conn, cve_id="CVE-2026-NOTAG")
    conn.commit()
    report = health.HealthReport()
    health._check_cve_completeness(conn, report)
    assert any(
        "without attack tags" in i.message and i.severity == "warning" for i in report.issues
    )


def test_completeness_warns_on_missing_description(conn):
    _insert_cve(conn, cve_id="CVE-2026-NODESC", description="")
    conn.commit()
    report = health.HealthReport()
    health._check_cve_completeness(conn, report)
    assert any("without description" in i.message for i in report.issues)


def test_completeness_info_on_missing_cvss(conn):
    _insert_cve(conn, cve_id="CVE-2026-NOCVSS", cvss=None)
    conn.commit()
    report = health.HealthReport()
    health._check_cve_completeness(conn, report)
    assert any("without CVSS score" in i.message and i.severity == "info" for i in report.issues)


# ── _check_stale_data ────────────────────────────────────────────────────


def test_stale_data_flags_old_cves(conn):
    old = (datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=60)).isoformat()
    _insert_cve(conn, cve_id="CVE-2026-STALE", last_seen=old)
    conn.commit()
    report = health.HealthReport()
    health._check_stale_data(conn, report)
    assert any(
        "not updated in 30+ days" in i.message and "CVEs" in i.message for i in report.issues
    )


def test_stale_data_flags_old_pocs(conn):
    old = (datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=60)).isoformat()
    _insert_poc(conn, url="https://github.com/u/stale", last_seen=old)
    conn.commit()
    report = health.HealthReport()
    health._check_stale_data(conn, report)
    assert any(
        "not updated in 30+ days" in i.message and "PoCs" in i.message for i in report.issues
    )


# ── _check_logical_duplicates ────────────────────────────────────────────


def test_duplicates_flags_cves_with_same_description(conn):
    _insert_cve(conn, cve_id="CVE-2026-DUP1", description="exactly the same description")
    _insert_cve(conn, cve_id="CVE-2026-DUP2", description="exactly the same description")
    conn.commit()
    report = health.HealthReport()
    health._check_logical_duplicates(conn, report)
    assert any("identical descriptions" in i.message for i in report.issues)


# ── _check_schema (missing pieces) ───────────────────────────────────────


def test_schema_flags_missing_table(tmp_path):
    """A bare DB without our schema should fail every table check.

    We call _check_schema directly because run_health_check assumes the
    schema exists when it gets to the data-quality checks.
    """
    db_path = tmp_path / "empty.db"
    raw = sqlite3.connect(db_path)
    report = health.HealthReport()
    health._check_schema(raw, report)
    raw.close()
    assert any(i.category == "schema" and "Missing table" in i.message for i in report.issues)


# ── run_health_check (end-to-end on a clean DB) ──────────────────────────


def test_run_health_check_returns_populated_report(fresh_db_path):
    report = health.run_health_check(db_path=str(fresh_db_path))
    # Stats are always populated by the data-quality checks
    assert "total_cves" in report.stats
    assert "total_pocs" in report.stats
