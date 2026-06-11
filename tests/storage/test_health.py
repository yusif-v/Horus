"""Health-check entrypoint: empty DB passes schema, missing DB errors."""

from __future__ import annotations

import pytest

from horus.storage import db, health


@pytest.fixture()
def fresh_db_path(tmp_path, monkeypatch):
    path = tmp_path / "horus.db"
    monkeypatch.setattr(db, "DB_PATH", path)
    db.initialize()
    return path


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
