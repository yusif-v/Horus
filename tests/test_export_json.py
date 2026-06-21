"""Tests for horus/export_json.py — static JSON export."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from horus.storage import db


@pytest.fixture
def populated_db(tmp_path, monkeypatch):
    """Create a test DB with one CVE and one PoC."""
    db_path = tmp_path / "horus.db"
    monkeypatch.setattr(db, "DB_PATH", db_path)
    db.initialize()

    with db.connect() as conn:
        conn.execute(
            """
            INSERT INTO cve (id, description, cvss_score, cvss_severity,
                             published_at, epss_score, kev, reputation_score, confidence,
                             first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
            """,
            (
                "CVE-2026-12345",
                "A critical test vulnerability",
                9.8,
                "CRITICAL",
                "2026-06-15T00:00:00Z",
                0.95,
                1,
                8.5,
                "high",
            ),
        )
        conn.execute(
            """
            INSERT INTO poc (url, source, stars, first_seen, last_seen, description)
            VALUES (?, ?, ?, datetime('now'), datetime('now'), ?)
            """,
            (
                "https://github.com/test/poc-cve-2026-12345",
                "github",
                42,
                "PoC for CVE-2026-12345",
            ),
        )
        conn.execute(
            "INSERT INTO poc_cve (poc_url, cve_id) VALUES (?, ?)",
            ("https://github.com/test/poc-cve-2026-12345", "CVE-2026-12345"),
        )

    return db_path


def test_export_creates_json_files(populated_db, tmp_path):
    from horus.export_json import export_all

    output_dir = tmp_path / "export"
    written = export_all(str(populated_db), str(output_dir))

    written_paths = [Path(p).name for p in written]
    assert "stats.json" in written_paths
    assert "2026.json" in written_paths
    assert "nvd_intel_2026.json" in written_paths


def test_export_stats_content(populated_db, tmp_path):
    from horus.export_json import export_all

    output_dir = tmp_path / "export2"
    export_all(str(populated_db), str(output_dir))

    stats = json.loads((output_dir / "stats.json").read_text())
    assert stats["cve_count"] == 1
    assert stats["poc_count"] == 1
    assert stats["kev_count"] == 1
    assert stats["with_epss"] == 1
    assert stats["linked_pocs"] == 1
    assert stats["cves_with_pocs"] == 1
    assert stats["avg_epss"] == 0.95
    assert stats["severity_breakdown"]["CRITICAL"] == 1
    assert "2026-06" in stats["monthly_cves"]


def test_export_year_cves_content(populated_db, tmp_path):
    from horus.export_json import export_all

    output_dir = tmp_path / "export3"
    export_all(str(populated_db), str(output_dir))

    data = json.loads((output_dir / "2026.json").read_text())
    assert data["year"] == 2026
    assert len(data["cves"]) == 1
    cve = data["cves"][0]
    assert cve["id"] == "CVE-2026-12345"
    assert cve["cvss_score"] == 9.8
    assert cve["cvss_severity"] == "CRITICAL"
    assert cve["epss_score"] == 0.95
    assert cve["kev"] is True
    assert cve["published_at"] == "2026-06-15T00:00:00Z"
    assert len(cve["repositories"]) == 1
    repo = cve["repositories"][0]
    assert repo["url"] == "https://github.com/test/poc-cve-2026-12345"
    assert repo["source"] == "github"
    assert repo["stars"] == 42


def test_export_nvd_intel_content(populated_db, tmp_path):
    from horus.export_json import export_all

    output_dir = tmp_path / "export4"
    export_all(str(populated_db), str(output_dir))

    intel = json.loads((output_dir / "nvd_intel_2026.json").read_text())
    assert "CVE-2026-12345" in intel
    entry = intel["CVE-2026-12345"]
    assert entry["s"] == 9.8
    assert entry["e"] == 0.95
    assert entry["k"] is True
    assert "critical" in entry["d"].lower()


def test_export_creates_output_dir(populated_db, tmp_path):
    from horus.export_json import export_all

    output_dir = tmp_path / "nested" / "deep" / "export"
    export_all(str(populated_db), str(output_dir))
    assert output_dir.exists()
    assert (output_dir / "stats.json").exists()
