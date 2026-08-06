"""Tests for horus/storage/weekly.py — weekly report data aggregation."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone

from horus.storage.weekly import (
    _week_boundaries,
    gather_weekly_data,
)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _make_conn() -> sqlite3.Connection:
    """Create an in-memory SQLite DB with the weekly-report-relevant schema."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(
        """
        PRAGMA foreign_keys = ON;

        CREATE TABLE cve (
            id TEXT PRIMARY KEY,
            description TEXT,
            cvss_score REAL,
            cvss_severity TEXT,
            published_at TEXT,
            epss_score REAL,
            kev INTEGER DEFAULT 0,
            reputation_score REAL,
            social_mentions INTEGER DEFAULT 0,
            poc_source_count INTEGER DEFAULT 0,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            trust_score REAL DEFAULT 0.0,
            threatfox_ioc_count INTEGER DEFAULT 0,
            stealer_hits INTEGER DEFAULT 0,
            kev_due_date TEXT
        );

        CREATE TABLE poc (
            url TEXT PRIMARY KEY,
            source TEXT NOT NULL,
            stars INTEGER,
            age_days INTEGER,
            description TEXT,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            exploit_type TEXT
        );

        CREATE TABLE product (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vendor TEXT NOT NULL,
            product TEXT NOT NULL,
            category TEXT NOT NULL,
            UNIQUE (vendor, product)
        );

        CREATE TABLE cve_product (
            cve_id TEXT NOT NULL REFERENCES cve(id) ON DELETE CASCADE,
            product_id INTEGER NOT NULL REFERENCES product(id),
            versions TEXT,
            PRIMARY KEY (cve_id, product_id)
        );

        CREATE TABLE cve_attack_tag (
            cve_id TEXT NOT NULL REFERENCES cve(id) ON DELETE CASCADE,
            tag TEXT NOT NULL,
            PRIMARY KEY (cve_id, tag)
        );

        CREATE TABLE cve_source (
            cve_id TEXT NOT NULL REFERENCES cve(id) ON DELETE CASCADE,
            source TEXT NOT NULL,
            PRIMARY KEY (cve_id, source)
        );

        CREATE TABLE poc_cve (
            poc_url TEXT NOT NULL REFERENCES poc(url) ON DELETE CASCADE,
            cve_id TEXT NOT NULL REFERENCES cve(id) ON DELETE CASCADE,
            PRIMARY KEY (poc_url, cve_id)
        );

        CREATE TABLE news_article (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            url TEXT NOT NULL UNIQUE,
            source TEXT NOT NULL,
            tier INTEGER NOT NULL DEFAULT 3,
            summary TEXT,
            published_at TEXT,
            first_seen TEXT NOT NULL
        );

        CREATE TABLE cve_threatfox_ioc (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT NOT NULL REFERENCES cve(id) ON DELETE CASCADE,
            ioc_type TEXT NOT NULL,
            ioc_value TEXT NOT NULL,
            threat_type TEXT,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            UNIQUE (cve_id, ioc_value)
        );

        CREATE TABLE cve_triage (
            cve_id TEXT PRIMARY KEY REFERENCES cve(id) ON DELETE CASCADE,
            status TEXT NOT NULL DEFAULT 'new',
            assigned_to INTEGER,
            note TEXT,
            updated_at TEXT NOT NULL,
            updated_by INTEGER
        );

        CREATE TABLE source_health (
            source_name TEXT PRIMARY KEY,
            last_run_at TEXT,
            last_status TEXT NOT NULL,
            last_error TEXT,
            cve_count INTEGER DEFAULT 0,
            poc_count INTEGER DEFAULT 0,
            consecutive_failures INTEGER DEFAULT 0
        );

        CREATE TABLE security_resource (
            url TEXT PRIMARY KEY,
            resource_type TEXT NOT NULL,
            title TEXT,
            description TEXT,
            source TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS ioc_indicator (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ioc_type TEXT NOT NULL,
            ioc_value TEXT NOT NULL,
            source TEXT NOT NULL,
            source_ref TEXT,
            cve_id TEXT REFERENCES cve(id) ON DELETE SET NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            UNIQUE (ioc_type, ioc_value, source)
        );
        """
    )
    return conn


def _seed_cve(
    conn: sqlite3.Connection,
    cve_id: str,
    first_seen: str,
    cvss_score: float | None = 7.5,
    severity: str = "HIGH",
    epss: float | None = 0.05,
    kev: int = 0,
    reputation: float = 3.5,
    description: str = "Test vulnerability",
    due_date: str | None = None,
) -> None:
    conn.execute(
        """INSERT INTO cve (id, description, cvss_score, cvss_severity,
           epss_score, kev, reputation_score, first_seen, last_seen, kev_due_date)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            cve_id,
            description,
            cvss_score,
            severity,
            epss,
            kev,
            reputation,
            first_seen,
            first_seen,
            due_date,
        ),
    )


def _seed_poc(
    conn: sqlite3.Connection,
    url: str,
    first_seen: str,
    source: str = "github",
    stars: int = 10,
) -> None:
    conn.execute(
        "INSERT INTO poc (url, source, stars, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)",
        (url, source, stars, first_seen, first_seen),
    )


# ── _week_boundaries ──────────────────────────────────────────────────────


class TestWeekBoundaries:
    def test_returns_four_boundaries(self):
        result = _week_boundaries(weeks_back=1)
        assert len(result) == 4

    def test_this_week_is_seven_days(self):
        start, end, _, _ = _week_boundaries(weeks_back=1)
        start_dt = datetime.strptime(start, "%Y-%m-%dT%H:%M:%S")
        end_dt = datetime.strptime(end, "%Y-%m-%dT%H:%M:%S")
        assert (end_dt - start_dt).days == 7

    def test_weeks_back_shifts_window(self):
        """weeks_back=2 should produce an earlier window than weeks_back=1."""
        start_1, _, _, _ = _week_boundaries(weeks_back=1)
        start_2, _, _, _ = _week_boundaries(weeks_back=2)
        dt_1 = datetime.strptime(start_1, "%Y-%m-%dT%H:%M:%S")
        dt_2 = datetime.strptime(start_2, "%Y-%m-%dT%H:%M:%S")
        assert dt_2 < dt_1
        assert (dt_1 - dt_2).days == 7

    def test_boundaries_align_to_monday(self):
        """Week start should always be a Monday (weekday 0)."""
        start, _, _, _ = _week_boundaries(weeks_back=1)
        dt = datetime.strptime(start, "%Y-%m-%dT%H:%M:%S")
        assert dt.weekday() == 0

    def test_last_week_precedes_this_week(self):
        _, _, _last_start, last_end = _week_boundaries(weeks_back=1)
        this_start, _, _, _ = _week_boundaries(weeks_back=1)
        assert last_end == this_start


# ── gather_weekly_data ────────────────────────────────────────────────────


class TestGatherWeeklyData:
    def test_empty_database_returns_zero_counts(self):
        conn = _make_conn()
        data = gather_weekly_data(conn, weeks_back=1)
        assert data.total_cves_this_week == 0
        assert data.total_pocs_this_week == 0
        assert data.kev_new_this_week == 0
        assert data.top_cves == []
        conn.close()

    def test_counts_cves_in_week_window(self):
        conn = _make_conn()
        now = _utc_now()
        # Find Monday of current week
        monday = now - timedelta(days=now.weekday())
        monday = monday.replace(hour=0, minute=0, second=0, microsecond=0)
        # Place CVE 2 weeks back from current week
        target_monday = monday - timedelta(days=14)  # 2 Mondays ago
        cve_time = target_monday + timedelta(days=1)
        cve_str = cve_time.strftime("%Y-%m-%dT%H:%M:%S")

        _seed_cve(conn, "CVE-2026-0001", cve_str, cvss_score=9.5, severity="CRITICAL")
        _seed_cve(conn, "CVE-2026-0002", cve_str, cvss_score=7.0, severity="HIGH")
        conn.commit()

        data = gather_weekly_data(conn, weeks_back=2)
        assert data.total_cves_this_week == 2
        assert data.critical_cves == 1
        assert data.high_cves == 1
        conn.close()

    def test_counts_pocs_in_week_window(self):
        conn = _make_conn()
        now = _utc_now()
        monday = now - timedelta(days=now.weekday())
        monday = monday.replace(hour=0, minute=0, second=0, microsecond=0)
        target_monday = monday - timedelta(days=14)
        poc_time = target_monday + timedelta(days=2)
        poc_str = poc_time.strftime("%Y-%m-%dT%H:%M:%S")

        _seed_poc(conn, "https://github.com/test/poc1", poc_str, stars=50)
        _seed_poc(conn, "https://github.com/test/poc2", poc_str, stars=30)
        conn.commit()

        data = gather_weekly_data(conn, weeks_back=2)
        assert data.total_pocs_this_week == 2
        conn.close()

    def test_kev_counting(self):
        conn = _make_conn()
        now = _utc_now()
        monday = now - timedelta(days=now.weekday())
        monday = monday.replace(hour=0, minute=0, second=0, microsecond=0)
        target_monday = monday - timedelta(days=14)
        cve_time = target_monday + timedelta(days=1)
        cve_str = cve_time.strftime("%Y-%m-%dT%H:%M:%S")

        _seed_cve(conn, "CVE-2026-0001", cve_str, kev=1, due_date="2026-05-01")
        _seed_cve(conn, "CVE-2026-0002", cve_str, kev=0)
        conn.commit()

        data = gather_weekly_data(conn, weeks_back=2)
        assert data.kev_new_this_week == 1
        assert data.kev_total == 1
        assert data.kev_overdue == 1  # due_date 2026-05-01 is in the past
        conn.close()

    def test_top_cves_ordered_by_reputation(self):
        conn = _make_conn()
        now = _utc_now()
        monday = now - timedelta(days=now.weekday())
        monday = monday.replace(hour=0, minute=0, second=0, microsecond=0)
        target_monday = monday - timedelta(days=14)
        cve_time = target_monday + timedelta(days=1)
        cve_str = cve_time.strftime("%Y-%m-%dT%H:%M:%S")

        _seed_cve(conn, "CVE-2026-0001", cve_str, reputation=5.0)
        _seed_cve(conn, "CVE-2026-0002", cve_str, reputation=8.0)
        _seed_cve(conn, "CVE-2026-0003", cve_str, reputation=3.0)
        conn.commit()

        data = gather_weekly_data(conn, weeks_back=2)
        assert len(data.top_cves) == 3
        assert data.top_cves[0]["id"] == "CVE-2026-0002"  # highest reputation first
        assert data.top_cves[2]["id"] == "CVE-2026-0003"
        conn.close()

    def test_severity_breakdown(self):
        conn = _make_conn()
        now = _utc_now()
        monday = now - timedelta(days=now.weekday())
        monday = monday.replace(hour=0, minute=0, second=0, microsecond=0)
        target_monday = monday - timedelta(days=14)
        cve_time = target_monday + timedelta(days=1)
        cve_str = cve_time.strftime("%Y-%m-%dT%H:%M:%S")

        _seed_cve(conn, "CVE-2026-0001", cve_str, cvss_score=9.5, severity="CRITICAL")
        _seed_cve(conn, "CVE-2026-0002", cve_str, cvss_score=8.0, severity="HIGH")
        _seed_cve(conn, "CVE-2026-0003", cve_str, cvss_score=8.5, severity="HIGH")
        _seed_cve(conn, "CVE-2026-0004", cve_str, cvss_score=5.0, severity="MEDIUM")
        conn.commit()

        data = gather_weekly_data(conn, weeks_back=2)
        assert data.severity_breakdown["CRITICAL"] == 1
        assert data.severity_breakdown["HIGH"] == 2
        assert data.severity_breakdown["MEDIUM"] == 1
        conn.close()

    def test_news_highlights(self):
        conn = _make_conn()
        now = _utc_now()
        monday = now - timedelta(days=now.weekday())
        monday = monday.replace(hour=0, minute=0, second=0, microsecond=0)
        target_monday = monday - timedelta(days=14)
        news_time = target_monday + timedelta(days=1)
        news_str = news_time.strftime("%Y-%m-%dT%H:%M:%S")

        conn.execute(
            """INSERT INTO news_article (title, url, source, tier, summary, first_seen)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                "Critical RCE in TestApp",
                "https://example.com/news/1",
                "cisa",
                1,
                "Summary text",
                news_str,
            ),
        )
        conn.commit()

        data = gather_weekly_data(conn, weeks_back=2)
        assert len(data.news_highlights) == 1
        assert data.news_highlights[0]["title"] == "Critical RCE in TestApp"
        assert data.news_highlights[0]["tier"] == 1
        conn.close()

    def test_threatfox_summary(self):
        conn = _make_conn()
        now = _utc_now()
        monday = now - timedelta(days=now.weekday())
        monday = monday.replace(hour=0, minute=0, second=0, microsecond=0)
        target_monday = monday - timedelta(days=14)
        cve_time = target_monday + timedelta(days=1)
        cve_str = cve_time.strftime("%Y-%m-%dT%H:%M:%S")

        _seed_cve(conn, "CVE-2026-0001", cve_str)
        conn.execute(
            """INSERT INTO cve_threatfox_ioc (cve_id, ioc_type, ioc_value, threat_type, first_seen, last_seen)
               VALUES (?, ?, ?, ?, ?, ?)""",
            ("CVE-2026-0001", "ip", "1.2.3.4", "cobalt-strike", cve_str, cve_str),
        )
        conn.execute(
            """INSERT INTO cve_threatfox_ioc (cve_id, ioc_type, ioc_value, threat_type, first_seen, last_seen)
               VALUES (?, ?, ?, ?, ?, ?)""",
            ("CVE-2026-0001", "domain", "evil.example.com", "cobalt-strike", cve_str, cve_str),
        )
        conn.commit()

        data = gather_weekly_data(conn, weeks_back=2)
        assert data.threatfox_summary["total_iocs"] == 2
        assert data.threatfox_summary["cves_with_iocs"] == 1
        assert data.threatfox_summary["type_counts"]["ip"] == 1
        assert data.threatfox_summary["type_counts"]["domain"] == 1
        conn.close()

    def test_triage_summary(self):
        conn = _make_conn()
        now = _utc_now()
        monday = now - timedelta(days=now.weekday())
        monday = monday.replace(hour=0, minute=0, second=0, microsecond=0)
        target_monday = monday - timedelta(days=14)
        cve_time = target_monday + timedelta(days=1)
        cve_str = cve_time.strftime("%Y-%m-%dT%H:%M:%S")

        _seed_cve(conn, "CVE-2026-0001", cve_str)
        _seed_cve(conn, "CVE-2026-0002", cve_str)
        _seed_cve(conn, "CVE-2026-0003", cve_str)
        conn.execute(
            "INSERT INTO cve_triage (cve_id, status, updated_at) VALUES (?, ?, ?)",
            ("CVE-2026-0001", "new", cve_str),
        )
        conn.execute(
            "INSERT INTO cve_triage (cve_id, status, updated_at) VALUES (?, ?, ?)",
            ("CVE-2026-0002", "done", cve_str),
        )
        conn.execute(
            "INSERT INTO cve_triage (cve_id, status, updated_at) VALUES (?, ?, ?)",
            ("CVE-2026-0003", "working", cve_str),
        )
        conn.commit()

        data = gather_weekly_data(conn, weeks_back=2)
        assert data.triage_summary["new"] == 1
        assert data.triage_summary["done"] == 1
        assert data.triage_summary["working"] == 1
        conn.close()

    def test_source_health(self):
        conn = _make_conn()
        conn.execute(
            """INSERT INTO source_health (source_name, last_run_at, last_status, cve_count, poc_count, consecutive_failures)
               VALUES (?, ?, ?, ?, ?, ?)""",
            ("nvd", "2026-08-01T12:00:00", "ok", 100, 50, 0),
        )
        conn.execute(
            """INSERT INTO source_health (source_name, last_run_at, last_status, cve_count, poc_count, consecutive_failures)
               VALUES (?, ?, ?, ?, ?, ?)""",
            ("github", "2026-08-01T12:00:00", "error", 0, 0, 3),
        )
        conn.commit()

        data = gather_weekly_data(conn, weeks_back=1)
        assert len(data.source_health) == 2
        sources = {sh["source"]: sh for sh in data.source_health}
        assert sources["nvd"]["status"] == "ok"
        assert sources["github"]["consecutive_failures"] == 3
        conn.close()

    def test_vendor_breakdown(self):
        conn = _make_conn()
        now = _utc_now()
        monday = now - timedelta(days=now.weekday())
        monday = monday.replace(hour=0, minute=0, second=0, microsecond=0)
        target_monday = monday - timedelta(days=14)
        cve_time = target_monday + timedelta(days=1)
        cve_str = cve_time.strftime("%Y-%m-%dT%H:%M:%S")

        _seed_cve(conn, "CVE-2026-0001", cve_str, cvss_score=8.0)
        _seed_cve(conn, "CVE-2026-0002", cve_str, cvss_score=9.0)
        conn.execute(
            "INSERT INTO product (vendor, product, category) VALUES (?, ?, ?)",
            ("Acme", "Widget", "app"),
        )
        conn.execute(
            "INSERT INTO cve_product (cve_id, product_id) VALUES (?, ?)", ("CVE-2026-0001", 1)
        )
        conn.execute(
            "INSERT INTO cve_product (cve_id, product_id) VALUES (?, ?)", ("CVE-2026-0002", 1)
        )
        conn.commit()

        data = gather_weekly_data(conn, weeks_back=2)
        assert len(data.top_vendors) == 1
        assert data.top_vendors[0]["vendor"] == "Acme"
        assert data.top_vendors[0]["cve_count"] == 2
        conn.close()

    def test_attack_tags(self):
        conn = _make_conn()
        now = _utc_now()
        monday = now - timedelta(days=now.weekday())
        monday = monday.replace(hour=0, minute=0, second=0, microsecond=0)
        target_monday = monday - timedelta(days=14)
        cve_time = target_monday + timedelta(days=1)
        cve_str = cve_time.strftime("%Y-%m-%dT%H:%M:%S")

        _seed_cve(conn, "CVE-2026-0001", cve_str)
        _seed_cve(conn, "CVE-2026-0002", cve_str)
        conn.execute(
            "INSERT INTO cve_attack_tag (cve_id, tag) VALUES (?, ?)", ("CVE-2026-0001", "rce")
        )
        conn.execute(
            "INSERT INTO cve_attack_tag (cve_id, tag) VALUES (?, ?)", ("CVE-2026-0002", "rce")
        )
        conn.execute(
            "INSERT INTO cve_attack_tag (cve_id, tag) VALUES (?, ?)", ("CVE-2026-0001", "xss")
        )
        conn.commit()

        data = gather_weekly_data(conn, weeks_back=2)
        assert len(data.top_tags) >= 1
        rce_tag = next(t for t in data.top_tags if t["tag"] == "rce")
        assert rce_tag["cve_count"] == 2
        conn.close()

    def test_weekly_trend_returns_buckets(self):
        conn = _make_conn()
        now = _utc_now()
        monday = now - timedelta(days=now.weekday())
        monday = monday.replace(hour=0, minute=0, second=0, microsecond=0)

        # Seed CVEs across different weeks
        for week_offset in range(4):
            target_monday = monday - timedelta(days=week_offset * 7)
            for day in range(7):
                cve_time = target_monday + timedelta(days=day)
                cve_str = cve_time.strftime("%Y-%m-%dT%H:%M:%S")
                _seed_cve(conn, f"CVE-2026-{1000 + week_offset * 7 + day:04d}", cve_str)

        conn.commit()
        data = gather_weekly_data(conn, weeks_back=2)
        assert len(data.weekly_trend) > 0
        conn.close()
