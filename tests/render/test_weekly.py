"""Tests for horus/render/weekly.py — weekly report text/md/html renderers."""

from __future__ import annotations

from horus.render.weekly import (
    _pct_change,
    _severity_emoji,
    _tier_label,
    _trend_arrow,
    render_weekly_report,
)
from horus.storage.weekly import WeeklyData

# ── Helpers ────────────────────────────────────────────────────────────────


def _make_weekly_data(**overrides) -> WeeklyData:
    """Create a minimal WeeklyData with defaults, applying overrides."""
    defaults = {
        "period_start": "2026-07-20",
        "period_end": "2026-07-27",
        "previous_period_start": "2026-07-13",
        "previous_period_end": "2026-07-20",
        "generated_at": "2026-08-05 18:00 UTC",
        "total_cves_this_week": 100,
        "total_cves_last_week": 80,
        "total_pocs_this_week": 20,
        "total_pocs_last_week": 15,
        "kev_new_this_week": 2,
        "kev_total": 10,
        "kev_overdue": 1,
        "critical_cves": 5,
        "high_cves": 25,
        "avg_cvss_this_week": 7.2,
        "avg_epss_this_week": 0.05,
        "avg_reputation_this_week": 3.5,
        "top_cves": [
            {
                "id": "CVE-2026-0001",
                "description": "A critical RCE vulnerability",
                "cvss_score": 9.8,
                "cvss_severity": "CRITICAL",
                "epss_score": 0.95,
                "kev": True,
                "reputation_score": 8.5,
                "social_mentions": 50,
                "poc_source_count": 3,
                "published_at": "2026-07-21",
                "trust_score": 85.0,
                "threatfox_ioc_count": 5,
                "stealer_hits": 0,
                "kev_due_date": "2026-08-15",
            },
            {
                "id": "CVE-2026-0002",
                "description": "A high severity XSS",
                "cvss_score": 7.5,
                "cvss_severity": "HIGH",
                "epss_score": 0.3,
                "kev": False,
                "reputation_score": 5.0,
                "social_mentions": 10,
                "poc_source_count": 1,
                "published_at": "2026-07-22",
                "trust_score": 60.0,
                "threatfox_ioc_count": 0,
                "stealer_hits": 0,
                "kev_due_date": None,
            },
        ],
        "kev_entries": [
            {
                "id": "CVE-2026-0001",
                "description": "A critical RCE vulnerability",
                "cvss_score": 9.8,
                "epss_score": 0.95,
                "kev_due_date": "2026-08-15",
                "published_at": "2026-07-21",
                "is_new": True,
                "is_overdue": False,
            },
        ],
        "epss_movers": [
            {
                "id": "CVE-2026-0001",
                "cvss_score": 9.8,
                "epss_score": 0.95,
                "kev": True,
                "reputation_score": 8.5,
                "description": "A critical RCE vulnerability",
            },
        ],
        "top_vendors": [
            {"vendor": "microsoft", "cve_count": 30, "avg_cvss": 7.5, "kev_count": 1},
            {"vendor": "cisco", "cve_count": 20, "avg_cvss": 8.0, "kev_count": 0},
        ],
        "top_tags": [
            {"tag": "rce", "cve_count": 15, "avg_cvss": 8.5},
            {"tag": "xss", "cve_count": 10, "avg_cvss": 6.5},
        ],
        "news_highlights": [
            {
                "title": "Major Security Incident",
                "url": "https://example.com/news/1",
                "source": "cisa",
                "tier": 1,
                "summary": "A major incident occurred",
                "published_at": "2026-07-23",
            },
        ],
        "threatfox_summary": {
            "total_iocs": 50,
            "cves_with_iocs": 10,
            "type_counts": {"ip": 20, "domain": 15, "hash": 10, "url": 5},
            "top_threat_types": [
                {"threat_type": "cobalt-strike", "count": 25},
                {"threat_type": "ransomware", "count": 10},
            ],
        },
        "top_pocs": [
            {
                "url": "https://github.com/test/poc1",
                "source": "github",
                "stars": 100,
                "description": "RCE PoC",
                "exploit_type": "RCE",
                "linked_cves": 1,
            },
        ],
        "severity_breakdown": {"CRITICAL": 5, "HIGH": 25, "MEDIUM": 40, "LOW": 10},
        "weekly_trend": [
            {"week": "2026-W28", "count": 80},
            {"week": "2026-W29", "count": 90},
            {"week": "2026-W30", "count": 100},
        ],
        "vendor_risk": [],
        "triage_summary": {
            "new": 50,
            "acknowledged": 20,
            "working": 10,
            "done": 15,
            "dismissed": 5,
        },
        "source_health": [
            {
                "source": "nvd",
                "last_run": "2026-07-25T12:00:00",
                "status": "ok",
                "error": None,
                "cves": 100,
                "pocs": 0,
                "consecutive_failures": 0,
            },
        ],
    }
    defaults.update(overrides)
    return WeeklyData(**defaults)


# ── Helper function tests ─────────────────────────────────────────────────


class TestPctChange:
    def test_increase(self):
        assert _pct_change(150, 100) == "+50%"

    def test_decrease(self):
        assert _pct_change(50, 100) == "-50%"

    def test_zero_last_week(self):
        assert _pct_change(10, 0) == "NEW"

    def test_both_zero(self):
        assert _pct_change(0, 0) == "0%"

    def test_same(self):
        assert _pct_change(100, 100) == "0%"


class TestTrendArrow:
    def test_up(self):
        assert _trend_arrow(100, 50) == "▲"

    def test_down(self):
        assert _trend_arrow(50, 100) == "▼"

    def test_flat(self):
        assert _trend_arrow(100, 100) == "→"


class TestSeverityEmoji:
    def test_critical(self):
        assert _severity_emoji("CRITICAL") == "🔴"

    def test_high(self):
        assert _severity_emoji("HIGH") == "🟠"

    def test_medium(self):
        assert _severity_emoji("MEDIUM") == "🟡"

    def test_low(self):
        assert _severity_emoji("LOW") == "🟢"

    def test_unknown(self):
        assert _severity_emoji("UNKNOWN") == "⚪"


class TestTierLabel:
    def test_tiers(self):
        assert _tier_label(1) == "CRITICAL"
        assert _tier_label(2) == "HIGH"
        assert _tier_label(3) == "MEDIUM"
        assert _tier_label(4) == "LOW"
        assert _tier_label(5) == "BACKGROUND"

    def test_unknown(self):
        assert _tier_label(99) == "INFO"


# ── Markdown renderer tests ───────────────────────────────────────────────


class TestRenderMarkdown:
    def test_header_contains_period(self):
        data = _make_weekly_data()
        report = render_weekly_report(data, fmt="md")
        assert "2026-07-20" in report
        assert "2026-07-27" in report

    def test_executive_summary_table(self):
        data = _make_weekly_data()
        report = render_weekly_report(data, fmt="md")
        assert "Executive Summary" in report
        assert "New CVEs" in report
        assert "100" in report

    def test_top_cves_table(self):
        data = _make_weekly_data()
        report = render_weekly_report(data, fmt="md")
        assert "CVE-2026-0001" in report
        assert "CVE-2026-0002" in report

    def test_kev_section(self):
        data = _make_weekly_data()
        report = render_weekly_report(data, fmt="md")
        assert "CISA" in report
        assert "KEV" in report

    def test_overdue_warning(self):
        data = _make_weekly_data(kev_overdue=1)
        report = render_weekly_report(data, fmt="md")
        assert "WARNING" in report or "OVERDUE" in report

    def test_no_overdue_when_zero(self):
        data = _make_weekly_data(kev_overdue=0, kev_entries=[])
        report = render_weekly_report(data, fmt="md")
        assert "OVERDUE" not in report

    def test_vendor_table(self):
        data = _make_weekly_data()
        report = render_weekly_report(data, fmt="md")
        assert "microsoft" in report
        assert "cisco" in report

    def test_news_section(self):
        data = _make_weekly_data()
        report = render_weekly_report(data, fmt="md")
        assert "Major Security Incident" in report

    def test_threatfox_section(self):
        data = _make_weekly_data()
        report = render_weekly_report(data, fmt="md")
        assert "ThreatFox" in report
        assert "50" in report  # total_iocs

    def test_triage_section(self):
        data = _make_weekly_data()
        report = render_weekly_report(data, fmt="md")
        assert "Triage" in report

    def test_source_health_section(self):
        data = _make_weekly_data()
        report = render_weekly_report(data, fmt="md")
        assert "Source Health" in report
        assert "nvd" in report

    def test_empty_data_minimal_report(self):
        data = _make_weekly_data(
            top_cves=[],
            kev_entries=[],
            epss_movers=[],
            top_vendors=[],
            top_tags=[],
            news_highlights=[],
            threatfox_summary={},
            top_pocs=[],
            severity_breakdown={},
            weekly_trend=[],
            triage_summary={},
            source_health=[],
        )
        report = render_weekly_report(data, fmt="md")
        assert "Executive Summary" in report
        assert "Weekly Threat Intelligence Report" in report


# ── Text renderer tests ───────────────────────────────────────────────────


class TestRenderText:
    def test_header_contains_period(self):
        data = _make_weekly_data()
        report = render_weekly_report(data, fmt="text")
        assert "2026-07-20" in report

    def test_executive_summary(self):
        data = _make_weekly_data()
        report = render_weekly_report(data, fmt="text")
        assert "EXECUTIVE SUMMARY" in report
        assert "100" in report

    def test_top_cves(self):
        data = _make_weekly_data()
        report = render_weekly_report(data, fmt="text")
        assert "CVE-2026-0001" in report

    def test_severity_distribution(self):
        data = _make_weekly_data()
        report = render_weekly_report(data, fmt="text")
        assert "CRITICAL" in report
        assert "HIGH" in report


# ── HTML renderer tests ───────────────────────────────────────────────────


class TestRenderHtml:
    def test_is_valid_html(self):
        data = _make_weekly_data()
        report = render_weekly_report(data, fmt="html")
        assert "<!DOCTYPE html>" in report
        assert "</html>" in report

    def test_contains_title(self):
        data = _make_weekly_data()
        report = render_weekly_report(data, fmt="html")
        assert "Weekly Threat Report" in report

    def test_kpi_cards(self):
        data = _make_weekly_data()
        report = render_weekly_report(data, fmt="html")
        assert "kpi-card" in report
        assert "100" in report  # total CVEs

    def test_cve_table(self):
        data = _make_weekly_data()
        report = render_weekly_report(data, fmt="html")
        assert "CVE-2026-0001" in report
        assert "data-table" in report

    def test_css_included(self):
        data = _make_weekly_data()
        report = render_weekly_report(data, fmt="html")
        assert "<style>" in report

    def test_dark_theme(self):
        data = _make_weekly_data()
        report = render_weekly_report(data, fmt="html")
        assert "#0d1117" in report  # dark bg color

    def test_news_section_html(self):
        data = _make_weekly_data()
        report = render_weekly_report(data, fmt="html")
        assert "Major Security Incident" in report
        assert "news-item" in report

    def test_empty_data_html(self):
        data = _make_weekly_data(
            top_cves=[],
            kev_entries=[],
            epss_movers=[],
            top_vendors=[],
            top_tags=[],
            news_highlights=[],
            threatfox_summary={},
            top_pocs=[],
            severity_breakdown={},
            weekly_trend=[],
            triage_summary={},
            source_health=[],
        )
        report = render_weekly_report(data, fmt="html")
        assert "<!DOCTYPE html>" in report
        assert "Executive Summary" in report
