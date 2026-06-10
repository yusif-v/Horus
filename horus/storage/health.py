"""Database health check system.

Validates data integrity, consistency, and correctness across all tables.
Designed to be run independently or as part of the Horus pipeline.

Checks:
  1. Schema integrity — all expected tables and columns exist
  2. CVE data quality — ID format, CVSS range, severity values, dates
  3. PoC data quality — URL format, source enum, stars/age ranges
  4. Referential integrity — orphan rows in join tables
  5. Enum consistency — attack tags, product categories, PoC sources
  6. Join table consistency — cve_attack_tag, cwe, poc_cve, cve_source
  7. Stale data detection — old unupdated records
  8. Duplicate detection — logical duplicates across tables
  9. Coverage metrics — enrichment completeness (EPSS, KEV)
 10. Source tracking — all CVEs have at least one source entry

Usage:
    from horus.storage.health import run_health_check
    report = run_health_check()
    report.print()
"""

from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from horus.config import STATE_DIR
from horus.core.vocab import ATTACK_TAGS, PRODUCT_CATEGORIES

DB_PATH_DEFAULT = STATE_DIR / "horus.db"


# ─── Allowed values ──────────────────────────────────────────────────────────

ALLOWED_POC_SOURCES = frozenset(
    {
        "github",
        "gitlab",
        "exploit-db",
        "packetstorm",
        "nitter",
        "twitter",
        "x",
        "manual",
    }
)

ALLOWED_CVE_SOURCES = frozenset(
    {
        "nvd",
        "github",
        "exploit-db",
        "packetstorm",
        "nitter",
        "twitter",
        "x",
        "manual",
    }
)

ALLOWED_SEVERITIES = frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL", ""})

CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


# ─── Report structures ──────────────────────────────────────────────────────


@dataclass
class HealthIssue:
    severity: str  # "error" | "warning" | "info"
    category: str
    message: str
    details: list[str] = field(default_factory=list)


@dataclass
class HealthReport:
    issues: list[HealthIssue] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)
    passed: bool = True

    def add(self, severity: str, category: str, message: str, details: list[str] | None = None):
        self.issues.append(
            HealthIssue(
                severity=severity,
                category=category,
                message=message,
                details=details or [],
            )
        )
        if severity == "error":
            self.passed = False

    def error(self, category: str, message: str, details=None):
        self.add("error", category, message, details)

    def warning(self, category: str, message: str, details=None):
        self.add("warning", category, message, details)

    def info(self, category: str, message: str, details=None):
        self.add("info", category, message, details)

    def print(self):
        """Print the health report to stdout."""
        errors = [i for i in self.issues if i.severity == "error"]
        warnings = [i for i in self.issues if i.severity == "warning"]
        infos = [i for i in self.issues if i.severity == "info"]

        print()
        print("=" * 60)
        print("  HORUS DATABASE HEALTH REPORT")
        print("=" * 60)

        # Stats
        if self.stats:
            print()
            print("── Statistics ──────────────────────────────────────────")
            for key, val in sorted(self.stats.items()):
                print(f"  {key}: {val}")

        # Issues
        if errors:
            print()
            print(f"── Errors ({len(errors)}) ─────────────────────────────────")
            for issue in errors:
                print(f"  [ERROR] [{issue.category}] {issue.message}")
                for d in issue.details[:5]:
                    print(f"           {d}")
                if len(issue.details) > 5:
                    print(f"           ... and {len(issue.details) - 5} more")

        if warnings:
            print()
            print(f"── Warnings ({len(warnings)}) ───────────────────────────────")
            for issue in warnings:
                print(f"  [WARN]  [{issue.category}] {issue.message}")
                for d in issue.details[:3]:
                    print(f"           {d}")
                if len(issue.details) > 3:
                    print(f"           ... and {len(issue.details) - 3} more")

        if infos:
            print()
            print(f"── Info ({len(infos)}) ──────────────────────────────────────")
            for issue in infos:
                print(f"  [INFO]  [{issue.category}] {issue.message}")

        print()
        if self.passed and not warnings:
            print("  PASSED — all checks OK")
        elif self.passed:
            print("  PASSED with warnings")
        else:
            print("  FAILED — errors found")
        print("=" * 60)
        print()


# ─── Check functions ────────────────────────────────────────────────────────


def _check_schema(conn: sqlite3.Connection, report: HealthReport):
    """Verify all expected tables and columns exist."""
    expected_tables = {
        "cve": {
            "id",
            "description",
            "cvss_score",
            "cvss_severity",
            "published_at",
            "epss_score",
            "kev",
            "exploitability_score",
            "first_seen",
            "last_seen",
        },
        "poc": {
            "url",
            "source",
            "stars",
            "age_days",
            "description",
            "fetched_date",
            "first_seen",
            "last_seen",
        },
        "product": {"id", "vendor", "product", "category"},
        "attack_tag": {"name"},
        "cwe": {"id", "attack_tag"},
        "cve_attack_tag": {"cve_id", "tag"},
        "cve_cwe": {"cve_id", "cwe_id"},
        "cve_product": {"cve_id", "product_id", "versions"},
        "cve_source": {"cve_id", "source"},
        "poc_cve": {"poc_url", "cve_id"},
        "meta": {"key", "value"},
    }

    existing_tables = {
        row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }

    for table, expected_cols in expected_tables.items():
        if table not in existing_tables:
            report.error("schema", f"Missing table: {table}")
            continue

        existing_cols = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
        missing = expected_cols - existing_cols
        if missing:
            report.error("schema", f"Table '{table}' missing columns: {', '.join(sorted(missing))}")

    # Check indexes
    expected_indexes = [
        "idx_cve_published_at",
        "idx_cve_cvss_score",
        "idx_cve_epss_score",
        "idx_cve_kev",
        "idx_cve_product_product_id",
        "idx_cve_attack_tag_tag",
        "idx_poc_cve_cve_id",
        "idx_poc_source",
    ]
    existing_indexes = {
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_%'"
        )
    }
    for idx in expected_indexes:
        if idx not in existing_indexes:
            report.warning("schema", f"Missing index: {idx}")


def _check_cve_data_quality(conn: sqlite3.Connection, report: HealthReport):
    """Validate CVE records for data quality issues."""
    re_id = CVE_ID_RE

    total = conn.execute("SELECT COUNT(*) FROM cve").fetchone()[0]
    report.stats["total_cves"] = total

    if total == 0:
        report.info("cve_data", "No CVEs in database")
        return

    # 1. Invalid CVE ID format
    rows = conn.execute("SELECT id FROM cve").fetchall()
    bad_ids = [(r[0],) for r in rows if not re_id.match(r[0])]
    if bad_ids:
        report.error(
            "cve_data",
            f"{len(bad_ids)} CVEs with invalid ID format",
            [f"  {r[0]}" for r in bad_ids[:10]],
        )

    # 2. CVSS score out of range (0-10)
    rows = conn.execute("SELECT id, cvss_score FROM cve WHERE cvss_score IS NOT NULL").fetchall()
    bad_cvss = [(r[0], r[1]) for r in rows if r[1] < 0 or r[1] > 10]
    if bad_cvss:
        report.error(
            "cve_data",
            f"{len(bad_cvss)} CVEs with CVSS out of range [0-10]",
            [f"  {r[0]}: {r[1]}" for r in bad_cvss[:10]],
        )

    # 3. Invalid severity values
    rows = conn.execute(
        "SELECT id, cvss_severity FROM cve WHERE cvss_severity IS NOT NULL"
    ).fetchall()
    bad_sev = [(r[0], r[1]) for r in rows if r[1].upper() not in ALLOWED_SEVERITIES]
    if bad_sev:
        report.error(
            "cve_data",
            f"{len(bad_sev)} CVEs with invalid severity",
            [f"  {r[0]}: '{r[1]}'" for r in bad_sev[:10]],
        )

    # 4. EPSS score out of range (0-1)
    rows = conn.execute("SELECT id, epss_score FROM cve WHERE epss_score IS NOT NULL").fetchall()
    bad_epss = [(r[0], r[1]) for r in rows if r[1] < 0 or r[1] > 1]
    if bad_epss:
        report.error(
            "cve_data",
            f"{len(bad_epss)} CVEs with EPSS out of range [0-1]",
            [f"  {r[0]}: {r[1]}" for r in bad_epss[:10]],
        )

    # 5. KEV not 0 or 1
    rows = conn.execute("SELECT id, kev FROM cve").fetchall()
    bad_kev = [(r[0], r[1]) for r in rows if r[1] not in (0, 1)]
    if bad_kev:
        report.error(
            "cve_data",
            f"{len(bad_kev)} CVEs with invalid KEV value",
            [f"  {r[0]}: {r[1]}" for r in bad_kev[:10]],
        )

    # 6. Missing first_seen / last_seen
    rows = conn.execute(
        "SELECT id FROM cve WHERE first_seen IS NULL OR last_seen IS NULL"
    ).fetchall()
    if rows:
        report.error(
            "cve_data",
            f"{len(rows)} CVEs with missing timestamps",
            [f"  {r[0]}" for r in rows[:10]],
        )

    # 7. Empty description
    rows = conn.execute(
        "SELECT id FROM cve WHERE description IS NULL OR description = ''"
    ).fetchall()
    if rows:
        report.warning(
            "cve_data", f"{len(rows)} CVEs with empty description", [f"  {r[0]}" for r in rows[:10]]
        )

    # 8. Future published_at
    now = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
    rows = conn.execute(
        "SELECT id, published_at FROM cve WHERE published_at > ?",
        (now,),
    ).fetchall()
    if rows:
        report.warning(
            "cve_data",
            f"{len(rows)} CVEs with future published_at",
            [f"  {r[0]}: {r[1]}" for r in rows[:10]],
        )

    # 9. Duplicate CVE IDs (shouldn't happen with PK, but check anyway)
    rows = conn.execute("SELECT id, COUNT(*) as cnt FROM cve GROUP BY id HAVING cnt > 1").fetchall()
    if rows:
        report.error(
            "cve_data",
            f"{len(rows)} duplicate CVE IDs",
            [f"  {r[0]}: {r[1]} copies" for r in rows[:10]],
        )

    # Coverage stats
    with_epss = conn.execute("SELECT COUNT(*) FROM cve WHERE epss_score IS NOT NULL").fetchone()[0]
    with_kev = conn.execute("SELECT COUNT(*) FROM cve WHERE kev = 1").fetchone()[0]
    with_cvss = conn.execute("SELECT COUNT(*) FROM cve WHERE cvss_score IS NOT NULL").fetchone()[0]
    with_desc = conn.execute(
        "SELECT COUNT(*) FROM cve WHERE description IS NOT NULL AND description != ''"
    ).fetchone()[0]
    with_tags = conn.execute("SELECT COUNT(DISTINCT cve_id) FROM cve_attack_tag").fetchone()[0]
    with_products = conn.execute("SELECT COUNT(DISTINCT cve_id) FROM cve_product").fetchone()[0]
    with_pocs = conn.execute("SELECT COUNT(DISTINCT cve_id) FROM poc_cve").fetchone()[0]

    report.stats["cves_with_epss"] = (
        f"{with_epss}/{total} ({with_epss * 100 // total if total else 0}%)"
    )
    report.stats["cves_with_kev"] = with_kev
    report.stats["cves_with_cvss"] = (
        f"{with_cvss}/{total} ({with_cvss * 100 // total if total else 0}%)"
    )
    report.stats["cves_with_description"] = (
        f"{with_desc}/{total} ({with_desc * 100 // total if total else 0}%)"
    )
    report.stats["cves_with_attack_tags"] = (
        f"{with_tags}/{total} ({with_tags * 100 // total if total else 0}%)"
    )
    report.stats["cves_with_products"] = (
        f"{with_products}/{total} ({with_products * 100 // total if total else 0}%)"
    )
    report.stats["cves_with_pocs"] = (
        f"{with_pocs}/{total} ({with_pocs * 100 // total if total else 0}%)"
    )


def _check_poc_data_quality(conn: sqlite3.Connection, report: HealthReport):
    """Validate PoC records for data quality issues."""
    total = conn.execute("SELECT COUNT(*) FROM poc").fetchone()[0]
    report.stats["total_pocs"] = total

    if total == 0:
        report.info("poc_data", "No PoCs in database")
        return

    # 1. Invalid source values
    rows = conn.execute("SELECT url, source FROM poc").fetchall()
    bad_sources = [(r[0], r[1]) for r in rows if r[1] not in ALLOWED_POC_SOURCES]
    if bad_sources:
        report.error(
            "poc_data",
            f"{len(bad_sources)} PoCs with invalid source",
            [f"  {r[1]}: {r[0][:60]}" for r in bad_sources[:10]],
        )

    # 2. Invalid URL format (should start with http)
    rows = conn.execute("SELECT url FROM poc").fetchall()
    bad_urls = [r[0] for r in rows if not r[0].startswith(("http://", "https://"))]
    if bad_urls:
        report.error(
            "poc_data", f"{len(bad_urls)} PoCs with invalid URL", [f"  {u}" for u in bad_urls[:10]]
        )

    # 3. Negative stars
    rows = conn.execute(
        "SELECT url, stars FROM poc WHERE stars IS NOT NULL AND stars < 0"
    ).fetchall()
    if rows:
        report.warning(
            "poc_data",
            f"{len(rows)} PoCs with negative stars",
            [f"  {r[1]}: {r[0][:60]}" for r in rows[:10]],
        )

    # 4. Negative age_days
    rows = conn.execute(
        "SELECT url, age_days FROM poc WHERE age_days IS NOT NULL AND age_days < 0"
    ).fetchall()
    if rows:
        report.warning(
            "poc_data",
            f"{len(rows)} PoCs with negative age_days",
            [f"  {r[1]}: {r[0][:60]}" for r in rows[:10]],
        )

    # 5. Missing timestamps
    rows = conn.execute(
        "SELECT url FROM poc WHERE first_seen IS NULL OR last_seen IS NULL"
    ).fetchall()
    if rows:
        report.error(
            "poc_data",
            f"{len(rows)} PoCs with missing timestamps",
            [f"  {r[0][:60]}" for r in rows[:10]],
        )

    # 6. Duplicate URLs (shouldn't happen with PK)
    rows = conn.execute(
        "SELECT url, COUNT(*) as cnt FROM poc GROUP BY url HAVING cnt > 1"
    ).fetchall()
    if rows:
        report.error(
            "poc_data",
            f"{len(rows)} duplicate PoC URLs",
            [f"  {r[0][:60]}: {r[1]} copies" for r in rows[:10]],
        )

    # Source breakdown
    rows = conn.execute(
        "SELECT source, COUNT(*) FROM poc GROUP BY source ORDER BY COUNT(*) DESC"
    ).fetchall()
    for source, count in rows:
        report.stats[f"pocs_source_{source}"] = count

    # Linked vs standalone
    linked = conn.execute("SELECT COUNT(DISTINCT poc_url) FROM poc_cve").fetchone()[0]
    report.stats["pocs_linked_to_cves"] = (
        f"{linked}/{total} ({linked * 100 // total if total else 0}%)"
    )
    report.stats["pocs_standalone"] = total - linked


def _check_referential_integrity(conn: sqlite3.Connection, report: HealthReport):
    """Check for orphan rows in join tables."""

    # cve_attack_tag → cve
    orphans = conn.execute("""
        SELECT cat.cve_id, cat.tag FROM cve_attack_tag cat
        LEFT JOIN cve c ON c.id = cat.cve_id
        WHERE c.id IS NULL
    """).fetchall()
    if orphans:
        report.error(
            "referential",
            f"{len(orphans)} cve_attack_tag rows reference non-existent CVEs",
            [f"  {r[0]} → {r[1]}" for r in orphans[:10]],
        )

    # cve_attack_tag → attack_tag
    orphans = conn.execute("""
        SELECT cat.cve_id, cat.tag FROM cve_attack_tag cat
        LEFT JOIN attack_tag a ON a.name = cat.tag
        WHERE a.name IS NULL
    """).fetchall()
    if orphans:
        report.error(
            "referential",
            f"{len(orphans)} cve_attack_tag rows reference non-existent attack tags",
            [f"  {r[0]} → {r[1]}" for r in orphans[:10]],
        )

    # cve_cwe → cve
    orphans = conn.execute("""
        SELECT cc.cve_id FROM cve_cwe cc
        LEFT JOIN cve c ON c.id = cc.cve_id
        WHERE c.id IS NULL
    """).fetchall()
    if orphans:
        report.error(
            "referential",
            f"{len(orphans)} cve_cwe rows reference non-existent CVEs",
            [f"  {r[0]}" for r in orphans[:10]],
        )

    # cve_product → cve
    orphans = conn.execute("""
        SELECT cp.cve_id FROM cve_product cp
        LEFT JOIN cve c ON c.id = cp.cve_id
        WHERE c.id IS NULL
    """).fetchall()
    if orphans:
        report.error(
            "referential",
            f"{len(orphans)} cve_product rows reference non-existent CVEs",
            [f"  {r[0]}" for r in orphans[:10]],
        )

    # cve_product → product
    orphans = conn.execute("""
        SELECT cp.cve_id, cp.product_id FROM cve_product cp
        LEFT JOIN product p ON p.id = cp.product_id
        WHERE p.id IS NULL
    """).fetchall()
    if orphans:
        report.error(
            "referential",
            f"{len(orphans)} cve_product rows reference non-existent products",
            [f"  {r[0]} → product_id={r[1]}" for r in orphans[:10]],
        )

    # poc_cve → poc
    orphans = conn.execute("""
        SELECT pc.poc_url FROM poc_cve pc
        LEFT JOIN poc p ON p.url = pc.poc_url
        WHERE p.url IS NULL
    """).fetchall()
    if orphans:
        report.error(
            "referential",
            f"{len(orphans)} poc_cve rows reference non-existent PoCs",
            [f"  {r[0][:60]}" for r in orphans[:10]],
        )

    # poc_cve → cve
    orphans = conn.execute("""
        SELECT pc.poc_url, pc.cve_id FROM poc_cve pc
        LEFT JOIN cve c ON c.id = pc.cve_id
        WHERE c.id IS NULL
    """).fetchall()
    if orphans:
        report.error(
            "referential",
            f"{len(orphans)} poc_cve rows reference non-existent CVEs",
            [f"  {r[1]} ← {r[0][:60]}" for r in orphans[:10]],
        )

    # cve_source → cve
    orphans = conn.execute("""
        SELECT cs.cve_id FROM cve_source cs
        LEFT JOIN cve c ON c.id = cs.cve_id
        WHERE c.id IS NULL
    """).fetchall()
    if orphans:
        report.error(
            "referential",
            f"{len(orphans)} cve_source rows reference non-existent CVEs",
            [f"  {r[0]}" for r in orphans[:10]],
        )


def _check_enum_consistency(conn: sqlite3.Connection, report: HealthReport):
    """Check that enum values match the locked vocabularies."""

    # Attack tags in DB vs vocab
    db_tags = {r[0] for r in conn.execute("SELECT name FROM attack_tag").fetchall()}
    extra_tags = db_tags - ATTACK_TAGS
    missing_tags = ATTACK_TAGS - db_tags
    if extra_tags:
        report.warning(
            "enum",
            f"{len(extra_tags)} attack tags in DB not in vocabulary",
            [f"  {t}" for t in sorted(extra_tags)[:10]],
        )
    if missing_tags:
        report.info(
            "enum",
            f"{len(missing_tags)} vocabulary attack tags not in DB",
            [f"  {t}" for t in sorted(missing_tags)[:10]],
        )

    # Product categories in DB vs vocab
    db_cats = {r[0] for r in conn.execute("SELECT DISTINCT category FROM product").fetchall()}
    extra_cats = db_cats - PRODUCT_CATEGORIES
    if extra_cats:
        report.warning(
            "enum",
            f"{len(extra_cats)} product categories in DB not in vocabulary",
            [f"  {c}" for c in sorted(extra_cats)[:10]],
        )

    # CVE sources in DB vs allowed
    db_sources = {r[0] for r in conn.execute("SELECT DISTINCT source FROM cve_source").fetchall()}
    extra_sources = db_sources - ALLOWED_CVE_SOURCES
    if extra_sources:
        report.warning(
            "enum",
            f"{len(extra_sources)} CVE sources in DB not in allowed set",
            [f"  {s}" for s in sorted(extra_sources)],
        )

    # PoC sources in DB vs allowed
    db_poc_sources = {r[0] for r in conn.execute("SELECT DISTINCT source FROM poc").fetchall()}
    extra_poc = db_poc_sources - ALLOWED_POC_SOURCES
    if extra_poc:
        report.warning(
            "enum",
            f"{len(extra_poc)} PoC sources in DB not in allowed set",
            [f"  {s}" for s in sorted(extra_poc)],
        )


def _check_cve_completeness(conn: sqlite3.Connection, report: HealthReport):
    """Check that CVEs have required related data."""

    # CVEs without any source entry
    orphans = conn.execute("""
        SELECT c.id FROM cve c
        LEFT JOIN cve_source cs ON cs.cve_id = c.id
        WHERE cs.cve_id IS NULL
    """).fetchall()
    if orphans:
        report.error(
            "completeness",
            f"{len(orphans)} CVEs without any source entry",
            [f"  {r[0]}" for r in orphans[:10]],
        )

    # CVEs without attack tags
    orphans = conn.execute("""
        SELECT c.id FROM cve c
        LEFT JOIN cve_attack_tag cat ON cat.cve_id = c.id
        WHERE cat.cve_id IS NULL
    """).fetchall()
    if orphans:
        report.warning(
            "completeness",
            f"{len(orphans)} CVEs without attack tags",
            [f"  {r[0]}" for r in orphans[:10]],
        )

    # CVEs without description
    orphans = conn.execute("""
        SELECT id FROM cve WHERE description IS NULL OR description = ''
    """).fetchall()
    if orphans:
        report.warning(
            "completeness",
            f"{len(orphans)} CVEs without description",
            [f"  {r[0]}" for r in orphans[:10]],
        )

    # CVEs without CVSS
    orphans = conn.execute("""
        SELECT id FROM cve WHERE cvss_score IS NULL
    """).fetchall()
    if orphans:
        report.info(
            "completeness",
            f"{len(orphans)} CVEs without CVSS score",
            [f"  {r[0]}" for r in orphans[:10]],
        )


def _check_stale_data(conn: sqlite3.Connection, report: HealthReport):
    """Detect stale or outdated data."""

    # CVEs not seen in 30+ days
    cutoff = (datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=30)).isoformat()
    stale = conn.execute(
        "SELECT id, last_seen FROM cve WHERE last_seen < ?",
        (cutoff,),
    ).fetchall()
    if stale:
        report.info(
            "stale",
            f"{len(stale)} CVEs not updated in 30+ days",
            [f"  {r[0]}: last_seen={r[1]}" for r in stale[:5]],
        )

    # PoCs not seen in 30+ days
    stale_pocs = conn.execute(
        "SELECT url, last_seen FROM poc WHERE last_seen < ?",
        (cutoff,),
    ).fetchall()
    if stale_pocs:
        report.info(
            "stale",
            f"{len(stale_pocs)} PoCs not updated in 30+ days",
            [f"  {r[0][:60]}: last_seen={r[1]}" for r in stale_pocs[:5]],
        )


def _check_logical_duplicates(conn: sqlite3.Connection, report: HealthReport):
    """Detect potential logical duplicates."""

    # Products with same vendor+product but different IDs (shouldn't happen with UNIQUE constraint)
    dups = conn.execute("""
        SELECT vendor, product, COUNT(*) as cnt
        FROM product
        GROUP BY vendor, product
        HAVING cnt > 1
    """).fetchall()
    if dups:
        report.error(
            "duplicates",
            f"{len(dups)} duplicate product entries",
            [f"  {r[0]}/{r[1]}: {r[2]} copies" for r in dups[:10]],
        )

    # CVEs with identical descriptions (potential duplicates)
    dups = conn.execute("""
        SELECT description, COUNT(*) as cnt, GROUP_CONCAT(id) as ids
        FROM cve
        WHERE description IS NOT NULL AND description != ''
        GROUP BY description
        HAVING cnt > 1
    """).fetchall()
    if dups:
        report.warning(
            "duplicates",
            f"{len(dups)} groups of CVEs with identical descriptions",
            [f'  {r[2]}: "{r[0][:50]}"' for r in dups[:5]],
        )


# ─── Main entry point ───────────────────────────────────────────────────────


def run_health_check(db_path: str | None = None) -> HealthReport:
    """Run all health checks and return a report."""
    report = HealthReport()

    if db_path is None:
        db_path = str(DB_PATH_DEFAULT)

    if not Path(db_path).exists():
        report.error("database", f"Database file not found: {db_path}")
        return report

    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys = ON")

    try:
        _check_schema(conn, report)
        _check_cve_data_quality(conn, report)
        _check_poc_data_quality(conn, report)
        _check_referential_integrity(conn, report)
        _check_enum_consistency(conn, report)
        _check_cve_completeness(conn, report)
        _check_stale_data(conn, report)
        _check_logical_duplicates(conn, report)
    finally:
        conn.close()

    return report


if __name__ == "__main__":
    report = run_health_check()
    report.print()
