"""Tests for horus/render/report.py — CVE/PoC text and markdown renderers."""

from __future__ import annotations

from horus.core.model import CVE, AffectedProduct, PoC
from horus.render.report import (
    _group_cves,
    _poc_detail,
    _poc_label,
    _primary_category,
    _render_markdown,
    _render_text,
    _standalone_pocs,
    render_report,
)

# ── Helpers ────────────────────────────────────────────────────────────────


def _make_cve(
    cve_id: str = "CVE-2026-0001",
    description: str = "A test vulnerability",
    cvss_score: float | None = 7.5,
    cvss_severity: str | None = "HIGH",
    affected: list[AffectedProduct] | None = None,
    kev: int = 0,
    epss_score: float | None = None,
    attack_tags: list[str] | None = None,
) -> CVE:
    return CVE(
        id=cve_id,
        description=description,
        cvss_score=cvss_score,
        cvss_severity=cvss_severity,
        affected=affected or [],
        kev=kev,
        epss_score=epss_score,
        attack_tags=attack_tags or [],
    )


def _make_poc(
    url: str = "https://github.com/test/poc",
    source: str = "github",
    stars: int | None = 50,
    age_days: int | None = 5,
    cve_refs: list[str] | None = None,
    description: str | None = "A PoC repo",
) -> PoC:
    return PoC(
        url=url,
        source=source,
        stars=stars,
        age_days=age_days,
        cve_refs=cve_refs or [],
        description=description,
    )


# ── _primary_category ─────────────────────────────────────────────────────


def test_primary_category_returns_first_non_unknown():
    cve = _make_cve(
        affected=[
            AffectedProduct(vendor="unknown", product="unknown", category="unknown"),
            AffectedProduct(vendor="nginx", product="nginx", category="web-server"),
        ]
    )
    assert _primary_category(cve) == "web-server"


def test_primary_category_all_unknown():
    cve = _make_cve(affected=[AffectedProduct(vendor="unknown", product="unknown")])
    assert _primary_category(cve) == "unknown"


def test_primary_category_no_affected():
    cve = _make_cve(affected=[])
    assert _primary_category(cve) == "unknown"


# ── _group_cves ───────────────────────────────────────────────────────────


def test_group_cves_groups_by_category():
    cves = [
        _make_cve(
            "CVE-2026-0001", affected=[AffectedProduct("nginx", "nginx", category="web-server")]
        ),
        _make_cve("CVE-2026-0002", affected=[AffectedProduct("linux", "linux", category="os")]),
    ]
    groups = _group_cves(cves)
    assert "web-server" in groups
    assert "os" in groups


def test_group_cves_sorts_by_cvss_desc():
    cves = [
        _make_cve(
            "CVE-2026-0001",
            cvss_score=5.0,
            affected=[AffectedProduct("nginx", "nginx", category="web-server")],
        ),
        _make_cve(
            "CVE-2026-0002",
            cvss_score=9.0,
            affected=[AffectedProduct("nginx", "nginx", category="web-server")],
        ),
    ]
    groups = _group_cves(cves)
    scores = [c.cvss_score for c in groups["web-server"]]
    assert scores == [9.0, 5.0]


def test_group_cves_unknown_last():
    cves = [
        _make_cve(
            "CVE-2026-0001", affected=[AffectedProduct("nginx", "nginx", category="web-server")]
        ),
        _make_cve(
            "CVE-2026-0002", affected=[AffectedProduct("unknown", "unknown", category="unknown")]
        ),
    ]
    groups = _group_cves(cves)
    keys = list(groups.keys())
    assert keys[-1] == "unknown"


# ── _standalone_pocs ──────────────────────────────────────────────────────


def test_standalone_pocs_filters_out_linked():
    pocs = [
        _make_poc("https://github.com/a", cve_refs=["CVE-2026-0001"]),
        _make_poc("https://github.com/b", cve_refs=["CVE-2026-9999"]),
    ]
    cves = [_make_cve("CVE-2026-0001")]
    standalone = _standalone_pocs(pocs, cves)
    assert len(standalone) == 1
    assert standalone[0].url == "https://github.com/b"


def test_standalone_pocs_empty_when_all_linked():
    pocs = [_make_poc("https://github.com/a", cve_refs=["CVE-2026-0001"])]
    cves = [_make_cve("CVE-2026-0001")]
    assert _standalone_pocs(pocs, cves) == []


# ── _poc_label ────────────────────────────────────────────────────────────


def test_poc_label_twitter_source():
    poc = _make_poc(source="twitter")
    assert _poc_label(poc) == f"{poc.url} [tweet]"


def test_poc_label_x_source():
    poc = _make_poc(source="x")
    assert _poc_label(poc) == f"{poc.url} [tweet]"


def test_poc_label_github_source():
    poc = _make_poc(source="github")
    assert _poc_label(poc) == poc.url


# ── _poc_detail ──────────────────────────────────────────────────────────


def test_poc_detail_with_twitter_source():
    poc = _make_poc(source="twitter", stars=10, age_days=3)
    detail = _poc_detail(poc)
    assert "10" in detail
    assert "3d" in detail
    assert "tweet" in detail


def test_poc_detail_without_twitter():
    poc = _make_poc(source="github", stars=5, age_days=2)
    detail = _poc_detail(poc)
    assert "5" in detail
    assert "2d" in detail
    assert "tweet" not in detail


# ── _render_text ──────────────────────────────────────────────────────────


def test_render_text_contains_header():
    cves = [_make_cve()]
    text = _render_text(cves, [], {})
    assert "Daily PoC Research Report" in text
    assert "CVEs: 1" in text


def test_render_text_contains_cve_line():
    cves = [_make_cve("CVE-2026-0001", cvss_score=7.5, cvss_severity="HIGH")]
    text = _render_text(cves, [], {})
    assert "CVE-2026-0001" in text
    assert "CVSS 7.5" in text


def test_render_text_contains_kev_badge():
    cves = [_make_cve(kev=1)]
    text = _render_text(cves, [], {})
    assert "[KEV]" in text


def test_render_text_contains_epss_badge():
    cves = [_make_cve(epss_score=0.45)]
    text = _render_text(cves, [], {})
    assert "EPSS" in text


def test_render_text_empty_findings():
    text = _render_text([], [], {})
    assert "No new findings today" in text


def test_render_text_attack_tags():
    cves = [_make_cve(attack_tags=["rce", "sql-injection"])]
    text = _render_text(cves, [], {})
    assert "rce" in text
    assert "sql-injection" in text


def test_render_text_standalone_pocs_sorted_by_stars():
    pocs = [
        _make_poc("https://github.com/low", stars=5),
        _make_poc("https://github.com/high", stars=100),
    ]
    text = _render_text([], pocs, {})
    high_pos = text.index("https://github.com/high")
    low_pos = text.index("https://github.com/low")
    assert high_pos < low_pos


# ── _render_markdown ──────────────────────────────────────────────────────


def test_render_markdown_contains_header():
    cves = [_make_cve()]
    md = _render_markdown(cves, [], {})
    assert "# Daily PoC Research Report" in md


def test_render_markdown_contains_badges():
    cves = [_make_cve(kev=1, epss_score=0.3)]
    md = _render_markdown(cves, [], {})
    assert "`KEV`" in md
    assert "EPSS" in md


def test_render_markdown_empty_findings():
    md = _render_markdown([], [], {})
    assert "No new findings today" in md


def test_render_markdown_bullet_points():
    cves = [_make_cve()]
    md = _render_markdown(cves, [], {})
    assert "- **CVE-2026-0001**" in md


# ── render_report (public API) ────────────────────────────────────────────


def test_render_report_text_format():
    cves = [_make_cve()]
    result = render_report(cves, [], {}, fmt="text")
    assert "Daily PoC Research Report" in result


def test_render_report_md_format():
    cves = [_make_cve()]
    result = render_report(cves, [], {}, fmt="md")
    assert "# Daily PoC Research Report" in result


def test_render_report_default_is_text():
    cves = [_make_cve()]
    result = render_report(cves, [], {})
    assert "Daily PoC Research Report" in result
    assert "#" not in result.split("\n")[0]  # not markdown header


# ── Additional coverage for uncovered branches ─────────────────────────────


def test_render_text_cve_with_versions():
    """Covers lines 90-91: affected product with versions."""
    cve = _make_cve(
        affected=[AffectedProduct(vendor="nginx", product="nginx", versions=["1.25.0", "1.24.0"])]
    )
    text = _render_text([cve], [], {})
    assert "affects: nginx/nginx" in text
    assert "1.25.0" in text


def test_render_text_cve_with_poc_links():
    """Covers line 92-93: CVE with linked PoCs in the text report."""
    cve = _make_cve()
    poc = _make_poc("https://github.com/test/poc", source="github", stars=42)
    links = {"CVE-2026-0001": [poc]}
    text = _render_text([cve], [], links)
    assert "PoC: https://github.com/test/poc" in text
    assert "42*" in text
    assert "[github]" in text


def test_render_text_standalone_poc_with_description():
    """Covers lines 100-101: standalone PoC with description."""
    poc = _make_poc(
        "https://github.com/standalone/poc",
        stars=10,
        age_days=2,
        cve_refs=["CVE-2026-9999"],
        description="A standalone exploit",
    )
    text = _render_text([], [poc], {})
    assert "A standalone exploit" in text
    assert "CVE-2026-9999" in text


def test_render_markdown_linked_poc_twitter():
    """Covers lines 146-147: markdown PoC link with twitter source."""
    cve = _make_cve()
    poc = _make_poc("https://x.com/user/status/123", source="twitter", stars=5)
    links = {"CVE-2026-0001": [poc]}
    md = _render_markdown([cve], [], links)
    assert "[tweet" in md
    assert "https://x.com/user/status/123" in md


def test_render_markdown_linked_poc_non_twitter():
    """Covers lines 148-149: markdown PoC link with non-twitter source."""
    cve = _make_cve()
    poc = _make_poc("https://github.com/test/poc", source="github", stars=10)
    links = {"CVE-2026-0001": [poc]}
    md = _render_markdown([cve], [], links)
    assert "[github]" in md
    assert "https://github.com/test/poc" in md


def test_render_markdown_standalone_poc_with_description():
    """Covers lines 157-158: standalone PoC with description in markdown."""
    poc = _make_poc(
        "https://github.com/standalone",
        stars=20,
        age_days=3,
        description="An awesome exploit",
    )
    md = _render_markdown([], [poc], {})
    assert "An awesome exploit" in md
    assert "20*" in md
    assert "3d" in md


def test_render_markdown_standalone_poc_with_refs():
    """Covers lines 154-156: standalone PoC with CVE refs."""
    poc = _make_poc(
        "https://github.com/ref-poc",
        stars=5,
        age_days=1,
        cve_refs=["CVE-2026-1111", "CVE-2026-2222"],
    )
    md = _render_markdown([], [poc], {})
    assert "CVE-2026-1111" in md
    assert "CVE-2026-2222" in md


def test_render_text_standalone_poc_twitter_label():
    """Standalone PoC with twitter source gets [tweet] label in text output."""
    poc = _make_poc(url="https://x.com/hacker/status/456", source="twitter", stars=3)
    text = _render_text([], [poc], {})
    assert "[tweet]" in text


def test_render_text_cve_with_versions_no_versions_key():
    """Affected product without versions list."""
    cve = _make_cve(
        affected=[AffectedProduct(vendor="linux", product="kernel", versions=[], category="os")]
    )
    text = _render_text([cve], [], {})
    assert "affects: linux/kernel" in text


def test_standalone_pocs_case_insensitive():
    """_standalone_pocs matches CVE refs case-insensitively (line 34-35)."""
    poc = _make_poc("https://github.com/a", cve_refs=["cve-2026-0001"])
    cves = [_make_cve("CVE-2026-0001")]
    standalone = _standalone_pocs([poc], cves)
    assert len(standalone) == 0  # linked, not standalone


def test_poc_detail_none_stars_and_age():
    """_poc_detail with None stars and None age_days."""
    poc = PoC(url="https://example.com", source="github", stars=None, age_days=None)
    detail = _poc_detail(poc)
    assert "0" in detail
    assert "tweet" not in detail
