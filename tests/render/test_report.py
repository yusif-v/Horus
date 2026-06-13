"""Report renderer — text + markdown output against fixture CVE/PoC sets."""

from __future__ import annotations

from horus.core.model import CVE, AffectedProduct, PoC
from horus.render import report
from horus.render.report import (
    _group_cves,
    _poc_detail,
    _poc_label,
    _primary_category,
    _standalone_pocs,
    render_report,
)


def _cve(
    id_: str = "CVE-2026-1111",
    *,
    score: float = 9.8,
    severity: str = "CRITICAL",
    description: str = "Critical RCE in Apache httpd via crafted header.",
    category: str = "web-server",
    tags: list[str] | None = None,
    kev: int = 0,
    epss: float | None = None,
) -> CVE:
    return CVE(
        id=id_,
        description=description,
        cvss_score=score,
        cvss_severity=severity,
        attack_tags=tags or [],
        affected=[AffectedProduct(vendor="apache", product="httpd", category=category)],
        kev=kev,
        epss_score=epss,
    )


def _poc(
    url: str = "https://github.com/u/exploit",
    *,
    source: str = "github",
    stars: int = 42,
    age: int = 5,
    refs: list[str] | None = None,
    description: str | None = "Exploit description",
) -> PoC:
    return PoC(
        url=url,
        source=source,
        stars=stars,
        age_days=age,
        description=description,
        cve_refs=refs or [],
    )


# ── helpers ──────────────────────────────────────────────────────────────


class TestHelpers:
    def test_primary_category_returns_first_non_unknown(self):
        cve = CVE(
            id="X",
            description="",
            affected=[
                AffectedProduct(vendor="v", product="p", category="unknown"),
                AffectedProduct(vendor="v", product="p", category="database"),
            ],
        )
        assert _primary_category(cve) == "database"

    def test_primary_category_defaults_to_unknown(self):
        cve = CVE(id="X", description="")
        assert _primary_category(cve) == "unknown"

    def test_group_cves_sorts_within_category_by_score(self):
        a = _cve("CVE-A", score=7.0)
        b = _cve("CVE-B", score=9.8)
        groups = _group_cves([a, b])
        assert [c.id for c in groups["web-server"]] == ["CVE-B", "CVE-A"]

    def test_group_cves_pushes_unknown_to_end(self):
        known = _cve("CVE-K", category="web-server")
        unknown = CVE(id="CVE-U", description="")
        groups = _group_cves([unknown, known])
        assert list(groups.keys())[-1] == "unknown"

    def test_standalone_pocs_excludes_linked(self):
        cves = [_cve("CVE-2026-1111")]
        linked = _poc(refs=["CVE-2026-1111"])
        free = _poc(url="https://github.com/u/other", refs=["CVE-9999-0000"])
        result = _standalone_pocs([linked, free], cves)
        assert result == [free]

    def test_poc_label_appends_tweet_marker(self):
        twitter_poc = _poc(url="https://twitter.com/x/status/1", source="twitter")
        assert "[tweet]" in _poc_label(twitter_poc)

    def test_poc_label_plain_for_github(self):
        gh = _poc()
        assert _poc_label(gh) == gh.url

    def test_poc_detail_includes_tweet_marker(self):
        twitter_poc = _poc(source="twitter", stars=0, age=2)
        assert "tweet" in _poc_detail(twitter_poc)


# ── text renderer ────────────────────────────────────────────────────────


class TestTextRender:
    def test_empty_inputs_message(self):
        out = render_report([], [], {}, fmt="text")
        assert "No new findings today." in out

    def test_includes_counts_header(self):
        out = render_report([_cve()], [], {}, fmt="text")
        assert "CVEs: 1" in out
        assert "Standalone PoCs: 0" in out

    def test_renders_cve_with_badges(self):
        cve = _cve(kev=1, epss=0.95)
        out = render_report([cve], [], {}, fmt="text")
        assert "CVE-2026-1111" in out
        assert "[CVSS 9.8 CRITICAL]" in out
        assert "[KEV]" in out
        assert "[EPSS 95.0%]" in out

    def test_renders_attack_tags_and_affected(self):
        cve = _cve(tags=["rce", "remote"])
        cve.affected[0].versions = ["2.4.59", "2.4.58"]
        out = render_report([cve], [], {}, fmt="text")
        assert "tags: rce, remote" in out
        assert "affects: apache/httpd" in out
        assert "2.4.59" in out

    def test_renders_linked_pocs_under_cve(self):
        cve = _cve()
        poc = _poc(refs=["CVE-2026-1111"])
        out = render_report([cve], [poc], {"CVE-2026-1111": [poc]}, fmt="text")
        assert "PoC: https://github.com/u/exploit" in out
        assert "42*" in out
        assert "[github]" in out

    def test_renders_standalone_section(self):
        free = _poc(refs=["CVE-OTHER"], description="standalone description")
        out = render_report([], [free], {}, fmt="text")
        assert "Standalone PoCs (1)" in out
        assert "refs: CVE-OTHER" in out
        assert "standalone description" in out


# ── markdown renderer ────────────────────────────────────────────────────


class TestMarkdownRender:
    def test_md_empty_outputs_italic_message(self):
        out = render_report([], [], {}, fmt="md")
        assert "_No new findings today._" in out

    def test_md_h1_title(self):
        out = render_report([_cve()], [], {}, fmt="md")
        assert out.startswith("# Daily PoC Research Report")

    def test_md_renders_cve_with_inline_badges(self):
        cve = _cve(kev=1, epss=0.123)
        out = render_report([cve], [], {}, fmt="md")
        assert "**CVE-2026-1111**" in out
        assert "**CVSS 9.8 CRITICAL**" in out
        assert "`KEV`" in out
        assert "`EPSS 12.3%`" in out

    def test_md_h2_category_sections(self):
        out = render_report([_cve()], [], {}, fmt="md")
        assert "## web-server (1)" in out

    def test_md_linked_poc_uses_link_syntax(self):
        cve = _cve()
        poc = _poc(refs=["CVE-2026-1111"])
        out = render_report([cve], [poc], {"CVE-2026-1111": [poc]}, fmt="md")
        assert "[https://github.com/u/exploit](https://github.com/u/exploit)" in out

    def test_md_twitter_poc_tagged_as_tweet(self):
        cve = _cve()
        twitter_poc = _poc(
            url="https://twitter.com/x/status/1",
            source="twitter",
            refs=["CVE-2026-1111"],
        )
        out = render_report([cve], [twitter_poc], {"CVE-2026-1111": [twitter_poc]}, fmt="md")
        assert "[tweet" in out

    def test_md_standalone_section_with_refs(self):
        free = _poc(refs=["CVE-OTHER"])
        out = render_report([], [free], {}, fmt="md")
        assert "## Standalone PoCs (1)" in out
        assert "refs: CVE-OTHER" in out


# ── public API ───────────────────────────────────────────────────────────


def test_render_report_defaults_to_text():
    out = report.render_report([], [], {})
    assert "===" in out  # text-mode separator


def test_render_report_md_format_switches_to_markdown():
    out = report.render_report([], [], {}, fmt="md")
    assert out.lstrip().startswith("#")
