"""Pipeline end-to-end: mocked plugins, real merge/persist/render path.

Covers the orchestration body in `run_pipeline` — selection, source +
enricher invocation order, NVD enrichment of unknown CVE refs, merge,
persistence to the test DB, report rendering. Plugin discovery is
bypassed by injecting `sources=`/`enrichers=` directly.
"""

from __future__ import annotations

import types

from horus.core.model import CVE, PoC
from horus.pipeline import PipelineOptions, PipelineResult, run_pipeline
from horus.storage import db


def _make_source(name, *, kind="poc", cves=None, pocs=None, default_enabled=True):
    """Build a fake source module exposing the contract the pipeline reads."""
    mod = types.ModuleType(f"fake_source_{name}")
    mod.NAME = name.upper()
    mod.DEFAULT_ENABLED = default_enabled
    mod.KIND = kind
    cves_out = list(cves or [])
    pocs_out = list(pocs or [])

    def run(ctx):
        return {"cves": cves_out, "pocs": pocs_out}

    mod.run = run
    return mod


def _make_enricher(name, *, calls=None):
    mod = types.ModuleType(f"fake_enricher_{name}")
    mod.NAME = name.upper()
    mod.DEFAULT_ENABLED = True
    record = calls if calls is not None else []

    def enrich(ctx):
        record.append((name, len(ctx.cves), len(ctx.pocs)))

    mod.enrich = enrich
    return mod


def _wipe_db():
    with db.connect() as conn:
        for table in (
            "poc_cve",
            "poc",
            "cve_attack_tag",
            "cve_cwe",
            "cve_product",
            "cve_source",
            "cve_watchlist",
            "cve_social_post",
            "cve",
            "security_resource",
            "meta",
        ):
            conn.execute(f"DELETE FROM {table}")


def test_pipeline_runs_full_cycle_with_mocked_plugins(tmp_path, monkeypatch):
    db.initialize()
    _wipe_db()

    nvd_cve = CVE(
        id="CVE-2026-1111",
        description="RCE in nginx",
        cvss_score=9.8,
        cvss_severity="CRITICAL",
    )
    gh_poc = PoC(
        url="https://github.com/u/exploit-2026-1111",
        source="github",
        stars=15,
        cve_refs=["CVE-2026-1111"],
        description="PoC for nginx",
    )

    sources = {
        "nvd": _make_source("nvd", kind="cve", cves=[nvd_cve]),
        "github": _make_source("github", pocs=[gh_poc]),
    }
    enricher_calls: list = []
    enrichers = {
        "kev": _make_enricher("kev", calls=enricher_calls),
        "epss": _make_enricher("epss", calls=enricher_calls),
    }

    # Block the NVD-fetch step (no network).
    monkeypatch.setattr("horus.sources.nvd_fetch.fetch_cve_by_id", lambda _id: None)

    opts = PipelineOptions(
        quiet=True,
        save_report_md=False,
        save_graph_html=False,
        print_report=False,
    )

    result = run_pipeline(opts, sources=sources, enrichers=enrichers)

    assert isinstance(result, PipelineResult)
    # CVE + PoC made it through merge
    assert any(c.id == "CVE-2026-1111" for c in result.cves)
    assert any(p.url.endswith("exploit-2026-1111") for p in result.pocs)
    # Linked correctly
    assert "CVE-2026-1111" in result.links
    assert result.links["CVE-2026-1111"][0].url == gh_poc.url
    # Both enrichers fired against the merged batch
    enrichers_seen = {name for name, _, _ in enricher_calls}
    assert enrichers_seen == {"kev", "epss"}
    # Persistence side-effect
    with db.connect() as conn:
        row = conn.execute("SELECT id FROM cve WHERE id = ?", ("CVE-2026-1111",)).fetchone()
        assert row is not None
        poc_row = conn.execute("SELECT url FROM poc WHERE url = ?", (gh_poc.url,)).fetchone()
        assert poc_row is not None
    # source_results captured per-source counts
    assert result.source_results["nvd"]["cves"] == 1
    assert result.source_results["github"]["pocs"] == 1


def test_pipeline_fetches_referenced_cves_from_nvd_for_orphan_pocs(monkeypatch):
    """A PoC referencing an unknown CVE triggers nvd_fetch.fetch_cve_by_id."""
    db.initialize()
    _wipe_db()

    orphan_poc = PoC(
        url="https://github.com/u/poc-for-unknown",
        source="github",
        stars=3,
        cve_refs=["CVE-2026-9999"],
    )

    sources = {"github": _make_source("github", pocs=[orphan_poc])}

    # Stub the NVD lookup so the pipeline gets a fake CVE back.
    fetched_for: list[str] = []

    def fake_fetch(cve_id):
        fetched_for.append(cve_id)
        return {"id": cve_id, "descriptions": [{"lang": "en", "value": "fetched cve"}]}

    def fake_parse(raw):
        return {
            "source": "NVD",
            "cve": raw["id"],
            "description": "fetched cve",
            "cvss_score": 5.0,
            "severity": "MEDIUM",
            "cwe_ids": [],
            "affected": [],
            "published_at": None,
        }

    monkeypatch.setattr("horus.sources.nvd_fetch.fetch_cve_by_id", fake_fetch)
    monkeypatch.setattr("horus.sources.nvd_fetch.parse_nvd_cve", fake_parse)

    opts = PipelineOptions(
        quiet=True,
        save_report_md=False,
        save_graph_html=False,
        print_report=False,
    )
    result = run_pipeline(opts, sources=sources, enrichers={})

    assert "CVE-2026-9999" in fetched_for
    assert any(c.id == "CVE-2026-9999" for c in result.cves)


def test_pipeline_continues_when_a_source_raises(monkeypatch, capsys):
    """One broken source must not abort the rest of the cycle."""
    db.initialize()
    _wipe_db()

    broken = types.ModuleType("broken_source")
    broken.NAME = "BROKEN"
    broken.DEFAULT_ENABLED = True
    broken.KIND = "poc"

    def broken_run(ctx):
        raise RuntimeError("source went sideways")

    broken.run = broken_run

    healthy_poc = PoC(url="https://github.com/u/ok", source="github", stars=10)
    healthy = _make_source("github", pocs=[healthy_poc])

    monkeypatch.setattr("horus.sources.nvd_fetch.fetch_cve_by_id", lambda _id: None)

    opts = PipelineOptions(
        quiet=True,
        save_report_md=False,
        save_graph_html=False,
        print_report=False,
    )
    result = run_pipeline(opts, sources={"broken": broken, "github": healthy}, enrichers={})

    # Broken source recorded an error in source_results
    assert "error" in result.source_results["broken"]
    # Healthy source still produced output
    assert any(p.url.endswith("/ok") for p in result.pocs)


def test_pipeline_filter_runs_only_requested_sources(monkeypatch):
    db.initialize()
    _wipe_db()

    nvd_cve = CVE(id="CVE-2026-AAAA", description="x", cvss_score=8.0)
    sources = {
        "nvd": _make_source("nvd", kind="cve", cves=[nvd_cve]),
        "github": _make_source(
            "github",
            pocs=[PoC(url="https://github.com/u/skip", source="github")],
        ),
    }

    monkeypatch.setattr("horus.sources.nvd_fetch.fetch_cve_by_id", lambda _id: None)

    opts = PipelineOptions(
        source_filter={"nvd"},
        quiet=True,
        save_report_md=False,
        save_graph_html=False,
        print_report=False,
    )
    result = run_pipeline(opts, sources=sources, enrichers={})

    assert "nvd" in result.source_results
    assert "github" not in result.source_results


def test_pipeline_log_callback_receives_progress_messages(monkeypatch):
    db.initialize()
    _wipe_db()

    sources = {
        "nvd": _make_source(
            "nvd", kind="cve", cves=[CVE(id="CVE-2026-Z", description="z", cvss_score=7)]
        )
    }
    monkeypatch.setattr("horus.sources.nvd_fetch.fetch_cve_by_id", lambda _id: None)

    messages: list[str] = []
    opts = PipelineOptions(
        log=messages.append,
        save_report_md=False,
        save_graph_html=False,
        print_report=False,
    )
    run_pipeline(opts, sources=sources, enrichers={})

    joined = "\n".join(messages)
    assert "running NVD" in joined
    assert "merging" in joined
    assert "persisting" in joined
