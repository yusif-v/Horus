from __future__ import annotations

import types

from horus.core.model import CVE
from horus.core.plugin_types import Plugin, PluginKind, PluginManifest
from horus.pipeline import PipelineOptions, run_pipeline
from horus.plugin_manager import PluginManager


def test_pipeline_runs_with_manager_sources():
    # minimal: ensure manager-built sources dict is accepted by run_pipeline
    from pathlib import Path

    bundled = Path(__file__).parent.parent.parent / "horus" / "plugins"
    mgr = PluginManager(bundled_root=bundled, external_dirs=[])
    opts = PipelineOptions(
        source_filter={"nvd"},
        enricher_filter=set(),
        print_report=False,
        save_report_md=False,
        save_graph_html=False,
        quiet=True,
    )
    # nvd hits network; we only assert discovery works and opts are sane.
    assert isinstance(mgr.sources(), dict)
    assert "nvd" in mgr.sources()
    assert opts.source_filter == {"nvd"}


def _plugin_source(
    name: str,
    *,
    kind: str = "poc",
    provides: list[str] | None = None,
    consumes: list[str] | None = None,
    run_result: dict | None = None,
    order: list[str] | None = None,
    seen: dict | None = None,
) -> Plugin:
    """Build a Plugin wrapping a stub module that records call order + ctx."""
    stub = types.ModuleType(f"fake_source_{name}")
    stub.NAME = name.upper()
    stub.DEFAULT_ENABLED = True
    stub.KIND = kind
    stub.PROVIDES = provides or []
    stub.CONSUMES = consumes or []
    if seen is not None:
        seen[name] = {"provided": None}

    def run(ctx):
        if order is not None:
            order.append(name)
        if seen is not None:
            seen[name]["provided"] = dict(ctx.provided)
        return run_result or {}

    stub.run = run
    return Plugin(
        name=name,
        kind=PluginKind.SOURCE,
        manifest=PluginManifest(
            name=name,
            type=PluginKind.SOURCE,
            version="0.0.1",
            enabled_by_default=True,
        ),
        module=stub,
        display_name=stub.NAME,
        plugin_kind_tag=stub.KIND,
        provides=stub.PROVIDES,
        consumes=stub.CONSUMES,
    )


def test_run_pipeline_orders_plugin_sources_by_kind_and_provides(monkeypatch):
    """Manager-style Plugin dicts drive ordering: CVE first, provider before consumer."""
    from horus.storage import db as _db

    _db.initialize()
    # No network: block the NVD-fetch step for any orphan CVE refs.
    monkeypatch.setattr("horus.core.nvd_fetch.fetch_cve_by_id", lambda _id: None)

    order: list[str] = []
    seen: dict[str, dict] = {}

    nvd = _plugin_source(
        "nvd",
        kind="cve",
        order=order,
        seen=seen,
        run_result={"cves": [CVE(id="CVE-2026-2222", description="x", cvss_score=8.0)]},
    )
    x_twitter = _plugin_source(
        "x_twitter",
        order=order,
        seen=seen,
        provides=["x_discovered_urls"],
        run_result={"x_discovered_urls": ["https://x.com/u/status/1"]},
    )
    github = _plugin_source("github", order=order, seen=seen, consumes=["x_discovered_urls"])

    sources = {"nvd": nvd, "x_twitter": x_twitter, "github": github}
    opts = PipelineOptions(
        source_filter={"nvd", "x_twitter", "github"},
        enricher_filter=set(),
        quiet=True,
        save_report_md=False,
        save_graph_html=False,
        print_report=False,
    )
    run_pipeline(opts, sources=sources, enrichers={})

    # CVE-kind source runs first, then the provider (x_twitter) before the
    # consumer (github) — the x_discovered_urls handoff must reach github's ctx.
    assert order == ["nvd", "x_twitter", "github"]
    assert seen["x_twitter"]["provided"] == {}
    assert seen["github"]["provided"] == {"x_discovered_urls": ["https://x.com/u/status/1"]}


def test_run_pipeline_passes_plugin_config_to_source(monkeypatch):
    """A Plugin's merged `config` (from horus.yaml `plugins.<name>.config`) reaches ctx.config."""
    from horus.storage import db as _db

    _db.initialize()
    monkeypatch.setattr("horus.core.nvd_fetch.fetch_cve_by_id", lambda _id: None)

    seen: dict[str, dict] = {}
    nvd = _plugin_source("nvd", kind="cve")
    nvd.config = {"max": 50, "lookback_days": 30}

    def run(ctx):
        seen["config"] = dict(ctx.config)
        return {}

    nvd.module.run = run

    opts = PipelineOptions(
        source_filter={"nvd"},
        enricher_filter=set(),
        quiet=True,
        save_report_md=False,
        save_graph_html=False,
        print_report=False,
    )
    run_pipeline(opts, sources={"nvd": nvd}, enrichers={})
    assert seen["config"] == {"max": 50, "lookback_days": 30}


def test_run_pipeline_passes_plugin_config_to_enricher(monkeypatch):
    """Per-plugin config also reaches EnricherContext for enricher wrappers."""
    from horus.storage import db as _db

    _db.initialize()
    monkeypatch.setattr("horus.core.nvd_fetch.fetch_cve_by_id", lambda _id: None)

    seen: dict[str, dict] = {}

    def enrich(ctx):
        seen["config"] = dict(ctx.config)

    enr = _plugin_source("epss")
    enr.kind = PluginKind.ENRICHER
    enr.module.enrich = enrich
    enr.config = {"cutoff": 0.1}

    opts = PipelineOptions(
        source_filter=set(),
        enricher_filter={"epss"},
        quiet=True,
        save_report_md=False,
        save_graph_html=False,
        print_report=False,
    )
    run_pipeline(opts, sources={}, enrichers={"epss": enr})
    assert seen["config"] == {"cutoff": 0.1}
