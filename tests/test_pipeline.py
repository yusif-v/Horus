"""Pipeline-level contract: discovery, selection, ctx wiring, CLI surface."""

from __future__ import annotations

from horus.core.context import EnricherContext, SourceContext
from horus.pipeline import (
    PipelineOptions,
    _select,
    discover_enrichers,
    discover_sources,
)


def test_discovery_finds_expected_plugins():
    sources = discover_sources()
    enrichers = discover_enrichers()
    assert {"nvd", "github", "x_twitter", "exploitdb"}.issubset(sources.keys())
    assert {"epss", "kev"}.issubset(enrichers.keys())


def test_source_context_has_required_fields():
    ctx = SourceContext(max_results=5, min_cvss=7.0)
    assert ctx.max_results == 5
    assert ctx.min_cvss == 7.0
    # Sensible defaults for fields the caller didn't set.
    assert ctx.known_cve_ids == set()
    assert ctx.known_poc_urls == set()
    assert ctx.last_run is None
    assert ctx.x_discovered_urls == []


def test_enricher_context_exposes_cves_and_pocs():
    ctx = EnricherContext(cves=[], pocs=[])
    assert ctx.cves == []
    assert ctx.pocs == []


def test_select_respects_filter():
    src = discover_sources()
    sel = _select(src, filter_={"nvd"}, disabled=set())
    assert sel.keys() == {"nvd"}


def test_select_respects_disabled_when_no_filter():
    src = discover_sources()
    sel = _select(src, filter_=None, disabled={"github"})
    assert "github" not in sel
    assert "nvd" in sel


def test_select_filter_overrides_disabled():
    # Explicit filter wins — if you ask for it, you get it.
    src = discover_sources()
    sel = _select(src, filter_={"github"}, disabled={"github"})
    assert sel.keys() == {"github"}


def test_pipeline_options_construct_clean():
    opts = PipelineOptions(max_results=10, min_cvss=8.0)
    assert opts.max_results == 10
    assert opts.min_cvss == 8.0
    assert opts.disabled_sources == set()
    assert opts.disabled_enrichers == set()


def test_cli_parser_includes_v08_flags():
    import horus.cli as cli

    parser = cli._build_parser(discover_sources(), discover_enrichers())
    help_text = parser.format_help()
    assert "--server" in help_text
    assert "--backfill-epss" in help_text
    assert "--server-once" in help_text


def test_plugins_accept_only_one_positional_argument():
    """Plugin signature contract: run(ctx) and enrich(ctx). Nothing else.

    A regression here means someone re-introduced the args=... glue.
    """
    import inspect

    for name, mod in discover_sources().items():
        sig = inspect.signature(mod.run)
        params = [
            p
            for p in sig.parameters.values()
            if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)
        ]
        assert len(params) == 1, f"source '{name}' has unexpected run() signature: {sig}"
    for name, mod in discover_enrichers().items():
        sig = inspect.signature(mod.enrich)
        params = [
            p
            for p in sig.parameters.values()
            if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)
        ]
        assert len(params) == 1, f"enricher '{name}' has unexpected enrich() signature: {sig}"
