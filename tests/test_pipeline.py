"""Pipeline-level integration: cli, server, and the shared pipeline all wire up."""

from __future__ import annotations

from horus.pipeline import (
    discover_enrichers,
    discover_sources,
    make_runner_args,
    select_enrichers,
    select_sources,
)


def test_discovery_finds_expected_plugins():
    sources = discover_sources()
    enrichers = discover_enrichers()
    assert {"nvd", "github", "x_twitter", "exploitdb"}.issubset(sources.keys())
    assert {"epss", "kev"}.issubset(enrichers.keys())


def test_make_runner_args_supplies_required_attrs():
    args = make_runner_args(max_results=5)
    for attr in ("quiet", "no_save", "no_graph", "format", "max_results", "min_cvss"):
        assert hasattr(args, attr), f"missing args.{attr}"
    assert args.max_results == 5


def test_select_sources_honors_filter():
    src = discover_sources()
    args = make_runner_args()
    sel = select_sources(src, filter_={"nvd"}, args=args)
    assert sel.keys() == {"nvd"}


def test_select_enrichers_honors_skip_flag():
    enr = discover_enrichers()
    args = make_runner_args(skip_kev=True)
    sel = select_enrichers(enr, filter_=None, args=args)
    assert "kev" not in sel
    assert "epss" in sel


def test_cli_help_runs():
    import horus.cli as cli
    parser = cli._build_parser(discover_sources(), discover_enrichers())
    # If argparse construction itself works, the CLI surface is healthy.
    help_text = parser.format_help()
    assert "--server" in help_text
    assert "--backfill-epss" in help_text
