"""Tests for horus/cli.py — argument parsing and dispatch."""

from __future__ import annotations

import contextlib
import io
from unittest.mock import MagicMock, patch

from horus.cli import _build_parser, _cmd_list_sources, main

MOCK_SOURCES = {
    "nvd": MagicMock(NAME="NVD CVE Feed", DEFAULT_ENABLED=True),
    "github": MagicMock(NAME="GitHub PoC Repos", DEFAULT_ENABLED=True),
}

MOCK_ENRICHERS = {
    "epss": MagicMock(NAME="EPSS Scorer", DEFAULT_ENABLED=True),
    "kev": MagicMock(NAME="KEV Enricher", DEFAULT_ENABLED=True),
}


def test_build_parser_includes_sources_flag():
    p = _build_parser(MOCK_SOURCES, MOCK_ENRICHERS)
    args = p.parse_args(["--sources", "nvd,github"])
    assert args.sources == "nvd,github"


def test_build_parser_includes_format_flag():
    p = _build_parser(MOCK_SOURCES, MOCK_ENRICHERS)
    args = p.parse_args(["--format", "md"])
    assert args.format == "md"


def test_build_parser_includes_quiet_flag():
    p = _build_parser(MOCK_SOURCES, MOCK_ENRICHERS)
    args = p.parse_args(["--quiet"])
    assert args.quiet is True


def test_build_parser_includes_list_sources_flag():
    p = _build_parser(MOCK_SOURCES, MOCK_ENRICHERS)
    args = p.parse_args(["--list-sources"])
    assert args.list_sources is True


def test_build_parser_includes_health_check_flag():
    p = _build_parser(MOCK_SOURCES, MOCK_ENRICHERS)
    args = p.parse_args(["--health-check"])
    assert args.health_check is True


def test_build_parser_includes_query_flag():
    p = _build_parser(MOCK_SOURCES, MOCK_ENRICHERS)
    args = p.parse_args(["--query", "CVE-2026-0001"])
    assert args.query == "CVE-2026-0001"


def test_build_parser_includes_auth_status_flag():
    p = _build_parser(MOCK_SOURCES, MOCK_ENRICHERS)
    args = p.parse_args(["--auth-status"])
    assert args.auth_status is True


def test_build_parser_includes_server_flag():
    p = _build_parser(MOCK_SOURCES, MOCK_ENRICHERS)
    args = p.parse_args(["--server"])
    assert args.server is True


def test_build_parser_includes_backfill_epss_flag():
    p = _build_parser(MOCK_SOURCES, MOCK_ENRICHERS)
    args = p.parse_args(["--backfill-epss"])
    assert args.backfill_epss is True


def test_build_parser_includes_no_save_flag():
    p = _build_parser(MOCK_SOURCES, MOCK_ENRICHERS)
    args = p.parse_args(["--no-save"])
    assert args.no_save is True


def test_build_parser_no_source_flags():
    p = _build_parser(MOCK_SOURCES, MOCK_ENRICHERS)
    args = p.parse_args([])
    assert args.no_nvd is False
    assert args.no_github is False


def test_build_parser_skip_enricher_flags():
    p = _build_parser(MOCK_SOURCES, MOCK_ENRICHERS)
    args = p.parse_args([])
    assert args.skip_epss is False
    assert args.skip_kev is False


def test_build_parser_version_flag():
    p = _build_parser(MOCK_SOURCES, MOCK_ENRICHERS)
    try:
        p.parse_args(["--version"])
        assert False, "Should have exited"
    except SystemExit:
        pass  # argparse exits after --version


def test_list_sources_prints(capsys=None):
    _cmd_list_sources(MOCK_SOURCES, MOCK_ENRICHERS)
    # We captured via manual stdout redirect; just test it doesn't crash


def test_list_sources_prints_sources_and_enrichers():
    import logging as _logging

    captured = io.StringIO()
    handler = _logging.StreamHandler(captured)
    handler.setLevel(_logging.INFO)
    cli_logger = _logging.getLogger("horus.cli")
    cli_logger.addHandler(handler)
    cli_logger.setLevel(_logging.INFO)
    try:
        _cmd_list_sources(MOCK_SOURCES, MOCK_ENRICHERS)
    finally:
        cli_logger.removeHandler(handler)
        cli_logger.setLevel(_logging.WARNING)
    output = captured.getvalue()
    assert "Sources:" in output
    assert "Enrichers:" in output


def test_main_list_sources_exits():
    with (
        patch("horus.cli._build_parser", return_value=_build_parser(MOCK_SOURCES, MOCK_ENRICHERS)),
        contextlib.suppress(SystemExit),
    ):
        main(["--list-sources"])


def test_main_health_check():
    mock_run = MagicMock()
    with (
        patch("horus.cli.run_pipeline"),
        patch("horus.cli._cmd_health_check", mock_run),
        contextlib.suppress(SystemExit),
    ):
        main(["--health-check"])
    mock_run.assert_called_once()


def test_main_query():
    mock_run = MagicMock()
    with (
        patch("horus.cli.run_pipeline"),
        patch("horus.cli._cmd_query", mock_run),
        contextlib.suppress(SystemExit),
    ):
        main(["--query", "CVE-2026-0001"])
    mock_run.assert_called_once()


def test_main_default_runs_pipeline():
    """Default (no flags) should run the full pipeline."""
    with patch("horus.cli.run_pipeline") as mock_pipeline:
        main(["--no-save", "--no-graph"])
    mock_pipeline.assert_called_once()
    opts = mock_pipeline.call_args[0][0]
    assert opts.save_report_md is False
    assert opts.save_graph_html is False


def test_main_sources_filter():
    with patch("horus.cli.run_pipeline") as mock_pipeline:
        main(["--no-save", "--no-graph", "--sources", "nvd,github"])
    opts = mock_pipeline.call_args[0][0]
    assert opts.source_filter == {"nvd", "github"}


def test_main_no_nvd_disabled():
    with patch("horus.cli.run_pipeline") as mock_pipeline:
        main(["--no-save", "--no-graph", "--no-nvd"])
    opts = mock_pipeline.call_args[0][0]
    assert "nvd" in opts.disabled_sources
