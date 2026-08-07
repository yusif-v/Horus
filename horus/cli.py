"""Horus CLI — argparse + dispatch.

All actual pipeline work lives in `horus.pipeline`. This module's job
is to:
  - build the argument parser dynamically from discovered plugins
  - dispatch one-shot commands (--query, --health-check, --backfill-epss,
    --server, --auth-status, --list-sources)
  - hand the parsed args to `run_pipeline` for the default scan flow

Usage:
    python3 -m horus
    python3 -m horus --sources nvd,github --format md
    python3 -m horus --server --config /etc/horus/config.yaml
"""

from __future__ import annotations

import argparse
import logging
import os

from . import __version__
from .logger import setup_logging
from .net.auth import github_token
from .pipeline import (
    PipelineOptions,
    discover_enrichers,
    discover_sources,
    run_pipeline,
)

logger = logging.getLogger(__name__)

# ── Argument parser ─────────────────────────────────────────────────────────


def _build_parser(sources: dict, enrichers: dict) -> argparse.ArgumentParser:
    """Build the CLI parser dynamically from discovered plugins."""
    p = argparse.ArgumentParser(
        prog="horus",
        description="Daily PoC research scanner — plugin-based CVE & PoC aggregator.",
    )
    p.add_argument("--version", action="version", version=f"horus {__version__}")

    # Scan tunables
    p.add_argument(
        "--min-cvss", type=float, default=None, help="Minimum CVSS base score for NVD items."
    )
    p.add_argument(
        "--max-results", type=int, default=None, help="Cap items per source after sorting."
    )
    p.add_argument(
        "--format", choices=("text", "md"), default="text", help="Output format (default: text)."
    )
    p.add_argument("--quiet", action="store_true", help="Suppress progress lines on stderr.")
    p.add_argument(
        "--no-save", action="store_true", help="Skip writing the markdown report to reports/."
    )
    p.add_argument(
        "--no-graph", action="store_true", help="Skip writing the interactive graph HTML."
    )
    p.add_argument(
        "--sources",
        type=str,
        default=None,
        help="Comma-separated list of sources to run (default: all enabled).",
    )
    p.add_argument(
        "--enrichers",
        type=str,
        default=None,
        help="Comma-separated list of enrichers to run (default: all enabled).",
    )

    # One-shot commands
    p.add_argument(
        "--list-sources",
        action="store_true",
        help="List available sources and enrichers, then exit.",
    )
    p.add_argument(
        "--health-check", action="store_true", help="Run database health check and exit."
    )
    p.add_argument(
        "--query",
        type=str,
        default=None,
        metavar="CVE-XXXX-XXXX",
        help="Query a CVE from the database and display its enrichment report.",
    )
    p.add_argument("--auth-status", action="store_true", help="Print GitHub auth status and exit.")
    p.add_argument(
        "--backfill-epss",
        action="store_true",
        help="Score every unscored CVE in the DB with EPSS, then exit.",
    )
    p.add_argument(
        "--backfill",
        choices=("products", "poc_cve", "all"),
        default=None,
        metavar="TARGET",
        help="One-shot data backfill: 'products' re-normalizes vendor/product names; "
        "'poc_cve' re-scans PoCs for CVE refs; 'all' runs both.",
    )
    p.add_argument(
        "--export-json",
        type=str,
        default=None,
        metavar="DIR",
        help="Export the database to CVE-Intel-compatible JSON files in DIR, then exit.",
    )
    p.add_argument(
        "--weekly-report",
        action="store_true",
        help="Generate a weekly threat intelligence report (text/md/html).",
    )
    p.add_argument(
        "--weekly-format",
        choices=("text", "md", "html", "pdf"),
        default="md",
        help="Weekly report output format (default: md).",
    )
    p.add_argument(
        "--weeks-back",
        type=int,
        default=1,
        metavar="N",
        help="Weekly report: how many weeks back (default: 1).",
    )
    p.add_argument(
        "--weekly-output",
        type=str,
        default=None,
        metavar="PATH",
        help="Save weekly report to file instead of stdout.",
    )
    p.add_argument(
        "--ai",
        action="store_true",
        help="Augment weekly report with AI-generated analysis and QA.",
    )
    p.add_argument(
        "--ai-provider",
        choices=("openai", "anthropic", "ollama"),
        default=None,
        help="AI provider override (default: from HORUS_AI_PROVIDER env var).",
    )

    # Server mode
    p.add_argument(
        "--server",
        action="store_true",
        help="Run as a 24/7 daemon polling sources on per-source intervals.",
    )
    p.add_argument(
        "--server-once",
        action="store_true",
        help="Run a single server poll cycle then exit (cron/testing).",
    )
    p.add_argument(
        "--config", type=str, default=None, help="Path to YAML/JSON config file (server mode)."
    )

    # Auto-generated --no-<src> / --skip-<enricher> flags
    for name, mod in sorted(sources.items()):
        p.add_argument(
            f"--no-{name}",
            action="store_true",
            help=f"Skip the {getattr(mod, 'NAME', name)} source.",
        )
    for name, mod in sorted(enrichers.items()):
        p.add_argument(
            f"--skip-{name}",
            action="store_true",
            help=f"Skip the {getattr(mod, 'NAME', name)} enrichment.",
        )

    return p


def _log(quiet: bool, msg: str) -> None:
    if not quiet:
        logger.info(msg)


# ── One-shot command handlers ───────────────────────────────────────────────


def _cmd_list_sources(sources: dict, enrichers: dict) -> None:
    logger.info("Sources:")
    for name, mod in sorted(sources.items()):
        on = "[on]" if getattr(mod, "DEFAULT_ENABLED", True) else "[off]"
        logger.info("  %-20s %-30s %s", name, getattr(mod, "NAME", name), on)
    logger.info("\nEnrichers:")
    for name, mod in sorted(enrichers.items()):
        on = "[on]" if getattr(mod, "DEFAULT_ENABLED", True) else "[off]"
        logger.info("  %-20s %-30s %s", name, getattr(mod, "NAME", name), on)


def _cmd_query(args) -> None:
    from .storage.query import query_cve

    print(query_cve(args.query, args.format))


def _cmd_health_check() -> None:
    from .storage.health import run_health_check

    run_health_check().print()


def _cmd_backfill_epss() -> None:
    from .enrichers.epss import backfill_all
    from .storage import db

    db.initialize()
    with db.connect() as conn:
        updated = backfill_all(conn)
    logger.info("EPSS backfill: %d CVEs updated", updated)


def _cmd_backfill(target: str) -> None:
    from .storage.backfills import run_backfill

    logger.info("%s", run_backfill(target).summary())


def _cmd_export_json(output_dir: str) -> None:
    from .export_json import export_all
    from .storage import db as _db_module

    db_path = str(_db_module.DB_PATH)
    written = export_all(db_path, output_dir)
    for path in written:
        logger.info("  %s", path)
    logger.info("Exported %d files to %s", len(written), output_dir)


def _cmd_weekly_report(args) -> None:
    from pathlib import Path

    from .config import STATE_DIR
    from .render.weekly import render_weekly_report
    from .storage import db as _db_module
    from .storage.weekly import gather_weekly_data

    db_path = STATE_DIR / "horus.db"
    if not db_path.exists():
        logger.error("Database not found at %s", db_path)
        return

    with _db_module.connect() as conn:
        weekly_data = gather_weekly_data(conn, weeks_back=args.weeks_back)

    report = render_weekly_report(weekly_data, fmt=args.weekly_format)

    if args.ai:
        from horus.ai import analyze_weekly_report

        ai_result = analyze_weekly_report(weekly_data, report, provider=args.ai_provider)
        if ai_result:
            report = f"## AI Threat Analysis\n\n{ai_result.narrative}\n\n---\n\n{report}"
            if ai_result.has_qa_findings():
                qa_section = "\n".join(f"- {issue}" for issue in ai_result.qa_issues)
                report += (
                    f"\n\n## AI Quality Assurance\n\n"
                    f"The following issues were identified:\n\n{qa_section}\n"
                )
        else:
            logger.warning("AI analysis unavailable — rendering template only")

    if args.weekly_format == "pdf":
        # Convert HTML to PDF
        import tempfile

        from playwright.sync_api import sync_playwright

        with tempfile.NamedTemporaryFile(suffix=".html", delete=False, mode="w") as f:
            f.write(report)
            html_path = f.name

        pdf_path = args.weekly_output or html_path.replace(".html", ".pdf")
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch()
                page = browser.new_page()
                page.goto(f"file://{html_path}")
                page.wait_for_timeout(2000)
                page.pdf(
                    path=pdf_path,
                    format="A4",
                    margin={"top": "15mm", "bottom": "15mm", "left": "15mm", "right": "15mm"},
                    print_background=True,
                    scale=0.9,
                )
                browser.close()
            logger.info("Weekly report PDF saved to %s", pdf_path)
        except Exception as e:
            logger.error("PDF generation failed: %s", e)
        finally:
            os.unlink(html_path)
        return

    if args.weekly_output:
        out = Path(args.weekly_output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(report)
        logger.info("Weekly report saved to %s", out)
    else:
        print(report)


def _cmd_server(args) -> None:
    from .server import Server, load_config

    cfg = load_config(args.config)
    srv = Server(cfg)
    if args.server_once:
        srv.run_once()
    else:
        srv.start()


def _cmd_auth_status() -> None:
    tok = github_token()
    if tok:
        logger.info("GitHub auth: OK (token ...%s, limit 5000/hr)", tok[-4:])
    else:
        logger.info("GitHub auth: none (unauthenticated, limit 60/hr)")


# ── Entry point ─────────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> None:
    setup_logging()

    sources = discover_sources()
    enrichers = discover_enrichers()
    args = _build_parser(sources, enrichers).parse_args(argv)

    # One-shot commands fall through here.
    if args.list_sources:
        return _cmd_list_sources(sources, enrichers)
    if args.query:
        return _cmd_query(args)
    if args.health_check:
        return _cmd_health_check()
    if args.backfill_epss:
        return _cmd_backfill_epss()
    if args.backfill:
        return _cmd_backfill(args.backfill)
    if args.export_json:
        return _cmd_export_json(args.export_json)
    if args.weekly_report:
        return _cmd_weekly_report(args)
    if args.server or args.server_once:
        return _cmd_server(args)
    if args.auth_status:
        return _cmd_auth_status()

    # ── HORUS_SOURCES_ENABLED / HORUS_SOURCES_DISABLED ────────────────────
    source_filter = set(args.sources.split(",")) if args.sources else None
    enricher_filter = set(args.enrichers.split(",")) if args.enrichers else None

    if source_filter is None:
        env_enabled = os.environ.get("HORUS_SOURCES_ENABLED")
        if env_enabled:
            source_filter = {s.strip() for s in env_enabled.split(",") if s.strip()}
            if source_filter:
                logger.info("Sources enabled via HORUS_SOURCES_ENABLED: %s", source_filter)

    disabled_sources = {n for n in sources if getattr(args, f"no_{n}", False)}
    disabled_enrichers = {n for n in enrichers if getattr(args, f"skip_{n}", False)}

    env_disabled = os.environ.get("HORUS_SOURCES_DISABLED")
    if env_disabled:
        extra_disabled = {s.strip() for s in env_disabled.split(",") if s.strip()}
        if extra_disabled:
            disabled_sources |= extra_disabled
            logger.info("Sources disabled via HORUS_SOURCES_DISABLED: %s", extra_disabled)

    run_pipeline(
        PipelineOptions(
            source_filter=source_filter,
            enricher_filter=enricher_filter,
            disabled_sources=disabled_sources,
            disabled_enrichers=disabled_enrichers,
            max_results=args.max_results,
            min_cvss=args.min_cvss,
            quiet=args.quiet,
            save_report_md=not args.no_save,
            save_graph_html=not args.no_graph,
            output_fmt=args.format,
            print_report=True,
            log=lambda m: _log(args.quiet, m),
        ),
        sources=sources,
        enrichers=enrichers,
    )


if __name__ == "__main__":
    main()
