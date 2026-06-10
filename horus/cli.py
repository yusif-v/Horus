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
import sys

from . import __version__
from .net.auth import github_token
from .pipeline import (
    PipelineOptions,
    discover_enrichers,
    discover_sources,
    run_pipeline,
)

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
        print(msg, file=sys.stderr)


# ── One-shot command handlers ───────────────────────────────────────────────


def _cmd_list_sources(sources: dict, enrichers: dict) -> None:
    print("Sources:")
    for name, mod in sorted(sources.items()):
        on = "[on]" if getattr(mod, "DEFAULT_ENABLED", True) else "[off]"
        print(f"  {name:20s} {getattr(mod, 'NAME', name):30s} {on}")
    print("\nEnrichers:")
    for name, mod in sorted(enrichers.items()):
        on = "[on]" if getattr(mod, "DEFAULT_ENABLED", True) else "[off]"
        print(f"  {name:20s} {getattr(mod, 'NAME', name):30s} {on}")


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
    print(f"EPSS backfill: {updated} CVEs updated")


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
        print(f"GitHub auth: OK (token ...{tok[-4:]}, limit 5000/hr)")
    else:
        print("GitHub auth: none (unauthenticated, limit 60/hr)")


# ── Entry point ─────────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> None:
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
    if args.server or args.server_once:
        return _cmd_server(args)
    if args.auth_status:
        return _cmd_auth_status()

    # Default flow: full scan via the shared pipeline.
    source_filter = set(args.sources.split(",")) if args.sources else None
    enricher_filter = set(args.enrichers.split(",")) if args.enrichers else None
    disabled_sources = {n for n in sources if getattr(args, f"no_{n}", False)}
    disabled_enrichers = {n for n in enrichers if getattr(args, f"skip_{n}", False)}

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
