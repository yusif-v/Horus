"""Horus — Daily PoC Research Scanner.

Plugin-based architecture. Sources, enrichers, and renderers are
self-contained modules that register themselves. Adding a new source
means creating a single file in sources/ — no other files change.

Usage:
    python3 -m horus
    python3 -m horus --min-cvss 7.0 --format md
    python3 -m horus --no-twitter --no-exploitdb
    python3 -m horus --sources github,nvd  # only these sources
    python3 -m horus --list-sources        # show available sources
"""

from __future__ import annotations

import argparse
import importlib
import pkgutil
import sys
from pathlib import Path

from . import __version__
from .core.merge import merge_findings, link_pocs_to_cves
from .render.graph import save_graph
from .render.persist import save_report
from .render.report import render_report
from .sources.auth import github_token
from .storage import db


# ── Plugin discovery ────────────────────────────────────────────────────────

def _discover_plugins(package_name: str, required_export: str = "run") -> dict:
    """Discover plugin modules in a package directory.

    Only modules that export `required_export` (a callable) are included.
    This filters out utility modules like auth.py, http.py.
    """
    package_path = Path(__file__).parent / package_name
    plugins = {}

    for finder, name, ispkg in pkgutil.iter_modules([str(package_path)]):
        if name.startswith("_"):
            continue
        try:
            mod = importlib.import_module(f".{name}", f"horus.{package_name}")
            # Only include if it has the required export
            if hasattr(mod, required_export) and callable(getattr(mod, required_export)):
                plugins[name] = mod
            elif required_export == "enrich" and hasattr(mod, "enrich"):
                plugins[name] = mod
        except ImportError as e:
            print(f"  [WARN] Could not load {package_name}/{name}: {e}", file=sys.stderr)

    return plugins


def _get_source_plugins() -> dict:
    """Discover all source modules in sources/."""
    return _discover_plugins("sources", required_export="run")


def _get_enricher_plugins() -> dict:
    """Discover all enricher modules in enrichers/."""
    return _discover_plugins("enrichers", required_export="enrich")


# ── CLI ─────────────────────────────────────────────────────────────────────

def _build_parser(sources: dict, enrichers: dict) -> argparse.ArgumentParser:
    """Build CLI parser dynamically from discovered plugins."""
    p = argparse.ArgumentParser(
        prog="horus",
        description="Daily PoC research scanner — plugin-based CVE & PoC aggregator.",
    )
    p.add_argument("--version", action="version", version=f"horus {__version__}")
    p.add_argument(
        "--min-cvss", type=float, default=None,
        help="Minimum CVSS base score for NVD items.",
    )
    p.add_argument(
        "--max-results", type=int, default=None,
        help="Cap items per source after sorting.",
    )
    p.add_argument(
        "--format", choices=("text", "md"), default="text",
        help="Output format (default: text).",
    )
    p.add_argument(
        "--quiet", action="store_true",
        help="Suppress progress lines on stderr.",
    )
    p.add_argument(
        "--auth-status", action="store_true",
        help="Print GitHub auth status and exit.",
    )
    p.add_argument(
        "--no-save", action="store_true",
        help="Skip writing the markdown report to reports/.",
    )
    p.add_argument(
        "--no-graph", action="store_true",
        help="Skip writing the interactive graph HTML.",
    )
    p.add_argument(
        "--list-sources", action="store_true",
        help="List all available sources and enrichers, then exit.",
    )
    p.add_argument(
        "--health-check", action="store_true",
        help="Run database health check and exit.",
    )
    p.add_argument(
        "--query", type=str, default=None, metavar="CVE-XXXX-XXXX",
        help="Query a CVE from the database and display enrichment report.",
    )
    p.add_argument(
        "--sources", type=str, default=None,
        help="Comma-separated list of sources to run (default: all enabled).",
    )
    p.add_argument(
        "--enrichers", type=str, default=None,
        help="Comma-separated list of enrichers to run (default: all enabled).",
    )

    # Auto-generate --no-<name> flags for sources
    for name, mod in sorted(sources.items()):
        flag = f"--no-{name}"
        help_text = f"Skip the {getattr(mod, 'NAME', name)} source."
        p.add_argument(flag, action="store_true", help=help_text)

    # Auto-generate --skip-<name> flags for enrichers
    for name, mod in sorted(enrichers.items()):
        flag = f"--skip-{name}"
        help_text = f"Skip the {getattr(mod, 'NAME', name)} enrichment."
        p.add_argument(flag, action="store_true", help=help_text)

    return p


def _log(quiet: bool, msg: str) -> None:
    if not quiet:
        print(msg, file=sys.stderr)


# ── Main pipeline ───────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> None:
    # Discover plugins
    sources = _get_source_plugins()
    enrichers = _get_enricher_plugins()

    # Parse args
    args = _build_parser(sources, enrichers).parse_args(argv)

    # --list-sources
    if args.list_sources:
        print("Sources:")
        for name, mod in sorted(sources.items()):
            enabled = getattr(mod, "DEFAULT_ENABLED", True)
            print(f"  {name:20s} {getattr(mod, 'NAME', name):30s} {'[on]' if enabled else '[off]'}")
        print("\nEnrichers:")
        for name, mod in sorted(enrichers.items()):
            enabled = getattr(mod, "DEFAULT_ENABLED", True)
            print(f"  {name:20s} {getattr(mod, 'NAME', name):30s} {'[on]' if enabled else '[off]'}")
        return

    # --query
    if args.query:
        from .storage.query import query_cve
        print(query_cve(args.query, args.format))
        return

    # --health-check
    if args.health_check:
        from .storage.health import run_health_check
        report = run_health_check()
        report.print()
        return

    # --auth-status
    if args.auth_status:
        tok = github_token()
        if tok:
            print(f"GitHub auth: OK (token ...{tok[-4:]}, limit 5000/hr)")
        else:
            print("GitHub auth: none (unauthenticated, limit 60/hr)")
        return

    # Initialize DB
    cves_migrated, pocs_migrated = db.initialize()
    if cves_migrated or pocs_migrated:
        _log(args.quiet, f"  Migrated {cves_migrated} CVEs and {pocs_migrated} PoCs from legacy state")

    # Determine which sources to run
    if args.sources:
        selected_sources = {k: v for k, v in sources.items() if k in args.sources.split(",")}
    else:
        selected_sources = {}
        for name, mod in sources.items():
            default = getattr(mod, "DEFAULT_ENABLED", True)
            if default and not getattr(args, f"no_{name}", False):
                selected_sources[name] = mod

    # Determine which enrichers to run
    if args.enrichers:
        selected_enrichers = {k: v for k, v in enrichers.items() if k in args.enrichers.split(",")}
    else:
        selected_enrichers = {}
        for name, mod in enrichers.items():
            default = getattr(mod, "DEFAULT_ENABLED", True)
            if default and not getattr(args, f"skip_{name}", False):
                selected_enrichers[name] = mod

    # Load known IDs from DB
    with db.connect() as conn:
        known_cve_ids = db.list_known_cve_ids(conn)
        known_poc_urls = db.list_known_poc_urls(conn)
        last_run_nvd = db.get_last_run(conn, "nvd")

    # ── Phase 1: Run sources ─────────────────────────────────────────────
    all_cves = []
    all_pocs = []
    source_results = {}  # {source_name: {"cves": [...], "pocs": [...]}}

    step = 0
    total_steps = len(selected_sources) + len(selected_enrichers) + 2  # +merge +persist

    for name, mod in sorted(selected_sources.items()):
        step += 1
        label = getattr(mod, "NAME", name)
        _log(args.quiet, f"[{step}/{total_steps}] Running {label}...")

        try:
            result = mod.run(
                known_cve_ids=known_cve_ids,
                known_poc_urls=known_poc_urls,
                args=args,
                last_run_nvd=last_run_nvd,
            )
            cves = result.get("cves", [])
            pocs = result.get("pocs", [])
            all_cves.extend(cves)
            all_pocs.extend(pocs)
            source_results[name] = {"cves": len(cves), "pocs": len(pocs)}
            _log(args.quiet, f"  Found {len(cves)} CVEs, {len(pocs)} PoCs")
        except Exception as e:
            print(f"  [ERROR] {label} failed: {e}", file=sys.stderr)
            source_results[name] = {"cves": 0, "pocs": 0, "error": str(e)}

    # ── Phase 2: Merge & deduplicate ─────────────────────────────────────
    step += 1
    _log(args.quiet, f"[{step}/{total_steps}] Merging and deduplicating...")
    cves, pocs = merge_findings(all_cves, all_pocs)
    links = link_pocs_to_cves(cves, pocs)
    _log(args.quiet, f"  {len(cves)} unique CVEs, {len(pocs)} unique PoCs after dedup")

    # ── Phase 3: Run enrichers ───────────────────────────────────────────
    for name, mod in sorted(selected_enrichers.items()):
        step += 1
        label = getattr(mod, "NAME", name)
        _log(args.quiet, f"[{step}/{total_steps}] Running {label}...")

        try:
            mod.enrich(cves=cves, pocs=pocs, args=args)
        except Exception as e:
            print(f"  [ERROR] {label} failed: {e}", file=sys.stderr)

    # ── Phase 4: Persist ─────────────────────────────────────────────────
    step += 1
    _log(args.quiet, f"[{step}/{total_steps}] Persisting to database...")
    with db.connect() as conn:
        for cve in cves:
            db.persist_cve(conn, cve)
        for poc in pocs:
            db.persist_poc(conn, poc)
            for ref in poc.cve_refs:
                db.link_poc_to_cve(conn, poc.url, ref)
        for name in source_results:
            db.mark_run(conn, name)

    # ── Phase 5: Output ──────────────────────────────────────────────────
    report_text = render_report(cves, pocs, links, fmt=args.format)
    print(report_text, end="")

    if not args.no_save:
        path = save_report(render_report(cves, pocs, links, fmt="md"), fmt="md")
        _log(args.quiet, f"  Report saved -> {path}")

    if not args.no_graph:
        with db.connect() as conn:
            graph_path = save_graph(conn)
        _log(args.quiet, f"  Graph saved  -> {graph_path}")


if __name__ == "__main__":
    main()
