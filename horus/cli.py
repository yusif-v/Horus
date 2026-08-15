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
from pathlib import Path
from typing import Any

from . import __version__
from .logger import setup_logging
from .net.auth import github_token
from .pipeline import PipelineOptions, run_pipeline

logger = logging.getLogger(__name__)

# ── Argument parser ─────────────────────────────────────────────────────────


def _build_parser(sources: dict, enrichers: dict) -> argparse.ArgumentParser:
    """Build the CLI parser dynamically from discovered plugins."""
    p = argparse.ArgumentParser(
        prog="horus",
        description="Daily PoC research scanner — plugin-based CVE & PoC aggregator.",
        # `allow_abbrev=False` so `--plugin` is NOT ambiguous with `--plugins-dir`
        # (an aborted flag-style invocation must fail, not silently run).
        allow_abbrev=False,
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
    p.add_argument(
        "--plugins-dir",
        type=str,
        default=None,
        help="External plugins directory (default: ~/.config/horus/plugins).",
    )

    # Plugin management — `horus plugin <action> [args]`
    plugin_sub = p.add_subparsers(dest="plugin_cmd", metavar="plugin")
    plugin_parser = plugin_sub.add_parser(
        "plugin",
        help="Manage plugins: list, enable, disable, config, add, remove, scaffold, validate.",
    )
    actions = plugin_parser.add_subparsers(dest="plugin_action", metavar="ACTION")
    # `--config` / `--plugins-dir` are also top-level options; SUPPRESS keeps a
    # subcommand-scoped value from clobbering the top-level one (and vice versa).

    def _plugin_flags(s: argparse.ArgumentParser) -> None:
        s.add_argument("--config", default=argparse.SUPPRESS)
        s.add_argument("--plugins-dir", default=argparse.SUPPRESS)

    _p = actions.add_parser("list", help="List all discovered (bundled + external) plugins.")
    _plugin_flags(_p)

    _p = actions.add_parser("enable", help="Set enabled: true for a plugin in horus.yaml.")
    _p.add_argument("name")
    _plugin_flags(_p)

    _p = actions.add_parser("disable", help="Set enabled: false for a plugin in horus.yaml.")
    _p.add_argument("name")
    _plugin_flags(_p)

    _p = actions.add_parser(
        "config", help="Show or set a plugin's config: `config <name> [<key> [<value>]]`."
    )
    _p.add_argument("name")
    _p.add_argument("key", nargs="?")
    _p.add_argument("value", nargs="?")
    _plugin_flags(_p)

    _p = actions.add_parser("add", help="Install a plugin folder into an external plugins dir.")
    _p.add_argument("name", metavar="path")
    _plugin_flags(_p)

    _p = actions.add_parser("remove", help="Remove an external plugin folder (never bundled).")
    _p.add_argument("name")
    _plugin_flags(_p)

    _p = actions.add_parser(
        "scaffold", help="Generate a starter plugin folder (manifest + main.py stub)."
    )
    _p.add_argument("kind", choices=("source", "enricher", "notification"))
    _p.add_argument("name")
    _plugin_flags(_p)

    _p = actions.add_parser("validate", help="Validate a plugin manifest + entrypoint + export.")
    _p.add_argument("name", metavar="name|path", help="Plugin name or path to a plugin folder.")
    _plugin_flags(_p)

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
    from .plugins.enrichers.epss.main import backfill_all
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

    render_fmt = "html" if args.weekly_format == "pdf" else args.weekly_format
    report = render_weekly_report(weekly_data, fmt=render_fmt)

    if args.ai:
        if render_fmt == "html":
            logger.warning("--ai is not supported with html/pdf output — rendering template only")
        else:
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
                page.wait_for_timeout(3000)
                # Force SVG rendering before PDF
                page.evaluate("""() => {
                    document.querySelectorAll('svg').forEach(s => {
                        s.setAttribute('width', s.getBoundingClientRect().width);
                        s.setAttribute('height', s.getBoundingClientRect().height);
                    });
                }""")
                page.pdf(
                    path=pdf_path,
                    format="A4",
                    margin={"top": "12mm", "bottom": "12mm", "left": "12mm", "right": "12mm"},
                    print_background=True,
                    prefer_css_page_size=True,
                    scale=0.85,
                    display_header_footer=True,
                    footer_template='<div style="font-size:8pt;width:100%;text-align:center;color:#888;padding:0 1cm;"><span class="pageNumber"></span> / <span class="totalPages"></span></div>',
                    header_template="<div></div>",
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


def _plugin_read_config(config_path: str | None) -> dict[str, Any]:
    """Parse the full config file (YAML if PyYAML is present, else JSON).

    Returns {} when the file is missing/unparseable so callers can safely
    rebuild a fresh `plugins:` block.
    """
    from .core.config_io import load_config_document

    return load_config_document(config_path)


def _plugin_write_config(config_path: str, data: dict[str, Any]) -> None:
    """Persist the config file, preserving key order via yaml.dump sort_keys=False."""
    import json

    p = Path(config_path).expanduser()
    p.parent.mkdir(parents=True, exist_ok=True)
    try:
        import yaml

        p.write_text(yaml.dump(data, sort_keys=False))
    except ImportError:
        p.write_text(json.dumps(data, indent=2, sort_keys=False))


def _plugin_set_enabled(config_path: str | None, name: str, enabled: bool) -> bool:
    """Set the `enabled` flag for a plugin in the config's `plugins:` block.

    Returns True when the change was persisted to a config file, False when
    there is no config file (callers must not claim success).
    """
    if not config_path:
        logger.warning("no config file; use --config to persist enable/disable state")
        return False
    doc = _plugin_read_config(config_path)
    plugins = doc.setdefault("plugins", {})
    entry = plugins.setdefault(name, {})
    entry["enabled"] = bool(enabled)
    _plugin_write_config(config_path, doc)
    return True


def _plugin_set_config(config_path: str | None, name: str, key: str, value: str | None) -> bool:
    """Set a config key for a plugin in the config's `plugins.<name>.config:` block.

    Returns True when the change was persisted to a config file, False when
    there is no config file (callers must not claim success).
    """
    if not config_path:
        logger.warning("no config file; use --config to persist plugin config")
        return False
    doc = _plugin_read_config(config_path)
    plugins = doc.setdefault("plugins", {})
    entry = plugins.setdefault(name, {})
    entry.setdefault("config", {})[key] = value
    _plugin_write_config(config_path, doc)
    return True


def _plugin_show_config(config_path: str | None, name: str) -> None:
    """Print the config block for a plugin from the `plugins.<name>.config:` section."""
    from .server import _load_plugins_section

    plugins = _load_plugins_section(config_path) if config_path else {}
    entry = (plugins.get(name) or {}).get("config", {})
    if not entry:
        print(f"no config for plugin '{name}'")
        return
    for k, v in sorted(entry.items()):
        print(f"  {k}: {v}")


def _plugin_find_external(plugins_dir: Path, name: str) -> Path | None:
    """Locate a plugin folder under an external dir's <kind>/<name> subdirs."""
    for sub in ("sources", "enrichers", "notifications"):
        candidate = plugins_dir / sub / name
        if candidate.exists():
            return candidate
    return None


def _plugin_infer_kind_dir(folder: Path) -> str | None:
    """Map a plugin folder's `[plugin] type` to its kind dir name (None if unknown)."""
    toml_path = folder / "plugin.toml"
    if not toml_path.exists():
        return None
    try:
        try:
            import tomllib
        except ImportError:  # pragma: no cover - py<3.11
            import tomli as tomllib

        with toml_path.open("rb") as fh:
            data = tomllib.load(fh)
    except Exception:
        return None
    ptype = data.get("plugin", {}).get("type")
    return {"source": "sources", "enricher": "enrichers", "notification": "notifications"}.get(
        ptype
    )


def _cmd_plugin(args: Any) -> None:
    """`horus plugin <subcommand>` — manage plugins via PluginManager."""
    from .core.plugin_types import PluginKind
    from .plugin_manager import PluginManager, scaffold_plugin, validate_plugin

    plugins_dir = (
        Path(args.plugins_dir) if args.plugins_dir else Path("~/.config/horus/plugins").expanduser()
    )
    bundled = Path(__file__).parent / "plugins"
    mgr = PluginManager(bundled_root=bundled, external_dirs=[plugins_dir])

    # Apply enable/disable from config if present.
    if args.config:
        from .server import _load_plugins_section

        mgr.apply_config(_load_plugins_section(args.config))

    if args.cmd == "list":
        for name, p in sorted(mgr.all().items()):
            state = "enabled" if mgr.is_enabled(name) else "disabled"
            loc = str(p.path) if p.path else "?"
            print(f"[{p.kind.value}] {name} v{p.manifest.version} ({p.display_name}) {state} {loc}")
        for name, err in mgr.broken:
            print(f"[broken] {name}: {err}")
    elif args.cmd == "scaffold":
        kind = PluginKind(args.kind)
        out = scaffold_plugin(kind, args.name, plugins_dir)
        print(f"scaffolded {kind.value} plugin -> {out}")
    elif args.cmd == "validate":
        target: Path | None = Path(args.name)
        if target is not None and not (target / "plugin.toml").exists():
            # Not a path to a plugin folder — treat as a name.
            target = _plugin_find_external(plugins_dir, args.name)
            if target is None:
                target = next(
                    (
                        bundled / sub / args.name
                        for sub in ("sources", "enrichers", "notifications")
                        if (bundled / sub / args.name).exists()
                    ),
                    None,
                )
                if target is None:
                    print(f"plugin '{args.name}' not found")
                    return
        assert target is not None
        errs = validate_plugin(target)
        print("OK" if not errs else "INVALID:\n" + "\n".join(errs))
    elif args.cmd in ("enable", "disable"):
        persisted = _plugin_set_enabled(args.config, args.name, args.cmd == "enable")
        if persisted:
            print(f"{args.name} {'enabled' if args.cmd == 'enable' else 'disabled'}")
        else:
            print(f"no config file; nothing persisted for '{args.name}'")
    elif args.cmd == "config":
        if args.key is None:
            _plugin_show_config(args.config, args.name)
        else:
            persisted = _plugin_set_config(args.config, args.name, args.key, args.value)
            if persisted:
                print(f"set {args.name}.{args.key} = {args.value}")
            else:
                print(f"no config file; nothing persisted for '{args.name}'")
    elif args.cmd == "add":
        import shutil

        src = Path(args.name)
        kind_dir = _plugin_infer_kind_dir(src)
        dest = (plugins_dir / kind_dir if kind_dir else plugins_dir) / src.name
        shutil.copytree(src, dest, dirs_exist_ok=True)
        print(f"added plugin -> {dest}")
    elif args.cmd == "remove":
        import shutil

        target = _plugin_find_external(plugins_dir, args.name)
        if target is None:
            print(f"plugin '{args.name}' not found in external dir")
            return
        shutil.rmtree(target)
        print(f"removed plugin -> {target}")


# ── Entry point ─────────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> None:
    setup_logging()

    from .plugin_manager import PluginManager

    bundled = Path(__file__).parent / "plugins"
    default_ext = Path("~/.config/horus/plugins").expanduser()

    # Flag generation + --list-sources use the default-enabled plugin set;
    # config is only resolvable after args are parsed.
    probe = PluginManager(bundled_root=bundled, external_dirs=[default_ext])
    probe_sources = {n: p.module for n, p in probe.sources().items()}
    probe_enrichers = {n: p.module for n, p in probe.enrichers().items()}
    args = _build_parser(probe_sources, probe_enrichers).parse_args(argv)

    # One-shot commands fall through here.
    if args.list_sources:
        return _cmd_list_sources(probe_sources, probe_enrichers)
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
    if args.plugin_cmd == "plugin":
        return _cmd_plugin(
            argparse.Namespace(
                cmd=args.plugin_action,
                kind=getattr(args, "kind", None),
                name=getattr(args, "name", None),
                key=getattr(args, "key", None),
                value=getattr(args, "value", None),
                plugins_dir=args.plugins_dir,
                config=args.config,
            )
        )

    # ── HORUS_SOURCES_ENABLED / HORUS_SOURCES_DISABLED ────────────────────
    source_filter = set(args.sources.split(",")) if args.sources else None
    enricher_filter = set(args.enrichers.split(",")) if args.enrichers else None

    if source_filter is None:
        env_enabled = os.environ.get("HORUS_SOURCES_ENABLED")
        if env_enabled:
            source_filter = {s.strip() for s in env_enabled.split(",") if s.strip()}
            if source_filter:
                logger.info("Sources enabled via HORUS_SOURCES_ENABLED: %s", source_filter)

    # Resolve the real plugin set from config so `plugins.<name>.enabled` and
    # `plugins.<name>.config` are honored for one-shot runs too.
    from .server import load_config

    cfg = load_config(args.config)
    ext = [Path(d).expanduser() for d in cfg.plugin_dirs]
    mgr = PluginManager(bundled_root=bundled, external_dirs=ext)
    mgr.apply_config(cfg.plugins)
    sources = mgr.sources()
    enrichers = mgr.enrichers()

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
