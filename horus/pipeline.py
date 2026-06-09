"""Pipeline orchestration: sources → merge → enrich → persist → render.

Single source of truth for "what a Horus run does." Both `cli.main` and
`server.Server.run_due` go through `run_pipeline` so the behavior cannot
drift between batch and daemon modes.

The pipeline is intentionally plain-Python — no Flask, no argparse, no
SystemExit. Callers pass in a `PipelineOptions` dataclass and get back a
`PipelineResult`.
"""

from __future__ import annotations

import importlib
import pkgutil
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .core.merge import link_pocs_to_cves, merge_findings
from .render.graph import save_graph
from .render.persist import save_report
from .render.report import render_report
from .storage import db


# ── Plugin discovery ─────────────────────────────────────────────────────────

def _discover_plugins(package_name: str, required_export: str = "run") -> dict[str, Any]:
    """Discover plugin modules inside a sub-package.

    Returns {module_name: module} for every module that exports the
    required callable. Modules whose name starts with `_` are skipped.
    """
    package_path = Path(__file__).parent / package_name
    plugins: dict[str, Any] = {}
    for _finder, name, _ispkg in pkgutil.iter_modules([str(package_path)]):
        if name.startswith("_"):
            continue
        try:
            mod = importlib.import_module(f".{name}", f"horus.{package_name}")
        except ImportError as e:
            print(f"  [WARN] could not load {package_name}/{name}: {e}", file=sys.stderr)
            continue
        if hasattr(mod, required_export) and callable(getattr(mod, required_export)):
            plugins[name] = mod
    return plugins


def discover_sources() -> dict[str, Any]:
    return _discover_plugins("sources", required_export="run")


def discover_enrichers() -> dict[str, Any]:
    return _discover_plugins("enrichers", required_export="enrich")


# ── Options & result ─────────────────────────────────────────────────────────

# CVE-producing source names (run first so their IDs are visible to PoC sources).
CVE_SOURCE_NAMES = {"nvd"}


@dataclass
class PipelineOptions:
    """Inputs to a pipeline run.

    `source_filter` / `enricher_filter`: when None, all DEFAULT_ENABLED
    plugins run. When a set, only those names run.

    `runner_args`: free-form object passed verbatim to each plugin's
    `run()` / `enrich()` as `args=...`. Plugins read `args.max_results`,
    `args.min_cvss`, etc. In CLI mode this is the argparse Namespace; in
    server mode it's a lightweight stand-in (see `make_runner_args`).
    """
    runner_args: Any
    source_filter: set[str] | None = None
    enricher_filter: set[str] | None = None
    quiet: bool = False
    save_report_md: bool = True
    save_graph_html: bool = True
    output_fmt: str = "text"        # 'text' | 'md' — used by render_report
    print_report: bool = True       # whether to print the rendered report to stdout
    log: Callable[[str], None] | None = None


@dataclass
class PipelineResult:
    cves: list = field(default_factory=list)
    pocs: list = field(default_factory=list)
    links: dict = field(default_factory=dict)
    watchlist_counts: dict[str, int] = field(default_factory=dict)
    source_results: dict[str, dict] = field(default_factory=dict)
    report_text: str = ""


def make_runner_args(
    *,
    quiet: bool = True,
    no_save: bool = True,
    no_graph: bool = True,
    fmt: str = "text",
    max_results: int | None = None,
    min_cvss: float | None = None,
    **extra: Any,
) -> Any:
    """Build a lightweight namespace for non-CLI callers (server mode).

    Plugins access this via `args.quiet`, `args.max_results`, etc. — we
    just need attribute access, not full argparse semantics.
    """
    import types
    ns = types.SimpleNamespace(
        quiet=quiet, no_save=no_save, no_graph=no_graph,
        format=fmt, max_results=max_results, min_cvss=min_cvss,
    )
    for k, v in extra.items():
        setattr(ns, k, v)
    return ns


# ── Selection helpers ────────────────────────────────────────────────────────

def select_sources(
    sources: dict[str, Any],
    *,
    filter_: set[str] | None,
    args: Any,
) -> dict[str, Any]:
    if filter_ is not None:
        return {k: v for k, v in sources.items() if k in filter_}
    out: dict[str, Any] = {}
    for name, mod in sources.items():
        if not getattr(mod, "DEFAULT_ENABLED", True):
            continue
        if getattr(args, f"no_{name}", False):
            continue
        out[name] = mod
    return out


def select_enrichers(
    enrichers: dict[str, Any],
    *,
    filter_: set[str] | None,
    args: Any,
) -> dict[str, Any]:
    if filter_ is not None:
        return {k: v for k, v in enrichers.items() if k in filter_}
    out: dict[str, Any] = {}
    for name, mod in enrichers.items():
        if not getattr(mod, "DEFAULT_ENABLED", True):
            continue
        if getattr(args, f"skip_{name}", False):
            continue
        out[name] = mod
    return out


# ── The pipeline ─────────────────────────────────────────────────────────────

def run_pipeline(
    opts: PipelineOptions,
    sources: dict[str, Any] | None = None,
    enrichers: dict[str, Any] | None = None,
) -> PipelineResult:
    """Execute one full Horus cycle and return the result.

    Phases:
        0. discover plugins (if not passed in)
        1a. run CVE sources (NVD) — authoritative IDs first
        1b. run PoC sources (x_twitter before github so x-discovered URLs
            get enriched in the same pass)
        2. merge + score (reputation, watchlist split)
        3. enrich (KEV, EPSS)
        4. persist (cve, poc, watchlist, mark_run)
        5. render report + graph
    """
    args = opts.runner_args
    log = opts.log or (lambda msg: None if opts.quiet else print(msg, file=sys.stderr))

    if sources is None:
        sources = discover_sources()
    if enrichers is None:
        enrichers = discover_enrichers()

    selected_sources = select_sources(sources, filter_=opts.source_filter, args=args)
    selected_enrichers = select_enrichers(enrichers, filter_=opts.enricher_filter, args=args)

    # DB init
    cves_migrated, pocs_migrated = db.initialize()
    if cves_migrated or pocs_migrated:
        log(f"  migrated {cves_migrated} CVEs and {pocs_migrated} PoCs from legacy state")

    with db.connect() as conn:
        known_cve_ids = db.list_known_cve_ids(conn)
        known_poc_urls = db.list_known_poc_urls(conn)
        last_run_nvd = db.get_last_run(conn, "nvd")

    # Plumbing for the run loop
    all_cves: list = []
    all_pocs: list = []
    all_social_signals: list[dict] = []
    source_results: dict[str, dict] = {}
    step = 0
    total_steps = len(selected_sources) + len(selected_enrichers) + 2  # +merge +persist

    def _run_source(name: str, mod: Any, **extra: Any) -> dict:
        nonlocal step
        step += 1
        label = getattr(mod, "NAME", name)
        log(f"[{step}/{total_steps}] running {label}...")
        try:
            result = mod.run(
                known_cve_ids=known_cve_ids,
                known_poc_urls=known_poc_urls,
                args=args,
                last_run_nvd=last_run_nvd if name == "nvd" else None,
                **extra,
            )
            cves = result.get("cves", [])
            pocs = result.get("pocs", [])
            all_cves.extend(cves)
            all_pocs.extend(pocs)
            all_social_signals.extend(result.get("social_signals", []))
            source_results[name] = {"cves": len(cves), "pocs": len(pocs)}
            log(f"  found {len(cves)} CVEs, {len(pocs)} PoCs")
            return result
        except Exception as e:
            print(f"  [ERROR] {label} failed: {e}", file=sys.stderr)
            source_results[name] = {"cves": 0, "pocs": 0, "error": str(e)}
            return {}

    # 1a — CVE sources first
    cve_source_names = CVE_SOURCE_NAMES & set(selected_sources.keys())
    poc_source_names = set(selected_sources.keys()) - CVE_SOURCE_NAMES
    for name in sorted(cve_source_names):
        _run_source(name, selected_sources[name])
    known_cve_ids.update({c.id.upper() for c in all_cves})

    # 1b — PoC sources, x_twitter first so github can enrich its URLs.
    x_discovered_urls: list[str] = []
    poc_order = sorted(poc_source_names, key=lambda n: (n != "x_twitter", n))
    for name in poc_order:
        extra: dict = {}
        if name == "github" and x_discovered_urls:
            extra["x_discovered_urls"] = x_discovered_urls
        result = _run_source(name, selected_sources[name], **extra)
        if name == "x_twitter":
            x_discovered_urls = result.get("x_discovered_urls", [])

    # 2 — merge
    step += 1
    log(f"[{step}/{total_steps}] merging and deduplicating...")
    cves, pocs, watchlist_counts = merge_findings(
        all_cves, all_pocs, social_signals=all_social_signals,
    )
    links = link_pocs_to_cves(cves, pocs)
    log(f"  {len(cves)} unique CVEs, {len(pocs)} unique PoCs after dedup")
    if watchlist_counts:
        log(f"  {len(watchlist_counts)} signal-only CVE IDs queued to watchlist")

    # 3 — enrichers
    for name, mod in sorted(selected_enrichers.items()):
        step += 1
        label = getattr(mod, "NAME", name)
        log(f"[{step}/{total_steps}] running {label}...")
        try:
            mod.enrich(cves=cves, pocs=pocs, args=args)
        except Exception as e:
            print(f"  [ERROR] {label} failed: {e}", file=sys.stderr)

    # 4 — persist
    step += 1
    log(f"[{step}/{total_steps}] persisting to database...")
    with db.connect() as conn:
        for cve in cves:
            db.persist_cve(conn, cve)
        for poc in pocs:
            db.persist_poc(conn, poc)
            for ref in poc.cve_refs:
                db.link_poc_to_cve(conn, poc.url, ref)
        for cve_id, mentions in watchlist_counts.items():
            db.persist_watchlist(conn, cve_id, source="x_twitter", social_mentions=mentions)
        for cve in cves:
            db.resolve_watchlist(conn, cve.id)
        for name in source_results:
            db.mark_run(conn, name)

    # 5 — render
    report_text = render_report(cves, pocs, links, fmt=opts.output_fmt)
    if opts.print_report:
        print(report_text, end="")
    if opts.save_report_md:
        report_md = render_report(cves, pocs, links, fmt="md")
        path = save_report(report_md, fmt="md")
        log(f"  report saved -> {path}")
    if opts.save_graph_html:
        with db.connect() as conn:
            graph_path = save_graph(conn)
        log(f"  graph saved  -> {graph_path}")

    return PipelineResult(
        cves=cves, pocs=pocs, links=links,
        watchlist_counts=watchlist_counts,
        source_results=source_results,
        report_text=report_text,
    )
