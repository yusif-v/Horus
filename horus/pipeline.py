"""Pipeline orchestration: sources → merge → enrich → persist → render.

Single source of truth for "what a Horus run does." Both `cli.main` and
`server.Server.run_due` call `run_pipeline(opts)`; the orchestration
logic lives here and nowhere else.

Plugins are decoupled from the CLI: every source receives a typed
`SourceContext` (not an argparse Namespace), every enricher receives an
`EnricherContext`. Adding a new tunable means adding a field to one of
those dataclasses, not coordinating across CLI / server / four plugin
files.
"""

from __future__ import annotations

import importlib
import pkgutil
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

from .core.context import EnricherContext, SourceContext
from .core.merge import link_pocs_to_cves, merge_findings
from .render.graph import save_graph
from .render.persist import save_report
from .render.report import render_report
from .storage import db


# ── Plugin discovery ─────────────────────────────────────────────────────────

def _discover_plugins(package_name: str, required_export: str = "run") -> dict[str, Any]:
    """Return {module_name: module} for plugins exporting `required_export`."""
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

    Plugin tunables (max_results, min_cvss) live on PipelineOptions and
    are funneled into each plugin's SourceContext. Plugins do not see
    these names.
    """
    source_filter: set[str] | None = None
    enricher_filter: set[str] | None = None
    disabled_sources: set[str] = field(default_factory=set)     # explicit opt-out
    disabled_enrichers: set[str] = field(default_factory=set)
    max_results: int | None = None
    min_cvss: float | None = None
    quiet: bool = False
    save_report_md: bool = True
    save_graph_html: bool = True
    output_fmt: str = "text"        # 'text' | 'md'
    print_report: bool = True
    log: Callable[[str], None] | None = None


@dataclass
class PipelineResult:
    cves: list = field(default_factory=list)
    pocs: list = field(default_factory=list)
    links: dict = field(default_factory=dict)
    watchlist_counts: dict[str, int] = field(default_factory=dict)
    source_results: dict[str, dict] = field(default_factory=dict)
    report_text: str = ""


# ── Selection helpers ────────────────────────────────────────────────────────

def _select(
    plugins: dict[str, Any],
    filter_: set[str] | None,
    disabled: set[str],
) -> dict[str, Any]:
    """Pick which plugins run this cycle.

    `filter_=None` → all DEFAULT_ENABLED plugins minus `disabled`.
    `filter_={...}` → exactly those names (filter wins; disabled ignored).
    """
    if filter_ is not None:
        return {k: v for k, v in plugins.items() if k in filter_}
    return {
        k: v for k, v in plugins.items()
        if getattr(v, "DEFAULT_ENABLED", True) and k not in disabled
    }


# ── The pipeline ─────────────────────────────────────────────────────────────

def run_pipeline(
    opts: PipelineOptions,
    sources: dict[str, Any] | None = None,
    enrichers: dict[str, Any] | None = None,
) -> PipelineResult:
    """Execute one full Horus cycle and return the result.

    Phases:
        0. discover plugins (if not passed in)
        1a. CVE sources (NVD) — authoritative IDs first
        1b. PoC sources — x_twitter before github so x-discovered URLs
            get enriched in the same pass
        2.  merge + score (reputation, watchlist split)
        3.  enrich (KEV, EPSS)
        4.  persist (cve, poc, watchlist, mark_run)
        5.  render report + graph
    """
    log = opts.log or (
        (lambda msg: None) if opts.quiet
        else (lambda msg: print(msg, file=sys.stderr))
    )

    if sources is None:
        sources = discover_sources()
    if enrichers is None:
        enrichers = discover_enrichers()

    selected_sources = _select(sources, opts.source_filter, opts.disabled_sources)
    selected_enrichers = _select(enrichers, opts.enricher_filter, opts.disabled_enrichers)

    # ── DB init + read dedup state ──────────────────────────────────────
    cves_migrated, pocs_migrated = db.initialize()
    if cves_migrated or pocs_migrated:
        log(f"  migrated {cves_migrated} CVEs and {pocs_migrated} PoCs from legacy state")

    with db.connect() as conn:
        known_cve_ids = db.list_known_cve_ids(conn)
        known_poc_urls = db.list_known_poc_urls(conn)
        # Every source gets its own last_run as a generic ctx field.
        last_runs = {name: db.get_last_run(conn, name) for name in selected_sources}

    # Plumbing for the run loop
    all_cves: list = []
    all_pocs: list = []
    all_social_signals: list[dict] = []
    source_results: dict[str, dict] = {}
    step = 0
    total_steps = len(selected_sources) + len(selected_enrichers) + 2  # +merge +persist
    x_discovered_urls: list[str] = []

    def _run_source(name: str, mod: Any) -> dict:
        nonlocal step
        step += 1
        label = getattr(mod, "NAME", name)
        log(f"[{step}/{total_steps}] running {label}...")
        ctx = SourceContext(
            known_cve_ids=known_cve_ids,
            known_poc_urls=known_poc_urls,
            max_results=opts.max_results,
            min_cvss=opts.min_cvss,
            last_run=last_runs.get(name),
            x_discovered_urls=x_discovered_urls if name == "github" else [],
        )
        try:
            result = mod.run(ctx) or {}
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
    cve_source_names: Iterable[str] = sorted(CVE_SOURCE_NAMES & set(selected_sources))
    for name in cve_source_names:
        _run_source(name, selected_sources[name])
    known_cve_ids.update({c.id.upper() for c in all_cves})

    # 1b — PoC sources, x_twitter first so github can enrich its URLs.
    poc_source_names = sorted(
        set(selected_sources) - CVE_SOURCE_NAMES,
        key=lambda n: (n != "x_twitter", n),
    )
    for name in poc_source_names:
        result = _run_source(name, selected_sources[name])
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
    enricher_ctx = EnricherContext(cves=cves, pocs=pocs)
    for name, mod in sorted(selected_enrichers.items()):
        step += 1
        label = getattr(mod, "NAME", name)
        log(f"[{step}/{total_steps}] running {label}...")
        try:
            mod.enrich(enricher_ctx)
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
