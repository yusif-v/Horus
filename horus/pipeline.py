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
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .core.context import EnricherContext, SourceContext
from .core.merge import link_pocs_to_cves, merge_findings
from .core.model import CVE, PoC
from .render.graph import save_graph
from .render.persist import save_report
from .render.report import render_report
from .storage import db

# Plugin attribute names — what the pipeline reads off each module.
_KIND_CVE = "cve"
_KIND_POC = "poc"
_DEFAULT_KIND = _KIND_POC  # safest assumption for plugins that forget to declare


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
    disabled_sources: set[str] = field(default_factory=set)  # explicit opt-out
    disabled_enrichers: set[str] = field(default_factory=set)
    max_results: int | None = None
    min_cvss: float | None = None
    quiet: bool = False
    save_report_md: bool = True
    save_graph_html: bool = True
    output_fmt: str = "text"  # 'text' | 'md'
    print_report: bool = True
    log: Callable[[str], None] | None = None


@dataclass
class PipelineResult:
    cves: list[CVE] = field(default_factory=list)
    pocs: list[PoC] = field(default_factory=list)
    links: dict[str, list[PoC]] = field(default_factory=dict)
    watchlist_counts: list[tuple[str, str, int]] = field(default_factory=list)
    source_results: dict[str, dict[str, Any]] = field(default_factory=dict)
    report_text: str = ""
    # Events extracted during the pipeline run for notification dispatch
    events: dict[str, list[dict]] = field(
        default_factory=lambda: {
            "kev_new": [],
            "epss_jump": [],
            "critical_cve": [],
            "watchlist_match": [],
            "poc_new": [],
        }
    )


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
        k: v
        for k, v in plugins.items()
        if getattr(v, "DEFAULT_ENABLED", True) and k not in disabled
    }


# ── Post-enrich scoring ──────────────────────────────────────────────────────


def _score_imminence(cves: list[CVE], conn) -> None:
    """Compute imminence for each CVE after enrichment (needs EPSS/KEV/velocity)."""
    from .core import forecast

    for cve in cves:
        vel = forecast.epss_velocity(cve.id, conn)
        cve.imminence_score, cve.imminence_bucket = forecast.compute_imminence(
            cve, epss_velocity=vel
        )


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
        (lambda msg: None) if opts.quiet else (lambda msg: print(msg, file=sys.stderr))
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
    all_cves: list[CVE] = []
    all_pocs: list[PoC] = []
    all_social_signals: list[dict[str, Any]] = []
    all_resources: list[dict[str, Any]] = []
    source_results: dict[str, dict[str, Any]] = {}
    step = 0
    total_steps = len(selected_sources) + len(selected_enrichers) + 3  # +cve_fetch +merge +persist
    x_discovered_urls: list[str] = []

    def _run_source(name: str, mod: Any) -> dict[str, Any]:
        nonlocal step
        step += 1
        label = getattr(mod, "NAME", name)
        log(f"[{step}/{total_steps}] running {label}...")
        provided = (
            {"x_discovered_urls": x_discovered_urls} if name in ("github", "codeberg") else {}
        )
        ctx = SourceContext(
            known_cve_ids=known_cve_ids,
            known_poc_urls=known_poc_urls,
            max_results=opts.max_results,
            min_cvss=opts.min_cvss,
            last_run=last_runs.get(name),
            provided=provided,
        )
        try:
            result = mod.run(ctx) or {}
            cves = result.get("cves", [])
            pocs = result.get("pocs", [])
            all_cves.extend(cves)
            all_pocs.extend(pocs)
            all_social_signals.extend(result.get("social_signals", []))
            all_resources.extend(result.get("resources", []))
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

    # 1c — Fetch CVEs referenced by PoCs from NVD
    # Many PoCs have CVE IDs in their names/descriptions but the CVE might not
    # be in our DB yet. Fetch them from NVD to create proper links.
    step += 1
    log(f"[{step}/{total_steps}] fetching CVEs referenced by PoCs from NVD...")
    from horus.core.merge import cve_from_nvd
    from horus.sources.nvd_fetch import fetch_cve_by_id, parse_nvd_cve

    # Collect all CVE IDs referenced by PoCs that aren't in our DB yet
    cve_ids_to_fetch: set[str] = set()
    for poc in all_pocs:
        for ref in poc.cve_refs:
            if ref.upper() not in known_cve_ids:
                cve_ids_to_fetch.add(ref.upper())

    log(f"  {len(cve_ids_to_fetch)} unique CVE IDs referenced by PoCs need fetching")
    fetched_count = 0
    for cve_id in sorted(cve_ids_to_fetch):
        raw = fetch_cve_by_id(cve_id)
        if raw:
            parsed = parse_nvd_cve(raw)
            if parsed:
                cve = cve_from_nvd(parsed)
                all_cves.append(cve)
                known_cve_ids.add(cve.id.upper())
                fetched_count += 1
    log(f"  fetched {fetched_count} CVEs from NVD")

    # 2 — merge
    step += 1
    log(f"[{step}/{total_steps}] merging and deduplicating...")
    cves, pocs, watchlist_counts = merge_findings(
        all_cves,
        all_pocs,
        social_signals=all_social_signals,
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
        _score_imminence(cves, conn)
        for cve in cves:
            db.persist_cve(conn, cve)
        for poc in pocs:
            db.persist_poc(conn, poc)
            for ref in poc.cve_refs:
                db.link_poc_to_cve(conn, poc.url, ref)
        for cve_id, source, mentions in watchlist_counts:
            db.persist_watchlist(conn, cve_id, source=source, social_mentions=mentions)
        for cve in cves:
            db.resolve_watchlist(conn, cve.id)
        # Persist security resources
        from horus.core.model import Resource

        for r_data in all_resources:
            r = Resource(
                url=r_data["url"],
                resource_type=r_data["resource_type"],
                source=r_data["source"],
                title=r_data["title"],
                description=r_data["description"],
                source_url=r_data["source_url"],
                source_author=r_data["source_author"],
                engagement_score=r_data["engagement_score"],
                tags=r_data["tags"],
                cve_refs=r_data["cve_refs"],
                tweet_created_at=r_data.get("tweet_created_at"),
            )
            db.persist_resource(conn, r)
        if all_social_signals:
            # Any CVE in the DB is a valid FK target — not just this cycle's batch.
            # Tweets about CVEs persisted in earlier runs should still land here
            # (they'd be treated as "signal-only" by the merge layer otherwise).
            db_cve_ids = {row[0] for row in conn.execute("SELECT id FROM cve")}
            posted = db.persist_social_posts(conn, all_social_signals, known_cve_ids=db_cve_ids)
            if posted:
                log(f"  persisted {posted} social posts")
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

    # Build events for notification dispatch
    events = _build_events(cves, pocs, enricher_ctx)

    result = PipelineResult(
        cves=cves,
        pocs=pocs,
        links=links,
        watchlist_counts=watchlist_counts,
        source_results=source_results,
        report_text=report_text,
        events=events,
    )

    # 6 — end-of-run hooks (notification dispatch, etc.)
    for hook in _END_HOOKS:
        try:
            hook(result)
        except Exception as e:
            print(f"  [WARN] end hook failed: {e}", file=sys.stderr)

    return result


# ── End-of-run hooks ─────────────────────────────────────────────────────────

_END_HOOKS: list[Callable[[PipelineResult], None]] = []


def register_end_hook(fn: Callable[[PipelineResult], None]) -> None:
    """Register a callback that runs after each pipeline completion."""
    _END_HOOKS.append(fn)


# ── Event extraction ─────────────────────────────────────────────────────────


def _build_events(
    cves: list[CVE], pocs: list[PoC], enricher_ctx: EnricherContext
) -> dict[str, list[dict]]:
    """Extract notification events from the pipeline result.

    Returns a dict keyed by notification category.
    """
    events: dict[str, list[dict]] = {
        "kev_new": [],
        "epss_jump": [],
        "critical_cve": [],
        "watchlist_match": [],
        "poc_new": [],
    }

    for cve in cves:
        # KEV additions
        if cve.kev:
            events["kev_new"].append(
                {
                    "cve_id": cve.id,
                    "cvss_score": cve.cvss_score,
                    "cvss_severity": cve.cvss_severity,
                }
            )

        # Critical CVE with PoC
        if cve.cvss_score is not None and cve.cvss_score >= 9:
            poc_count = sum(1 for p in pocs if cve.id in (p.cve_refs or []))
            if poc_count > 0:
                events["critical_cve"].append(
                    {
                        "cve_id": cve.id,
                        "cvss_score": cve.cvss_score,
                        "cvss_severity": cve.cvss_severity,
                        "poc_count": poc_count,
                    }
                )

        # EPSS jump (score >= 0.5)
        if cve.epss_score is not None and cve.epss_score >= 0.5:
            events["epss_jump"].append(
                {
                    "cve_id": cve.id,
                    "epss_score": cve.epss_score,
                }
            )

    # Watchlist matches — check team_watchlist table
    try:
        from .storage import db as _db

        with _db.connect() as conn:
            wl_rows = conn.execute("SELECT team, vendor, product FROM team_watchlist").fetchall()
            for cve in cves:
                for wl_team, wl_vendor, wl_product in wl_rows:
                    # Check if this CVE affects a watched vendor/product
                    cve_products = getattr(cve, "products", []) or []
                    for cp in cve_products:
                        vendor_match = (
                            cp.get("vendor", "").lower() == wl_vendor.lower() if wl_vendor else True
                        )
                        product_match = (
                            cp.get("product", "").lower() == wl_product.lower()
                            if wl_product
                            else True
                        )
                        if vendor_match and product_match:
                            events["watchlist_match"].append(
                                {
                                    "cve_id": cve.id,
                                    "vendor": wl_vendor or cp.get("vendor", ""),
                                    "product": wl_product or cp.get("product", ""),
                                    "team": wl_team,
                                }
                            )
    except Exception:
        pass  # Watchlist table may not exist yet

    # New PoCs for tracked CVEs
    for poc in pocs:
        for ref in poc.cve_refs or []:
            events["poc_new"].append(
                {
                    "cve_id": ref,
                    "url": poc.url,
                    "source": poc.source,
                }
            )

    return events
