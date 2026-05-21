"""CLI entry point."""

import argparse
import sys

from . import __version__
from .core.merge import link_pocs_to_cves, merge_findings
from .render.graph import save_graph
from .render.persist import save_report
from .render.report import render_report
from .sources.auth import github_token
from .sources.github import search_github
from .sources.nvd import fetch_recent_cves
from .storage import db


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog='horus',
        description='Daily PoC research scanner (GitHub + NVD).',
    )
    p.add_argument('--version', action='version', version=f'horus {__version__}')
    p.add_argument(
        '--min-cvss', type=float, default=None,
        help='Minimum CVSS base score for NVD items (default: no floor).',
    )
    p.add_argument(
        '--max-results', type=int, default=None,
        help='Cap items per source after sorting (default: no cap).',
    )
    p.add_argument(
        '--format', choices=('text', 'md'), default='text',
        help='Output format (default: text).',
    )
    p.add_argument(
        '--quiet', action='store_true',
        help='Suppress progress lines on stderr; only print the report.',
    )
    p.add_argument(
        '--auth-status', action='store_true',
        help='Print GitHub auth status and exit.',
    )
    p.add_argument(
        '--no-save', action='store_true',
        help='Skip writing the markdown report to reports/.',
    )
    p.add_argument(
        '--no-graph', action='store_true',
        help='Skip writing the interactive graph HTML to reports/.',
    )
    return p


def _log(quiet: bool, msg: str) -> None:
    if not quiet:
        print(msg, file=sys.stderr)


def main(argv: list[str] | None = None) -> None:
    args = _build_parser().parse_args(argv)

    if args.auth_status:
        tok = github_token()
        if tok:
            print(f'GitHub auth: OK (token ...{tok[-4:]}, limit 5000/hr)')
        else:
            print('GitHub auth: none (unauthenticated, limit 60/hr)')
        return

    cves_migrated, pocs_migrated = db.initialize()
    if cves_migrated or pocs_migrated:
        _log(
            args.quiet,
            f'  Migrated {cves_migrated} CVEs and {pocs_migrated} PoCs'
            ' from legacy JSON state',
        )

    with db.connect() as conn:
        known_cve_ids = db.list_known_cve_ids(conn)
        known_poc_urls = db.list_known_poc_urls(conn)
        last_run_nvd = db.get_last_run(conn, 'nvd')

    _log(args.quiet, '[1/2] Searching GitHub for new PoC repos...')
    github_raw = search_github(known_poc_urls, max_results=args.max_results)
    _log(args.quiet, f'  Found {len(github_raw)} relevant repos')

    _log(args.quiet, '[2/2] Fetching recent CVEs from NVD...')
    nvd_raw = fetch_recent_cves(
        known_cve_ids,
        last_run_iso=last_run_nvd,
        min_cvss=args.min_cvss,
        max_results=args.max_results,
    )
    _log(args.quiet, f'  Found {len(nvd_raw)} relevant CVEs')

    cves, pocs = merge_findings(nvd_raw, github_raw)
    links = link_pocs_to_cves(cves, pocs)

    with db.connect() as conn:
        for cve in cves:
            db.persist_cve(conn, cve)
        for poc in pocs:
            db.persist_poc(conn, poc)
            for ref in poc.cve_refs:
                db.link_poc_to_cve(conn, poc.url, ref)
        db.mark_run(conn, 'github')
        db.mark_run(conn, 'nvd')

    print(render_report(cves, pocs, links, fmt=args.format), end='')

    if not args.no_save:
        path = save_report(
            render_report(cves, pocs, links, fmt='md'),
            fmt='md',
        )
        _log(args.quiet, f'  Report saved → {path}')

    if not args.no_graph:
        with db.connect() as conn:
            graph_path = save_graph(conn)
        _log(args.quiet, f'  Graph saved  → {graph_path}')


if __name__ == '__main__':
    main()
