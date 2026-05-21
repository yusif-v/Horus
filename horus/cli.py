"""CLI entry point."""

import argparse
import sys

from . import __version__
from .core.merge import link_pocs_to_cves, merge_findings
from .render.persist import save_report
from .render.report import render_report
from .sources.auth import github_token
from .sources.github import search_github
from .sources.nvd import fetch_recent_cves
from .storage.state import (
    load_last_run, load_seen, mark_run, save_last_run, save_seen,
)


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

    seen = load_seen()
    last_run = load_last_run()

    _log(args.quiet, '[1/2] Searching GitHub for new PoC repos...')
    github_raw = search_github(seen, max_results=args.max_results)
    mark_run(last_run, 'github')
    _log(args.quiet, f'  Found {len(github_raw)} relevant repos')

    _log(args.quiet, '[2/2] Fetching recent CVEs from NVD...')
    nvd_raw = fetch_recent_cves(
        seen,
        last_run_iso=last_run.get('nvd'),
        min_cvss=args.min_cvss,
        max_results=args.max_results,
    )
    mark_run(last_run, 'nvd')
    _log(args.quiet, f'  Found {len(nvd_raw)} relevant CVEs')

    save_seen(seen)
    save_last_run(last_run)

    cves, pocs = merge_findings(nvd_raw, github_raw)
    links = link_pocs_to_cves(cves, pocs)

    print(render_report(cves, pocs, links, fmt=args.format), end='')

    if not args.no_save:
        path = save_report(
            render_report(cves, pocs, links, fmt='md'),
            fmt='md',
        )
        _log(args.quiet, f'  Report saved → {path}')


if __name__ == '__main__':
    main()
