"""CLI entry point."""

import argparse
import sys

from . import __version__
from .report import print_report
from .sources.github import search_github
from .sources.nvd import fetch_recent_cves
from .state import load_last_run, load_seen, mark_run, save_last_run, save_seen


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
    return p


def _log(quiet: bool, msg: str) -> None:
    if not quiet:
        print(msg, file=sys.stderr)


def main(argv: list[str] | None = None) -> None:
    args = _build_parser().parse_args(argv)

    seen = load_seen()
    last_run = load_last_run()

    _log(args.quiet, '[1/2] Searching GitHub for new PoC repos...')
    gh_results = search_github(seen, max_results=args.max_results)
    mark_run(last_run, 'github')
    _log(args.quiet, f'  Found {len(gh_results)} relevant repos')

    _log(args.quiet, '[2/2] Fetching recent CVEs from NVD...')
    nvd_results = fetch_recent_cves(
        seen,
        last_run_iso=last_run.get('nvd'),
        min_cvss=args.min_cvss,
        max_results=args.max_results,
    )
    mark_run(last_run, 'nvd')
    _log(args.quiet, f'  Found {len(nvd_results)} relevant CVEs')

    save_seen(seen)
    save_last_run(last_run)
    print_report(gh_results + nvd_results, fmt=args.format)


if __name__ == '__main__':
    main()
