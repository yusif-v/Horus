"""CLI entry point."""

from .report import print_report
from .sources.github import search_github
from .sources.nvd import fetch_recent_cves
from .state import load_seen, save_seen


def main() -> None:
    seen = load_seen()

    print('[1/2] Searching GitHub for new PoC repos...')
    gh_results = search_github(seen)
    print(f'  Found {len(gh_results)} relevant repos')

    print('[2/2] Fetching recent CVEs from NVD...')
    nvd_results = fetch_recent_cves(seen)
    print(f'  Found {len(nvd_results)} relevant CVEs')

    save_seen(seen)
    print_report(gh_results + nvd_results)


if __name__ == '__main__':
    main()
