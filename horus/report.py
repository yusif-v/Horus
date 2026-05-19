"""Human-readable report formatting."""

from datetime import datetime


def _print_github(items: list[dict]) -> None:
    print()
    print('--- GitHub Repos (new PoCs) ---')
    for i, item in enumerate(items, 1):
        cve_str = f' | CVEs: {", ".join(item["cves"])}' if item.get('cves') else ''
        print(
            f'\n[{i}] {item["repo"]} '
            f'({item.get("stars", 0)} stars, {item.get("age_days", 0)}d old{cve_str})'
        )
        print(f'    {item["url"]}')
        print(f'    {item["description"][:200]}')


def _print_nvd(items: list[dict]) -> None:
    print()
    print('--- Recent CVEs (NVD) ---')
    for i, item in enumerate(items, 1):
        score = item.get('cvss_score')
        score_str = f' [CVSS: {score} {item.get("severity", "")}]' if score else ''
        print(f'\n[{i}] {item["cve"]}{score_str}')
        print(f'    {item["description"][:200]}')


def print_report(results: list[dict]) -> None:
    today = datetime.now().strftime('%Y-%m-%d')
    print(f'=== Daily PoC Research Report — {today} ===')
    print()
    print('=' * 60)
    print(f'RESULTS: {len(results)} new items found')
    print('=' * 60)

    if not results:
        print()
        print('No new PoC disclosures found today.')
        return

    gh_items = sorted(
        (r for r in results if r['source'] == 'GitHub'),
        key=lambda x: x.get('stars', 0), reverse=True,
    )
    nvd_items = sorted(
        (r for r in results if r['source'] == 'NVD'),
        key=lambda x: x.get('cvss_score') or 0, reverse=True,
    )

    if gh_items:
        _print_github(gh_items)
    if nvd_items:
        _print_nvd(nvd_items)

    print()
    print('=' * 60)
    print(f'Total: {len(results)} items | GitHub: {len(gh_items)} | NVD: {len(nvd_items)}')
    print('=' * 60)
