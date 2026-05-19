"""Human-readable report formatting (text + markdown)."""

from datetime import datetime


def _split(results: list[dict]) -> tuple[list[dict], list[dict]]:
    gh = sorted(
        (r for r in results if r['source'] == 'GitHub'),
        key=lambda x: x.get('stars', 0), reverse=True,
    )
    nvd = sorted(
        (r for r in results if r['source'] == 'NVD'),
        key=lambda x: x.get('cvss_score') or 0, reverse=True,
    )
    return gh, nvd


# ---------------------------------------------------------------------------
# Plain text
# ---------------------------------------------------------------------------

def _text_github(items: list[dict]) -> None:
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


def _text_nvd(items: list[dict]) -> None:
    print()
    print('--- Recent CVEs (NVD) ---')
    for i, item in enumerate(items, 1):
        score = item.get('cvss_score')
        score_str = f' [CVSS: {score} {item.get("severity", "")}]' if score else ''
        print(f'\n[{i}] {item["cve"]}{score_str}')
        print(f'    {item["description"][:200]}')


def _render_text(results: list[dict]) -> None:
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

    gh, nvd = _split(results)
    if gh:
        _text_github(gh)
    if nvd:
        _text_nvd(nvd)

    print()
    print('=' * 60)
    print(f'Total: {len(results)} items | GitHub: {len(gh)} | NVD: {len(nvd)}')
    print('=' * 60)


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------

def _md_github(items: list[dict]) -> None:
    print('\n## GitHub Repos (new PoCs)\n')
    for item in items:
        cve_str = f' — CVEs: {", ".join(item["cves"])}' if item.get('cves') else ''
        print(
            f'- **[{item["repo"]}]({item["url"]})** '
            f'· {item.get("stars", 0)}★ · {item.get("age_days", 0)}d old{cve_str}'
        )
        desc = item.get('description', '').strip()
        if desc:
            print(f'  > {desc[:200]}')


def _md_nvd(items: list[dict]) -> None:
    print('\n## Recent CVEs (NVD)\n')
    for item in items:
        score = item.get('cvss_score')
        score_str = f' · **CVSS {score} {item.get("severity", "")}**' if score else ''
        print(f'- **{item["cve"]}**{score_str}')
        desc = item.get('description', '').strip()
        if desc:
            print(f'  > {desc[:200]}')


def _render_markdown(results: list[dict]) -> None:
    today = datetime.now().strftime('%Y-%m-%d')
    print(f'# Daily PoC Research Report — {today}\n')

    if not results:
        print('_No new PoC disclosures found today._')
        return

    gh, nvd = _split(results)
    print(f'**Total:** {len(results)} items · GitHub: {len(gh)} · NVD: {len(nvd)}')

    if gh:
        _md_github(gh)
    if nvd:
        _md_nvd(nvd)


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

def print_report(results: list[dict], fmt: str = 'text') -> None:
    if fmt == 'md':
        _render_markdown(results)
    else:
        _render_text(results)
