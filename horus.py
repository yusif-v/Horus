#!/usr/bin/env python3
"""
Horus — Daily PoC Research Scanner
Version: 0.1.0

Searches GitHub and NVD for new vulnerability disclosures with proof-of-concept exploits.
Runs as a daily cron job, outputs findings to stdout (delivered via cron).
"""

__version__ = "0.1.0"

import json
import re
import subprocess
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timedelta
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# GitHub search queries for PoC repos — focused on recent, high-value targets
GITHUB_QUERIES = [
    'CVE-2026 exploit poc',
    'CVE-2025 exploit poc',
    '0day exploit github',
    'RCE PoC CVE',
    'vulnerability exploit proof-of-concept',
]

# Keywords that indicate a FRESH/RELEVANT PoC (not just another CVE list repo)
FRESH_POC_KEYWORDS = [
    'poc', 'exploit', 'proof of concept', 'proof-of-concept', 'rce',
    'remote code execution', '0day', 'zero-day', 'lpe', 'privilege escalation',
    'sql injection', 'xss', 'csrf', 'ssrf', 'rce', 'arbitrary code',
    'command injection', 'file inclusion', 'deserialization', 'buffer overflow',
    'use-after-free', 'heap overflow', 'sandbox escape', 'kernel',
]

# Keywords that indicate OLD/LOW-VALUE repos (CVE lists, archives, etc.)
LOW_VALUE_KEYWORDS = [
    'awesome', 'collection', 'list', 'archive', 'database', 'knowledge base',
    'cve list', 'cve database', 'vulnerability database', 'security advisories',
    'weekly digest', 'daily digest', 'newsletter', 'curated list',
]

# Output file for deduplication
STATE_DIR = Path(__file__).parent / 'state'
STATE_FILE = STATE_DIR / 'seen_items.json'

# Only report repos created in the last 30 days
MAX_REPO_AGE_DAYS = 30

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_seen() -> set:
    if STATE_FILE.exists():
        try:
            return set(json.loads(STATE_FILE.read_text()))
        except Exception:
            return set()
    return set()


def save_seen(seen: set):
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(list(seen)))


def is_fresh_poc(text: str) -> bool:
    """Check if text describes a fresh PoC, not just a CVE list."""
    text_lower = text.lower()

    # Exclude low-value repos
    for kw in LOW_VALUE_KEYWORDS:
        if kw in text_lower:
            return False

    # Must contain at least one fresh PoC keyword
    return any(kw in text_lower for kw in FRESH_POC_KEYWORDS)


def extract_cves(text: str) -> list:
    return list(set(re.findall(r'CVE-\d{4}-\d{4,}', text, re.IGNORECASE)))


def extract_github_links(text: str) -> list:
    links = re.findall(r'https?://(?:github|gitlab)\.com/[^\s\)"<>]+', text)
    return list(set(links))


# ---------------------------------------------------------------------------
# GitHub Search (via GitHub API — free, no auth for public repos)
# ---------------------------------------------------------------------------

def search_github() -> list[dict]:
    """Search GitHub for new PoC/exploit repositories."""
    results = []
    seen = load_seen()

    for query in GITHUB_QUERIES:
        encoded = urllib.parse.quote(query)
        url = f'https://api.github.com/search/repositories?q={encoded}&sort=created&order=desc&per_page=15'

        try:
            req = urllib.request.Request(url, headers={
                'User-Agent': 'Mozilla/5.0 (compatible; PoC-Research/1.0)',
                'Accept': 'application/vnd.github.v3+json',
            })
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read())

            for item in data.get('items', []):
                repo_name = item.get('full_name', '')
                description = item.get('description', '') or ''
                repo_url = item.get('html_url', '')
                created_at = item.get('created_at', '')
                stars = item.get('stargazers_count', 0)

                # Skip repos older than MAX_REPO_AGE_DAYS
                if created_at:
                    try:
                        created_date = datetime.strptime(created_at, '%Y-%m-%dT%H:%M:%SZ')
                        age_days = (datetime.utcnow() - created_date).days
                        if age_days > MAX_REPO_AGE_DAYS:
                            continue
                    except ValueError:
                        pass

                # Skip repos with too few stars (likely low quality)
                if stars < 10:
                    continue

                # Must be a fresh PoC, not a CVE list
                combined_text = f'{repo_name} {description}'
                if not is_fresh_poc(combined_text):
                    continue

                item_key = f'github:{repo_name}'
                if item_key in seen:
                    continue
                seen.add(item_key)

                cves = extract_cves(combined_text)

                results.append({
                    'source': 'GitHub',
                    'repo': repo_name,
                    'url': repo_url,
                    'description': description[:300],
                    'cves': cves,
                    'stars': stars,
                    'created': created_at[:10] if created_at else '',
                    'age_days': age_days if created_at else 0,
                })
        except Exception as e:
            print(f'  [WARN] GitHub search failed for "{query}": {e}', file=sys.stderr)

    return results


# ---------------------------------------------------------------------------
# NVD / CVE Feed (free, no auth)
# ---------------------------------------------------------------------------

def fetch_recent_cves() -> list[dict]:
    """Fetch recently published CVEs from NVD."""
    results = []

    today = datetime.utcnow()
    yesterday = today - timedelta(days=2)  # 2-day window to catch stragglers

    start_date = yesterday.strftime('%Y-%m-%dT%H:%M:%S.000')
    end_date = today.strftime('%Y-%m-%dT%H:%M:%S.000')

    url = (
        f'https://services.nvd.nist.gov/rest/json/cves/2.0'
        f'?pubStartDate={start_date}&pubEndDate={end_date}'
        f'&resultsPerPage=20'
    )

    try:
        req = urllib.request.Request(url, headers={
            'User-Agent': 'Mozilla/5.0 (compatible; PoC-Research/1.0)',
        })
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())

        seen = load_seen()
        for item in data.get('vulnerabilities', []):
            cve = item.get('cve', {})
            cve_id = cve.get('id', 'Unknown')
            desc = ''
            for d in cve.get('descriptions', []):
                if d.get('lang') == 'en':
                    desc = d.get('value', '')
                    break

            # Only include if it mentions PoC/exploit
            if not is_fresh_poc(desc):
                continue

            item_key = f'nvd:{cve_id}'
            if item_key in seen:
                continue
            seen.add(item_key)

            # Extract CVSS score
            metrics = cve.get('metrics', {})
            cvss_score = None
            severity = None
            for metric_key in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                if metric_key in metrics:
                    try:
                        cvss_data = metrics[metric_key][0]['cvssData']
                        cvss_score = cvss_data.get('baseScore')
                        severity = cvss_data.get('baseSeverity')
                    except (KeyError, IndexError):
                        pass
                    if cvss_score:
                        break

            results.append({
                'source': 'NVD',
                'cve': cve_id,
                'description': desc[:300],
                'cvss_score': cvss_score,
                'severity': severity,
            })
    except Exception as e:
        print(f'  [WARN] NVD fetch failed: {e}', file=sys.stderr)

    return results


# ---------------------------------------------------------------------------
# X / Twitter via xurl (if available)
# ---------------------------------------------------------------------------

def search_x_via_xurl() -> list[dict]:
    """Search X for PoC disclosures using xurl CLI (requires setup)."""
    results = []
    seen = load_seen()

    # Check if xurl is available
    try:
        subprocess.run(['xurl', '--help'], capture_output=True, timeout=5)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return results  # xurl not installed, skip

    X_QUERIES = [
        '(CVE OR cve) (github.com OR gitlab.com) (exploit OR poc OR PoC) -is:retweet',
        '0day (github.com OR gitlab.com) exploit -is:retweet',
        'RCE (github.com OR gitlab.com) (CVE OR disclosed) -is:retweet',
    ]

    for query in X_QUERIES:
        try:
            proc = subprocess.run(
                ['xurl', 'search', query, '-n', '10'],
                capture_output=True, text=True, timeout=30
            )
            if proc.returncode != 0:
                continue

            data = json.loads(proc.stdout)
            tweets = data if isinstance(data, list) else data.get('data', data.get('tweets', []))

            for tweet in tweets:
                text = tweet.get('text', tweet.get('full_text', ''))
                tweet_id = tweet.get('id', tweet.get('id_str', ''))

                if not text or len(text) < 20:
                    continue
                if not is_fresh_poc(text):
                    continue

                item_key = f'x:{tweet_id}'
                if item_key in seen:
                    continue
                seen.add(item_key)

                cves = extract_cves(text)
                gh_links = extract_github_links(text)

                if cves or gh_links:
                    results.append({
                        'source': 'X/Twitter',
                        'text': text[:300],
                        'cves': cves,
                        'github_links': list(set(gh_links))[:5],
                        'tweet_id': tweet_id,
                    })
        except Exception as e:
            print(f'  [WARN] xurl search failed: {e}', file=sys.stderr)

    return results


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    today = datetime.now().strftime('%Y-%m-%d')
    print(f'=== Daily PoC Research Report — {today} ===')
    print()

    all_results = []

    # 1. Search GitHub
    print('[1/2] Searching GitHub for new PoC repos...')
    gh_results = search_github()
    all_results.extend(gh_results)
    print(f'  Found {len(gh_results)} relevant repos')

    # 2. Fetch recent CVEs from NVD
    print('[2/2] Fetching recent CVEs from NVD...')
    nvd_results = fetch_recent_cves()
    all_results.extend(nvd_results)
    print(f'  Found {len(nvd_results)} relevant CVEs')

    # 3. Optionally search X via xurl (if configured with paid API)
    print('[*/2] Checking for xurl (X/Twitter search)...')
    x_results = search_x_via_xurl()
    if x_results:
        all_results.extend(x_results)
        print(f'  Found {len(x_results)} relevant tweets')
    else:
        print('  xurl not configured — skipping X search')
        print('  (X API is now pay-per-use; GitHub + NVD provide good coverage)')

    # Save seen items
    save_seen(load_seen())

    # Output report
    print()
    print('=' * 60)
    print(f'RESULTS: {len(all_results)} new items found')
    print('=' * 60)

    if not all_results:
        print()
        print('No new PoC disclosures found today.')
        return

    # Group by source
    x_items = [r for r in all_results if r['source'] == 'X/Twitter']
    gh_items = [r for r in all_results if r['source'] == 'GitHub']
    nvd_items = [r for r in all_results if r['source'] == 'NVD']

    # Sort GitHub by stars (highest first)
    gh_items.sort(key=lambda x: x.get('stars', 0), reverse=True)

    # Sort NVD by CVSS score (highest first)
    nvd_items.sort(key=lambda x: x.get('cvss_score') or 0, reverse=True)

    if x_items:
        print()
        print('--- X / Twitter ---')
        for i, item in enumerate(x_items, 1):
            print(f'\n[{i}] {item["text"][:200]}')
            if item.get('cves'):
                print(f'    CVEs: {", ".join(item["cves"])}')
            if item.get('github_links'):
                for link in item['github_links'][:3]:
                    print(f'    PoC: {link}')

    if gh_items:
        print()
        print('--- GitHub Repos (new PoCs) ---')
        for i, item in enumerate(gh_items, 1):
            cve_str = f' | CVEs: {", ".join(item["cves"])}' if item.get('cves') else ''
            print(f'\n[{i}] {item["repo"]} ({item.get("stars", 0)} stars, {item.get("age_days", 0)}d old{cve_str})')
            print(f'    {item["url"]}')
            print(f'    {item["description"][:200]}')

    if nvd_items:
        print()
        print('--- Recent CVEs (NVD) ---')
        for i, item in enumerate(nvd_items, 1):
            score_str = f' [CVSS: {item["cvss_score"]} {item.get("severity", "")}]' if item.get('cvss_score') else ''
            print(f'\n[{i}] {item["cve"]}{score_str}')
            print(f'    {item["description"][:200]}')

    print()
    print('=' * 60)
    print(f'Total: {len(all_results)} items | X: {len(x_items)} | GitHub: {len(gh_items)} | NVD: {len(nvd_items)}')
    print('=' * 60)


if __name__ == '__main__':
    main()
