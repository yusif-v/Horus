"""NVD CVE feed source."""

import sys
from datetime import datetime, timedelta

from ..config import NVD_LOOKBACK_DAYS, NVD_MAX_LOOKBACK_DAYS
from ..core.filters import is_fresh_poc
from .http import fetch_json


def _extract_cwes(weaknesses: list) -> list[str]:
    out: set[str] = set()
    for w in weaknesses or []:
        for d in w.get('description', []):
            val = d.get('value', '')
            if val.startswith('CWE-'):
                out.add(val)
    return sorted(out)


def _extract_affected(configurations: list) -> list[dict]:
    """Pull vendor/product/version-range triples from CPE 2.3 entries.

    A CPE URI looks like: cpe:2.3:a:nginx:nginx:1.25.2:*:*:*:*:*:*:*
                                  ^  ^      ^      ^
                                  |  vendor product version
                                  part
    """
    out: dict[tuple[str, str], dict] = {}
    for cfg in configurations or []:
        for node in cfg.get('nodes', []):
            for match in node.get('cpeMatch', []):
                cpe = match.get('criteria', '')
                parts = cpe.split(':')
                if len(parts) < 6 or parts[0] != 'cpe':
                    continue
                vendor, product, version = parts[3], parts[4], parts[5]
                key = (vendor, product)
                bucket = out.setdefault(key, {
                    'vendor': vendor, 'product': product, 'versions': [],
                })
                # Prefer the explicit range fields over the version slot.
                start_incl = match.get('versionStartIncluding')
                start_excl = match.get('versionStartExcluding')
                end_incl = match.get('versionEndIncluding')
                end_excl = match.get('versionEndExcluding')
                if any([start_incl, start_excl, end_incl, end_excl]):
                    lo = start_incl or start_excl
                    hi = end_incl or end_excl
                    lo_op = '>=' if start_incl else '>'
                    hi_op = '<=' if end_incl else '<'
                    parts_range = []
                    if lo:
                        parts_range.append(f'{lo_op} {lo}')
                    if hi:
                        parts_range.append(f'{hi_op} {hi}')
                    bucket['versions'].append(', '.join(parts_range))
                elif version not in ('*', '-', ''):
                    bucket['versions'].append(version)
    # Dedupe versions per entry
    for b in out.values():
        b['versions'] = sorted(set(b['versions']))
    return list(out.values())


def _extract_cvss(metrics: dict) -> tuple[float | None, str | None]:
    for key in ('cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
        entries = metrics.get(key)
        if not entries:
            continue
        try:
            data = entries[0]['cvssData']
        except (KeyError, IndexError):
            continue
        score = data.get('baseScore')
        if score is not None:
            return score, data.get('baseSeverity')
    return None, None


def _resolve_start(now: datetime, last_run_iso: str | None) -> datetime:
    """Pick an adaptive lookback window based on last successful run."""
    default_start = now - timedelta(days=NVD_LOOKBACK_DAYS)
    if not last_run_iso:
        return default_start
    try:
        last = datetime.strptime(last_run_iso, '%Y-%m-%dT%H:%M:%SZ')
    except ValueError:
        return default_start
    # Pull a little earlier than last run to catch stragglers, but cap it.
    candidate = last - timedelta(hours=6)
    floor = now - timedelta(days=NVD_MAX_LOOKBACK_DAYS)
    return max(candidate, floor)


def fetch_recent_cves(
    known_cve_ids: set[str],
    last_run_iso: str | None = None,
    min_cvss: float | None = None,
    max_results: int | None = None,
) -> list[dict]:
    """Fetch recently published CVEs from NVD that mention a PoC.

    Mutates `known_cve_ids` to include every CVE we report this run.
    """
    now = datetime.utcnow()
    start = _resolve_start(now, last_run_iso).strftime('%Y-%m-%dT%H:%M:%S.000')
    end = now.strftime('%Y-%m-%dT%H:%M:%S.000')

    url = (
        f'https://services.nvd.nist.gov/rest/json/cves/2.0'
        f'?pubStartDate={start}&pubEndDate={end}&resultsPerPage=50'
    )

    try:
        data = fetch_json(url)
    except Exception as e:
        print(f'  [WARN] NVD fetch failed: {e}', file=sys.stderr)
        return []

    results: list[dict] = []
    for item in data.get('vulnerabilities', []):
        cve = item.get('cve', {})
        cve_id = cve.get('id', 'Unknown')

        desc = ''
        for d in cve.get('descriptions', []):
            if d.get('lang') == 'en':
                desc = d.get('value', '')
                break

        if not is_fresh_poc(desc):
            continue

        score, severity = _extract_cvss(cve.get('metrics', {}))

        if min_cvss is not None and (score is None or score < min_cvss):
            continue

        if cve_id in known_cve_ids:
            continue
        known_cve_ids.add(cve_id)

        published_iso = cve.get('published')
        published_at = None
        if published_iso:
            try:
                published_at = datetime.strptime(
                    published_iso[:19], '%Y-%m-%dT%H:%M:%S',
                )
            except ValueError:
                pass

        results.append({
            'source': 'NVD',
            'cve': cve_id,
            'description': desc[:300],
            'cvss_score': score,
            'severity': severity,
            'cwe_ids': _extract_cwes(cve.get('weaknesses', [])),
            'affected': _extract_affected(cve.get('configurations', [])),
            'published_at': published_at,
        })

    results.sort(key=lambda x: x.get('cvss_score') or 0, reverse=True)
    if max_results is not None:
        results = results[:max_results]
    return results
