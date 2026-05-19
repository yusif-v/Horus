"""NVD CVE feed source."""

import sys
from datetime import datetime, timedelta

from ..config import NVD_LOOKBACK_DAYS, NVD_MAX_LOOKBACK_DAYS
from ..filters import is_fresh_poc
from ..http import fetch_json


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
    seen: set[str],
    last_run_iso: str | None = None,
    min_cvss: float | None = None,
    max_results: int | None = None,
) -> list[dict]:
    """Fetch recently published CVEs from NVD that mention a PoC.

    Mutates `seen` to include newly-reported keys.
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

        key = f'nvd:{cve_id}'
        if key in seen:
            continue
        seen.add(key)

        results.append({
            'source': 'NVD',
            'cve': cve_id,
            'description': desc[:300],
            'cvss_score': score,
            'severity': severity,
        })

    results.sort(key=lambda x: x.get('cvss_score') or 0, reverse=True)
    if max_results is not None:
        results = results[:max_results]
    return results
