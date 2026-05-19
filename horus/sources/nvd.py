"""NVD CVE feed source."""

import sys
from datetime import datetime, timedelta

from ..config import NVD_LOOKBACK_DAYS
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


def fetch_recent_cves(seen: set[str]) -> list[dict]:
    """Fetch recently published CVEs from NVD that mention a PoC.

    Mutates `seen` to include newly-reported keys.
    """
    today = datetime.utcnow()
    start = (today - timedelta(days=NVD_LOOKBACK_DAYS)).strftime('%Y-%m-%dT%H:%M:%S.000')
    end = today.strftime('%Y-%m-%dT%H:%M:%S.000')

    url = (
        f'https://services.nvd.nist.gov/rest/json/cves/2.0'
        f'?pubStartDate={start}&pubEndDate={end}&resultsPerPage=20'
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

        key = f'nvd:{cve_id}'
        if key in seen:
            continue
        seen.add(key)

        score, severity = _extract_cvss(cve.get('metrics', {}))

        results.append({
            'source': 'NVD',
            'cve': cve_id,
            'description': desc[:300],
            'cvss_score': score,
            'severity': severity,
        })

    return results
