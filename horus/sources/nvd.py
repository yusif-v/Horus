"""CVE source — NVD (National Vulnerability Database).

Fetches recently published CVEs from the NVD API.
"""

from __future__ import annotations
import sys
from datetime import datetime, timedelta

from ..config import NVD_LOOKBACK_DAYS, NVD_MAX_LOOKBACK_DAYS
from ..core.filters import extract_cves
from ..net.http import fetch_json


NAME = "NVD CVE Feed"
DEFAULT_ENABLED = True


def _extract_cwes(weaknesses: list) -> list[str]:
    out: set[str] = set()
    for w in weaknesses or []:
        for d in w.get("description", []):
            val = d.get("value", "")
            if val.startswith("CWE-"):
                out.add(val)
    return sorted(out)


def _extract_affected(configurations: list) -> list[dict]:
    out: dict[tuple[str, str], dict] = {}
    for cfg in configurations or []:
        for node in cfg.get("nodes", []):
            for match in node.get("cpeMatch", []):
                cpe = match.get("criteria", "")
                parts = cpe.split(":")
                if len(parts) < 6 or parts[0] != "cpe":
                    continue
                vendor, product, version = parts[3], parts[4], parts[5]
                key = (vendor, product)
                bucket = out.setdefault(key, {"vendor": vendor, "product": product, "versions": []})
                start_incl = match.get("versionStartIncluding")
                start_excl = match.get("versionStartExcluding")
                end_incl = match.get("versionEndIncluding")
                end_excl = match.get("versionEndExcluding")
                if any([start_incl, start_excl, end_incl, end_excl]):
                    lo = start_incl or start_excl
                    hi = end_incl or end_excl
                    lo_op = ">=" if start_incl else ">"
                    hi_op = "<=" if end_incl else "<"
                    parts_range = []
                    if lo: parts_range.append(f"{lo_op} {lo}")
                    if hi: parts_range.append(f"{hi_op} {hi}")
                    bucket["versions"].append(", ".join(parts_range))
                elif version not in ("*", "-", ""):
                    bucket["versions"].append(version)
    for b in out.values():
        b["versions"] = sorted(set(b["versions"]))
    return list(out.values())


def _extract_cvss(metrics: dict) -> tuple[float | None, str | None]:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if not entries:
            continue
        try:
            data = entries[0]["cvssData"]
        except (KeyError, IndexError):
            continue
        score = data.get("baseScore")
        if score is not None:
            return score, data.get("baseSeverity")
    return None, None


def _resolve_start(now: datetime, last_run_iso: str | None) -> datetime:
    default_start = now - timedelta(days=NVD_LOOKBACK_DAYS)
    if not last_run_iso:
        return default_start
    try:
        last = datetime.strptime(last_run_iso, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return default_start
    candidate = last - timedelta(hours=6)
    floor = now - timedelta(days=NVD_MAX_LOOKBACK_DAYS)
    return max(candidate, floor)


def run(ctx) -> dict:
    """Fetch recent CVEs from NVD. Returns {"cves": [dict], "pocs": []}."""
    now = datetime.utcnow()
    start = _resolve_start(now, ctx.last_run).strftime("%Y-%m-%dT%H:%M:%S.000")
    end = now.strftime("%Y-%m-%dT%H:%M:%S.000")

    results = []
    seen_this_run: set[str] = set()
    results_per_page = 50
    max_pages = 20  # safety cap: 1000 CVEs max per run
    total_results = None

    for page in range(max_pages):
        url = (
            f"https://services.nvd.nist.gov/rest/json/cves/2.0"
            f"?pubStartDate={start}&pubEndDate={end}"
            f"&resultsPerPage={results_per_page}"
            f"&startIndex={page * results_per_page}"
        )

        try:
            data = fetch_json(url)
        except Exception as e:
            print(f"  [WARN] NVD fetch failed (page {page}): {e}", file=sys.stderr)
            break

        if page == 0:
            total_results = data.get("totalResults", 0)

        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            break

        for item in vulnerabilities:
            cve = item.get("cve", {})
            cve_id = cve.get("id", "Unknown")

            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break

            score, severity = _extract_cvss(cve.get("metrics", {}))

            if ctx.min_cvss is not None and (score is None or score < ctx.min_cvss):
                continue

            if cve_id in ctx.known_cve_ids or cve_id in seen_this_run:
                continue
            seen_this_run.add(cve_id)

            published_iso = cve.get("published")
            published_at = None
            if published_iso:
                try:
                    published_at = datetime.strptime(published_iso[:19], "%Y-%m-%dT%H:%M:%S")
                except ValueError:
                    pass

            results.append({
                "source": "NVD",
                "cve": cve_id,
                "description": desc[:300],
                "cvss_score": score,
                "severity": severity,
                "cwe_ids": _extract_cwes(cve.get("weaknesses", [])),
                "affected": _extract_affected(cve.get("configurations", [])),
                "published_at": published_at,
            })

        # Check if we've fetched all results
        fetched = (page + 1) * results_per_page
        if total_results is not None and fetched >= total_results:
            break

    results.sort(key=lambda x: x.get("cvss_score") or 0, reverse=True)
    if ctx.max_results is not None:
        results = results[: ctx.max_results]

    from ..core.merge import cve_from_nvd
    cves = [cve_from_nvd(r) for r in results]
    return {"cves": cves, "pocs": []}
