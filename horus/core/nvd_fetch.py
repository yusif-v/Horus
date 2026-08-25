"""Fetch individual CVEs from NVD by ID.

Used when we discover a CVE reference in a PoC or other source and need to
verify it exists in NVD + create a stub CVE record.
"""

from __future__ import annotations

import contextlib
import json
import sys
import urllib.request
from datetime import datetime
from typing import Any

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def fetch_cve_by_id(cve_id: str) -> dict[str, Any] | None:
    """Fetch a single CVE from NVD by its ID.

    Returns a dict suitable for parse_nvd_cve(), or None if the CVE doesn't
    exist or the API fails.
    """
    url = f"{NVD_API_BASE}?cveId={cve_id.upper()}"
    try:
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "Mozilla/5.0 (compatible; Horus-PoC-Scanner)")
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
    except Exception as e:
        print(f"  [WARN] NVD fetch failed for {cve_id}: {e}", file=sys.stderr)
        return None

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return None

    cve = vulns[0].get("cve")
    return cve if isinstance(cve, dict) else None


def parse_nvd_cve(raw: dict[str, Any]) -> dict[str, Any] | None:
    """Parse a raw NVD CVE dict into our internal format.

    Returns dict with: id, description, cvss_score, severity, published_at,
    cwe_ids, affected. Returns None if parsing fails.
    """
    try:
        cve_id = raw.get("id")
        if not cve_id:
            return None

        # Extract description (prefer English)
        descriptions = raw.get("descriptions", [])
        desc = ""
        for d in descriptions:
            if d.get("lang") == "en":
                desc = d.get("value", "")[:300]
                break
        if not desc:
            desc = descriptions[0].get("value", "")[:300] if descriptions else ""

        # Extract CVSS score (prefer v3, fall back to v2)
        metrics = raw.get("metrics", {})
        cvss_score = None
        severity = None

        cvss3 = metrics.get("cvssMetricV31", []) or metrics.get("cvssMetricV30", [])
        if cvss3:
            cvss_data = cvss3[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            severity = cvss_data.get("baseSeverity", "").upper()
        else:
            cvss2 = metrics.get("cvssMetricV2", [])
            if cvss2:
                cvss_data = cvss2[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                if cvss_score is not None:
                    if cvss_score >= 7.0:
                        severity = "HIGH"
                    elif cvss_score >= 4.0:
                        severity = "MEDIUM"
                    else:
                        severity = "LOW"

        # Extract CWE IDs
        cwe_ids = []
        weaknesses = raw.get("weaknesses", [])
        for w in weaknesses:
            for d in w.get("description", []):
                if d.get("lang") == "en":
                    val = d.get("value", "")
                    if val.startswith("CWE-"):
                        cwe_ids.append(val)

        # Extract published date
        published_at = None
        published_iso = raw.get("published")
        if published_iso:
            with contextlib.suppress(ValueError, TypeError):
                published_at = datetime.fromisoformat(published_iso.replace("Z", "+00:00"))

        # Extract affected products from configurations
        affected: list[dict[str, Any]] = []
        configs = raw.get("configurations", [])
        for config in configs:
            for node in config.get("nodes", []):
                for cpe in node.get("cpeMatch", []):
                    if cpe.get("vulnerable"):
                        criteria = cpe.get("criteria", "")
                        parts = criteria.split(":")
                        if len(parts) >= 5:
                            vendor = parts[3] if parts[3] != "*" else "unknown"
                            product = parts[4] if parts[4] != "*" else "unknown"
                            if vendor != "unknown" or product != "unknown":
                                from .classify import classify_product_category

                                affected.append(
                                    {
                                        "vendor": vendor,
                                        "product": product,
                                        "versions": [],
                                        "category": classify_product_category(vendor, product),
                                    }
                                )

        return {
            "source": "NVD",
            "cve": cve_id,
            "description": desc,
            "cvss_score": cvss_score,
            "severity": severity,
            "cwe_ids": cwe_ids,
            "affected": affected,
            "published_at": published_at,
        }
    except Exception as e:
        print(f"  [WARN] Failed to parse NVD CVE {raw.get('id', '?')}: {e}", file=sys.stderr)
        return None
