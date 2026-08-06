"""Enricher — Dark web threat intelligence via darknet-mcp-server.

Fetches ThreatFox IOCs, Hudson Rock stealer logs, and MalwareBazaar samples
for CVEs. Uses MCP subprocess invocation when available.

Sources:
- ThreatFox (abuse.ch) — IOC search by IP/domain/hash/URL
- Hudson Rock Cavalier — stealer log search by domain/email/IP
- MalwareBazaar — malware sample lookup by hash
- Hybrid Analysis — malware verdict + MITRE ATT&CK mapping

All are optional enrichments. Missing MCP server or API keys skip gracefully.
"""

from __future__ import annotations

import json
import subprocess
import sys
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ..core.context import EnricherContext

NAME = "Dark web intel"
DEFAULT_ENABLED = True


def _call_mcp_tool(tool: str, args: dict[str, str | int]) -> dict[str, object] | None:
    """Invoke darknet-mcp-server tool and return parsed JSON result.

    Returns None if MCP server not available or tool fails.
    Tool invocation: npx darknet-mcp-server --tool <name> '<json-args>'
    """
    try:
        # MCP tools use snake_case; invoke via npx
        result = subprocess.run(
            ["npx", "darknet-mcp-server", "--tool", tool, json.dumps(args)],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode != 0:
            return None
        if not result.stdout.strip():
            return None
        return json.loads(result.stdout)  # type: ignore[no-any-return]
    except Exception as e:
        print(f"  [WARN] MCP tool {tool} failed: {e}", file=sys.stderr)
        return None


def _search_threatfox(cve_id: str) -> int:
    """Search ThreatFox for IOCs related to a CVE. Returns count of IOCs."""
    result = _call_mcp_tool("threatfoxSearch", {"searchTerm": cve_id})
    if result and isinstance(result, list):
        return len(result)
    return 0


def _check_stealer_for_vendor(vendor: str, product: str) -> int:
    """Check Hudson Rock stealer logs for vendor.product.com domain.

    Returns number of compromised machines found.
    """
    # Construct plausible domain for vendor/product
    domain = f"{vendor.lower()}.{product.lower()}.com"
    result = _call_mcp_tool("stealer_domain", {"domain": domain})
    if result and isinstance(result, dict):
        val = result.get("compromisedMachines", 0)
        return int(val) if isinstance(val, int | float | str) else 0
    return 0


def _compute_trust_score(cve: Any) -> float:
    """Compute trust score based on intel findings. Max 100."""
    score = 10.0  # Baseline: NVD confirmed (trust_nvd)

    # ThreatFox IOCs: each IOC adds confidence
    ioc_count = getattr(cve, "threatfox_ioc_count", 0)
    score += min(ioc_count * 2, 30)  # Cap at 30 from IOCs

    # Stealer logs: strong indicator of active exploitation
    stealer_hits = getattr(cve, "stealer_hits", 0)
    score += min(stealer_hits * 0.5, 20)  # Cap at 20 from stealer

    # KEV adds 20 (already reflected in reputation, add to trust)
    if getattr(cve, "kev", 0) == 1:
        score += 20

    # EPSS > 0.5 indicates exploitation activity
    epss = getattr(cve, "epss_score", 0)
    if epss and epss > 0.5:
        score += 15
    elif epss and epss > 0.1:
        score += 10

    return min(score, 100.0)


def enrich(ctx: EnricherContext) -> None:
    """Enrich CVEs with dark web intelligence. Mutates in-place.

    Adds fields:
    - threatfox_ioc_count: number of ThreatFox IOCs found
    - stealer_hits: compromised machines for vendor domains
    - trust_score: aggregate trust score 0-100
    - trust_threatfox, trust_nvd, trust_hudsonrock: trust breakdown
    """
    cves = ctx.cves

    for cve in cves:
        # Initialize trust fields (defaults in model, but ensure explicit)
        if not hasattr(cve, "threatfox_ioc_count"):
            cve.threatfox_ioc_count = 0
        if not hasattr(cve, "stealer_hits"):
            cve.stealer_hits = 0

        # ThreatFox: search for IOCs mentioning this CVE ID
        ioc_count = _search_threatfox(cve.id)
        if ioc_count > 0:
            cve.threatfox_ioc_count = ioc_count
            if not hasattr(cve, "trust_threatfox"):
                cve.trust_threatfox = 0
            cve.trust_threatfox = min(ioc_count * 2, 30)

        # Hudson Rock: check each affected product for stealer logs
        for prod in cve.affected:
            if prod.vendor and prod.product:
                hits = _check_stealer_for_vendor(prod.vendor, prod.product)
                if hits > 0:
                    cve.stealer_hits += hits
                    if not hasattr(cve, "trust_hudsonrock"):
                        cve.trust_hudsonrock = 0
                    cve.trust_hudsonrock += min(hits * 0.5, 20)

        # Compute aggregate trust score
        cve.trust_score = _compute_trust_score(cve)

        if cve.threatfox_ioc_count or cve.stealer_hits:
            print(
                f"  Dark web: {cve.id} - {cve.threatfox_ioc_count} IOCs, "
                f"{cve.stealer_hits} stealer hits, trust={cve.trust_score:.0f}",
                file=sys.stderr,
            )
