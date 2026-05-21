"""Fold raw source records into typed CVE and PoC objects.

The two source modules still return plain dicts (so the wire format stays
inspectable). This layer is the single place that knows how to turn those
dicts into the domain model defined in `horus.model`.
"""

from datetime import datetime

from .classify import classify_attack_tags, classify_product_category
from .filters import extract_cves
from .model import CVE, AffectedProduct, PoC


def cve_from_nvd(raw: dict) -> CVE:
    """Build a CVE from one NVD result dict (see sources/nvd.py)."""
    desc = raw.get('description', '')
    cwes = raw.get('cwe_ids', [])  # nvd source may attach these in v0.4+
    category = classify_product_category(desc)

    affected: list[AffectedProduct] = []
    for ap in raw.get('affected', []):
        affected.append(AffectedProduct(
            vendor=ap.get('vendor', 'unknown'),
            product=ap.get('product', 'unknown'),
            versions=list(ap.get('versions', [])),
            category=classify_product_category(ap.get('vendor', ''), ap.get('product', '')),
        ))
    if not affected and category != 'unknown':
        affected.append(AffectedProduct(
            vendor='unknown', product='unknown', category=category,
        ))

    now = datetime.utcnow()
    return CVE(
        id=raw['cve'],
        description=desc,
        cvss_score=raw.get('cvss_score'),
        cvss_severity=raw.get('severity'),
        published_at=raw.get('published_at'),
        attack_tags=classify_attack_tags(desc, cwes),
        cwe_ids=cwes,
        affected=affected,
        sources=['nvd'],
        first_seen=now,
        last_seen=now,
    )


def poc_from_github(raw: dict) -> PoC:
    """Build a PoC from one GitHub result dict (see sources/github.py)."""
    text = f'{raw.get("repo", "")} {raw.get("description", "")}'
    return PoC(
        url=raw.get('url', ''),
        source='github',
        stars=raw.get('stars'),
        age_days=raw.get('age_days'),
        description=raw.get('description'),
        cve_refs=raw.get('cves') or extract_cves(text),
    )


def merge_findings(
    nvd_raw: list[dict],
    github_raw: list[dict],
) -> tuple[list[CVE], list[PoC]]:
    """Convert raw results to CVE + PoC lists. No CVEs are synthesized from
    GitHub-only findings — those live as standalone PoCs with cve_refs that
    may or may not match a known CVE.
    """
    cves = [cve_from_nvd(r) for r in nvd_raw]
    pocs = [poc_from_github(r) for r in github_raw]
    return cves, pocs


def link_pocs_to_cves(cves: list[CVE], pocs: list[PoC]) -> dict[str, list[PoC]]:
    """Return CVE id → list of PoCs that reference it.

    Pure derivation from `PoC.cve_refs` ∩ {cve.id for cve in cves}.
    """
    known_ids = {c.id.upper() for c in cves}
    links: dict[str, list[PoC]] = {cid: [] for cid in known_ids}
    for poc in pocs:
        for ref in poc.cve_refs:
            ref_upper = ref.upper()
            if ref_upper in known_ids:
                links[ref_upper].append(poc)
    return links
