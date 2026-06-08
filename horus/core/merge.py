"""Merge layer — combine results from all sources.

Takes raw CVE and PoC dicts from any source, deduplicates, and produces
typed domain objects.
"""

from __future__ import annotations
from datetime import datetime

from .classify import classify_attack_tags, classify_product_category
from .filters import extract_cves
from .model import CVE, AffectedProduct, PoC


def cve_from_nvd(raw: dict) -> CVE:
    """Build a CVE from an NVD result dict."""
    desc = raw.get("description", "")
    cwes = raw.get("cwe_ids", [])
    category = classify_product_category(desc)

    affected: list[AffectedProduct] = []
    for ap in raw.get("affected", []):
        affected.append(AffectedProduct(
            vendor=ap.get("vendor", "unknown"),
            product=ap.get("product", "unknown"),
            versions=list(ap.get("versions", [])),
            category=classify_product_category(ap.get("vendor", ""), ap.get("product", "")),
        ))
    if not affected and category != "unknown":
        affected.append(AffectedProduct(vendor="unknown", product="unknown", category=category))

    now = datetime.utcnow()
    return CVE(
        id=raw["cve"],
        description=desc,
        cvss_score=raw.get("cvss_score"),
        cvss_severity=raw.get("severity"),
        published_at=raw.get("published_at"),
        attack_tags=classify_attack_tags(desc, cwes),
        cwe_ids=cwes,
        affected=affected,
        sources=["nvd"],
        epss_score=raw.get("epss_score"),
        kev=raw.get("kev", 0),
        first_seen=now,
        last_seen=now,
    )


def poc_from_github(raw: dict) -> PoC:
    text = f'{raw.get("repo", "")} {raw.get("description", "")}'
    return PoC(
        url=raw.get("url", ""),
        source="github",
        stars=raw.get("stars"),
        age_days=raw.get("age_days"),
        description=raw.get("description"),
        cve_refs=raw.get("cves") or extract_cves(text),
    )


def poc_from_twitter(raw: dict) -> PoC:
    text = raw.get("description", "") or ""
    return PoC(
        url=raw.get("url", ""),
        source="twitter",
        stars=raw.get("stars"),
        age_days=raw.get("age_days"),
        description=text[:300],
        cve_refs=raw.get("cves") or extract_cves(text),
    )


def poc_from_nitter(raw: dict) -> PoC:
    return PoC(
        url=raw.get("url", ""),
        source="nitter",
        stars=raw.get("stars"),
        age_days=raw.get("age_days"),
        description=raw.get("description"),
        cve_refs=raw.get("cves", []),
    )


def poc_from_exploitdb(raw: dict) -> PoC:
    return PoC(
        url=raw.get("url", ""),
        source="exploit-db",
        stars=None,
        age_days=None,
        description=raw.get("description"),
        cve_refs=raw.get("cves", []),
    )


def poc_from_x(raw: dict) -> PoC:
    return PoC(
        url=raw.get("url", ""),
        source="x",
        stars=raw.get("stars"),
        age_days=raw.get("age_days"),
        description=raw.get("description"),
        cve_refs=raw.get("cves", []),
    )


# Map source names to builder functions
POC_BUILDERS = {
    "github": poc_from_github,
    "twitter": poc_from_twitter,
    "nitter": poc_from_nitter,
    "exploit-db": poc_from_exploitdb,
    "x": poc_from_x,
}


def deduplicate_pocs(pocs: list[PoC]) -> list[PoC]:
    """Merge duplicate PoCs by URL, keeping the richest metadata."""
    seen: dict[str, PoC] = {}
    source_priority = {"exploit-db": 3, "github": 2, "x": 1, "nitter": 1, "twitter": 0}

    for poc in pocs:
        if poc.url in seen:
            existing = seen[poc.url]
            existing.cve_refs = list(set(existing.cve_refs + poc.cve_refs))
            if poc.stars and (not existing.stars or poc.stars > existing.stars):
                existing.stars = poc.stars
            if poc.description and (not existing.description or
                                    len(poc.description) > len(existing.description)):
                existing.description = poc.description
            if source_priority.get(poc.source, 0) > source_priority.get(existing.source, 0):
                existing.source = poc.source
        else:
            seen[poc.url] = poc
    return list(seen.values())


def merge_findings(all_cves: list, all_pocs: list) -> tuple[list[CVE], list[PoC]]:
    """Deduplicate CVEs and PoCs from all sources.

    CVEs are deduplicated by ID (first seen wins).
    PoCs are deduplicated by URL (richest metadata wins).
    """
    # Deduplicate CVEs by ID
    seen_cves: dict[str, CVE] = {}
    for cve in all_cves:
        if cve.id not in seen_cves:
            seen_cves[cve.id] = cve
    cves = list(seen_cves.values())

    # Deduplicate PoCs
    pocs = deduplicate_pocs(all_pocs)

    return cves, pocs


def link_pocs_to_cves(cves: list[CVE], pocs: list[PoC]) -> dict[str, list[PoC]]:
    """Return {cve_id: [PoC, ...]} mapping."""
    known_ids = {c.id.upper() for c in cves}
    links: dict[str, list[PoC]] = {cid: [] for cid in known_ids}
    for poc in pocs:
        for ref in poc.cve_refs:
            ref_upper = ref.upper()
            if ref_upper in known_ids:
                links[ref_upper].append(poc)
    return links
