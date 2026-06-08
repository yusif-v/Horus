"""Merge layer — combine results from all sources.

Takes raw CVE and PoC dicts from any source, deduplicates, and produces
typed domain objects. Also aggregates social signals and computes
reputation scores.
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
        confidence="high",
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


# Map source names to builder functions
POC_BUILDERS = {
    "github": poc_from_github,
    "twitter": poc_from_twitter,
    "nitter": poc_from_nitter,
    "exploit-db": poc_from_exploitdb,
}


def deduplicate_pocs(pocs: list[PoC]) -> list[PoC]:
    """Merge duplicate PoCs by URL, keeping the richest metadata."""
    seen: dict[str, PoC] = {}
    source_priority = {"exploit-db": 3, "github": 2, "nitter": 1, "twitter": 0}

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


def aggregate_social_signals(cves: list[CVE], social_signals: list[dict]) -> None:
    """Take social signal dicts from X source and increment social_mentions on matching CVEs.

    Each signal dict has: {"cve_id": "CVE-2026-XXXX", "tweet_url": "...", "likes": N, ...}
    Mutates CVEs in-place.
    """
    cve_map = {c.id.upper(): c for c in cves}
    for signal in social_signals:
        cve_id = signal.get("cve_id", "").upper()
        if cve_id in cve_map:
            cve_map[cve_id].social_mentions += 1


# Products with massive deployment footprints — a critical CVE here typically
# matters far more than the same CVSS on a niche library. Matched case-insensitively
# against AffectedProduct.product/vendor.
UBIQUITOUS_PRODUCTS = {
    # Web servers / proxies
    "nginx", "apache", "httpd", "apache http server", "tomcat", "iis",
    "haproxy", "envoy", "caddy", "traefik",
    # Languages / runtimes
    "php", "node.js", "nodejs", "python", "openjdk", "java", "ruby", "go",
    # CMS / app platforms
    "wordpress", "drupal", "joomla", "magento", "moodle",
    # Databases
    "mysql", "mariadb", "postgresql", "mongodb", "redis", "elasticsearch",
    "sqlite",
    # Network / infra
    "openssl", "openssh", "curl", "libxml2", "zlib", "glibc",
    "systemd", "samba", "bind",
    # Cloud / orchestration
    "kubernetes", "docker", "containerd", "kafka", "rabbitmq",
    # Browsers / clients
    "chrome", "firefox", "safari", "edge",
    # Frameworks
    "spring", "spring framework", "spring boot", "django", "laravel",
    "rails", "ruby on rails", "express", "next.js", "react",
    # OS / hypervisors
    "windows", "linux kernel", "macos", "vmware esxi", "vsphere",
}


def cve_affects_ubiquitous(cve: CVE) -> bool:
    """True if any affected product is in the ubiquitous-impact set."""
    for ap in cve.affected:
        if ap.product and ap.product.lower() in UBIQUITOUS_PRODUCTS:
            return True
        if ap.vendor and ap.vendor.lower() in UBIQUITOUS_PRODUCTS:
            return True
    return False


def compute_reputation_score(cve: CVE) -> float:
    """Compute a composite reputation score (0-10).

    Formula:
        CVSS_score * 0.35                    (0-3.5)
      + EPSS * 10 * 0.25                    (0-2.5)
      + KEV_bonus: 1.5 if kev else 0        (0-1.5)
      + min(social_mentions * 0.15, 1.0)    (0-1.0)
      + min(poc_source_count * 0.5, 1.5)    (0-1.5)
      + ubiquity_bonus: 1.0 if affects a widely-deployed product (nginx,
        php, wordpress, openssl, kubernetes, ...)
      Total cap: 10.0
    """
    if cve.cvss_score is None:
        return 0.0

    score = cve.cvss_score * 0.35

    if cve.epss_score is not None:
        score += cve.epss_score * 10 * 0.25

    if cve.kev:
        score += 1.5

    score += min(cve.social_mentions * 0.15, 1.0)
    score += min(cve.poc_source_count * 0.5, 1.5)

    if cve_affects_ubiquitous(cve):
        score += 1.0

    return min(score, 10.0)


def merge_findings(
    all_cves: list,
    all_pocs: list,
    social_signals: list | None = None,
) -> tuple[list[CVE], list[PoC], dict[str, int]]:
    """Deduplicate CVEs and PoCs from all sources.

    CVEs are deduplicated by ID (NVD = authoritative; first seen wins).
    PoCs are deduplicated by URL (richest metadata wins).
    Social signals are aggregated onto matching CVEs and used to compute
    `social_mentions`.

    Returns:
        (cves, pocs, watchlist_counts)
        watchlist_counts maps {cve_id: mention_count} for CVE IDs that
        appeared ONLY in third-party signals (no NVD record) — these are
        low-confidence candidates that should go into cve_watchlist, not
        the authoritative cve table.
    """
    # Deduplicate CVEs by ID — these all came from authoritative sources (NVD).
    seen_cves: dict[str, CVE] = {}
    for cve in all_cves:
        if cve.id not in seen_cves:
            seen_cves[cve.id] = cve
    cves = list(seen_cves.values())
    known_ids = {c.id.upper() for c in cves}

    # Aggregate social signals: matched IDs bump social_mentions on the CVE;
    # unmatched IDs become watchlist candidates.
    watchlist_counts: dict[str, int] = {}
    if social_signals:
        for signal in social_signals:
            cve_id = (signal.get("cve_id") or "").upper()
            if not cve_id:
                continue
            if cve_id in known_ids:
                # aggregate_social_signals would also work, but inline keeps
                # the one-pass split simple.
                next(c for c in cves if c.id.upper() == cve_id).social_mentions += 1
            else:
                watchlist_counts[cve_id] = watchlist_counts.get(cve_id, 0) + 1

    # Count distinct PoC sources per CVE
    poc_sources_per_cve: dict[str, set[str]] = {}
    for poc in all_pocs:
        for ref in poc.cve_refs:
            ref_upper = ref.upper()
            if ref_upper not in poc_sources_per_cve:
                poc_sources_per_cve[ref_upper] = set()
            poc_sources_per_cve[ref_upper].add(poc.source)
    for cve in cves:
        cve.poc_source_count = len(poc_sources_per_cve.get(cve.id.upper(), set()))

    # Confidence: NVD-backed CVEs default to "high". A NVD CVE with extra
    # corroborating signal stays high; a CVE with NO authoritative record
    # never makes it into `cves` (it goes to watchlist instead).
    for cve in cves:
        if not cve.confidence:
            cve.confidence = "high"

    # Compute reputation scores
    for cve in cves:
        cve.reputation_score = compute_reputation_score(cve)

    # Deduplicate PoCs
    pocs = deduplicate_pocs(all_pocs)

    return cves, pocs, watchlist_counts


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
