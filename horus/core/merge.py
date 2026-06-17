"""Merge layer — combine results from all sources.

Takes raw CVE and PoC dicts from any source, deduplicates, and produces
typed domain objects. Also aggregates social signals and computes
reputation scores.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .classify import classify_attack_tags, classify_product_category
from .filters import extract_cves
from .model import CVE, AffectedProduct, PoC

# Known vendor/product keywords for description-based extraction
# These are matched as whole words in the CVE description
_DESCRIPTION_VENDOR_KEYWORDS: list[tuple[str, str, str]] = [
    # (keyword, vendor, product) — keyword matched case-insensitive
    ("nginx", "nginx", "nginx"),
    ("apache", "apache", "httpd"),
    ("httpd", "apache", "httpd"),
    ("tomcat", "apache", "tomcat"),
    ("iis", "microsoft", "iis"),
    ("microsoft iis", "microsoft", "iis"),
    ("windows", "microsoft", "windows"),
    ("microsoft windows", "microsoft", "windows"),
    ("macos", "apple", "macos"),
    ("mac os x", "apple", "macos"),
    ("os x", "apple", "macos"),
    ("ios", "apple", "ios"),
    ("ipados", "apple", "ios"),
    ("chrome", "google", "chrome"),
    ("google chrome", "google", "chrome"),
    ("chromium", "google", "chromium"),
    ("firefox", "mozilla", "firefox"),
    ("mozilla firefox", "mozilla", "firefox"),
    ("safari", "apple", "safari"),
    ("edge", "microsoft", "edge"),
    ("microsoft edge", "microsoft", "edge"),
    ("mysql", "oracle", "mysql"),
    ("mariadb", "mariadb", "mariadb"),
    ("postgresql", "postgresql", "postgresql"),
    ("postgres", "postgresql", "postgresql"),
    ("mongodb", "mongodb", "mongodb"),
    ("redis", "redis", "redis"),
    ("elasticsearch", "elastic", "elasticsearch"),
    ("elastic search", "elastic", "elasticsearch"),
    ("oracle database", "oracle", "oracle"),
    ("oracle db", "oracle", "oracle"),
    ("sql server", "microsoft", "mssql"),
    ("mssql", "microsoft", "mssql"),
    ("wordpress", "wordpress", "wordpress"),
    ("drupal", "drupal", "drupal"),
    ("joomla", "joomla", "joomla"),
    ("magento", "adobe", "magento"),
    ("docker", "docker", "docker"),
    ("kubernetes", "kubernetes", "kubernetes"),
    ("jenkins", "jenkins", "jenkins"),
    ("gitlab", "gitlab", "gitlab"),
    ("github", "github", "github"),
    ("terraform", "hashicorp", "terraform"),
    ("vault", "hashicorp", "vault"),
    ("consul", "hashicorp", "consul"),
    ("ansible", "ansible", "ansible"),
    ("puppet", "puppet", "puppet"),
    ("vmware", "vmware", "vmware"),
    ("vsphere", "vmware", "vsphere"),
    ("esxi", "vmware", "esxi"),
    ("fortinet", "fortinet", "fortinet"),
    ("fortigate", "fortinet", "fortinet"),
    ("fortios", "fortinet", "fortinet"),
    ("palo alto", "paloalto", "paloalto"),
    ("paloalto", "paloalto", "paloalto"),
    ("checkpoint", "checkpoint", "checkpoint"),
    ("cisco", "cisco", "cisco"),
    ("juniper", "juniper", "juniper"),
    ("f5", "f5", "f5"),
    ("big-ip", "f5", "big-ip"),
    ("bigip", "f5", "big-ip"),
    ("haproxy", "haproxy", "haproxy"),
    ("envoy", "envoy", "envoy"),
    ("istio", "istio", "istio"),
    ("grafana", "grafana", "grafana"),
    ("prometheus", "prometheus", "prometheus"),
    ("influxdb", "influxdb", "influxdb"),
    ("splunk", "splunk", "splunk"),
    ("datadog", "datadog", "datadog"),
    ("zabbix", "zabbix", "zabbix"),
    ("nagios", "nagios", "nagios"),
    ("android", "google", "android"),
    ("linux", "linux", "linux"),
    ("ubuntu", "canonical", "ubuntu"),
    ("debian", "debian", "debian"),
    ("centos", "centos", "centos"),
    ("red hat", "redhat", "redhat"),
    ("redhat", "redhat", "redhat"),
    ("fedora", "fedora", "fedora"),
    ("suse", "suse", "suse"),
    ("opensuse", "suse", "suse"),
    ("freebsd", "freebsd", "freebsd"),
    ("openbsd", "openbsd", "openbsd"),
    ("netbsd", "netbsd", "netbsd"),
    ("openssh", "openssh", "openssh"),
    ("openssl", "openssl", "openssl"),
    ("nginx plus", "nginx", "nginx"),
    ("node.js", "node.js", "node.js"),
    ("nodejs", "node.js", "node.js"),
    ("python", "python", "python"),
    ("php", "php", "php"),
    ("ruby", "ruby", "ruby"),
    ("perl", "perl", "perl"),
    ("golang", "go", "go"),
    ("java", "oracle", "java"),
    ("spring", "spring", "spring"),
    ("django", "django", "django"),
    ("flask", "flask", "flask"),
    ("laravel", "laravel", "laravel"),
    ("symfony", "symfony", "symfony"),
    ("rails", "rails", "rails"),
    ("react", "meta", "react"),
    ("vue", "vue", "vue"),
    ("angular", "google", "angular"),
    ("svelte", "svelte", "svelte"),
    ("next.js", "vercel", "next.js"),
    ("nextjs", "vercel", "next.js"),
    ("nuxt", "nuxt", "nuxt"),
    ("express", "express", "express"),
    ("fastapi", "fastapi", "fastapi"),
    ("kafka", "apache", "kafka"),
    ("spark", "apache", "spark"),
    ("hadoop", "apache", "hadoop"),
    ("cassandra", "apache", "cassandra"),
    ("couchdb", "apache", "couchdb"),
    ("solr", "apache", "solr"),
    ("lucene", "apache", "lucene"),
    ("activemq", "apache", "activemq"),
    ("rabbitmq", "rabbitmq", "rabbitmq"),
    ("nginx unit", "nginx", "nginx"),
    ("varnish", "varnish", "varnish"),
    ("traefik", "traefik", "traefik"),
    ("caddy", "caddy", "caddy"),
    ("haproxy", "haproxy", "haproxy"),
    ("keepalived", "keepalived", "keepalived"),
    ("bind", "isc", "bind"),
    ("unbound", "nlnetlabs", "unbound"),
    ("powerdns", "powerdns", "powerdns"),
    ("adobe", "adobe", "adesign"),
    ("acrobat", "adobe", "acrobat"),
    ("photoshop", "adobe", "photoshop"),
    ("illustrator", "adobe", "illustrator"),
    ("indesign", "adobe", "indesign"),
    ("fortigate", "fortinet", "fortinet"),
    ("sonicwall", "sonicwall", "sonicwall"),
    ("sophos", "sophos", "sophos"),
    ("barracuda", "barracuda", "barracuda"),
    ("trend micro", "trendmicro", "trendmicro"),
    ("trendmicro", "trendmicro", "trendmicro"),
    ("kaspersky", "kaspersky", "kaspersky"),
    ("mcafee", "mcafee", "mcafee"),
    ("symantec", "symantec", "symantec"),
    ("norton", "norton", "norton"),
    ("bitdefender", "bitdefender", "bitdefender"),
    ("eset", "eset", "eset"),
    ("avast", "avast", "avast"),
    ("avg", "avg", "avg"),
    ("malwarebytes", "malwarebytes", "malwarebytes"),
    ("crowdstrike", "crowdstrike", "crowdstrike"),
    ("sentinelone", "sentinelone", "sentinelone"),
    ("carbon black", "carbonblack", "carbonblack"),
    ("carbonblack", "carbonblack", "carbonblack"),
    ("palo alto networks", "paloalto", "paloalto"),
    ("zscaler", "zscaler", "zscaler"),
    ("cloudflare", "cloudflare", "cloudflare"),
    ("akamai", "akamai", "akamai"),
    ("fastly", "fastly", "fastly"),
    ("aws", "aws", "aws"),
    ("amazon web services", "aws", "aws"),
    ("azure", "microsoft", "azure"),
    ("gcp", "google", "gcp"),
    ("google cloud", "google", "gcp"),
    ("firebase", "google", "firebase"),
    ("heroku", "heroku", "heroku"),
    ("netlify", "netlify", "netlify"),
    ("vercel", "vercel", "vercel"),
    ("shopify", "shopify", "shopify"),
    ("bigcommerce", "bigcommerce", "bigcommerce"),
    ("woocommerce", "woocommerce", "woocommerce"),
    ("prestashop", "prestashop", "prestashop"),
    ("magento", "adobe", "magento"),
    ("drupal", "drupal", "drupal"),
    ("joomla", "joomla", "joomla"),
    ("typo3", "typo3", "typo3"),
    ("ghost", "ghost", "ghost"),
    ("strapi", "strapi", "strapi"),
    ("contentful", "contentful", "contentful"),
    ("sanity", "sanity", "sanity"),
    ("prismic", "prismic", "prismic"),
    ("netlify cms", "netlify", "netlify"),
    ("strapi", "strapi", "strapi"),
    ("keycloak", "keycloak", "keycloak"),
    ("okta", "okta", "okta"),
    ("auth0", "auth0", "auth0"),
    ("onelogin", "onelogin", "onelogin"),
    ("ping identity", "pingidentity", "pingidentity"),
    ("pingidentity", "pingidentity", "pingidentity"),
    ("forgerock", "forgerock", "forgerock"),
    ("sailpoint", "sailpoint", "sailpoint"),
    ("cyberark", "cyberark", "cyberark"),
    ("beyondtrust", "beyondtrust", "beyondtrust"),
    ("thycotic", "thycotic", "thycotic"),
    ("hashicorp vault", "hashicorp", "vault"),
    ("aws secrets manager", "aws", "aws"),
    ("azure key vault", "microsoft", "azure"),
    ("gcp secret manager", "google", "gcp"),
    ("lastpass", "lastpass", "lastpass"),
    ("1password", "1password", "1password"),
    ("bitwarden", "bitwarden", "bitwarden"),
    ("dashlane", "dashlane", "dashlane"),
    ("keeper", "keeper", "keeper"),
    ("nordpass", "nordpass", "nordpass"),
    ("protonmail", "protonmail", "protonmail"),
    ("tutanota", "tutanota", "tutanota"),
    ("signal", "signal", "signal"),
    ("telegram", "telegram", "telegram"),
    ("whatsapp", "meta", "whatsapp"),
    ("slack", "slack", "slack"),
    ("microsoft teams", "microsoft", "teams"),
    ("teams", "microsoft", "teams"),
    ("zoom", "zoom", "zoom"),
    ("webex", "cisco", "webex"),
    ("gotomeeting", "gotomeeting", "gotomeeting"),
    ("bluejeans", "bluejeans", "bluejeans"),
    ("jitsi", "jitsi", "jitsi"),
    ("bigbluebutton", "bigbluebutton", "bigbluebutton"),
    ("moodle", "moodle", "moodle"),
    ("canvas", "canvas", "canvas"),
    ("blackboard", "blackboard", "blackboard"),
    ("schoology", "schoology", "schoology"),
    ("edmodo", "edmodo", "edmodo"),
    ("google classroom", "google", "google"),
    ("microsoft teams for education", "microsoft", "microsoft"),
]


def _extract_vendor_from_description(desc: str) -> tuple[str | None, str | None]:
    """Try to extract vendor and product from a CVE description.

    Returns (vendor, product) or (None, None) if no match.
    Uses keyword matching against known vendor/product names.
    """
    desc_lower = desc.lower()
    # Sort by keyword length descending so longer matches take priority
    # (e.g., "palo alto networks" before "palo")
    for keyword, vendor, product in sorted(
        _DESCRIPTION_VENDOR_KEYWORDS, key=lambda x: len(x[0]), reverse=True
    ):
        if keyword in desc_lower:
            return vendor, product
    return None, None


def cve_from_nvd(raw: dict[str, Any]) -> CVE:
    """Build a CVE from an NVD result dict."""
    desc = raw.get("description", "")
    cwes = raw.get("cwe_ids", [])
    category = classify_product_category(desc)

    affected: list[AffectedProduct] = []
    for ap in raw.get("affected", []):
        vendor = ap.get("vendor", "unknown")
        product = ap.get("product", "unknown")
        # Fallback: try to extract vendor/product from description when CPE gives unknown
        if vendor == "unknown" or product == "unknown":
            desc_vendor, desc_product = _extract_vendor_from_description(desc)
            if vendor == "unknown" and desc_vendor:
                vendor = desc_vendor
            if product == "unknown" and desc_product:
                product = desc_product
        affected.append(
            AffectedProduct(
                vendor=vendor,
                product=product,
                versions=list(ap.get("versions", [])),
                category=classify_product_category(vendor, product),
            )
        )
    if not affected and category != "unknown":
        affected.append(AffectedProduct(vendor="unknown", product="unknown", category=category))

    now = datetime.now(timezone.utc).replace(tzinfo=None)
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


def poc_from_github(raw: dict[str, Any]) -> PoC:
    text = f"{raw.get('repo', '')} {raw.get('description', '')} {raw.get('url', '')}"
    return PoC(
        url=raw.get("url", ""),
        source=raw.get("source", "github"),
        stars=raw.get("stars"),
        age_days=None,  # Computed dynamically from repo_created_at
        description=raw.get("description"),
        cve_refs=raw.get("cves") or extract_cves(text),
        repo_created_at=raw.get("repo_created_at"),
    )


def poc_from_twitter(raw: dict[str, Any]) -> PoC:
    text = raw.get("description", "") or ""
    return PoC(
        url=raw.get("url", ""),
        source="twitter",
        stars=raw.get("stars"),
        age_days=raw.get("age_days"),
        description=text[:300],
        cve_refs=raw.get("cves") or extract_cves(text),
    )


def poc_from_nitter(raw: dict[str, Any]) -> PoC:
    return PoC(
        url=raw.get("url", ""),
        source="nitter",
        stars=raw.get("stars"),
        age_days=raw.get("age_days"),
        description=raw.get("description"),
        cve_refs=raw.get("cves", []),
    )


def poc_from_exploitdb(raw: dict[str, Any]) -> PoC:
    return PoC(
        url=raw.get("url", ""),
        source="exploit-db",
        stars=None,
        age_days=None,
        description=raw.get("description"),
        cve_refs=raw.get("cves", []),
    )


def poc_from_gitlab(raw: dict[str, Any]) -> PoC:
    text = f"{raw.get('repo', '')} {raw.get('description', '')} {raw.get('url', '')}"
    return PoC(
        url=raw.get("url", ""),
        source="gitlab",
        stars=raw.get("stars"),
        age_days=raw.get("age_days"),
        description=raw.get("description"),
        cve_refs=raw.get("cves") or extract_cves(text),
    )


def poc_from_codeberg(raw: dict[str, Any]) -> PoC:
    text = f"{raw.get('repo', '')} {raw.get('description', '')} {raw.get('url', '')}"
    return PoC(
        url=raw.get("url", ""),
        source="codeberg",
        stars=raw.get("stars"),
        age_days=None,  # Computed dynamically from repo_created_at
        description=raw.get("description"),
        cve_refs=raw.get("cves") or extract_cves(text),
        repo_created_at=raw.get("repo_created_at"),
    )


def poc_from_pastebin(raw: dict[str, Any]) -> PoC:
    return PoC(
        url=raw.get("url", ""),
        source="pastebin",
        stars=None,
        age_days=None,
        description=raw.get("description", "")[:300],
        cve_refs=raw.get("cves", []),
    )


def poc_from_web(raw: dict[str, Any]) -> PoC:
    """Generic PoC from any web URL (HackerOne, Bugcrowd, etc.)."""
    source = raw.get("source", "web")
    return PoC(
        url=raw.get("url", ""),
        source=source,
        stars=None,
        age_days=None,
        description=raw.get("description", "")[:300],
        cve_refs=raw.get("cves", []),
    )


# Map source names to builder functions
POC_BUILDERS = {
    "github": poc_from_github,
    "twitter": poc_from_twitter,
    "nitter": poc_from_nitter,
    "exploit-db": poc_from_exploitdb,
    "gitlab": poc_from_gitlab,
    "codeberg": poc_from_codeberg,
    "pastebin": poc_from_pastebin,
    "hackerone": poc_from_web,
    "bugcrowd": poc_from_web,
    "web": poc_from_web,
}


def deduplicate_pocs(pocs: list[PoC]) -> list[PoC]:
    """Merge duplicate PoCs by URL, keeping the richest metadata."""
    seen: dict[str, PoC] = {}
    source_priority = {
        "exploit-db": 3,
        "github": 2,
        "gitlab": 2,
        "codeberg": 2,
        "hackerone": 2,
        "bugcrowd": 2,
        "pastebin": 1,
        "nitter": 1,
        "twitter": 0,
        "web": 0,
    }

    for poc in pocs:
        if poc.url in seen:
            existing = seen[poc.url]
            existing.cve_refs = list(set(existing.cve_refs + poc.cve_refs))
            if poc.stars and (not existing.stars or poc.stars > existing.stars):
                existing.stars = poc.stars
            if poc.description and (
                not existing.description or len(poc.description) > len(existing.description)
            ):
                existing.description = poc.description
            if source_priority.get(poc.source, 0) > source_priority.get(existing.source, 0):
                existing.source = poc.source
        else:
            seen[poc.url] = poc
    return list(seen.values())


def aggregate_social_signals(cves: list[CVE], social_signals: list[dict[str, Any]]) -> None:
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
    "nginx",
    "apache",
    "httpd",
    "apache http server",
    "tomcat",
    "iis",
    "haproxy",
    "envoy",
    "caddy",
    "traefik",
    # Languages / runtimes
    "php",
    "node.js",
    "nodejs",
    "python",
    "openjdk",
    "java",
    "ruby",
    "go",
    # CMS / app platforms
    "wordpress",
    "drupal",
    "joomla",
    "magento",
    "moodle",
    # Databases
    "mysql",
    "mariadb",
    "postgresql",
    "mongodb",
    "redis",
    "elasticsearch",
    "sqlite",
    # Network / infra
    "openssl",
    "openssh",
    "curl",
    "libxml2",
    "zlib",
    "glibc",
    "systemd",
    "samba",
    "bind",
    # Cloud / orchestration
    "kubernetes",
    "docker",
    "containerd",
    "kafka",
    "rabbitmq",
    # Browsers / clients
    "chrome",
    "firefox",
    "safari",
    "edge",
    # Frameworks
    "spring",
    "spring framework",
    "spring boot",
    "django",
    "laravel",
    "rails",
    "ruby on rails",
    "express",
    "next.js",
    "react",
    # OS / hypervisors
    "windows",
    "linux kernel",
    "macos",
    "vmware esxi",
    "vsphere",
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
    all_cves: list[CVE],
    all_pocs: list[PoC],
    social_signals: list[dict[str, Any]] | None = None,
) -> tuple[list[CVE], list[PoC], list[tuple[str, str, int]]]:
    """Deduplicate CVEs and PoCs from all sources.

    CVEs are deduplicated by ID (NVD = authoritative; first seen wins).
    PoCs are deduplicated by URL (richest metadata wins).
    Social signals are aggregated onto matching CVEs and used to compute
    `social_mentions`.

    Returns:
        (cves, pocs, watchlist_entries)
        watchlist_entries is a list of (cve_id, source, mention_count)
        for CVE IDs that appeared ONLY in third-party signals (no NVD
        record). `source` is the name of the source that surfaced the
        signal — taken from the signal dict's "source" key (the pipeline
        stamps this). Persist these to cve_watchlist, not the
        authoritative cve table.
    """
    # Deduplicate CVEs by ID — these all came from authoritative sources (NVD).
    seen_cves: dict[str, CVE] = {}
    for cve in all_cves:
        if cve.id not in seen_cves:
            seen_cves[cve.id] = cve
    cves = list(seen_cves.values())
    known_ids = {c.id.upper() for c in cves}

    # Aggregate social signals: matched IDs bump social_mentions on the CVE;
    # unmatched IDs become watchlist candidates keyed by (cve_id, source).
    watchlist: dict[tuple[str, str], int] = {}
    if social_signals:
        for signal in social_signals:
            cve_id = (signal.get("cve_id") or "").upper()
            if not cve_id:
                continue
            if cve_id in known_ids:
                next(c for c in cves if c.id.upper() == cve_id).social_mentions += 1
            else:
                source = signal.get("source") or "unknown"
                key = (cve_id, source)
                watchlist[key] = watchlist.get(key, 0) + 1

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

    watchlist_entries = [(cid, src, n) for (cid, src), n in watchlist.items()]
    return cves, pocs, watchlist_entries


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
