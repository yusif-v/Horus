"""CVE source — NVD (National Vulnerability Database).

Fetches recently published CVEs from the NVD API.
"""

from __future__ import annotations

import contextlib
import sys
from datetime import datetime, timedelta, timezone

from ..config import NVD_LOOKBACK_DAYS, NVD_MAX_LOOKBACK_DAYS
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


# Known vendor name normalizations (NVD CPE uses various spellings)
_VENDOR_ALIASES: dict[str, str] = {
    "apache_software_foundation": "apache",
    "apache_http_server_project": "apache",
    "the_nginx_project": "nginx",
    "nginx_software": "nginx",
    "microsoft_corporation": "microsoft",
    "microsoft_corp.": "microsoft",
    "google_llc": "google",
    "google_inc.": "google",
    "oracle_corporation": "oracle",
    "oracle_corp": "oracle",
    "red_hat": "redhat",
    "red_hat_inc.": "redhat",
    "ibm_corp": "ibm",
    "international_business_machines": "ibm",
    "cisco_systems": "cisco",
    "cisco_systems_inc.": "cisco",
    "juniper_networks": "juniper",
    "vmware_inc.": "vmware",
    "adobe_inc.": "adobe",
    "adobe_systems": "adobe",
    "mozilla_foundation": "mozilla",
    "the_gnome_foundation": "gnome",
    "canonical_ltd.": "canonical",
    "debian_gnu/linux": "debian",
    "ubuntu": "canonical",
    "apple_inc.": "apple",
    "apple_computer": "apple",
    "facebook": "meta",
    "facebook_inc.": "meta",
    "netapp_inc.": "netapp",
    "fortinet_inc.": "fortinet",
    "palo_alto_networks": "paloalto",
    "checkpoint_software": "checkpoint",
    "f5_networks": "f5",
    "f5_inc.": "f5",
    "sap_se": "sap",
    "sap_ag": "sap",
    "schneider_electric": "schneider",
    "schneider_electric_se": "schneider",
    "siemens_ag": "siemens",
    "siemens_energy": "siemens",
    "hpe": "hewlett-packard",
    "hp_inc.": "hp",
    "hewlett_packard": "hewlett-packard",
    "dell_technologies": "dell",
    "dell_inc.": "dell",
    "lenovo_group": "lenovo",
    "huawei_technologies": "huawei",
    "xiaomi_tech": "xiaomi",
    "samsung_electronics": "samsung",
    "sony_corporation": "sony",
    "intel_corporation": "intel",
    "intel_corp.": "intel",
    "amd": "amd",
    "nvidia_corporation": "nvidia",
    "the_linux_foundation": "linux",
    "linux_foundation": "linux",
    "the_wordpress_foundation": "wordpress",
    "wordpress_foundation": "wordpress",
    "the_drupal_association": "drupal",
    "mozilla_corporation": "mozilla",
    "atlassian_corp.": "atlassian",
    "atlassian_corp": "atlassian",
    "github_inc.": "github",
    "gitlab_inc.": "gitlab",
    "docker_inc.": "docker",
    "hashicorp_inc.": "hashicorp",
    "elastic_n.v.": "elastic",
    "elasticsearch": "elastic",
    "mongodb_inc.": "mongodb",
    "redis_labs": "redis",
    "postgresql_global_development_group": "postgresql",
    "mysql_ab": "mysql",
    "mariadb_foundation": "mariadb",
    "percona_llc": "percona",
    "akamai_technologies": "akamai",
    "cloudflare_inc.": "cloudflare",
    "fastly_inc.": "fastly",
    "incapsula": "imperva",
    "barracuda_networks": "barracuda",
    "sophos_ltd.": "ophos",
    "trend_micro": "trendmicro",
    "trend_micro_inc.": "trendmicro",
    "kaspersky_lab": "kaspersky",
    "mcafee_corp.": "mcafee",
    "symantec_corporation": "symantec",
    "broadcom_inc.": "broadcom",
    "veritas_technologies": "veritas",
    "opensuse": "suse",
    "suse_linux": "suse",
    "rocky_linux": "rocky",
    "almalinux": "almalinux",
    "centos": "centos",
    "fedora_project": "fedora",
    "arch_linux": "arch",
    "gentoo_foundation": "gentoo",
    "slackware_linux": "slackware",
    "void_linux": "void",
    "nixos_foundation": "nixos",
    "freebsd_foundation": "freebsd",
    "openbsd": "openbsd",
    "netbsd_foundation": "netbsd",
    "the_moodle_project": "moodle",
    "moodle_pt": "moodle",
    "nextcloud_gmbh": "nextcloud",
    "owncloud_gmbh": "owncloud",
    "synology_inc.": "synology",
    "qnap_systems": "qnap",
    "western_digital": "westerndigital",
    "seagate_technology": "seagate",
    "toshiba_corporation": "toshiba",
    "hitachi_ltd.": "hitachi",
    "fujitsu_limited": "fujitsu",
    "nec_corporation": "nec",
    "panasonic_corporation": "panasonic",
    "lg_electronics": "lg",
    "philips": "philips",
    "siemens_healthineers": "siemens",
    "ge_healthcare": "ge",
    "medtronic_plc": "medtronic",
    "boston_scientific": "bostonscientific",
    "abbott_laboratories": "abbott",
    "roche_diagnostics": "roche",
    "thermo_fisher_scientific": "thermofisher",
    "zeiss": "zeiss",
    "olympus_corporation": "olympus",
    "canon_inc.": "canon",
    "epson": "epson",
    "hp": "hp",
    "brother_industries": "brother",
    "lexmark_international": "lexmark",
    "ricoh_company": "ricoh",
    "konica_minolta": "konica",
    "sharp_corporation": "sharp",
    "toshiba_tec": "toshiba",
    "xerox_corporation": "xerox",
    "kodak_alaris": "kodak",
    "fujifilm": "fujifilm",
    "nikon_corporation": "nikon",
    "sigma_corporation": "sigma",
    "tamron": "tamron",
    "sony_semiconductor": "sony",
    "stmicroelectronics": "stmicro",
    "nxp_semiconductors": "nxp",
    "texas_instruments": "ti",
    "qualcomm_inc.": "qualcomm",
    "mediatek_inc.": "mediatek",
    "broadcom_corporation": "broadcom",
    "realtek_semiconductor": "realtek",
    "marvell_technology": "marvell",
    "microchip_technology": "microchip",
    "analog_devices": "analogdevices",
    "maxim_integrated": "maxim",
    "linear_technology": "linear",
    "instruments": "ti",
    "renesas_electronics": "renesas",
    "rohm_semiconductor": "rohm",
    "toshiba_semiconductor": "toshiba",
    "infineon_technologies": "infineon",
    "nexperia": "nexperia",
    "vishay_intertechnology": "vishay",
    "wurth_elektronik": "wurth",
    "te_connectivity": "te",
    "amphenol_corporation": "amphenol",
    "molex": "molex",
    "jae_electronics": "jae",
    "hirose_electric": "hirose",
    "kyocera_corporation": "kyocera",
    "murata_manufacturing": "murata",
    "tdk_corporation": "tdk",
    "samsung_electro-mechanics": "samsung",
    "yageo_corporation": "yageo",
    "bourns_inc.": "bourns",
    "littelfuse": "littelfuse",
    "eaton_corporation": "eaton",
    "abb_ltd": "abb",
    "honeywell_international": "honeywell",
    "emerson_electric": "emerson",
    "rockwell_automation": "rockwell",
    "general_electric": "ge",
    "mitsubishi_electric": "mitsubishi",
    "omron_corporation": "omron",
    "phoenix_contact": "phoenix",
    "weidmuller": "weidmuller",
    "wago": "wago",
    "festo": "festo",
    "smc_corporation": "smc",
    "ckd_corporation": "ckd",
    "norgren": "norgren",
    "parker_hannifin": "parker",
    "danfoss": "danfoss",
    "bosch_rexroth": "bosch",
    "hydac": "hydac",
    "bucher_hydraulics": "bucher",
    "eaton_hydraulics": "eaton",
    "sauer-danfoss": "sauer",
    "linde_hydraulics": "linde",
    "kawasaki_heavy_industries": "kawasaki",
    "komatsu_ltd.": "komatsu",
    "hitachi_construction_machinery": "hitachi",
    "volvo_construction_equipment": "volvo",
    "caterpillar_inc.": "caterpillar",
    "deere_&_company": "deere",
    "jcb": "jcb",
    "liebherr": "liebherr",
    "manitou": "manitou",
    "bobcat": "bobcat",
    "doosan": "doosan",
    "hyundai_construction_equipment": "hyundai",
    "sany": "sany",
    "zoomlion": "zoomlion",
    "xcmg": "xcmg",
    "liugong": "liugong",
    "shantui": "shantui",
    "lonking": "lonking",
    "lingong": "lingong",
    "sunward": "sunward",
    "yutong": "yutong",
    "byd": "byd",
    "geely": "geely",
    "chery": "chery",
    "great_wall_motors": "gwm",
    "haval": "haval",
    "mg_motor": "mg",
    "rover": "rover",
    "jaguar_land_rover": "jlr",
    "tata_motors": "tata",
    "mahindra": "mahindra",
    "maruti_suzuki": "maruti",
    "toyota_motor_corporation": "toyota",
    "honda_motor": "honda",
    "nissan_motor": "nissan",
    "mazda_motor": "mazda",
    "subaru_corporation": "subaru",
    "mitsubishi_motors": "mitsubishi",
    "suzuki_motor_corporation": "suzuki",
    "isuzu_motors": "isuzu",
    "daihatsu": "daihatsu",
    "hino_motors": "hino",
    "fuso": "fuso",
    "ud_trucks": "ud",
    "volvo_trucks": "volvo",
    "scania": "scania",
    "man_truck_&_bus": "man",
    "daf_trucks": "daf",
    "iveco": "iveco",
    "paccar": "paccar",
    "kenworth": "kenworth",
    "peterbilt": "peterbilt",
    "freightliner": "freightliner",
    "western_star": "westernstar",
    "mack_trucks": "mack",
    "navistar": "navistar",
    "oshkosh": "oshkosh",
    "bae_systems": "bae",
    "lockheed_martin": "lockheedmartin",
    "northrop_grumman": "northropgrumman",
    "raytheon_technologies": "raytheon",
    "general_dynamics": "generaldynamics",
    "boeing": "boeing",
    "airbus": "airbus",
    "embraer": "embraer",
    "bombardier": "bombardier",
    "gulfstream": "gulfstream",
    "dassault_aviation": "dassault",
    "cessna": "cessna",
    "beechcraft": "beechcraft",
    "pilatus": "pilatus",
    "diamond_aircraft": "diamond",
    "cirrus": "cirrus",
    "mooney": "mooney",
    "piper": "piper",
}

# Product name normalizations
_PRODUCT_ALIASES: dict[str, str] = {
    "http_server": "httpd",
    "httpd_server": "httpd",
    "apache_http_server": "httpd",
    "apache_tomcat": "tomcat",
    "tomcat": "tomcat",
    "nginx": "nginx",
    "nginx_plus": "nginx",
    "iis": "iis",
    "windows": "windows",
    "windows_10": "windows",
    "windows_11": "windows",
    "windows_server": "windows",
    "windows_server_2019": "windows",
    "windows_server_2022": "windows",
    "macos": "macos",
    "mac_os_x": "macos",
    "os_x": "macos",
    "ios": "ios",
    "ipados": "ios",
    "watchos": "ios",
    "tvos": "ios",
    "android": "android",
    "linux": "linux",
    "debian": "debian",
    "rhel": "redhat",
    "red_hat_enterprise_linux": "redhat",
    "fedora": "fedora",
    "suse": "suse",
    "gentoo": "gentoo",
    "alpine": "alpine",
    "freebsd": "freebsd",
    "netbsd": "netbsd",
    "chrome": "chrome",
    "google_chrome": "chrome",
    "chromium": "chromium",
    "firefox": "firefox",
    "mozilla_firefox": "firefox",
    "safari": "safari",
    "edge": "edge",
    "microsoft_edge": "edge",
    "opera": "opera",
    "brave": "brave",
    "vivaldi": "vivaldi",
    "mysql": "mysql",
    "mariadb": "mariadb",
    "postgresql": "postgresql",
    "postgres": "postgresql",
    "mongodb": "mongodb",
    "redis": "redis",
    "sqlite": "sqlite",
    "oracle_database": "oracle",
    "oracle_db": "oracle",
    "mssql": "mssql",
    "sql_server": "mssql",
    "wordpress": "wordpress",
    "drupal": "drupal",
    "joomla": "joomla",
    "magento": "magento",
    "shopify": "shopify",
    "prestashop": "prestashop",
    "woocommerce": "woocommerce",
    "django": "django",
    "flask": "flask",
    "rails": "rails",
    "ruby_on_rails": "rails",
    "laravel": "laravel",
    "symfony": "symfony",
    "spring": "spring",
    "spring_boot": "spring",
    "express": "express",
    "expressjs": "express",
    "nextjs": "next.js",
    "next.js": "next.js",
    "nuxt": "nuxt",
    "nuxtjs": "nuxt",
    "react": "react",
    "reactjs": "react",
    "vue": "vue",
    "vuejs": "vue",
    "angular": "angular",
    "angularjs": "angular",
    "svelte": "svelte",
    "nodejs": "node.js",
    "node.js": "node.js",
    "deno": "deno",
    "bun": "bun",
    "python": "python",
    "php": "php",
    "ruby": "ruby",
    "perl": "perl",
    "golang": "go",
    "go": "go",
    "rust": "rust",
    "java": "java",
    "kotlin": "kotlin",
    "scala": "scala",
    "clojure": "clojure",
    "elixir": "elixir",
    "erlang": "erlang",
    "haskell": "haskell",
    "lua": "lua",
    "r": "r",
    "swift": "swift",
    "objective-c": "objective-c",
    "c": "c",
    "c++": "c++",
    "c#": "c#",
    ".net": ".net",
    "dotnet": ".net",
    "asp.net": "asp.net",
    "docker": "docker",
    "kubernetes": "kubernetes",
    "k8s": "kubernetes",
    "jenkins": "jenkins",
    "gitlab": "gitlab",
    "github": "github",
    "bitbucket": "bitbucket",
    "terraform": "terraform",
    "ansible": "ansible",
    "puppet": "puppet",
    "chef": "chef",
    "saltstack": "salt",
    "vagrant": "vagrant",
    "virtualbox": "virtualbox",
    "vmware": "vmware",
    "vsphere": "vsphere",
    "esxi": "esxi",
    "hyper-v": "hyperv",
    "proxmox": "proxmox",
    "openstack": "openstack",
    "aws": "aws",
    "amazon_web_services": "aws",
    "azure": "azure",
    "gcp": "gcp",
    "google_cloud": "gcp",
    "firebase": "firebase",
    "heroku": "heroku",
    "netlify": "netlify",
    "vercel": "vercel",
    "cloudflare": "cloudflare",
    "akamai": "akamai",
    "fastly": "fastly",
    "imperva": "imperva",
    "cloudfront": "aws",
    "route53": "aws",
    "lambda": "aws",
    "ec2": "aws",
    "s3": "aws",
    "rds": "aws",
    "dynamodb": "aws",
    "sqs": "aws",
    "sns": "aws",
    "ecs": "aws",
    "eks": "aws",
    "fargate": "aws",
    "azure_ad": "azure",
    "azure_active_directory": "azure",
    "office365": "microsoft",
    "office_365": "microsoft",
    "microsoft_365": "microsoft",
    "m365": "microsoft",
    "teams": "microsoft",
    "sharepoint": "microsoft",
    "onedrive": "microsoft",
    "outlook": "outlook",
    "exchange": "exchange",
    "exchange_server": "exchange",
    "active_directory": "microsoft",
    "ad": "microsoft",
    "fortios": "fortinet",
    "fortigate": "fortinet",
    "fortianalyzer": "fortinet",
    "fortiswitch": "fortinet",
    "fortiweb": "fortinet",
    "forticlient": "fortinet",
    "fortisandbox": "fortinet",
    "fortiedr": "fortinet",
    "fortisiem": "fortinet",
    "fortiwaf": "fortinet",
    "fortiddos": "fortinet",
    "fortimail": "fortinet",
    "fortinac": "fortinet",
    "fortiems": "fortinet",
    "fortiinsight": "fortinet",
    "fortiportal": "fortinet",
    "fortiisolator": "fortinet",
    "fortitester": "fortinet",
    "fortiauthenticator": "fortinet",
    "fortitoken": "fortinet",
    "fortimanager": "fortinet",
    "palo_alto": "paloalto",
    "pan-os": "paloalto",
    "panos": "paloalto",
    "checkpoint": "checkpoint",
    "checkpoint_firewall": "checkpoint",
    "juniper": "juniper",
    "junos": "juniper",
    "srx": "juniper",
    "ex": "juniper",
    "qfx": "juniper",
    "mx": "juniper",
    "cisco": "cisco",
    "ios_xe": "cisco",
    "ios_xr": "cisco",
    "nx-os": "cisco",
    "aci": "cisco",
    "asa": "cisco",
    "firepower": "cisco",
    "meraki": "cisco",
    "umbrella": "cisco",
    "duo": "cisco",
    "anyconnect": "cisco",
    "vpn": "cisco",
    "f5": "f5",
    "big-ip": "f5",
    "bigip": "f5",
    "nginx_unit": "nginx",
    "nginx_controller": "nginx",
    "nginx_app_protect": "nginx",
    "nginx_service_mesh": "nginx",
    "nginx_api_gateway": "nginx",
    "nginx_load_balancer": "nginx",
    "nginx_web_server": "nginx",
    "nginx_reverse_proxy": "nginx",
    "nginx_cache": "nginx",
    "openresty": "nginx",
    "tengine": "nginx",
    "apache_kafka": "kafka",
    "kafka": "kafka",
    "apache_spark": "spark",
    "spark": "spark",
    "apache_flink": "flink",
    "flink": "flink",
    "apache_hadoop": "hadoop",
    "hadoop": "hadoop",
    "apache_cassandra": "cassandra",
    "cassandra": "cassandra",
    "apache_couchdb": "couchdb",
    "couchdb": "couchdb",
    "apache_solr": "solr",
    "solr": "solr",
    "apache_lucene": "lucene",
    "lucene": "lucene",
    "apache_tika": "tika",
    "tika": "tika",
    "apache_nifi": "nifi",
    "nifi": "nifi",
    "apache_airflow": "airflow",
    "airflow": "airflow",
    "apache_beam": "beam",
    "beam": "beam",
    "apache_iceberg": "iceberg",
    "iceberg": "iceberg",
    "apache_hudi": "hudi",
    "hudi": "hudi",
    "apache_delta": "delta",
    "delta_lake": "delta",
    "dremio": "dremio",
    "presto": "presto",
    "trino": "trino",
    "clickhouse": "clickhouse",
    "duckdb": "duckdb",
    "snowflake": "snowflake",
    "databricks": "databricks",
    "looker": "google",
    "tableau": "tableau",
    "powerbi": "microsoft",
    "power_bi": "microsoft",
    "grafana": "grafana",
    "prometheus": "prometheus",
    "loki": "grafana",
    "tempo": "grafana",
    "mimir": "grafana",
    "cortex": "grafana",
    "thanos": "thanos",
    "victoriametrics": "victoriametrics",
    "influxdb": "influxdb",
    "timescaledb": "timescale",
    "questdb": "questdb",
    "opentsdb": "opentsdb",
    "graphite": "graphite",
    "statsd": "statsd",
    "telegraf": "influxdb",
    "collectd": "collectd",
    "nagios": "nagios",
    "zabbix": "zabbix",
    "icinga": "icinga",
    "sensu": "sensu",
    "datadog": "datadog",
    "newrelic": "newrelic",
    "dynatrace": "dynatrace",
    "appdynamics": "appdynamics",
    "splunk": "splunk",
    "elastic": "elastic",
    "elk": "elastic",
    "logstash": "elastic",
    "kibana": "elastic",
    "beats": "elastic",
    "filebeat": "elastic",
    "metricbeat": "elastic",
    "packetbeat": "elastic",
    "auditbeat": "elastic",
    "heartbeat": "elastic",
    "functionbeat": "elastic",
    "journalbeat": "elastic",
    "winlogbeat": "elastic",
    "apm": "elastic",
    "opentelemetry": "opentelemetry",
    "otel": "opentelemetry",
    "jaeger": "jaeger",
    "zipkin": "zipkin",
    "opentracing": "opentracing",
    "envoy": "envoy",
    "istio": "istio",
    "linkerd": "linkerd",
    "consul": "hashicorp",
    "vault": "hashicorp",
    "nomad": "hashicorp",
    "packer": "hashicorp",
    "boundary": "hashicorp",
    "waypoint": "hashicorp",
}


def _normalize_vendor(vendor: str) -> str:
    """Normalize vendor name from CPE to a canonical form."""
    return _VENDOR_ALIASES.get(vendor, vendor)


def _normalize_product(product: str, vendor: str) -> str:
    """Normalize product name from CPE to a canonical form."""
    normalized = _PRODUCT_ALIASES.get(product, product)
    # If product is same as vendor, use vendor name
    if normalized == vendor:
        return vendor
    return normalized


def _extract_affected(configurations: list) -> list[dict]:
    out: dict[tuple[str, str], dict] = {}
    for cfg in configurations or []:
        for node in cfg.get("nodes", []):
            for match in node.get("cpeMatch", []):
                cpe = match.get("criteria", "")
                parts = cpe.split(":")
                if len(parts) < 6 or parts[0] != "cpe":
                    continue
                vendor = parts[3].strip().lower()
                product = parts[4].strip().lower()
                version = parts[5]
                # Skip wildcards and empty values
                if not vendor or vendor in ("*", "-", ""):
                    continue
                if not product or product in ("*", "-", ""):
                    continue
                # Normalize known vendor names
                vendor = _normalize_vendor(vendor)
                product = _normalize_product(product, vendor)
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
                    if lo:
                        parts_range.append(f"{lo_op} {lo}")
                    if hi:
                        parts_range.append(f"{hi_op} {hi}")
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


KIND = "cve"  # produces authoritative CVE records


def run(ctx) -> dict:
    """Fetch recent CVEs from NVD. Returns {"cves": [dict], "pocs": []}."""
    now = datetime.now(timezone.utc).replace(tzinfo=None)
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
                with contextlib.suppress(ValueError):
                    published_at = datetime.strptime(published_iso[:19], "%Y-%m-%dT%H:%M:%S")

            results.append(
                {
                    "source": "NVD",
                    "cve": cve_id,
                    "description": desc[:300],
                    "cvss_score": score,
                    "severity": severity,
                    "cwe_ids": _extract_cwes(cve.get("weaknesses", [])),
                    "affected": _extract_affected(cve.get("configurations", [])),
                    "published_at": published_at,
                }
            )

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
