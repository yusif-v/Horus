"""Closed vocabularies and lookup tables for classification.

Locking these lists means downstream grouping, filtering, and graph
clustering all stay coherent. New tags require an intentional edit here.
"""

# ---------------------------------------------------------------------------
# Attack tags
# ---------------------------------------------------------------------------

ATTACK_TAGS: frozenset[str] = frozenset({
    'rce', 'lpe', 'sandbox-escape', 'auth-bypass',
    'sql-injection', 'xss', 'csrf', 'ssrf', 'xxe',
    'deserialization', 'path-traversal', 'command-injection',
    'file-inclusion', 'buffer-overflow', 'use-after-free',
    'heap-overflow', 'race-condition', 'info-disclosure',
    'dos', 'supply-chain', 'crypto-weakness',
})

# CWE → attack tag (authoritative when NVD gives us CWE)
CWE_TO_TAG: dict[str, str] = {
    'CWE-20': 'command-injection',
    'CWE-22': 'path-traversal',
    'CWE-77': 'command-injection',
    'CWE-78': 'command-injection',
    'CWE-79': 'xss',
    'CWE-89': 'sql-injection',
    'CWE-94': 'rce',
    'CWE-119': 'buffer-overflow',
    'CWE-120': 'buffer-overflow',
    'CWE-122': 'heap-overflow',
    'CWE-125': 'info-disclosure',
    'CWE-190': 'buffer-overflow',
    'CWE-200': 'info-disclosure',
    'CWE-269': 'lpe',
    'CWE-287': 'auth-bypass',
    'CWE-295': 'crypto-weakness',
    'CWE-352': 'csrf',
    'CWE-362': 'race-condition',
    'CWE-400': 'dos',
    'CWE-416': 'use-after-free',
    'CWE-434': 'rce',
    'CWE-502': 'deserialization',
    'CWE-611': 'xxe',
    'CWE-732': 'lpe',
    'CWE-787': 'buffer-overflow',
    'CWE-798': 'crypto-weakness',
    'CWE-862': 'auth-bypass',
    'CWE-863': 'auth-bypass',
    'CWE-918': 'ssrf',
    'CWE-1188': 'auth-bypass',
}

# Description keyword → attack tag (fallback when no CWE is present)
KEYWORD_TO_TAG: dict[str, str] = {
    'remote code execution': 'rce',
    'arbitrary code execution': 'rce',
    'arbitrary command': 'command-injection',
    'command injection': 'command-injection',
    'sql injection': 'sql-injection',
    'cross-site scripting': 'xss',
    'cross site scripting': 'xss',
    'cross-site request forgery': 'csrf',
    'server-side request forgery': 'ssrf',
    'xml external entity': 'xxe',
    'deserialization': 'deserialization',
    'path traversal': 'path-traversal',
    'directory traversal': 'path-traversal',
    'file inclusion': 'file-inclusion',
    'buffer overflow': 'buffer-overflow',
    'heap overflow': 'heap-overflow',
    'use-after-free': 'use-after-free',
    'use after free': 'use-after-free',
    'race condition': 'race-condition',
    'privilege escalation': 'lpe',
    'sandbox escape': 'sandbox-escape',
    'authentication bypass': 'auth-bypass',
    'auth bypass': 'auth-bypass',
    'information disclosure': 'info-disclosure',
    'denial of service': 'dos',
    'supply chain': 'supply-chain',
    ' rce ': 'rce',
    ' xss ': 'xss',
    ' csrf ': 'csrf',
    ' ssrf ': 'ssrf',
    ' lpe ': 'lpe',
    ' dos ': 'dos',
}

# ---------------------------------------------------------------------------
# Product categories
# ---------------------------------------------------------------------------

PRODUCT_CATEGORIES: frozenset[str] = frozenset({
    'web-server', 'database', 'cms', 'framework', 'language-runtime',
    'kernel', 'browser', 'mail-server', 'vpn', 'network-device',
    'container', 'ci-cd', 'sdk-library', 'auth-system', 'monitoring',
    'virtualization', 'mobile', 'firmware', 'unknown',
})

# Product name → category. Matched as substring against vendor+product+text.
PRODUCT_TO_CATEGORY: dict[str, str] = {
    # web servers / proxies
    'nginx': 'web-server', 'apache': 'web-server', 'httpd': 'web-server',
    'iis': 'web-server', 'caddy': 'web-server', 'haproxy': 'web-server',
    'tomcat': 'web-server', 'envoy': 'web-server',
    # databases
    'mysql': 'database', 'mariadb': 'database', 'postgres': 'database',
    'postgresql': 'database', 'mongodb': 'database', 'redis': 'database',
    'elasticsearch': 'database', 'sqlite': 'database', 'oracle': 'database',
    'mssql': 'database', 'clickhouse': 'database', 'cassandra': 'database',
    # cms / apps
    'wordpress': 'cms', 'drupal': 'cms', 'joomla': 'cms', 'magento': 'cms',
    'ghost': 'cms', 'strapi': 'cms', 'typo3': 'cms',
    # frameworks
    'django': 'framework', 'flask': 'framework', 'rails': 'framework',
    'laravel': 'framework', 'spring': 'framework', 'express': 'framework',
    'next.js': 'framework', 'nextjs': 'framework', 'fastapi': 'framework',
    'symfony': 'framework', 'struts': 'framework',
    # runtimes
    'node.js': 'language-runtime', 'nodejs': 'language-runtime',
    'python': 'language-runtime', 'php': 'language-runtime',
    'java': 'language-runtime', 'ruby': 'language-runtime',
    'go ': 'language-runtime', 'golang': 'language-runtime',
    'dotnet': 'language-runtime', '.net': 'language-runtime',
    # kernels / os
    'linux kernel': 'kernel', 'windows kernel': 'kernel', 'kernel': 'kernel',
    'freebsd': 'kernel', 'macos': 'kernel', 'darwin': 'kernel',
    # browsers
    'chrome': 'browser', 'chromium': 'browser', 'firefox': 'browser',
    'safari': 'browser', 'edge': 'browser', 'webkit': 'browser',
    # mail
    'exchange': 'mail-server', 'postfix': 'mail-server', 'sendmail': 'mail-server',
    'exim': 'mail-server', 'dovecot': 'mail-server',
    # vpn / network
    'openvpn': 'vpn', 'wireguard': 'vpn', 'pulse secure': 'vpn',
    'fortigate': 'network-device', 'pfsense': 'network-device',
    'cisco': 'network-device', 'juniper': 'network-device',
    'mikrotik': 'network-device',
    # containers / orchestration
    'docker': 'container', 'kubernetes': 'container', 'containerd': 'container',
    'podman': 'container', 'runc': 'container',
    # ci/cd
    'jenkins': 'ci-cd', 'gitlab': 'ci-cd', 'github actions': 'ci-cd',
    'argocd': 'ci-cd', 'teamcity': 'ci-cd',
    # auth
    'keycloak': 'auth-system', 'okta': 'auth-system', 'auth0': 'auth-system',
    'oauth': 'auth-system', 'saml': 'auth-system',
    # monitoring
    'grafana': 'monitoring', 'prometheus': 'monitoring', 'zabbix': 'monitoring',
    'nagios': 'monitoring', 'datadog': 'monitoring',
    # virtualization
    'vmware': 'virtualization', 'vsphere': 'virtualization',
    'hyper-v': 'virtualization', 'kvm': 'virtualization',
    'virtualbox': 'virtualization', 'xen': 'virtualization',
    # mobile
    'android': 'mobile', 'ios': 'mobile',
}
