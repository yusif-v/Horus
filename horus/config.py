"""Static configuration: queries, keyword lists, paths, thresholds."""

from pathlib import Path

GITHUB_QUERIES = [
    'CVE-2026 exploit poc',
    'CVE-2025 exploit poc',
    '0day exploit github',
    'RCE PoC CVE',
    'vulnerability exploit proof-of-concept',
]

FRESH_POC_KEYWORDS = [
    'poc', 'exploit', 'proof of concept', 'proof-of-concept', 'rce',
    'remote code execution', '0day', 'zero-day', 'lpe', 'privilege escalation',
    'sql injection', 'xss', 'csrf', 'ssrf', 'arbitrary code',
    'command injection', 'file inclusion', 'deserialization', 'buffer overflow',
    'use-after-free', 'heap overflow', 'sandbox escape', 'kernel',
]

LOW_VALUE_KEYWORDS = [
    'awesome', 'collection', 'list', 'archive', 'database', 'knowledge base',
    'cve list', 'cve database', 'vulnerability database', 'security advisories',
    'weekly digest', 'daily digest', 'newsletter', 'curated list',
]

PROJECT_ROOT = Path(__file__).resolve().parent.parent
STATE_DIR = PROJECT_ROOT / 'state'
STATE_FILE = STATE_DIR / 'seen_items.json'
LAST_RUN_FILE = STATE_DIR / 'last_run.json'

REPORTS_DIR = PROJECT_ROOT / 'reports'

MAX_REPO_AGE_DAYS = 30
MIN_REPO_STARS = 10
NVD_LOOKBACK_DAYS = 2
NVD_MAX_LOOKBACK_DAYS = 14  # cap when using last-run timestamp
HTTP_TIMEOUT = 15

USER_AGENT = 'Mozilla/5.0 (compatible; Horus-PoC-Scanner/0.2)'
