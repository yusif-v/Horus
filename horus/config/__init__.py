"""Static configuration: paths, queries, keyword lists, tunables.

Submodules:
    paths     — PROJECT_ROOT, STATE_DIR, REPORTS_DIR
    queries   — GITHUB_QUERIES, FRESH_POC_KEYWORDS, LOW_VALUE_KEYWORDS
    tunables  — HTTP_TIMEOUT, NVD_LOOKBACK_DAYS, MIN_REPO_STARS, USER_AGENT, ...

Top-level re-exports below preserve `from horus.config import X` callsites.
"""

from .paths import PROJECT_ROOT, STATE_DIR, REPORTS_DIR
from .queries import GITHUB_QUERIES, FRESH_POC_KEYWORDS, LOW_VALUE_KEYWORDS
from .tunables import (
    MAX_REPO_AGE_DAYS,
    MIN_REPO_STARS,
    NVD_LOOKBACK_DAYS,
    NVD_MAX_LOOKBACK_DAYS,
    HTTP_TIMEOUT,
    USER_AGENT,
)

__all__ = [
    "PROJECT_ROOT", "STATE_DIR", "REPORTS_DIR",
    "GITHUB_QUERIES", "FRESH_POC_KEYWORDS", "LOW_VALUE_KEYWORDS",
    "MAX_REPO_AGE_DAYS", "MIN_REPO_STARS",
    "NVD_LOOKBACK_DAYS", "NVD_MAX_LOOKBACK_DAYS",
    "HTTP_TIMEOUT", "USER_AGENT",
]
