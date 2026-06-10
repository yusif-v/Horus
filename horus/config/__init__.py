"""Static configuration: paths, queries, keyword lists, tunables.

Submodules:
    paths     — PROJECT_ROOT, STATE_DIR, REPORTS_DIR
    queries   — GITHUB_QUERIES, FRESH_POC_KEYWORDS, LOW_VALUE_KEYWORDS
    tunables  — HTTP_TIMEOUT, NVD_LOOKBACK_DAYS, MIN_REPO_STARS, USER_AGENT, ...

Top-level re-exports below preserve `from horus.config import X` callsites.
"""

from .paths import PROJECT_ROOT, REPORTS_DIR, STATE_DIR
from .queries import FRESH_POC_KEYWORDS, GITHUB_QUERIES, LOW_VALUE_KEYWORDS
from .tunables import (
    HTTP_TIMEOUT,
    MAX_REPO_AGE_DAYS,
    MIN_REPO_STARS,
    NVD_LOOKBACK_DAYS,
    NVD_MAX_LOOKBACK_DAYS,
    USER_AGENT,
)

__all__ = [
    "FRESH_POC_KEYWORDS",
    "GITHUB_QUERIES",
    "HTTP_TIMEOUT",
    "LOW_VALUE_KEYWORDS",
    "MAX_REPO_AGE_DAYS",
    "MIN_REPO_STARS",
    "NVD_LOOKBACK_DAYS",
    "NVD_MAX_LOOKBACK_DAYS",
    "PROJECT_ROOT",
    "REPORTS_DIR",
    "STATE_DIR",
    "USER_AGENT",
]
