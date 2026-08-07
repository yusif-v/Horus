"""Numeric tunables and HTTP defaults. Change these to tweak source behavior."""

import os

from .. import __version__

MAX_REPO_AGE_DAYS = 90
MIN_REPO_STARS = 1

NVD_LOOKBACK_DAYS = 2
NVD_MAX_LOOKBACK_DAYS = 14  # cap when using last-run timestamp

HTTP_TIMEOUT = 30

USER_AGENT = f"Mozilla/5.0 (compatible; Horus-PoC-Scanner/{__version__})"

# ThreatFox API key (override via HORUS_THREATFOX_API_KEY env var)
THREATFOX_API_KEY = os.environ.get(
    "HORUS_THREATFOX_API_KEY",
    "5c31475de44c048c0d17cc8b254d10133e2f190f66952d29",
)
