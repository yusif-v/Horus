"""Numeric tunables and HTTP defaults. Change these to tweak source behavior."""

from .. import __version__

MAX_REPO_AGE_DAYS = 30
MIN_REPO_STARS = 10

NVD_LOOKBACK_DAYS = 2
NVD_MAX_LOOKBACK_DAYS = 14  # cap when using last-run timestamp

HTTP_TIMEOUT = 30

USER_AGENT = f"Mozilla/5.0 (compatible; Horus-PoC-Scanner/{__version__})"
