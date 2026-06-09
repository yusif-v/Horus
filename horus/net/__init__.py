"""Transport layer: HTTP helpers, auth, and vendor-specific clients.

Modules:
    http     — fetch_json + a thin urlopen wrapper used by all sources
    auth     — credential lookup (GitHub token, etc.)
    xsearch  — X (Twitter) internal GraphQL client via Chrome cookies

Imported from sources/ and enrichers/; never imports from them.
"""

from .http import fetch_json
from .auth import github_token
from .xsearch import XSearch, XSearchError, XAuthError

__all__ = ["fetch_json", "github_token", "XSearch", "XSearchError", "XAuthError"]
