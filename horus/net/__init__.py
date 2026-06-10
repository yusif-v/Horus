"""Transport layer: HTTP helpers, auth, and vendor-specific clients.

Modules:
    http     — fetch_json + a thin urlopen wrapper used by all sources
    auth     — credential lookup (GitHub token, etc.)
    xsearch  — X (Twitter) internal GraphQL client via Chrome cookies

Imported from sources/ and enrichers/; never imports from them.
"""

from .auth import github_token
from .http import fetch_json
from .xsearch import XAuthError, XSearch, XSearchError

__all__ = ["XAuthError", "XSearch", "XSearchError", "fetch_json", "github_token"]
