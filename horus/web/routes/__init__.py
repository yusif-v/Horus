"""Flask blueprints, one per logical section of the UI."""

from .api import bp as api_bp
from .auth import bp as auth_bp
from .cves import bp as cves_bp
from .dashboard import bp as dashboard_bp
from .pocs import bp as pocs_bp
from .resources import bp as resources_bp
from .search import bp as search_bp
from .triage import bp as triage_bp

ALL_BLUEPRINTS = [
    auth_bp,
    dashboard_bp,
    search_bp,
    triage_bp,
    cves_bp,
    pocs_bp,
    resources_bp,
    api_bp,
]
