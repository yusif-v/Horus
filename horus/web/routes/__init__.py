"""Flask blueprints, one per logical section of the UI."""

from .admin import bp as admin_bp
from .api import bp as api_bp
from .auth import bp as auth_bp
from .correlations import bp as correlations_bp
from .cves import bp as cves_bp
from .dashboard import bp as dashboard_bp
from .epss_trends import bp as epss_trends_bp
from .news import bp as news_bp
from .pocs import bp as pocs_bp
from .profile import bp as profile_bp
from .resources import bp as resources_bp
from .search import bp as search_bp
from .triage import bp as triage_bp
from .vendors import bp as vendors_bp
from .watchlist import bp as watchlist_bp

ALL_BLUEPRINTS = [
    auth_bp,
    dashboard_bp,
    search_bp,
    triage_bp,
    cves_bp,
    pocs_bp,
    resources_bp,
    news_bp,
    vendors_bp,
    epss_trends_bp,
    correlations_bp,
    api_bp,
    admin_bp,
    watchlist_bp,
    profile_bp,
]
