"""Smoke: every web route returns 200 against a fresh empty DB."""

from __future__ import annotations

import pytest

from horus.storage import db
from horus.web import app as flask_app


@pytest.fixture(scope="module", autouse=True)
def _init_db():
    db.initialize()


@pytest.fixture()
def client():
    flask_app.config.update(TESTING=True)
    with flask_app.test_client() as c:
        yield c


@pytest.mark.parametrize("path", [
    "/", "/triage", "/cves", "/pocs",
    "/search?q=test", "/api/stats",
])
def test_route_returns_200(client, path):
    r = client.get(path)
    assert r.status_code == 200, f"{path} returned {r.status_code}"


def test_unknown_cve_returns_404(client):
    r = client.get("/cve/CVE-9999-99999")
    assert r.status_code == 404


def test_unknown_cve_api_returns_404_json(client):
    r = client.get("/api/cve/CVE-9999-99999")
    assert r.status_code == 404
    assert r.get_json() == {"error": "not found"}


def test_api_stats_contract_keys_present(client):
    data = client.get("/api/stats").get_json()
    # Lock the API contract so consumers don't break silently.
    must_have = {
        "cve_count", "poc_count", "kev_count",
        "avg_reputation", "avg_epss",
        "social_heat", "social_mentions_total", "watchlist_count",
        "actionable", "weaponized", "imminent",
    }
    assert must_have.issubset(data.keys())


def test_pages_share_horizontal_anchor(client):
    """The scrollbar-gutter + .nav max-width fix must remain in the CSS."""
    css = client.get("/static/horus.css").get_data(as_text=True)
    assert "scrollbar-gutter: stable" in css
    assert "max-width: 1320px" in css   # both .nav and .container use it
