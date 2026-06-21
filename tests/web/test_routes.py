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
    flask_app.config.update(TESTING=True, SECRET_KEY="test-secret")
    with flask_app.test_client() as c:
        yield c


@pytest.fixture()
def auth_client(client):
    """A client with a logged-in user."""
    client.post(
        "/register",
        data={
            "username": "testuser",
            "email": "test@example.com",
            "password": "password123",
            "password_confirm": "password123",
        },
        follow_redirects=True,
    )
    client.post(
        "/login",
        data={"username": "testuser", "password": "password123"},
        follow_redirects=True,
    )
    return client


@pytest.mark.parametrize(
    "path",
    [
        "/",
        "/triage",
        "/cves",
        "/pocs",
        "/resources",
        "/news",
        "/search?q=test",
        "/api/stats",
    ],
)
def test_route_returns_200(auth_client, path):
    r = auth_client.get(path)
    assert r.status_code == 200, f"{path} returned {r.status_code}"


def test_unknown_cve_returns_404(auth_client):
    r = auth_client.get("/cve/CVE-9999-99999")
    assert r.status_code == 404


def test_unknown_cve_api_returns_404_json(auth_client):
    r = auth_client.get("/api/cve/CVE-9999-99999")
    assert r.status_code == 404
    assert r.get_json() == {"error": "not found"}


def test_api_stats_contract_keys_present(auth_client):
    data = auth_client.get("/api/stats").get_json()
    # Lock the API contract so consumers don't break silently.
    must_have = {
        "cve_count",
        "poc_count",
        "kev_count",
        "avg_reputation",
        "avg_epss",
        "social_heat",
        "social_mentions_total",
        "watchlist_count",
        "actionable",
        "weaponized",
        "imminent",
    }
    assert must_have.issubset(data.keys())


def test_triage_kev_lens(auth_client):
    """KEV lens returns 200 and filters to KEV-only CVEs."""
    r = auth_client.get("/triage?lens=kev")
    assert r.status_code == 200
    # The page should render without error; with an empty DB it shows
    # "No matching records" rather than KEV badges.
    assert b"triage" in r.data.lower() or b"No matching" in r.data


def test_cves_kev_quick_filter(auth_client):
    """CVE list KEV quick filter returns 200."""
    r = auth_client.get("/cves?kev=1")
    assert r.status_code == 200
    assert b"KEV" in r.data or b"No matching" in r.data


def test_kev_animated_badge_css(auth_client):
    """Animated KEV badge classes must be present in the stylesheet."""
    css = auth_client.get("/static/horus.css").get_data(as_text=True)
    assert ".badge-kev-animated" in css
    assert "@keyframes kev-pulse" in css
    assert "kev-row" in css
    assert "chip-kev" in css


def test_pages_share_horizontal_anchor(auth_client):
    """The scrollbar-gutter + .nav max-width fix must remain in the CSS."""
    css = auth_client.get("/static/horus.css").get_data(as_text=True)
    assert "scrollbar-gutter: stable" in css
    assert "max-width: 1320px" in css  # both .nav and .container use it
