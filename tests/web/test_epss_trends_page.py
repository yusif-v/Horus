"""Test GET /epss-trends dashboard page."""

from __future__ import annotations

from datetime import date, timedelta

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
    client.post(
        "/register",
        data={
            "username": "epsspageuser",
            "email": "epsspage@example.com",
            "password": "password123",
            "password_confirm": "password123",
        },
        follow_redirects=True,
    )
    client.post(
        "/login",
        data={"username": "epsspageuser", "password": "password123"},
        follow_redirects=True,
    )
    return client


def _seed_cve(conn, cve_id="CVE-2026-2000"):
    conn.execute(
        "INSERT OR IGNORE INTO cve (id, description, published_at, cvss_score, kev, cvss_severity, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            cve_id,
            "Test CVE for EPSS page",
            "2026-01-01T00:00:00Z",
            7.5,
            1,
            "HIGH",
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:00:00Z",
        ),
    )


def _seed_epss_history(conn, cve_id, scores):
    today = date.today()
    for i, score in enumerate(scores):
        recorded = (today - timedelta(days=len(scores) - 1 - i)).isoformat()
        conn.execute(
            "INSERT OR IGNORE INTO epss_history (cve_id, score, recorded_at) VALUES (?, ?, ?)",
            (cve_id, score, recorded),
        )


def test_epss_trends_page_returns_200(auth_client):
    r = auth_client.get("/epss-trends")
    assert r.status_code == 200


def test_epss_trends_page_contains_title(auth_client):
    r = auth_client.get("/epss-trends")
    assert b"EPSS" in r.data
    assert b"trends" in r.data.lower()


def test_epss_trends_page_with_days_param(auth_client):
    r = auth_client.get("/epss-trends?days=30")
    assert r.status_code == 200


def test_epss_trends_page_shows_movers(auth_client):
    with db.connect() as conn:
        _seed_cve(conn, "CVE-2026-MOVER1")
        _seed_epss_history(conn, "CVE-2026-MOVER1", [0.05, 0.15, 0.35, 0.55, 0.85])
    r = auth_client.get("/epss-trends?days=30")
    assert r.status_code == 200
    assert b"CVE-2026-MOVER1" in r.data


def test_epss_trends_page_shows_threshold_alerts(auth_client):
    with db.connect() as conn:
        _seed_cve(conn, "CVE-2026-CROSS")
        _seed_epss_history(conn, "CVE-2026-CROSS", [0.3, 0.4, 0.55, 0.6])
    r = auth_client.get("/epss-trends?days=30")
    assert r.status_code == 200
    assert b"CVE-2026-CROSS" in r.data


def test_epss_trends_page_empty_state(auth_client):
    r = auth_client.get("/epss-trends?days=1")
    assert r.status_code == 200
