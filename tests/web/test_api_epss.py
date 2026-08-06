"""Test GET /api/cve/<id>/epss-trend and GET /api/epss-trends endpoints."""

from __future__ import annotations

import json
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
            "username": "epssuser",
            "email": "epss@example.com",
            "password": "password123",
            "password_confirm": "password123",
        },
        follow_redirects=True,
    )
    client.post(
        "/login",
        data={"username": "epssuser", "password": "password123"},
        follow_redirects=True,
    )
    return client


def _seed_cve(conn, cve_id="CVE-2026-1000"):
    conn.execute(
        "INSERT OR IGNORE INTO cve (id, description, published_at, cvss_score, kev, cvss_severity, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            cve_id,
            "Test CVE for EPSS",
            "2026-01-01T00:00:00Z",
            8.1,
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


def test_epss_trend_endpoint(auth_client):
    with db.connect() as conn:
        _seed_cve(conn)
        _seed_epss_history(conn, "CVE-2026-1000", [0.1, 0.2, 0.3, 0.5, 0.7])
    r = auth_client.get("/api/cve/CVE-2026-1000/epss-trend")
    assert r.status_code == 200
    body = json.loads(r.data)
    assert body["cve_id"] == "CVE-2026-1000"
    assert body["current_score"] == 0.7
    assert "velocity" in body
    assert "trend" in body
    assert "days_above_50pct" in body
    assert "history" in body
    assert len(body["history"]) == 5


def test_epss_trend_empty(auth_client):
    with db.connect() as conn:
        _seed_cve(conn, "CVE-2026-EMPTY")
    r = auth_client.get("/api/cve/CVE-2026-EMPTY/epss-trend")
    assert r.status_code == 200
    body = json.loads(r.data)
    assert body["cve_id"] == "CVE-2026-EMPTY"
    assert body["current_score"] is None
    assert body["history"] == []


def test_epss_trends_endpoint(auth_client):
    with db.connect() as conn:
        _seed_cve(conn, "CVE-2026-MOVER")
        _seed_epss_history(conn, "CVE-2026-MOVER", [0.05, 0.15, 0.35, 0.55, 0.85])
    r = auth_client.get("/api/epss-trends?days=30")
    assert r.status_code == 200
    body = json.loads(r.data)
    assert "movers" in body
    assert "threshold_alerts" in body


def test_epss_trends_default_params(auth_client):
    r = auth_client.get("/api/epss-trends")
    assert r.status_code == 200
    body = json.loads(r.data)
    assert "movers" in body
    assert "threshold_alerts" in body


def test_epss_trends_with_limit(auth_client):
    r = auth_client.get("/api/epss-trends?days=30&limit=5")
    assert r.status_code == 200
    body = json.loads(r.data)
    assert isinstance(body["movers"], list)
