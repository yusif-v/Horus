"""Triage route tests for KEV due-date filters."""

from __future__ import annotations

import pytest

from horus.storage import db
from horus.web import app as flask_app


@pytest.fixture(autouse=True)
def _reset():
    db.initialize()
    with db.connect() as conn:
        conn.execute("DELETE FROM cve")
        conn.execute("DELETE FROM cve_triage")
        conn.execute("DELETE FROM user_role")
        conn.execute("DELETE FROM user")


@pytest.fixture()
def client():
    flask_app.config.update(TESTING=True, SECRET_KEY="test-secret")
    with flask_app.test_client() as c:
        _register(c, "testuser")
        yield c


def _register(client, username):
    return client.post(
        "/register",
        data={
            "username": username,
            "email": f"{username}@example.com",
            "password": "password123",
            "password_confirm": "password123",
        },
        follow_redirects=True,
    )


def _login(client, username):
    return client.post(
        "/login",
        data={"username": username, "password": "password123"},
        follow_redirects=False,
    )


def _register_cve(cve_id, kev=0, kev_due_date=None):
    with db.connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO cve (id, description, cvss_score, cvss_severity, "
            "first_seen, last_seen, kev, kev_due_date) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                cve_id,
                "Test",
                9.0,
                "CRITICAL",
                "2026-01-01T00:00:00Z",
                "2026-01-01T00:00:00Z",
                kev,
                kev_due_date,
            ),
        )


def test_triage_lens_kev_overdue(client):
    _login(client, "testuser")
    _register_cve("CVE-2023-0001", kev=1, kev_due_date="2025-01-01")
    r = client.get("/triage?lens=kev_overdue")
    assert r.status_code == 200
    assert b"CVE-2023-0001" in r.data


def test_triage_lens_kev_due_soon(client):
    _login(client, "testuser")
    _register_cve("CVE-2026-9999", kev=1, kev_due_date="2026-07-15")
    r = client.get("/triage?lens=kev_due_soon")
    assert r.status_code == 200


def test_triage_lens_all(client):
    _login(client, "testuser")
    _register_cve("CVE-2023-0001", kev=1)
    r = client.get("/triage")
    assert r.status_code == 200
    assert b"CVE-2023-0001" in r.data


def test_triage_lens_imminent(client):
    _login(client, "testuser")
    _register_cve("CVE-2026-0001", kev=0, kev_due_date=None)
    # Set EPSs score >= 0.5
    with db.connect() as conn:
        conn.execute("UPDATE cve SET epss_score = 0.6 WHERE id = 'CVE-2026-0001'")
    r = client.get("/triage?lens=imminent")
    assert r.status_code == 200


def test_triage_status_filter(client):
    _login(client, "testuser")
    _register_cve("CVE-2026-0001", kev=1)
    with db.connect() as conn:
        conn.execute(
            "INSERT INTO cve_triage (cve_id, status, updated_at) VALUES (?, ?, ?)",
            ("CVE-2026-0001", "acknowledged", "2026-01-01T00:00:00Z"),
        )
    r = client.get("/triage?status=acknowledged")
    assert r.status_code == 200


def test_triage_update_with_analyst(client):
    _login(client, "testuser")
    _register_cve("CVE-2026-0001", kev=1)
    # Analyst role CAN write per WRITE_ALL
    r = client.post(
        "/triage/CVE-2026-0001/update",
        data={"status": "working", "assign_self": "on"},
        follow_redirects=True,
    )
    assert r.status_code == 200
    with db.connect() as conn:
        row = conn.execute(
            "SELECT status, assigned_to FROM cve_triage WHERE cve_id = 'CVE-2026-0001'"
        ).fetchone()
    assert row[0] == "working"
