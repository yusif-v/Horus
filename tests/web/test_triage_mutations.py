"""Triage mutation tests — analyst can write, viewer cannot, audit recorded."""

from __future__ import annotations

import pytest

from horus.storage import db
from horus.web import app as flask_app


@pytest.fixture(autouse=True)
def _reset():
    db.initialize()
    with db.connect() as conn:
        conn.execute("DELETE FROM cve_triage")
        conn.execute("DELETE FROM audit_event")
        conn.execute("DELETE FROM user_role")
        conn.execute("DELETE FROM user")
        conn.execute("DELETE FROM poc_cve")
        conn.execute("DELETE FROM cve")


@pytest.fixture()
def client():
    flask_app.config.update(TESTING=True, SECRET_KEY="test-secret")
    with flask_app.test_client() as c:
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


def _make_analyst(client, username):
    _register(client, "seed_admin")
    _register(client, username)
    with db.connect() as conn:
        conn.execute(
            "DELETE FROM user_role WHERE user_id = (SELECT id FROM user WHERE username = ?)",
            (username,),
        )
        conn.execute(
            "INSERT INTO user_role (user_id, role_id) "
            "SELECT u.id, r.id FROM user u, role r "
            "WHERE u.username = ? AND r.name = 'analyst'",
            (username,),
        )
    _login(client, username)


def _make_viewer(client, username):
    _register(client, "seed_admin")
    _register(client, username)
    # default role from register is 'viewer'
    _login(client, username)


def _add_kev_cve(cve_id):
    """Add a KEV CVE so it shows on the default triage lens."""
    with db.connect() as conn:
        conn.execute(
            "INSERT INTO cve (id, cvss_score, cvss_severity, kev, "
            "published_at, first_seen, last_seen) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (cve_id, 9.0, "CRITICAL", 1, "2026-06-01", "2026-06-01", "2026-06-01"),
        )


class TestAccessControl:
    def test_anon_cannot_update(self, client):
        _add_kev_cve("CVE-2026-0001")
        r = client.post(
            "/triage/CVE-2026-0001/update",
            data={"status": "working"},
            follow_redirects=False,
        )
        assert r.status_code == 302  # redirect to login

    def test_viewer_cannot_update(self, client):
        _add_kev_cve("CVE-2026-0001")
        _make_viewer(client, "viewer1")
        r = client.post(
            "/triage/CVE-2026-0001/update",
            data={"status": "working"},
        )
        assert r.status_code == 403

    def test_analyst_can_update(self, client):
        _add_kev_cve("CVE-2026-0001")
        _make_analyst(client, "analyst1")
        r = client.post(
            "/triage/CVE-2026-0001/update",
            data={"status": "working"},
            follow_redirects=True,
        )
        assert r.status_code == 200
        with db.connect() as conn:
            row = conn.execute(
                "SELECT status FROM cve_triage WHERE cve_id = ?", ("CVE-2026-0001",)
            ).fetchone()
        assert row[0] == "working"


class TestValidation:
    def test_invalid_status_rejected(self, client):
        _add_kev_cve("CVE-2026-0001")
        _make_analyst(client, "analyst1")
        r = client.post(
            "/triage/CVE-2026-0001/update",
            data={"status": "bogus"},
        )
        assert r.status_code == 400

    def test_unknown_cve_404(self, client):
        _make_analyst(client, "analyst1")
        r = client.post(
            "/triage/CVE-1999-9999/update",
            data={"status": "working"},
        )
        assert r.status_code == 404


class TestStateTransitions:
    def test_upsert_creates_then_updates(self, client):
        _add_kev_cve("CVE-2026-0001")
        _make_analyst(client, "analyst1")
        client.post("/triage/CVE-2026-0001/update", data={"status": "acknowledged"})
        client.post(
            "/triage/CVE-2026-0001/update",
            data={"status": "done", "note": "patched"},
        )
        with db.connect() as conn:
            row = conn.execute(
                "SELECT status, note FROM cve_triage WHERE cve_id = ?",
                ("CVE-2026-0001",),
            ).fetchone()
        assert row[0] == "done"
        assert row[1] == "patched"

    def test_assign_self_sets_assignee(self, client):
        _add_kev_cve("CVE-2026-0001")
        _make_analyst(client, "analyst1")
        client.post(
            "/triage/CVE-2026-0001/update",
            data={"status": "working", "assign_self": "on"},
        )
        with db.connect() as conn:
            row = conn.execute(
                "SELECT u.username FROM cve_triage t "
                "JOIN user u ON u.id = t.assigned_to "
                "WHERE t.cve_id = ?",
                ("CVE-2026-0001",),
            ).fetchone()
        assert row[0] == "analyst1"


class TestDismissedFilter:
    def test_dismissed_hidden_by_default(self, client):
        _add_kev_cve("CVE-2026-0001")
        _add_kev_cve("CVE-2026-0002")
        _make_analyst(client, "analyst1")
        client.post("/triage/CVE-2026-0001/update", data={"status": "dismissed"})
        r = client.get("/triage")
        assert b"CVE-2026-0001" not in r.data
        assert b"CVE-2026-0002" in r.data

    def test_dismissed_visible_with_toggle(self, client):
        _add_kev_cve("CVE-2026-0001")
        _make_analyst(client, "analyst1")
        client.post("/triage/CVE-2026-0001/update", data={"status": "dismissed"})
        r = client.get("/triage?show_dismissed=1")
        assert b"CVE-2026-0001" in r.data


class TestAuditTrail:
    def test_update_writes_audit_event(self, client):
        _add_kev_cve("CVE-2026-0001")
        _make_analyst(client, "analyst1")
        client.post(
            "/triage/CVE-2026-0001/update",
            data={"status": "working", "note": "investigating"},
        )
        with db.connect() as conn:
            row = conn.execute(
                "SELECT actor_username, action, target_id, after_json "
                "FROM audit_event WHERE action = 'triage.update'"
            ).fetchone()
        assert row is not None
        assert row[0] == "analyst1"
        assert row[2] == "CVE-2026-0001"
        assert b'"status": "working"' in row[3].encode() or '"working"' in row[3]
