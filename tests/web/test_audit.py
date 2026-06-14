"""Audit log tests: helper, integration with admin + watchlist, retention."""

from __future__ import annotations

import json

import pytest

from horus.storage import db
from horus.web import app as flask_app


@pytest.fixture(autouse=True)
def _reset():
    db.initialize()
    with db.connect() as conn:
        conn.execute("DELETE FROM audit_event")
        conn.execute("DELETE FROM team_watchlist")
        conn.execute("DELETE FROM user_role")
        conn.execute("DELETE FROM user")


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


def _events(action: str | None = None) -> list[dict]:
    with db.connect() as conn:
        if action:
            rows = conn.execute(
                "SELECT * FROM audit_event WHERE action = ? ORDER BY id", (action,)
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM audit_event ORDER BY id").fetchall()
    return [dict(r) for r in rows]


class TestAdminAudit:
    def test_user_create_logged(self, client):
        _register(client, "admin1")
        _login(client, "admin1")
        client.post(
            "/admin/users/new",
            data={
                "username": "alice",
                "email": "alice@example.com",
                "password": "password123",
                "team": "red",
                "roles": ["analyst"],
            },
        )
        events = _events("user.create")
        assert len(events) == 1
        e = events[0]
        assert e["actor_username"] == "admin1"
        assert e["target_type"] == "user"
        after = json.loads(e["after_json"])
        assert after["username"] == "alice"
        assert after["team"] == "red"
        assert "password_hash" not in e["after_json"]

    def test_user_update_logged(self, client):
        _register(client, "admin1")
        _login(client, "admin1")
        client.post(
            "/admin/users/new",
            data={
                "username": "bob",
                "email": "bob@example.com",
                "password": "password123",
                "team": "none",
            },
        )
        with db.connect() as conn:
            uid = conn.execute("SELECT id FROM user WHERE username = 'bob'").fetchone()[0]
        client.post(
            f"/admin/users/{uid}/edit",
            data={
                "email": "bob@example.com",
                "team": "blue",
                "is_active": "on",
                "roles": ["analyst"],
            },
        )
        events = _events("user.update")
        assert len(events) == 1
        before = json.loads(events[0]["before_json"])
        after = json.loads(events[0]["after_json"])
        assert before["team"] == "none"
        assert after["team"] == "blue"
        assert after["roles"] == ["analyst"]
        assert after["password_changed"] is False

    def test_password_change_flagged_but_not_logged(self, client):
        _register(client, "admin1")
        _login(client, "admin1")
        client.post(
            "/admin/users/new",
            data={
                "username": "carol",
                "email": "carol@example.com",
                "password": "password123",
                "team": "none",
            },
        )
        with db.connect() as conn:
            uid = conn.execute("SELECT id FROM user WHERE username = 'carol'").fetchone()[0]
        client.post(
            f"/admin/users/{uid}/edit",
            data={
                "email": "carol@example.com",
                "team": "none",
                "is_active": "on",
                "password": "newpassword456",
                "roles": ["viewer"],
            },
        )
        events = _events("user.update")
        after = json.loads(events[0]["after_json"])
        assert after["password_changed"] is True
        # The new password itself must never appear in the audit row.
        assert "newpassword456" not in events[0]["after_json"]
        assert "password_hash" not in events[0]["after_json"]

    def test_user_delete_logged(self, client):
        _register(client, "admin1")
        _login(client, "admin1")
        client.post(
            "/admin/users/new",
            data={
                "username": "dave",
                "email": "dave@example.com",
                "password": "password123",
                "team": "none",
            },
        )
        with db.connect() as conn:
            uid = conn.execute("SELECT id FROM user WHERE username = 'dave'").fetchone()[0]
        client.post(f"/admin/users/{uid}/delete")
        events = _events("user.delete")
        assert len(events) == 1
        before = json.loads(events[0]["before_json"])
        assert before["username"] == "dave"


class TestWatchlistAudit:
    def test_add_logged(self, client):
        _register(client, "admin1")
        _login(client, "admin1")
        client.post(
            "/watchlist/add",
            data={"team": "red", "vendor": "acme", "product": "vpn"},
        )
        events = _events("watchlist.add")
        assert len(events) == 1
        after = json.loads(events[0]["after_json"])
        assert after["team"] == "red"
        assert after["vendor"] == "acme"

    def test_delete_logged(self, client):
        _register(client, "admin1")
        _login(client, "admin1")
        client.post(
            "/watchlist/add",
            data={"team": "red", "vendor": "acme", "product": "vpn"},
        )
        with db.connect() as conn:
            entry_id = conn.execute("SELECT id FROM team_watchlist").fetchone()[0]
        client.post(f"/watchlist/{entry_id}/delete")
        events = _events("watchlist.delete")
        assert len(events) == 1
        before = json.loads(events[0]["before_json"])
        assert before["vendor"] == "acme"


class TestAuditPage:
    def test_non_admin_denied(self, client):
        _register(client, "admin1")
        _register(client, "viewer1")
        _login(client, "viewer1")
        r = client.get("/admin/audit")
        assert r.status_code == 403

    def test_admin_can_view(self, client):
        _register(client, "admin1")
        _login(client, "admin1")
        client.post(
            "/admin/users/new",
            data={
                "username": "xyz",
                "email": "xyz@example.com",
                "password": "password123",
                "team": "red",
            },
        )
        r = client.get("/admin/audit")
        assert r.status_code == 200
        assert b"user.create" in r.data
        assert b"admin1" in r.data

    def test_filter_by_action(self, client):
        _register(client, "admin1")
        _login(client, "admin1")
        client.post(
            "/admin/users/new",
            data={
                "username": "xyz",
                "email": "xyz@example.com",
                "password": "password123",
                "team": "red",
            },
        )
        client.post(
            "/watchlist/add",
            data={"team": "red", "vendor": "acme", "product": "vpn"},
        )
        r = client.get("/admin/audit?action=watchlist.add")
        # The action string appears as both an option label and a row chip;
        # check for the row-specific content instead.
        assert b"acme" in r.data  # watchlist row shown
        assert b"xyz@example.com" not in r.data  # user.create row filtered out


class TestRetentionAcrossUserDeletion:
    def test_actor_username_preserved_after_user_deleted(self, client):
        _register(client, "admin1")
        _register(client, "admin2")
        # Make admin2 an admin so they can delete admin1 later.
        with db.connect() as conn:
            conn.execute(
                "INSERT INTO user_role (user_id, role_id) "
                "SELECT u.id, r.id FROM user u, role r "
                "WHERE u.username = 'admin2' AND r.name = 'admin'"
            )
        _login(client, "admin1")
        # admin1 creates a user — this audit row's actor is admin1.
        client.post(
            "/admin/users/new",
            data={
                "username": "ghost",
                "email": "g@example.com",
                "password": "password123",
                "team": "red",
            },
        )
        client.get("/logout")
        _login(client, "admin2")
        with db.connect() as conn:
            uid = conn.execute("SELECT id FROM user WHERE username = 'admin1'").fetchone()[0]
        client.post(f"/admin/users/{uid}/delete")

        with db.connect() as conn:
            row = conn.execute(
                "SELECT actor_id, actor_username FROM audit_event "
                "WHERE action = 'user.create' AND actor_username = 'admin1'"
            ).fetchone()
        assert row is not None
        # FK ON DELETE SET NULL means actor_id is now NULL but the username
        # snapshot is preserved.
        assert row[0] is None
        assert row[1] == "admin1"
