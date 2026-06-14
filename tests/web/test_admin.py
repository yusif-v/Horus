"""Tests for admin blueprint: user management + red/blue team field."""

from __future__ import annotations

import pytest

from horus.storage import db
from horus.web import app as flask_app


@pytest.fixture(autouse=True)
def _reset_users():
    db.initialize()
    with db.connect() as conn:
        conn.execute("DELETE FROM user_role")
        conn.execute("DELETE FROM user")


@pytest.fixture()
def client():
    flask_app.config.update(TESTING=True, SECRET_KEY="test-secret")
    with flask_app.test_client() as c:
        yield c


def _register(client, username, email=None, password="password123"):
    return client.post(
        "/register",
        data={
            "username": username,
            "email": email or f"{username}@example.com",
            "password": password,
            "password_confirm": password,
        },
        follow_redirects=True,
    )


def _login(client, username, password="password123"):
    return client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=True,
    )


def _login_as_admin(client, username="admin"):
    # First registered user gets admin role.
    _register(client, username=username)
    _login(client, username=username)


def _login_as_viewer(client):
    _register(client, username="seed_admin")  # first user → admin
    _register(client, username="viewer1")  # second user → viewer
    _login(client, username="viewer1")


class TestAccessControl:
    def test_non_admin_forbidden_from_users_list(self, client):
        _login_as_viewer(client)
        r = client.get("/admin/users")
        assert r.status_code == 403

    def test_anon_redirected_from_users_list(self, client):
        r = client.get("/admin/users", follow_redirects=False)
        assert r.status_code == 302
        assert "/login" in r.headers["Location"]

    def test_admin_can_view_users_list(self, client):
        _login_as_admin(client)
        r = client.get("/admin/users")
        assert r.status_code == 200
        assert b"admin" in r.data


class TestCreateUser:
    def test_admin_creates_user_with_team(self, client):
        _login_as_admin(client)
        r = client.post(
            "/admin/users/new",
            data={
                "username": "alice",
                "email": "alice@example.com",
                "password": "password123",
                "team": "red",
                "roles": ["analyst"],
            },
            follow_redirects=True,
        )
        assert r.status_code == 200
        with db.connect() as conn:
            row = conn.execute("SELECT team FROM user WHERE username = ?", ("alice",)).fetchone()
        assert row is not None
        assert row[0] == "red"

    def test_create_rejects_invalid_team(self, client):
        _login_as_admin(client)
        r = client.post(
            "/admin/users/new",
            data={
                "username": "bob",
                "email": "bob@example.com",
                "password": "password123",
                "team": "purple",
            },
        )
        assert r.status_code == 400

    def test_create_rejects_short_password(self, client):
        _login_as_admin(client)
        r = client.post(
            "/admin/users/new",
            data={
                "username": "bob",
                "email": "bob@example.com",
                "password": "short",
                "team": "blue",
            },
        )
        assert r.status_code == 400


class TestEditUser:
    def test_admin_assigns_team(self, client):
        _login_as_admin(client)
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
        r = client.post(
            f"/admin/users/{uid}/edit",
            data={
                "email": "carol@example.com",
                "team": "blue",
                "is_active": "on",
                "roles": ["viewer"],
            },
            follow_redirects=True,
        )
        assert r.status_code == 200
        with db.connect() as conn:
            row = conn.execute("SELECT team FROM user WHERE id = ?", (uid,)).fetchone()
        assert row[0] == "blue"

    def test_deactivate_user(self, client):
        _login_as_admin(client)
        client.post(
            "/admin/users/new",
            data={
                "username": "dave",
                "email": "dave@example.com",
                "password": "password123",
                "team": "blue",
            },
        )
        with db.connect() as conn:
            uid = conn.execute("SELECT id FROM user WHERE username = 'dave'").fetchone()[0]
        # is_active omitted → unchecked
        client.post(
            f"/admin/users/{uid}/edit",
            data={"email": "dave@example.com", "team": "blue"},
            follow_redirects=True,
        )
        with db.connect() as conn:
            row = conn.execute("SELECT is_active FROM user WHERE id = ?", (uid,)).fetchone()
        assert row[0] == 0


class TestLastAdminGuard:
    def test_cannot_remove_last_admin_role(self, client):
        _login_as_admin(client, username="solo")
        with db.connect() as conn:
            uid = conn.execute("SELECT id FROM user WHERE username = 'solo'").fetchone()[0]
        r = client.post(
            f"/admin/users/{uid}/edit",
            data={
                "email": "solo@example.com",
                "team": "none",
                "is_active": "on",
                "roles": ["viewer"],  # admin removed
            },
        )
        assert r.status_code == 400

    def test_cannot_deactivate_last_admin(self, client):
        _login_as_admin(client, username="solo")
        with db.connect() as conn:
            uid = conn.execute("SELECT id FROM user WHERE username = 'solo'").fetchone()[0]
        r = client.post(
            f"/admin/users/{uid}/edit",
            data={
                "email": "solo@example.com",
                "team": "none",
                "roles": ["admin"],
                # is_active omitted
            },
        )
        assert r.status_code == 400


class TestDelete:
    def test_admin_cannot_delete_self(self, client):
        _login_as_admin(client, username="solo")
        with db.connect() as conn:
            uid = conn.execute("SELECT id FROM user WHERE username = 'solo'").fetchone()[0]
        r = client.post(f"/admin/users/{uid}/delete")
        assert r.status_code == 400

    def test_admin_deletes_other_user(self, client):
        _login_as_admin(client, username="boss")
        client.post(
            "/admin/users/new",
            data={
                "username": "tmp",
                "email": "tmp@example.com",
                "password": "password123",
                "team": "red",
            },
        )
        with db.connect() as conn:
            uid = conn.execute("SELECT id FROM user WHERE username = 'tmp'").fetchone()[0]
        r = client.post(f"/admin/users/{uid}/delete", follow_redirects=True)
        assert r.status_code == 200
        with db.connect() as conn:
            assert conn.execute("SELECT 1 FROM user WHERE id = ?", (uid,)).fetchone() is None
