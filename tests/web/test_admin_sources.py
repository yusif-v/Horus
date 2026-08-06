"""Tests for the read-only /admin/sources health page."""

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
        conn.execute("DELETE FROM source_health")


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
    _register(client, username="seed_admin")  # first user -> admin
    _register(client, username="viewer1")  # second user -> viewer
    _login(client, username="viewer1")


class TestAdminSourcesPage:
    def test_admin_sees_sources_page(self, client):
        _login_as_admin(client)
        with db.connect() as conn:
            db.upsert_source_health(conn, "nvd", status="ok", cve_count=7)
        r = client.get("/admin/sources")
        assert r.status_code == 200
        assert b"nvd" in r.data

    def test_non_admin_forbidden(self, client):
        _login_as_viewer(client)
        r = client.get("/admin/sources")
        assert r.status_code == 403

    def test_anon_redirected(self, client):
        r = client.get("/admin/sources", follow_redirects=False)
        assert r.status_code == 302
        assert "/login" in r.headers["Location"]

    def test_empty_state(self, client):
        _login_as_admin(client)
        r = client.get("/admin/sources")
        assert r.status_code == 200
        assert b"No source runs recorded yet." in r.data
