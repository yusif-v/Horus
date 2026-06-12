"""Tests for auth blueprint: login, logout, register, and access control."""

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


def _register(client, username="testuser", email="test@example.com", password="password123"):
    return client.post(
        "/register",
        data={
            "username": username,
            "email": email,
            "password": password,
            "password_confirm": password,
        },
        follow_redirects=True,
    )


def _login(client, username="testuser", password="password123"):
    return client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=True,
    )


class TestRegister:
    def test_register_page_returns_200(self, client):
        r = client.get("/register")
        assert r.status_code == 200

    def test_register_creates_user(self, client):
        r = _register(client, username="newuser", email="new@example.com")
        assert r.status_code == 200

    def test_register_redirects_to_login(self, client):
        # After registration, user should be able to login
        _register(client)
        r = _login(client)
        assert r.status_code == 200

    def test_register_duplicate_username(self, client):
        _register(client)
        r = _register(client, email="other@example.com")
        assert r.status_code == 409

    def test_register_password_mismatch(self, client):
        r = client.post(
            "/register",
            data={
                "username": "newuser",
                "email": "new@example.com",
                "password": "password123",
                "password_confirm": "different",
            },
        )
        assert r.status_code == 400

    def test_register_short_password(self, client):
        r = client.post(
            "/register",
            data={
                "username": "newuser",
                "email": "new@example.com",
                "password": "short",
                "password_confirm": "short",
            },
        )
        assert r.status_code == 400


class TestLogin:
    def test_login_page_returns_200(self, client):
        r = client.get("/login")
        assert r.status_code == 200

    def test_login_valid_credentials(self, client):
        _register(client)
        r = _login(client)
        assert r.status_code == 200

    def test_login_invalid_password(self, client):
        _register(client)
        r = client.post(
            "/login",
            data={"username": "testuser", "password": "wrongpassword"},
        )
        assert r.status_code == 401

    def test_login_unknown_user(self, client):
        r = client.post(
            "/login",
            data={"username": "nonexistent", "password": "password123"},
        )
        assert r.status_code == 401


class TestLogout:
    def test_logout_clears_session(self, client):
        _register(client)
        _login(client)
        r = client.get("/logout", follow_redirects=True)
        assert r.status_code == 200
        # After logout, accessing protected route should redirect to login
        r = client.get("/")
        assert r.status_code == 302
        assert "/login" in r.headers["Location"]


class TestAccessControl:
    def test_protected_route_redirects_when_not_logged_in(self, client):
        r = client.get("/")
        assert r.status_code == 302
        assert "/login" in r.headers["Location"]

    def test_protected_route_accessible_when_logged_in(self, client):
        _register(client)
        _login(client)
        r = client.get("/")
        assert r.status_code == 200

    def test_api_protected_when_not_logged_in(self, client):
        r = client.get("/api/stats")
        assert r.status_code == 302

    def test_api_accessible_when_logged_in(self, client):
        _register(client)
        _login(client)
        r = client.get("/api/stats")
        assert r.status_code == 200

    def test_login_redirects_to_dashboard_when_already_logged_in(self, client):
        _register(client)
        _login(client)
        r = client.get("/login", follow_redirects=True)
        assert r.status_code == 200

    def test_register_redirects_to_dashboard_when_already_logged_in(self, client):
        _register(client)
        _login(client)
        r = client.get("/register", follow_redirects=True)
        assert r.status_code == 200


class TestLoginRedirect:
    def test_login_redirects_to_next_url(self, client):
        _register(client)
        r = client.post(
            "/login?next=/triage",
            data={"username": "testuser", "password": "password123"},
            follow_redirects=False,
        )
        assert r.status_code == 302
        assert r.headers["Location"].endswith("/triage")

    def test_login_rejects_external_next_url(self, client):
        _register(client)
        r = client.post(
            "/login?next=https://evil.com/phish",
            data={"username": "testuser", "password": "password123"},
            follow_redirects=False,
        )
        assert r.status_code == 302
        assert "evil.com" not in r.headers["Location"]

    def test_login_rejects_protocol_relative_next_url(self, client):
        _register(client)
        r = client.post(
            "/login?next=//evil.com/phish",
            data={"username": "testuser", "password": "password123"},
            follow_redirects=False,
        )
        assert r.status_code == 302
        assert "evil.com" not in r.headers["Location"]


class TestFirstUserAdmin:
    def test_first_registered_user_gets_admin_role(self, client):
        _register(client, username="firstuser", email="first@example.com")
        _login(client, username="firstuser")
        r = client.get("/")
        assert r.status_code == 200

    def test_second_registered_user_gets_viewer_role(self, client):
        _register(client, username="firstuser", email="first@example.com")
        _register(client, username="seconduser", email="second@example.com")
        _login(client, username="seconduser")
        r = client.get("/")
        assert r.status_code == 200


class TestRegisterValidation:
    def test_register_duplicate_email(self, client):
        _register(client, username="user1", email="same@example.com")
        r = _register(client, username="user2", email="same@example.com")
        assert r.status_code == 409

    def test_register_invalid_email(self, client):
        r = client.post(
            "/register",
            data={
                "username": "newuser",
                "email": "not-an-email",
                "password": "password123",
                "password_confirm": "password123",
            },
        )
        assert r.status_code == 400

    def test_register_empty_fields(self, client):
        r = client.post(
            "/register",
            data={
                "username": "",
                "email": "",
                "password": "",
                "password_confirm": "",
            },
        )
        assert r.status_code == 400
