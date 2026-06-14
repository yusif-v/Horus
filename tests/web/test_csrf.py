"""CSRF protection tests (opt-in: force CSRF on inside the test client).

The default test fixture disables CSRF so existing tests stay terse.
These tests flip `CSRF_FORCE_IN_TESTING` to verify enforcement.
"""

from __future__ import annotations

import re

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
def csrf_client():
    flask_app.config.update(TESTING=True, SECRET_KEY="test-secret", CSRF_FORCE_IN_TESTING=True)
    with flask_app.test_client() as c:
        yield c
    flask_app.config.pop("CSRF_FORCE_IN_TESTING", None)


def _extract_token(html: str) -> str:
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert m, "csrf_token field missing from rendered form"
    return m.group(1)


class TestCSRFEnforcement:
    def test_post_register_without_token_rejected(self, csrf_client):
        r = csrf_client.post(
            "/register",
            data={
                "username": "alice",
                "email": "alice@example.com",
                "password": "password123",
                "password_confirm": "password123",
            },
        )
        assert r.status_code == 400

    def test_post_login_without_token_rejected(self, csrf_client):
        r = csrf_client.post("/login", data={"username": "x", "password": "y"})
        assert r.status_code == 400

    def test_post_with_valid_token_accepted(self, csrf_client):
        # Pull the token from the rendered register form, then submit.
        r = csrf_client.get("/register")
        token = _extract_token(r.get_data(as_text=True))
        r = csrf_client.post(
            "/register",
            data={
                "csrf_token": token,
                "username": "alice",
                "email": "alice@example.com",
                "password": "password123",
                "password_confirm": "password123",
            },
            follow_redirects=True,
        )
        assert r.status_code == 200

    def test_post_with_wrong_token_rejected(self, csrf_client):
        csrf_client.get("/register")  # seed session token
        r = csrf_client.post(
            "/register",
            data={
                "csrf_token": "not-the-right-token",
                "username": "alice",
                "email": "alice@example.com",
                "password": "password123",
                "password_confirm": "password123",
            },
        )
        assert r.status_code == 400

    def test_safe_methods_skip_csrf(self, csrf_client):
        # GET should work without a token even with enforcement on.
        r = csrf_client.get("/login")
        assert r.status_code == 200

    def test_header_token_accepted(self, csrf_client):
        r = csrf_client.get("/register")
        token = _extract_token(r.get_data(as_text=True))
        r = csrf_client.post(
            "/register",
            data={
                "username": "alice",
                "email": "alice@example.com",
                "password": "password123",
                "password_confirm": "password123",
            },
            headers={"X-CSRF-Token": token},
            follow_redirects=True,
        )
        assert r.status_code == 200


class TestCSRFTokenRendering:
    def test_login_form_has_token(self, csrf_client):
        r = csrf_client.get("/login")
        assert b'name="csrf_token"' in r.data

    def test_register_form_has_token(self, csrf_client):
        r = csrf_client.get("/register")
        assert b'name="csrf_token"' in r.data
