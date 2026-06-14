"""Zero-trust role gating: explicit role decorators on every route."""

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
        follow_redirects=False,
    )


# Read-only routes that every authenticated role (viewer/analyst/admin) may hit.
READ_ROUTES = [
    "/",
    "/triage",
    "/cves",
    "/pocs",
    "/resources",
    "/api/stats",
]


class TestViewerCanRead:
    def test_viewer_can_read_all_pages(self, client):
        _register(client, "admin1")
        _register(client, "viewer1")  # second user → viewer
        _login(client, "viewer1")
        for path in READ_ROUTES:
            r = client.get(path)
            assert r.status_code == 200, f"{path} returned {r.status_code} for viewer"


class TestViewerCannotAdmin:
    def test_viewer_forbidden_from_admin_users(self, client):
        _register(client, "admin1")
        _register(client, "viewer1")
        _login(client, "viewer1")
        r = client.get("/admin/users")
        assert r.status_code == 403

    def test_viewer_cannot_create_user(self, client):
        _register(client, "admin1")
        _register(client, "viewer1")
        _login(client, "viewer1")
        r = client.post(
            "/admin/users/new",
            data={
                "username": "x",
                "email": "x@example.com",
                "password": "password123",
                "team": "red",
            },
        )
        assert r.status_code == 403


class TestUnauthenticatedRedirects:
    @pytest.mark.parametrize("path", READ_ROUTES)
    def test_anon_redirected_to_login(self, client, path):
        r = client.get(path, follow_redirects=False)
        assert r.status_code == 302
        assert "/login" in r.headers["Location"]


class TestRoleStrippedUserDenied:
    def test_user_with_no_roles_cannot_read(self, client):
        # Register a normal user, then strip their role to simulate
        # an admin demoting them to "no role at all".
        _register(client, "admin1")
        _register(client, "stripped")
        with db.connect() as conn:
            conn.execute(
                "DELETE FROM user_role WHERE user_id = "
                "(SELECT id FROM user WHERE username = 'stripped')"
            )
        _login(client, "stripped")
        # Logged in but roleless → role_required must 403.
        r = client.get("/")
        assert r.status_code == 403

    def test_inactive_user_session_cleared(self, client):
        _register(client, "admin1")
        _register(client, "tmp")
        _login(client, "tmp")
        with db.connect() as conn:
            conn.execute("UPDATE user SET is_active = 0 WHERE username = 'tmp'")
        r = client.get("/", follow_redirects=False)
        # load_user clears the session for deactivated users → redirect to login.
        assert r.status_code == 302
        assert "/login" in r.headers["Location"]
