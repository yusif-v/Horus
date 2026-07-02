"""Telegram linking + notification preferences tests."""

from __future__ import annotations

import json

import pytest

from horus.storage import db
from horus.web import app as flask_app


@pytest.fixture(autouse=True)
def _reset():
    db.initialize()
    with db.connect() as conn:
        conn.execute("DELETE FROM notification_pref")
        conn.execute("DELETE FROM telegram_link_token")
        conn.execute("DELETE FROM audit_event")
        conn.execute("DELETE FROM user_role")
        conn.execute("DELETE FROM user")


@pytest.fixture()
def client():
    flask_app.config.update(
        TESTING=True, SECRET_KEY="test-secret", TELEGRAM_BOT_USERNAME="HorusTestBot"
    )
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


class TestAccessControl:
    def test_anon_redirected_telegram(self, client):
        r = client.get("/profile/telegram", follow_redirects=False)
        assert r.status_code == 302
        assert "/login" in r.headers["Location"]

    def test_anon_redirected_notifications(self, client):
        r = client.get("/profile/notifications", follow_redirects=False)
        assert r.status_code == 302
        assert "/login" in r.headers["Location"]

    def test_viewer_can_access_own_profile(self, client):
        _register(client, "admin1")
        _register(client, "viewer1")  # default viewer role
        _login(client, "viewer1")
        r = client.get("/profile/telegram")
        assert r.status_code == 200
        r = client.get("/profile/notifications")
        assert r.status_code == 200


class TestTokenGeneration:
    def test_generate_creates_token(self, client):
        _register(client, "alice")
        _login(client, "alice")
        client.post("/profile/telegram/generate")
        with db.connect() as conn:
            rows = conn.execute(
                "SELECT token, used_at, expires_at FROM telegram_link_token"
            ).fetchall()
        assert len(rows) == 1
        assert rows[0][0]  # token is non-empty
        assert rows[0][1] is None  # not yet used
        assert rows[0][2] > rows[0][1] if rows[0][1] else True

    def test_regenerate_invalidates_prior(self, client):
        _register(client, "alice")
        _login(client, "alice")
        client.post("/profile/telegram/generate")
        client.post("/profile/telegram/generate")
        with db.connect() as conn:
            rows = conn.execute(
                "SELECT token, used_at FROM telegram_link_token ORDER BY created_at"
            ).fetchall()
        assert len(rows) == 2
        # First token must be marked used; second active.
        assert rows[0][1] is not None
        assert rows[1][1] is None

    def test_deep_link_uses_bot_username(self, client):
        _register(client, "alice")
        _login(client, "alice")
        client.post("/profile/telegram/generate")
        r = client.get("/profile/telegram")
        assert b"https://t.me/HorusTestBot?start=" in r.data

    def test_no_token_no_deep_link(self, client):
        _register(client, "alice")
        _login(client, "alice")
        r = client.get("/profile/telegram")
        # No active token yet → deep link absent.
        assert b"t.me/HorusTestBot?start" not in r.data


class TestUnlink:
    def test_unlink_clears_telegram_state(self, client):
        _register(client, "alice")
        _login(client, "alice")
        # Simulate the bot having completed linking.
        with db.connect() as conn:
            conn.execute(
                "UPDATE user SET telegram_chat_id = ?, telegram_username = ?, "
                "telegram_linked_at = ? WHERE username = 'alice'",
                (123456, "alice_tg", "2026-06-15T10:00:00Z"),
            )
        r = client.post("/profile/telegram/unlink", follow_redirects=True)
        assert r.status_code == 200
        with db.connect() as conn:
            row = conn.execute(
                "SELECT telegram_chat_id, telegram_username FROM user WHERE username = 'alice'"
            ).fetchone()
        assert row[0] is None
        assert row[1] is None

    def test_unlink_expires_pending_tokens(self, client):
        _register(client, "alice")
        _login(client, "alice")
        client.post("/profile/telegram/generate")
        client.post("/profile/telegram/unlink")
        with db.connect() as conn:
            row = conn.execute("SELECT used_at FROM telegram_link_token").fetchone()
        assert row[0] is not None


class TestNotificationPrefs:
    def test_defaults_shown_when_no_prefs_stored(self, client):
        _register(client, "alice")
        _login(client, "alice")
        r = client.get("/profile/notifications")
        # kev_new default-on; epss_jump default-off — both rendered.
        assert b"pref_kev_new" in r.data
        assert b"pref_epss_jump" in r.data

    def test_save_writes_prefs(self, client):
        _register(client, "alice")
        _login(client, "alice")
        client.post(
            "/profile/notifications",
            data={
                "pref_kev_new": "on",
                "pref_epss_jump": "on",
                # critical_cve omitted → disabled
            },
        )
        with db.connect() as conn:
            rows = conn.execute(
                "SELECT kind, enabled FROM notification_pref "
                "WHERE user_id = (SELECT id FROM user WHERE username = 'alice')"
            ).fetchall()
        prefs = {r[0]: r[1] for r in rows}
        assert prefs["kev_new"] == 1
        assert prefs["epss_jump"] == 1
        assert prefs["critical_cve"] == 0

    def test_per_user_isolation(self, client):
        _register(client, "alice")
        _register(client, "bob")
        _login(client, "alice")
        client.post(
            "/profile/notifications",
            data={"pref_kev_new": "on", "pref_critical_cve": "on"},
        )
        client.get("/logout")
        _login(client, "bob")
        client.post(
            "/profile/notifications",
            data={},  # bob disables everything
        )
        with db.connect() as conn:
            alice_rows = conn.execute(
                "SELECT kind, enabled FROM notification_pref "
                "WHERE user_id = (SELECT id FROM user WHERE username = 'alice') "
                "AND enabled = 1"
            ).fetchall()
            bob_rows = conn.execute(
                "SELECT kind, enabled FROM notification_pref "
                "WHERE user_id = (SELECT id FROM user WHERE username = 'bob') "
                "AND enabled = 1"
            ).fetchall()
        assert len(alice_rows) >= 2
        assert len(bob_rows) == 0


class TestDashboardBanner:
    def test_banner_shown_when_unlinked(self, client):
        _register(client, "alice")
        _login(client, "alice")
        r = client.get("/")
        assert b"Connect Telegram" in r.data

    def test_banner_hidden_when_linked(self, client):
        _register(client, "alice")
        _login(client, "alice")
        with db.connect() as conn:
            conn.execute("UPDATE user SET telegram_chat_id = 999 WHERE username = 'alice'")
        r = client.get("/")
        assert b"Connect Telegram" not in r.data


class TestAuditTrail:
    def test_token_generation_logged(self, client):
        _register(client, "alice")
        _login(client, "alice")
        client.post("/profile/telegram/generate")
        with db.connect() as conn:
            row = conn.execute(
                "SELECT actor_username, action FROM audit_event "
                "WHERE action = 'telegram.link.token_created'"
            ).fetchone()
        assert row is not None
        assert row[0] == "alice"

    def test_unlink_logged(self, client):
        _register(client, "alice")
        _login(client, "alice")
        with db.connect() as conn:
            conn.execute("UPDATE user SET telegram_chat_id = 999 WHERE username = 'alice'")
        client.post("/profile/telegram/unlink")
        with db.connect() as conn:
            row = conn.execute(
                "SELECT before_json FROM audit_event WHERE action = 'telegram.unlink'"
            ).fetchone()
        assert row is not None
        before = json.loads(row[0])
        assert before["telegram_chat_id"] == 999

    def test_pref_change_logged_with_diff(self, client):
        _register(client, "alice")
        _login(client, "alice")
        # First save with kev on.
        client.post(
            "/profile/notifications",
            data={"pref_kev_new": "on"},
        )
        # Second save flips kev off.
        client.post(
            "/profile/notifications",
            data={},
        )
        with db.connect() as conn:
            rows = conn.execute(
                "SELECT before_json, after_json FROM audit_event "
                "WHERE action = 'notification_pref.update' "
                "ORDER BY id DESC LIMIT 1"
            ).fetchall()
        before = json.loads(rows[0][0])
        after = json.loads(rows[0][1])
        # In the latest event, kev was previously enabled and is now disabled.
        assert before.get("kev_new") is True
        assert after.get("kev_new") is False


class TestSettings:
    def test_settings_get_renders(self, client):
        _register(client, "alice")
        _login(client, "alice")
        r = client.get("/profile/settings")
        assert r.status_code == 200
        assert b"Email" in r.data

    def test_settings_post_updates_email(self, client):
        _register(client, "alice")
        _login(client, "alice")
        client.post(
            "/profile/settings",
            data={"email": "new@example.com", "team": "none", "theme": "system"},
        )
        with db.connect() as conn:
            row = conn.execute("SELECT email FROM user WHERE username = 'alice'").fetchone()
        assert row[0] == "new@example.com"

    def test_settings_post_invalid_email(self, client):
        _register(client, "alice")
        _login(client, "alice")
        r = client.post(
            "/profile/settings",
            data={"email": "bad-email", "team": "none", "theme": "system"},
            follow_redirects=True,
        )
        assert b"valid email" in r.data

    def test_theme_post_sets_valid(self, client):
        _register(client, "alice")
        _login(client, "alice")
        r = client.post("/profile/theme", data={"theme": "dark"})
        assert r.status_code == 204

    def test_theme_post_invalid(self, client):
        _register(client, "alice")
        _login(client, "alice")
        r = client.post("/profile/theme", data={"theme": "invalid"})
        assert r.status_code == 400

    def test_settings_password_change_short_password(self, client):
        _register(client, "alice")
        _login(client, "alice")
        r = client.post(
            "/profile/settings",
            data={
                "email": "alice@example.com",
                "team": "none",
                "theme": "system",
                "new_password": "short",
                "new_password_confirm": "short",
                "current_password": "password123",
            },
            follow_redirects=True,
        )
        assert b"8 characters" in r.data

    def test_settings_password_change_mismatch(self, client):
        _register(client, "alice")
        _login(client, "alice")
        r = client.post(
            "/profile/settings",
            data={
                "email": "alice@example.com",
                "team": "none",
                "theme": "system",
                "new_password": "verylongpassword",
                "new_password_confirm": "differentpassword",
                "current_password": "password123",
            },
            follow_redirects=True,
        )
        assert b"do not match" in r.data

    def test_settings_password_change_no_current(self, client):
        _register(client, "alice")
        _login(client, "alice")
        r = client.post(
            "/profile/settings",
            data={
                "email": "alice@example.com",
                "team": "none",
                "theme": "system",
                "new_password": "verylongpassword",
                "new_password_confirm": "verylongpassword",
            },
            follow_redirects=True,
        )
        assert b"Current password" in r.data
