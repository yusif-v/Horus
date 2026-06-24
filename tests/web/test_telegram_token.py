"""Telegram link-token generation surfaces a usable token even when the
bot username is not configured (no deep link).

Regression: previously the template hid the generated token entirely behind
`{% if deep_link %}`, so generating a token with TELEGRAM_BOT_USERNAME unset
produced a dead end — a token in the DB the user could never see or use.
"""

from __future__ import annotations

import pytest

from horus.storage import db
from horus.web import app as flask_app


@pytest.fixture()
def auth_client():
    db.initialize()
    flask_app.config.update(TESTING=True, SECRET_KEY="test-secret")
    # Ensure the bot username is unconfigured for this test.
    flask_app.config["TELEGRAM_BOT_USERNAME"] = ""
    with flask_app.test_client() as c:
        c.post(
            "/register",
            data={
                "username": "tguser",
                "email": "tg@example.com",
                "password": "password123",
                "password_confirm": "password123",
            },
            follow_redirects=True,
        )
        c.post(
            "/login",
            data={"username": "tguser", "password": "password123"},
            follow_redirects=True,
        )
        yield c


def test_generate_shows_manual_token_without_bot_username(auth_client):
    # Generate a token.
    r = auth_client.post("/profile/telegram/generate", follow_redirects=True)
    assert r.status_code == 200

    # Find the pending token in the DB.
    with db.connect() as conn:
        row = conn.execute(
            "SELECT token FROM telegram_link_token WHERE used_at IS NULL"
            " ORDER BY created_at DESC LIMIT 1"
        ).fetchone()
    assert row is not None
    token = row[0]

    # The telegram page must surface a usable manual command.
    page = auth_client.get("/profile/telegram")
    assert page.status_code == 200
    assert f"/start {token}".encode() in page.data
