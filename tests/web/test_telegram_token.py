"""Telegram link-token generation surfaces a usable token even when the
bot username is not configured (no deep link).

Regression: previously the template hid the generated token entirely behind
`{% if deep_link %}`, so generating a token with TELEGRAM_BOT_USERNAME unset
produced a dead end — a token in the DB the user could never see or use.
"""

from __future__ import annotations

import re

import pytest

from horus.storage import db
from horus.web import app as flask_app


@pytest.fixture()
def auth_client(monkeypatch):
    db.initialize()
    flask_app.config.update(TESTING=True, SECRET_KEY="test-secret")
    # Ensure the bot username is unconfigured for this test — clear BOTH the
    # app config and the env var, since _bot_username() falls back to env.
    flask_app.config["TELEGRAM_BOT_USERNAME"] = ""
    monkeypatch.delenv("TELEGRAM_BOT_USERNAME", raising=False)
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

    # The telegram page must surface a usable manual command. Parse the token
    # from the page itself (the shared test DB has tokens for other users, so
    # a global "latest pending token" DB query is not reliable here).
    page = auth_client.get("/profile/telegram")
    assert page.status_code == 200
    body = page.get_data(as_text=True)
    m = re.search(r"/start (\S+)", body)
    assert m, "manual /start command not rendered"
    # No deep link should appear when the bot username is unconfigured.
    assert "t.me/" not in body


def test_generate_renders_deep_link_when_bot_username_set(monkeypatch):
    db.initialize()
    flask_app.config.update(TESTING=True, SECRET_KEY="test-secret")
    monkeypatch.setenv("TELEGRAM_BOT_USERNAME", "CVEHorusbot")
    flask_app.config["TELEGRAM_BOT_USERNAME"] = "CVEHorusbot"
    with flask_app.test_client() as c:
        c.post(
            "/register",
            data={
                "username": "tgdl",
                "email": "tgdl@example.com",
                "password": "password123",
                "password_confirm": "password123",
            },
            follow_redirects=True,
        )
        c.post(
            "/login",
            data={"username": "tgdl", "password": "password123"},
            follow_redirects=True,
        )
        c.post("/profile/telegram/generate", follow_redirects=True)
        page = c.get("/profile/telegram")

    assert page.status_code == 200
    # The page must render this user's deep link (token parsed from the page,
    # not a global DB query, so the assertion is order-independent).
    assert re.search(r"https://t\.me/CVEHorusbot\?start=\S+", page.get_data(as_text=True))
