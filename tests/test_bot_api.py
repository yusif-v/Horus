"""Telegram Bot API client — focused tests for TelegramAPI wrapper."""

from __future__ import annotations

import urllib.error
from unittest.mock import MagicMock, patch

import pytest


def test_telegram_api_init():
    """TelegramAPI stores token and base URL correctly."""
    from horus.bot.api import TelegramAPI

    api = TelegramAPI("test-token-123", timeout=60)
    assert api._token == "test-token-123"
    assert api._timeout == 60
    assert "test-token-123" in api._base


def test_send_message_calls_api():
    """send_message constructs correct payload and calls _call."""
    from horus.bot.api import TelegramAPI

    api = TelegramAPI("test-token")
    mock_call = MagicMock(return_value={"ok": True})
    api._call = mock_call

    api.send_message(42, "hello world")
    mock_call.assert_called_once()

    # _call is called with positional args: method, payload
    args = mock_call.call_args[0]
    assert args[0] == "sendMessage"
    assert args[1]["chat_id"] == 42
    assert args[1]["text"] == "hello world"


def test_get_updates_calls_api():
    """get_updates passes correct parameters."""
    from horus.bot.api import TelegramAPI

    api = TelegramAPI("test-token")
    mock_call = MagicMock(return_value={"ok": True, "result": []})
    api._call = mock_call

    api.get_updates(offset=100, limit=50, timeout=0)

    args = mock_call.call_args[0]
    assert args[0] == "getUpdates"
    payload = args[1]
    assert payload["limit"] == 50
    assert payload["timeout"] == 0
    assert payload["offset"] == 100


def test_get_me_returns_result():
    """get_me extracts result from response."""
    from horus.bot.api import TelegramAPI

    api = TelegramAPI("test-token")
    mock_call = MagicMock(return_value={"ok": True, "result": {"id": 123, "username": "botname"}})
    api._call = mock_call

    result = api.get_me()
    assert result == {"id": 123, "username": "botname"}


def test_telegram_error_on_non_ok_response():
    """TelegramError raised when API returns ok=false."""
    from horus.bot.api import TelegramAPI, TelegramError

    api = TelegramAPI("test-token")

    def raise_on_non_ok(method, payload, timeout=None):
        raise TelegramError("API error: {'ok': False}")

    api._call = raise_on_non_ok

    with pytest.raises(TelegramError, match="API error"):
        api.send_message(42, "test")


def test_telegram_error_on_http_error():
    """TelegramError raised on HTTPError from urllib."""

    def raise_http_error(*args, **kwargs):
        raise urllib.error.HTTPError("url", 401, "Unauthorized", {}, None)

    with patch("urllib.request.urlopen", side_effect=raise_http_error):
        from horus.bot.api import TelegramAPI, TelegramError

        api = TelegramAPI("test-token")
        with pytest.raises(TelegramError, match="HTTP 401"):
            api.send_message(42, "test")
