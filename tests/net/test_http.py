"""Tests for horus/net/http.py — HTTP fetch with retry logic."""

from __future__ import annotations

import json
import urllib.error
from unittest.mock import MagicMock, patch

from horus.net.http import fetch_json


def _make_response(data: dict) -> MagicMock:
    """Create a mock response that works as a context manager."""
    resp = MagicMock()
    resp.read.return_value = json.dumps(data).encode()
    resp.__enter__ = MagicMock(return_value=resp)
    resp.__exit__ = MagicMock(return_value=False)
    return resp


def test_fetch_json_returns_parsed_data():
    mock_resp = _make_response({"key": "value"})
    with patch("horus.net.http.urllib.request.urlopen", return_value=mock_resp):
        result = fetch_json("https://example.com/api")
    assert result == {"key": "value"}


def test_fetch_json_retries_on_500():
    mock_resp = _make_response({"ok": True})

    call_count = 0

    def fake_urlopen(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count < 3:
            raise urllib.error.HTTPError("https://example.com", 500, "Server Error", {}, None)
        return mock_resp

    with patch("horus.net.http.urllib.request.urlopen", side_effect=fake_urlopen):
        with patch("horus.net.http.time.sleep"):
            result = fetch_json("https://example.com/api", max_retries=3, base_delay=0.01)
    assert result == {"ok": True}
    assert call_count == 3


def test_fetch_json_raises_on_4xx():
    with patch("horus.net.http.urllib.request.urlopen") as mock_open:
        mock_open.side_effect = urllib.error.HTTPError(
            "https://example.com", 403, "Forbidden", {}, None
        )
        try:
            fetch_json("https://example.com/api")
            assert False, "Should have raised"
        except urllib.error.HTTPError as e:
            assert e.code == 403


def test_fetch_json_raises_after_max_retries():
    with patch("horus.net.http.urllib.request.urlopen") as mock_open:
        mock_open.side_effect = urllib.error.HTTPError(
            "https://example.com", 503, "Service Unavailable", {}, None
        )
        with patch("horus.net.http.time.sleep"):
            try:
                fetch_json("https://example.com/api", max_retries=2, base_delay=0.01)
                assert False, "Should have raised"
            except urllib.error.HTTPError:
                pass


def test_fetch_json_merges_user_agent():
    mock_resp = _make_response({"ok": True})
    with patch("horus.net.http.urllib.request.urlopen", return_value=mock_resp) as mock_open:
        fetch_json("https://example.com/api")
        call_args = mock_open.call_args
        req = call_args[0][0]
        # urllib normalizes header names; check case-insensitively
        headers_lower = {k.lower(): v for k, v in req.headers.items()}
        assert "user-agent" in headers_lower


def test_fetch_json_sends_accept_header():
    mock_resp = _make_response({"ok": True})
    with patch("horus.net.http.urllib.request.urlopen", return_value=mock_resp) as mock_open:
        fetch_json("https://example.com/api", accept="application/json")
        call_args = mock_open.call_args
        req = call_args[0][0]
        headers = dict(req.headers)
        assert headers.get("Accept") == "application/json"


def test_fetch_json_merges_custom_headers():
    mock_resp = _make_response({"ok": True})
    with patch("horus.net.http.urllib.request.urlopen", return_value=mock_resp) as mock_open:
        fetch_json("https://example.com/api", headers={"Authorization": "Bearer token123"})
        call_args = mock_open.call_args
        req = call_args[0][0]
        headers = dict(req.headers)
        assert "Authorization" in headers


# ── Additional coverage for uncovered branches ─────────────────────────────


def test_fetch_json_retries_on_429():
    """Covers lines 35-37: retry on HTTP 429 (rate limit)."""
    mock_resp = _make_response({"ok": True})
    call_count = 0

    def fake_urlopen(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count < 2:
            raise urllib.error.HTTPError("https://example.com", 429, "Too Many Requests", {}, None)
        return mock_resp

    with patch("horus.net.http.urllib.request.urlopen", side_effect=fake_urlopen):
        with patch("horus.net.http.time.sleep"):
            result = fetch_json("https://example.com/api", max_retries=3, base_delay=0.01)
    assert result == {"ok": True}
    assert call_count == 2


def test_fetch_json_respects_retry_after_header():
    """Covers lines 38-44: Retry-After header is respected on 429."""
    mock_resp = _make_response({"ok": True})
    call_count = 0
    sleep_calls = []

    def fake_urlopen(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count < 2:
            from email.message import Message

            headers = Message()
            headers["Retry-After"] = "5"
            raise urllib.error.HTTPError(
                "https://example.com", 429, "Too Many Requests", headers, None
            )
        return mock_resp

    def fake_sleep(seconds):
        sleep_calls.append(seconds)

    with patch("horus.net.http.urllib.request.urlopen", side_effect=fake_urlopen):
        with patch("horus.net.http.time.sleep", side_effect=fake_sleep):
            result = fetch_json("https://example.com/api", max_retries=3, base_delay=0.01)
    assert result == {"ok": True}
    assert sleep_calls[0] == 5.0  # Respects Retry-After


def test_fetch_json_retries_on_urlerror():
    """Covers lines 49-53: retry on URLError (network issues)."""
    mock_resp = _make_response({"ok": True})
    call_count = 0

    def fake_urlopen(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count < 3:
            raise urllib.error.URLError("Connection refused")
        return mock_resp

    with patch("horus.net.http.urllib.request.urlopen", side_effect=fake_urlopen):
        with patch("horus.net.http.time.sleep"):
            result = fetch_json("https://example.com/api", max_retries=3, base_delay=0.01)
    assert result == {"ok": True}
    assert call_count == 3


def test_fetch_json_retries_on_timeout_error():
    """Covers lines 49-53: retry on TimeoutError."""
    mock_resp = _make_response({"ok": True})
    call_count = 0

    def fake_urlopen(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count < 2:
            raise TimeoutError("timed out")
        return mock_resp

    with patch("horus.net.http.urllib.request.urlopen", side_effect=fake_urlopen):
        with patch("horus.net.http.time.sleep"):
            result = fetch_json("https://example.com/api", max_retries=3, base_delay=0.01)
    assert result == {"ok": True}
    assert call_count == 2


def test_fetch_json_non_retryable_4xx_raises_immediately():
    """Lines 48: 4xx errors (except 429) are raised immediately without retry."""
    call_count = 0

    def fake_urlopen(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        raise urllib.error.HTTPError("https://example.com", 404, "Not Found", {}, None)

    with patch("horus.net.http.urllib.request.urlopen", side_effect=fake_urlopen):
        try:
            fetch_json("https://example.com/api", max_retries=5, base_delay=0.01)
            assert False, "Should have raised"
        except urllib.error.HTTPError as e:
            assert e.code == 404
    assert call_count == 1  # No retries


def test_fetch_json_retry_after_invalid_falls_back_to_delay():
    """Lines 43-44: Invalid Retry-After value falls back to exponential backoff."""
    mock_resp = _make_response({"ok": True})
    call_count = 0

    def fake_urlopen(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count < 2:
            from email.message import Message

            headers = Message()
            headers["Retry-After"] = "not-a-number"
            raise urllib.error.HTTPError("https://example.com", 429, "Rate limited", headers, None)
        return mock_resp

    with patch("horus.net.http.urllib.request.urlopen", side_effect=fake_urlopen):
        with patch("horus.net.http.time.sleep"):
            result = fetch_json("https://example.com/api", max_retries=3, base_delay=0.01)
    assert result == {"ok": True}
