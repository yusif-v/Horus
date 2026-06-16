"""Telegram Bot API wrapper — stdlib only, no external deps.

https://core.telegram.org/bots/api
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any


class TelegramAPI:
    """Minimal Telegram Bot API client using only urllib."""

    def __init__(self, token: str, timeout: int = 30):
        self._token = token
        self._timeout = timeout
        self._base = f"https://api.telegram.org/bot{token}"

    def _call(
        self,
        method: str,
        payload: dict[str, Any] | None = None,
        timeout: int | None = None,
    ) -> dict[str, Any]:
        url = f"{self._base}/{method}"
        data = json.dumps(payload).encode() if payload else None
        headers = {"Content-Type": "application/json"}
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout or self._timeout) as resp:
                result: dict[str, Any] = json.loads(resp.read())
                if not result.get("ok"):
                    raise TelegramError(f"API error: {result}")
                return result
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="replace")
            raise TelegramError(f"HTTP {e.code}: {body}") from e
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise TelegramError(f"network error: {e}") from e

    def get_updates(
        self, offset: int = 0, limit: int = 100, timeout: int = 30
    ) -> list[dict[str, Any]]:
        """Long-poll for updates. Set timeout=0 for short poll."""
        payload: dict[str, Any] = {"limit": limit, "timeout": timeout}
        if offset:
            payload["offset"] = offset
        # urlopen must wait at least the long-poll window plus network slack.
        result = self._call("getUpdates", payload, timeout=timeout + 10)
        return result.get("result", [])

    def send_message(
        self,
        chat_id: int,
        text: str,
        parse_mode: str = "Markdown",
        disable_web_page_preview: bool = False,
    ) -> dict[str, Any]:
        return self._call(
            "sendMessage",
            {
                "chat_id": chat_id,
                "text": text,
                "parse_mode": parse_mode,
                "disable_web_page_preview": disable_web_page_preview,
            },
        )

    def get_me(self) -> dict[str, Any]:
        """Get bot info — useful for startup validation."""
        result = self._call("getMe")
        return result.get("result", {})


class TelegramError(Exception):
    pass
