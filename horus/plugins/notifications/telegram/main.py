"""Telegram notification plugin — per-user dispatch via NotificationContext."""

from __future__ import annotations

from typing import Any

from horus.core.plugin_types import NotificationContext
from horus.notifications.format import format_event_message


def _batch_messages(messages: list[str], max_len: int = 4000) -> list[str]:
    """Split messages into batches that fit Telegram's char limit."""
    batches: list[str] = []
    current = ""
    for msg in messages:
        if len(current) + len(msg) + 2 > max_len:
            if current:
                batches.append(current)
            current = msg
        else:
            current = current + "\n\n" + msg if current else msg
    if current:
        batches.append(current)
    return batches


def notify(events: dict[str, list[dict[str, Any]]], ctx: NotificationContext) -> None:
    if not ctx.token:
        return
    for user_row in ctx.users:
        # user_row shape: (id, username, chat_id)
        _user_id, username, chat_id = user_row[0], user_row[1], user_row[2]
        prefs = ctx.prefs
        messages = []
        for kind, items in events.items():
            if not items:
                continue
            if not prefs.get(kind, False):
                continue
            for item in items:
                msg = format_event_message(kind, item, username)
                if msg:
                    messages.append(msg)
        if messages:
            for batch in _batch_messages(messages):
                ctx.send(chat_id, batch)
