"""Per-user notification dispatch — decides who to notify and sends via Telegram.

Called at the end of each pipeline run via the on_run_end hook.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone

from ..storage import db as _storage
from ..bot.api import TelegramAPI, TelegramError
from .format import format_event_message
from ..web.notifications import CATEGORIES, DEFAULT_PREFS


def _now_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _user_prefs(conn, user_id: int) -> dict[str, bool]:
    rows = conn.execute(
        "SELECT kind, enabled FROM notification_pref WHERE user_id = ?",
        (user_id,),
    ).fetchall()
    stored = {r[0]: bool(r[1]) for r in rows}
    return {k: stored.get(k, default) for k, default in DEFAULT_PREFS.items()}


def dispatch(events: dict[str, list[dict]], token: str | None = None) -> None:
    """Send Telegram notifications to users based on events from the current pipeline run.

    Events dict keys match CATEGORIES:
        "kev_new"         — list of {"cve_id": ..., "cvss_score": ..., "cvss_severity": ...}
        "epss_jump"       — list of {"cve_id": ..., "epss_score": ...}
        "critical_cve"    — list of {"cve_id": ..., "cvss_score": ..., "cvss_severity": ..., "poc_count": ...}
        "watchlist_match" — list of {"cve_id": ..., "vendor": ..., "product": ..., "team": ...}
        "poc_new"         — list of {"cve_id": ..., "url": ..., "source": ...}
    """
    if not token:
        token = _get_token()
    if not token:
        return

    api = TelegramAPI(token)

    with _storage.connect() as conn:
        # Get all users with Telegram linked
        users = conn.execute(
            "SELECT id, username, telegram_chat_id FROM user "
            "WHERE telegram_chat_id IS NOT NULL"
        ).fetchall()

        if not users:
            return

        for user_row in users:
            user_id = user_row[0]
            username = user_row[1]
            chat_id = user_row[2]

            prefs = _user_prefs(conn, user_id)
            messages = []

            for kind, items in events.items():
                if not items:
                    continue
                if not prefs.get(kind, DEFAULT_PREFS.get(kind, False)):
                    continue

                for item in items:
                    msg = format_event_message(kind, item, username)
                    if msg:
                        messages.append(msg)

            if messages:
                # Batch into one message per user (Telegram has 4096 char limit)
                batched = _batch_messages(messages)
                for batch in batched:
                    try:
                        api.send_message(chat_id, batch)
                    except TelegramError as e:
                        print(f"[notify] failed to notify @{username}: {e}", file=sys.stderr)


def _batch_messages(messages: list[str], max_len: int = 4000) -> list[str]:
    """Split messages into batches that fit Telegram's char limit."""
    batches = []
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


def _get_token() -> str | None:
    """Get bot token from env var."""
    import os
    return os.environ.get("TELEGRAM_BOT_TOKEN") or None
