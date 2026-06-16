"""Telegram bot listener — long-polling with command handling.

Usage:
    python -m horus.bot.telegram --token <bot_token>

Commands:
    /start <token>  — Link Horus account via deep-link token
    /help           — Show available commands
    /status         — Show notification preferences summary
    /unlink         — Disconnect Telegram from Horus account
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from datetime import datetime, timezone

from ..storage import db as _storage
from .api import TelegramAPI, TelegramError


def _now_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _handle_start(api: TelegramAPI, chat_id: int, username: str | None, text: str) -> None:
    """Consume a deep-link token and link the user."""
    parts = text.split(maxsplit=1)
    if len(parts) < 2:
        api.send_message(
            chat_id,
            "⚠️ No token provided.\n"
            "Generate a link token in your Horus profile:\n"
            "Profile → Telegram → Generate Link",
        )
        return

    token = parts[1].strip()
    with _storage.connect() as conn:
        row = conn.execute(
            "SELECT user_id FROM telegram_link_token "
            "WHERE token = ? AND used_at IS NULL AND expires_at > ?",
            (token, _now_str()),
        ).fetchone()

        if not row:
            api.send_message(
                chat_id,
                "❌ Invalid or expired token.\n"
                "Generate a new one in your Horus profile.",
            )
            return

        user_id = row[0]
        conn.execute(
            "UPDATE telegram_link_token SET used_at = ? WHERE token = ?",
            (_now_str(), token),
        )
        conn.execute(
            "UPDATE user SET telegram_chat_id = ?, telegram_username = ?, "
            "telegram_linked_at = ? WHERE id = ?",
            (chat_id, username, _now_str(), user_id),
        )

    api.send_message(
        chat_id,
        "✅ *Account linked successfully!*\n\n"
        "You'll receive notifications when:\n"
        "• New KEV additions match your watchlist\n"
        "• Critical CVEs with PoCs appear\n"
        "• EPSS scores jump above 0.5\n\n"
        "Use /status to see your preferences.",
    )


def _handle_help(api: TelegramAPI, chat_id: int) -> None:
    api.send_message(
        chat_id,
        "*Horus CVE Intelligence Bot*\n\n"
        "Commands:\n"
        "• `/start <token>` — Link your Horus account\n"
        "• `/status` — View notification preferences\n"
        "• `/unlink` — Disconnect this Telegram account\n"
        "• `/help` — Show this message\n\n"
        "Generate link tokens at:\n"
        "horus.local/profile/telegram",
    )


def _handle_status(api: TelegramAPI, chat_id: int) -> None:
    """Show user's notification preferences."""
    with _storage.connect() as conn:
        user_row = conn.execute(
            "SELECT id, username FROM user WHERE telegram_chat_id = ?",
            (chat_id,),
        ).fetchone()

    if not user_row:
        api.send_message(chat_id, "❌ No linked account. Use /start <token> first.")
        return

    user_id = user_row[0]
    username = user_row[1]

    with _storage.connect() as conn:
        stored = {
            r[0]: bool(r[1])
            for r in conn.execute(
                "SELECT kind, enabled FROM notification_pref WHERE user_id = ?",
                (user_id,),
            ).fetchall()
        }

    from ...notifications import CATEGORIES, DEFAULT_PREFS

    lines = [f"📋 *Notification Preferences for @{username}*\n"]
    for kind, (label, desc, default) in CATEGORIES.items():
        enabled = stored.get(kind, default)
        icon = "🟢" if enabled else "🔴"
        lines.append(f"{icon} *{label}* — {'ON' if enabled else 'OFF'}")

    api.send_message(chat_id, "\n".join(lines))


def _handle_unlink(api: TelegramAPI, chat_id: int) -> None:
    with _storage.connect() as conn:
        row = conn.execute(
            "SELECT username FROM user WHERE telegram_chat_id = ?",
            (chat_id,),
        ).fetchone()
        if not row:
            api.send_message(chat_id, "❌ No linked account.")
            return

        conn.execute(
            "UPDATE user SET telegram_chat_id = NULL, telegram_username = NULL, "
            "telegram_linked_at = NULL WHERE telegram_chat_id = ?",
            (chat_id, ),
        )
        conn.execute(
            "UPDATE telegram_link_token SET used_at = ? "
            "WHERE user_id = (SELECT id FROM user WHERE telegram_chat_id IS NULL AND username = ?) "
            "AND used_at IS NULL",
            (_now_str(), row[0]),
        )

    api.send_message(chat_id, "✅ Telegram disconnected. You won't receive notifications anymore.")


def _process_update(api: TelegramAPI, update: dict) -> None:
    """Route a single update to the appropriate handler."""
    message = update.get("message")
    if not message:
        return

    chat = message.get("chat", {})
    chat_id = chat.get("id")
    if not chat_id:
        return

    text = message.get("text", "").strip()
    if not text:
        return

    from_user = message.get("from", {})
    username = from_user.get("username")

    if text.startswith("/start"):
        _handle_start(api, chat_id, username, text)
    elif text == "/help":
        _handle_help(api, chat_id)
    elif text == "/status":
        _handle_status(api, chat_id)
    elif text == "/unlink":
        _handle_unlink(api, chat_id)


def run_listener(token: str, poll_timeout: int = 30) -> None:
    """Main long-polling loop. Blocks forever until interrupted."""
    api = TelegramAPI(token)

    # Validate token
    try:
        me = api.get_me()
        print(f"[bot] connected as @{me.get('username', '?')} (id={me.get('id')})", file=sys.stderr)
    except TelegramError as e:
        print(f"[bot] failed to connect: {e}", file=sys.stderr)
        sys.exit(1)

    offset = 0
    print(f"[bot] listening for updates (poll_timeout={poll_timeout}s)...", file=sys.stderr)

    while True:
        try:
            updates = api.get_updates(offset=offset, timeout=poll_timeout)
            for update in updates:
                offset = update["update_id"] + 1
                try:
                    _process_update(api, update)
                except TelegramError as e:
                    print(f"[bot] error processing update: {e}", file=sys.stderr)
        except TelegramError as e:
            print(f"[bot] poll error: {e}", file=sys.stderr)
            time.sleep(5)
        except KeyboardInterrupt:
            print("[bot] shutting down", file=sys.stderr)
            break


def main() -> None:
    parser = argparse.ArgumentParser(description="Horus Telegram bot listener")
    parser.add_argument(
        "--token",
        default=os.environ.get("TELEGRAM_BOT_TOKEN", ""),
        help="Bot token (or TELEGRAM_BOT_TOKEN env var)",
    )
    parser.add_argument(
        "--poll-timeout",
        type=int,
        default=30,
        help="Long-poll timeout in seconds (default: 30)",
    )
    args = parser.parse_args()

    if not args.token:
        print(
            "[bot] ERROR: No token. Set TELEGRAM_BOT_TOKEN or pass --token.",
            file=sys.stderr,
        )
        sys.exit(1)

    run_listener(args.token, args.poll_timeout)


if __name__ == "__main__":
    main()
