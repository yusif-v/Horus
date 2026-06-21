"""Telegram bot listener — long-polling with command handling.

Usage:
    python -m horus.bot.telegram --token <bot_token>

Commands:
    /start <token>  — Link Horus account via deep-link token (only pre-link command)
    /help           — Show available commands (open)
    /whoami         — Show Horus account bound to this chat
    /status         — Show notification preferences summary
    /unlink         — Disconnect Telegram from Horus account
    /cve <query>    — Search CVEs by ID or keyword (top 10)
    /kev            — Latest 10 known-exploited CVEs
    /top            — Top 10 CVEs by EPSS
    /poc <query>    — Search PoCs by URL/description (top 10)

All commands except /start and /help require the chat to be linked to a
Horus account; anything else returns an "access restricted" message.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import time
from datetime import datetime, timezone

from ..storage import db as _storage
from .api import TelegramAPI, TelegramError


def _now_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _base_url() -> str:
    return os.environ.get("HORUS_BASE_URL", "http://localhost:8080").rstrip("/")


def _md_escape(text: str) -> str:
    """Escape characters that break Telegram Markdown (legacy mode)."""
    return text.replace("_", r"\_").replace("*", r"\*").replace("`", r"\`").replace("[", r"\[")


def _linked_user(chat_id: int) -> dict | None:
    """Return user row (dict) for a linked chat, or None if not linked."""
    with _storage.connect() as conn:
        row = conn.execute(
            "SELECT id, username, email, team, telegram_username, telegram_linked_at"
            " FROM user WHERE telegram_chat_id = ?",
            (chat_id,),
        ).fetchone()
    return dict(row) if row else None


def _not_linked_message(api: TelegramAPI, chat_id: int) -> None:
    api.send_message(
        chat_id,
        "🔒 *Access restricted*\n\n"
        "This bot is only for registered Horus users. To use it, you need a "
        "Horus account and a one-time link token:\n\n"
        f"1. Sign in at {_base_url()}\n"
        "2. Go to *Profile → Telegram → Generate link token*\n"
        "3. Tap the resulting link or send `/start <token>` here.",
    )


def _fmt_cve_row(cve: dict) -> str:
    """One-line CVE summary for Telegram lists."""
    cid = cve["id"]
    score = cve.get("cvss_score")
    sev = (cve.get("cvss_severity") or "").upper()[:4]
    epss = cve.get("epss_score")
    kev = "🚨" if cve.get("kev") else ""
    parts = [f"[{cid}]({_base_url()}/cve/{cid})"]
    if score is not None:
        parts.append(f"CVSS {score}")
    if sev:
        parts.append(sev)
    if epss is not None:
        parts.append(f"EPSS {epss * 100:.1f}%")
    if kev:
        parts.append(kev + " KEV")
    head = " · ".join(parts)
    desc = (cve.get("description") or "").strip()
    if desc:
        desc = _md_escape(desc[:140] + ("…" if len(desc) > 140 else ""))
        return f"• {head}\n  {desc}"
    return f"• {head}"


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
                "❌ Invalid or expired token.\nGenerate a new one in your Horus profile.",
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
        "*Account*\n"
        "• `/start <token>` — Link your Horus account\n"
        "• `/whoami` — Show the Horus user bound to this chat\n"
        "• `/status` — View notification preferences\n"
        "• `/unlink` — Disconnect this Telegram account\n\n"
        "*Queries*\n"
        "• `/cve <id|keyword>` — Lookup or keyword search (top 10)\n"
        "• `/kev` — Latest 10 known-exploited CVEs\n"
        "• `/top` — Top 10 CVEs by EPSS\n"
        "• `/poc <keyword>` — Search public PoCs (top 10)\n\n"
        f"Web UI: {_base_url()}",
    )


def _handle_whoami(api: TelegramAPI, chat_id: int, user: dict) -> None:
    linked = user.get("telegram_linked_at") or "—"
    team = (user.get("team") or "none").upper()
    tg_handle = user.get("telegram_username")
    handle = f"@{tg_handle}" if tg_handle else "(no Telegram handle)"
    api.send_message(
        chat_id,
        "👤 *Identity*\n\n"
        f"• Horus user: `{_md_escape(user['username'])}`\n"
        f"• Email: `{_md_escape(user.get('email') or '—')}`\n"
        f"• Team: `{team}`\n"
        f"• Telegram: {_md_escape(handle)} (chat\\_id `{chat_id}`)\n"
        f"• Linked at: `{linked}`",
    )


def _handle_cve(api: TelegramAPI, chat_id: int, text: str) -> None:
    """Lookup by CVE-ID or keyword search across description/products."""
    parts = text.split(maxsplit=1)
    if len(parts) < 2 or not parts[1].strip():
        api.send_message(chat_id, "Usage: `/cve <CVE-ID or keyword>`\nExample: `/cve Windows`")
        return
    query = parts[1].strip()
    is_cve_id = bool(re.match(r"(?i)cve-\d{4}-\d{4,}", query))

    with _storage.connect() as conn:
        pattern = f"%{query}%"
        if is_cve_id:
            rows = conn.execute(
                "SELECT id, cvss_score, cvss_severity, description, epss_score, kev,"
                " published_at FROM cve WHERE id = ? COLLATE NOCASE LIMIT 1",
                (query.upper(),),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT DISTINCT c.id, c.cvss_score, c.cvss_severity, c.description,"
                " c.epss_score, c.kev, c.published_at"
                " FROM cve c"
                " LEFT JOIN cve_product cp ON cp.cve_id = c.id"
                " LEFT JOIN product p ON p.id = cp.product_id"
                " WHERE c.description LIKE ? OR p.vendor LIKE ? OR p.product LIKE ?"
                " ORDER BY c.published_at DESC LIMIT 10",
                (pattern, pattern, pattern),
            ).fetchall()

    if not rows:
        api.send_message(chat_id, f"No CVEs match `{_md_escape(query)}`.")
        return

    cves = [dict(r) for r in rows]
    header = (
        f"🔎 *{_md_escape(query.upper())}*"
        if is_cve_id
        else f"🔎 *{_md_escape(query)}* — {len(cves)} result{'s' if len(cves) != 1 else ''}"
    )
    body = "\n\n".join(_fmt_cve_row(c) for c in cves)
    api.send_message(chat_id, f"{header}\n\n{body}", disable_web_page_preview=True)


def _handle_kev(api: TelegramAPI, chat_id: int) -> None:
    with _storage.connect() as conn:
        rows = conn.execute(
            "SELECT id, cvss_score, cvss_severity, description, epss_score, kev, published_at"
            " FROM cve WHERE kev = 1 ORDER BY published_at DESC LIMIT 10"
        ).fetchall()
    cves = [dict(r) for r in rows]
    if not cves:
        api.send_message(chat_id, "No KEV-tagged CVEs in the local index yet.")
        return
    body = "\n\n".join(_fmt_cve_row(c) for c in cves)
    api.send_message(
        chat_id,
        f"🚨 *Known Exploited* — latest {len(cves)}\n\n{body}",
        disable_web_page_preview=True,
    )


def _handle_top(api: TelegramAPI, chat_id: int) -> None:
    with _storage.connect() as conn:
        rows = conn.execute(
            "SELECT id, cvss_score, cvss_severity, description, epss_score, kev, published_at"
            " FROM cve WHERE epss_score IS NOT NULL"
            " ORDER BY epss_score DESC LIMIT 10"
        ).fetchall()
    cves = [dict(r) for r in rows]
    if not cves:
        api.send_message(chat_id, "No EPSS data in the local index.")
        return
    body = "\n\n".join(_fmt_cve_row(c) for c in cves)
    api.send_message(
        chat_id,
        f"📈 *Top by EPSS* — exploitation probability\n\n{body}",
        disable_web_page_preview=True,
    )


def _handle_poc(api: TelegramAPI, chat_id: int, text: str) -> None:
    parts = text.split(maxsplit=1)
    if len(parts) < 2 or not parts[1].strip():
        api.send_message(chat_id, "Usage: `/poc <keyword>`\nExample: `/poc Confluence`")
        return
    query = parts[1].strip()
    pattern = f"%{query}%"
    with _storage.connect() as conn:
        rows = conn.execute(
            "SELECT p.url, p.source, p.stars, p.description,"
            " GROUP_CONCAT(pc.cve_id) AS cve_ids"
            " FROM poc p LEFT JOIN poc_cve pc ON pc.poc_url = p.url"
            " WHERE p.url LIKE ? OR p.description LIKE ?"
            " GROUP BY p.url ORDER BY p.first_seen DESC LIMIT 10",
            (pattern, pattern),
        ).fetchall()
    if not rows:
        api.send_message(chat_id, f"No PoCs match `{_md_escape(query)}`.")
        return
    lines = [f"🧨 *PoC search:* {_md_escape(query)} — {len(rows)} result(s)\n"]
    for r in rows:
        url = r["url"]
        src = r["source"] or "?"
        stars = r["stars"]
        star_part = f" ★{stars}" if stars else ""
        cves = (r["cve_ids"] or "").split(",")[:3]
        cve_part = " · " + ", ".join(c for c in cves if c) if cves and cves[0] else ""
        short = url if len(url) <= 60 else url[:57] + "…"
        lines.append(f"• [{_md_escape(short)}]({url}) ({src}{star_part}){cve_part}")
    api.send_message(chat_id, "\n\n".join(lines), disable_web_page_preview=True)


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

    from ..web.notifications import CATEGORIES

    lines = [f"📋 *Notification Preferences for @{username}*\n"]
    for kind, (label, _desc, default) in CATEGORIES.items():
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
            (chat_id,),
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

    # Strip @botname suffix that Telegram appends in group chats (e.g. /cve@CVEHorusbot)
    head = text.split()[0]
    cmd = head.split("@", 1)[0].lower()

    # /start and /help are the only commands available before linking.
    if cmd == "/start":
        _handle_start(api, chat_id, username, text)
        return
    if cmd in ("/help", "/h"):
        _handle_help(api, chat_id)
        return

    # Everything else requires a linked Horus account.
    user = _linked_user(chat_id)
    if not user:
        _not_linked_message(api, chat_id)
        return

    if cmd == "/whoami":
        _handle_whoami(api, chat_id, user)
    elif cmd == "/status":
        _handle_status(api, chat_id)
    elif cmd == "/unlink":
        _handle_unlink(api, chat_id)
    elif cmd == "/cve":
        _handle_cve(api, chat_id, text)
    elif cmd == "/kev":
        _handle_kev(api, chat_id)
    elif cmd == "/top":
        _handle_top(api, chat_id)
    elif cmd == "/poc":
        _handle_poc(api, chat_id, text)
    elif cmd.startswith("/"):
        api.send_message(chat_id, f"Unknown command `{_md_escape(cmd)}` — try /help.")


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
                except Exception as e:
                    print(f"[bot] error processing update: {e}", file=sys.stderr)
        except TelegramError as e:
            print(f"[bot] poll error: {e}", file=sys.stderr)
            time.sleep(5)
        except KeyboardInterrupt:
            print("[bot] shutting down", file=sys.stderr)
            break
        except Exception as e:
            print(f"[bot] unexpected error, retrying: {e}", file=sys.stderr)
            time.sleep(5)


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
