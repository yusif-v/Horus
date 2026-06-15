"""User self-service: Telegram linking + notification preferences.

Linking flow:
  1. User clicks "Connect Telegram" → POST /profile/telegram/generate
  2. Server creates a single-use token (TTL 30 min) and shows a deep link
     `https://t.me/<bot_username>?start=<token>`.
  3. User opens the link in Telegram → bot receives `/start <token>` →
     bot calls Horus to consume the token and write `telegram_chat_id`.
     (Bot listener lands next session; this module just creates tokens.)
  4. User can `POST /profile/telegram/unlink` to clear the link.

Per-user notification preferences live in `notification_pref` and are
edited through `/profile/notifications`. Categories are defined in
`horus/web/notifications.py`.

All routes require an authenticated user (READ_ALL is enough — viewers
can opt in to their own notifications).
"""

from __future__ import annotations

import os
import secrets
from datetime import datetime, timedelta, timezone

from flask import Blueprint, current_app, g, redirect, request, url_for

from ...storage import db as _storage
from .. import audit
from .._render import page
from ..notifications import CATEGORIES, effective_prefs
from .auth import READ_ALL, role_required

bp = Blueprint("profile", __name__, url_prefix="/profile")

LINK_TOKEN_TTL = timedelta(minutes=30)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _fmt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _bot_username() -> str:
    return current_app.config.get("TELEGRAM_BOT_USERNAME") or os.environ.get(
        "TELEGRAM_BOT_USERNAME", ""
    )


def _stored_prefs(conn, user_id: int) -> dict[str, bool]:
    rows = conn.execute(
        "SELECT kind, enabled FROM notification_pref WHERE user_id = ?",
        (user_id,),
    ).fetchall()
    return {r[0]: bool(r[1]) for r in rows}


# ─── Telegram ─────────────────────────────────────────────────────────────────


@bp.route("/telegram")
@role_required(*READ_ALL)
def telegram():
    with _storage.connect() as conn:
        user_row = conn.execute(
            "SELECT telegram_chat_id, telegram_username, telegram_linked_at FROM user WHERE id = ?",
            (g.user["id"],),
        ).fetchone()
        active_token = conn.execute(
            "SELECT token, expires_at FROM telegram_link_token "
            "WHERE user_id = ? AND used_at IS NULL AND expires_at > ? "
            "ORDER BY created_at DESC LIMIT 1",
            (g.user["id"], _fmt(_now())),
        ).fetchone()

    linked = user_row and user_row["telegram_chat_id"] is not None
    bot = _bot_username()
    deep_link = (
        f"https://t.me/{bot}?start={active_token['token']}" if active_token and bot else None
    )

    return page(
        "profile_telegram.html",
        title="Telegram notifications",
        active="profile",
        linked=linked,
        link_state=dict(user_row) if user_row else {},
        active_token=dict(active_token) if active_token else None,
        deep_link=deep_link,
        bot_configured=bool(bot),
        flash=request.args.get("flash", ""),
    )


@bp.route("/telegram/generate", methods=["POST"])
@role_required(*READ_ALL)
def telegram_generate():
    token = secrets.token_urlsafe(24)
    expires = _now() + LINK_TOKEN_TTL
    with _storage.connect() as conn:
        # Invalidate any prior unused tokens so only the latest is live.
        conn.execute(
            "UPDATE telegram_link_token SET used_at = ? WHERE user_id = ? AND used_at IS NULL",
            (_fmt(_now()), g.user["id"]),
        )
        conn.execute(
            "INSERT INTO telegram_link_token (token, user_id, created_at, expires_at) "
            "VALUES (?, ?, ?, ?)",
            (token, g.user["id"], _fmt(_now()), _fmt(expires)),
        )

    audit.record(
        "telegram.link.token_created",
        "user",
        g.user["id"],
        after={"expires_at": _fmt(expires)},
    )
    return redirect(url_for("profile.telegram", flash="New link token generated."))


@bp.route("/telegram/unlink", methods=["POST"])
@role_required(*READ_ALL)
def telegram_unlink():
    with _storage.connect() as conn:
        before = conn.execute(
            "SELECT telegram_chat_id, telegram_username FROM user WHERE id = ?",
            (g.user["id"],),
        ).fetchone()
        conn.execute(
            "UPDATE user SET telegram_chat_id = NULL, telegram_username = NULL, "
            "telegram_linked_at = NULL WHERE id = ?",
            (g.user["id"],),
        )
        # Also expire any pending tokens.
        conn.execute(
            "UPDATE telegram_link_token SET used_at = ? WHERE user_id = ? AND used_at IS NULL",
            (_fmt(_now()), g.user["id"]),
        )

    audit.record(
        "telegram.unlink",
        "user",
        g.user["id"],
        before=dict(before) if before else None,
    )
    return redirect(url_for("profile.telegram", flash="Telegram disconnected."))


# ─── Notification preferences ────────────────────────────────────────────────


@bp.route("/notifications", methods=["GET", "POST"])
@role_required(*READ_ALL)
def notifications():
    user_id = g.user["id"]

    if request.method == "POST":
        with _storage.connect() as conn:
            before = _stored_prefs(conn, user_id)
            for kind in CATEGORIES:
                enabled = 1 if request.form.get(f"pref_{kind}") == "on" else 0
                conn.execute(
                    """
                    INSERT INTO notification_pref (user_id, kind, enabled)
                    VALUES (?, ?, ?)
                    ON CONFLICT(user_id, kind) DO UPDATE SET enabled = excluded.enabled
                    """,
                    (user_id, kind, enabled),
                )
            after = _stored_prefs(conn, user_id)

        audit.record(
            "notification_pref.update",
            "user",
            user_id,
            before=before,
            after=after,
        )
        return redirect(url_for("profile.notifications", flash="Preferences saved."))

    with _storage.connect() as conn:
        stored = _stored_prefs(conn, user_id)
    prefs = effective_prefs(stored)

    categories = [
        {
            "kind": kind,
            "label": label,
            "description": desc,
            "enabled": prefs[kind],
            "default": default,
        }
        for kind, (label, desc, default) in CATEGORIES.items()
    ]

    return page(
        "profile_notifications.html",
        title="Notifications",
        active="profile",
        categories=categories,
        flash=request.args.get("flash", ""),
    )
