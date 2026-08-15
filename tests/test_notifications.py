"""Notification dispatch — telegram plugin notify path with captured sends."""

from __future__ import annotations

import tempfile
from pathlib import Path

from horus.storage import db as _db

_SCHEMA_PATH = Path(__file__).resolve().parent.parent / "horus" / "storage" / "schema.sql"


def _fresh_db(suffix=""):
    """Create a fresh isolated DB, return (seed_fn, cleanup_fn)."""
    tmp = Path(tempfile.mkdtemp(prefix="horus-notify-"))
    db_path = tmp / "horus.db"
    old = _db.DB_PATH
    _db.DB_PATH = db_path

    def _seed_linked(username, chat_id):
        with _db.connect() as conn:
            conn.executescript(_SCHEMA_PATH.read_text())
            conn.execute(
                "INSERT INTO user (username, email, password_hash, created_at, "
                "telegram_chat_id, telegram_username, telegram_linked_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    username,
                    f"{username}@example.com",
                    "x",
                    "2026-01-01T00:00:00Z",
                    chat_id,
                    f"{username}_tg",
                    "2026-01-01T00:00:00Z",
                ),
            )
            return conn.execute("SELECT id FROM user WHERE username = ?", (username,)).fetchone()[0]

    def _seed_unlinked(username):
        with _db.connect() as conn:
            conn.executescript(_SCHEMA_PATH.read_text())
            conn.execute(
                "INSERT INTO user (username, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (username, f"{username}@example.com", "x", "2026-01-01T00:00:00Z"),
            )

    def _cleanup():
        _db.DB_PATH = old

    return _seed_linked, _seed_unlinked, _cleanup


def _notification_ctx(token="fake-token", prefs=None):
    """Build a NotificationContext from the DB-seeded users, mirroring server.py.

    `prefs` is a per-user override map: {user_id: {kind: bool}}. Prefs are
    keyed by user so opt-outs are honored per user (no OR-merge across users).
    Returns (ctx, sent) where `sent` is the list of (chat_id, message) the
    plugin's `send` callback captured.
    """
    from horus.core.plugin_types import NotificationContext
    from horus.web.notifications import effective_prefs

    with _db.connect() as conn:
        users = conn.execute(
            "SELECT id, username, telegram_chat_id FROM user WHERE telegram_chat_id IS NOT NULL"
        ).fetchall()
        # Per-user prefs: that user's DB rows merged with defaults (server.py logic).
        prefs_by_user: dict[int, dict[str, bool]] = {}
        for user_id, _username, _chat_id in users:
            rows = conn.execute(
                "SELECT kind, enabled FROM notification_pref WHERE user_id = ?",
                (user_id,),
            ).fetchall()
            stored = {kind: bool(enabled) for kind, enabled in rows}
            if prefs is not None and user_id in prefs:
                stored.update(prefs[user_id])
            prefs_by_user[user_id] = effective_prefs(stored)

    sent: list[tuple[int, str]] = []
    ctx = NotificationContext(
        token=token,
        users=users,
        prefs=prefs_by_user,
        send=lambda chat_id, msg: sent.append((chat_id, msg)),
    )
    return ctx, sent


# ═══════════════════════════════════════════════════════════════════════════════
# 1. format_event_message
# ═══════════════════════════════════════════════════════════════════════════════


def test_format_kev_new():
    from horus.notifications.format import format_event_message

    msg = format_event_message(
        "kev_new",
        {"cve_id": "CVE-2026-1234", "cvss_score": 9.8, "cvss_severity": "CRITICAL"},
        "alice",
    )
    assert "NEW KEV ADDITION" in msg
    assert "CVE-2026-1234" in msg
    assert "CVSS 9.8 CRITICAL" in msg
    assert "nvd.nist.gov" in msg


def test_format_kev_new_no_cvss():
    from horus.notifications.format import format_event_message

    msg = format_event_message("kev_new", {"cve_id": "CVE-2026-0001"}, "alice")
    assert "no CVSS" in msg


def test_format_epss_jump():
    from horus.notifications.format import format_event_message

    msg = format_event_message(
        "epss_jump", {"cve_id": "CVE-2026-1234", "epss_score": 0.75}, "alice"
    )
    assert "EPSS JUMP" in msg
    assert "75.0%" in msg


def test_format_epss_zero_score():
    from horus.notifications.format import format_event_message

    msg = format_event_message("epss_jump", {"cve_id": "CVE-2026-1234", "epss_score": 0}, "alice")
    assert "N/A" in msg


def test_format_critical_cve():
    from horus.notifications.format import format_event_message

    msg = format_event_message(
        "critical_cve",
        {"cve_id": "CVE-2026-1234", "cvss_score": 9.8, "cvss_severity": "CRITICAL", "poc_count": 3},
        "alice",
    )
    assert "CRITICAL CVE + PoC" in msg
    assert "3 PoCs" in msg


def test_format_critical_cve_one_poc():
    from horus.notifications.format import format_event_message

    msg = format_event_message(
        "critical_cve",
        {"cve_id": "CVE-2026-1234", "cvss_score": 9.8, "cvss_severity": "CRITICAL", "poc_count": 1},
        "alice",
    )
    assert "1 PoC" in msg
    assert "PoCs" not in msg


def test_format_watchlist_match():
    from horus.notifications.format import format_event_message

    msg = format_event_message(
        "watchlist_match",
        {"cve_id": "CVE-2026-1234", "vendor": "Apache", "product": "Log4j", "team": "red"},
        "alice",
    )
    assert "WATCHLIST MATCH" in msg
    assert "Apache/Log4j" in msg
    assert "red team" in msg


def test_format_watchlist_match_no_product():
    from horus.notifications.format import format_event_message

    msg = format_event_message(
        "watchlist_match", {"cve_id": "CVE-2026-1234", "vendor": "Apache"}, "alice"
    )
    assert "Apache" in msg


def test_format_poc_new():
    from horus.notifications.format import format_event_message

    msg = format_event_message(
        "poc_new",
        {"cve_id": "CVE-2026-1234", "url": "https://github.com/poc/repo", "source": "github"},
        "alice",
    )
    assert "NEW PoC" in msg
    assert "github" in msg


def test_format_unknown_kind_returns_none():
    from horus.notifications.format import format_event_message

    assert format_event_message("unknown_kind", {}, "alice") is None


def test_format_kev_overdue():
    """KEV overdue formatter includes deadline info."""
    from horus.notifications.format import format_event_message

    msg = format_event_message(
        "kev_overdue",
        {
            "cve_id": "CVE-2026-1234",
            "cvss_score": 9.8,
            "cvss_severity": "CRITICAL",
            "due_date": "2024-06-01",
        },
        "alice",
    )
    assert "KEV OVERDUE" in msg
    assert "2024-06-01 (passed)" in msg
    assert "CVE-2026-1234" in msg


def test_format_kev_due_soon():
    """KEV due soon formatter includes deadline without (passed)."""
    from horus.notifications.format import format_event_message

    msg = format_event_message(
        "kev_due_soon",
        {
            "cve_id": "CVE-2026-5678",
            "cvss_score": 7.5,
            "cvss_severity": "HIGH",
            "due_date": "2026-07-15",
        },
        "alice",
    )
    assert "KEV DUE SOON" in msg
    assert "2026-07-15" in msg
    assert "(passed)" not in msg
    assert "CVE-2026-5678" in msg


# ═══════════════════════════════════════════════════════════════════════════════
# 2. notify — telegram plugin per-user routing
# ═══════════════════════════════════════════════════════════════════════════════


def test_notify_sends_to_linked_user():
    _seed_linked, _, _cleanup = _fresh_db("n1")
    try:
        _seed_linked("alice", chat_id=42)
        from horus.plugins.notifications.telegram.main import notify

        events = {
            "kev_new": [
                {"cve_id": "CVE-2026-1234", "cvss_score": 9.8, "cvss_severity": "CRITICAL"}
            ],
        }

        ctx, sent = _notification_ctx()
        notify(events, ctx)

        assert len(sent) == 1
        chat_id, msg = sent[0]
        assert chat_id == 42
        assert "NEW KEV ADDITION" in msg
        assert "CVE-2026-1234" in msg
    finally:
        _cleanup()


def test_notify_skips_disabled_category():
    _seed_linked, _, _cleanup = _fresh_db("n2")
    try:
        alice_id = _seed_linked("alice", chat_id=42)
        from horus.plugins.notifications.telegram.main import notify

        events = {
            "kev_new": [
                {"cve_id": "CVE-2026-1234", "cvss_score": 9.8, "cvss_severity": "CRITICAL"}
            ],
        }

        ctx, sent = _notification_ctx(prefs={alice_id: {"kev_new": False}})
        notify(events, ctx)

        assert sent == []
    finally:
        _cleanup()


def test_notify_no_token_is_noop():
    _seed_linked, _, _cleanup = _fresh_db("n3")
    try:
        _seed_linked("alice", chat_id=42)
        from horus.plugins.notifications.telegram.main import notify

        events = {"kev_new": [{"cve_id": "CVE-2026-1234"}]}

        ctx, sent = _notification_ctx(token=None)
        notify(events, ctx)  # should not raise

        assert sent == []
    finally:
        _cleanup()


def test_notify_respects_per_user_opt_out():
    """A user who disabled a kind must not receive it even if another enabled it."""
    _seed_linked, _, _cleanup = _fresh_db("n8")
    try:
        alice_id = _seed_linked("alice", chat_id=42)
        bob_id = _seed_linked("bob", chat_id=99)
        with _db.connect() as conn:
            for uid, enabled in ((alice_id, 1), (bob_id, 0)):
                conn.execute(
                    "INSERT INTO notification_pref (user_id, kind, enabled) VALUES (?, ?, ?)",
                    (uid, "poc_new", enabled),
                )
        from horus.plugins.notifications.telegram.main import notify

        events = {
            "poc_new": [
                {"cve_id": "CVE-2026-1234", "url": "https://github.com/x/y", "source": "github"}
            ],
        }

        ctx, sent = _notification_ctx()
        notify(events, ctx)

        # Only alice (enabled) gets the poc_new event; bob opted out.
        assert [ch for ch, _ in sent] == [42]
    finally:
        _cleanup()


def test_notify_no_linked_users_is_noop():
    _, _seed_unlinked, _cleanup = _fresh_db("n4")
    try:
        _seed_unlinked("bob")
        from horus.plugins.notifications.telegram.main import notify

        events = {"kev_new": [{"cve_id": "CVE-2026-1234"}]}

        ctx, sent = _notification_ctx()
        notify(events, ctx)

        assert sent == []
    finally:
        _cleanup()


def test_notify_batches_multiple_events():
    _seed_linked, _, _cleanup = _fresh_db("n5")
    try:
        _seed_linked("alice", chat_id=42)
        from horus.plugins.notifications.telegram.main import notify

        events = {
            "kev_new": [
                {"cve_id": "CVE-2026-1001", "cvss_score": 9.8, "cvss_severity": "CRITICAL"},
                {"cve_id": "CVE-2026-1002", "cvss_score": 7.5, "cvss_severity": "HIGH"},
            ],
        }

        ctx, sent = _notification_ctx()
        notify(events, ctx)

        assert len(sent) == 1
        chat_id, msg = sent[0]
        assert chat_id == 42
        assert "CVE-2026-1001" in msg
        assert "CVE-2026-1002" in msg
    finally:
        _cleanup()


def test_notify_skips_empty_event_lists():
    _seed_linked, _, _cleanup = _fresh_db("n6")
    try:
        _seed_linked("alice", chat_id=42)
        from horus.plugins.notifications.telegram.main import notify

        events = {"kev_new": [], "critical_cve": []}

        ctx, sent = _notification_ctx()
        notify(events, ctx)

        assert sent == []
    finally:
        _cleanup()


def test_notify_telegram_error_is_caught():
    """A send failure for one user must not stop other users (server `_send` behavior)."""
    _seed_linked, _, _cleanup = _fresh_db("n7")
    try:
        _seed_linked("alice", chat_id=42)
        _seed_linked("bob", chat_id=99)
        from horus.bot.api import TelegramError
        from horus.plugins.notifications.telegram.main import notify

        events = {
            "kev_new": [
                {"cve_id": "CVE-2026-1234", "cvss_score": 9.8, "cvss_severity": "CRITICAL"}
            ],
        }

        delivered: list[tuple[int, str]] = []
        attempts: list[int] = []

        def _send(chat_id, message):
            attempts.append(chat_id)
            try:
                if chat_id == 42:
                    raise TelegramError("network")
                delivered.append((chat_id, message))
            except TelegramError:
                pass

        ctx, _sent = _notification_ctx()
        ctx.send = _send
        notify(events, ctx)

        assert attempts == [42, 99]
        assert len(delivered) == 1
        assert delivered[0][0] == 99
    finally:
        _cleanup()


# ═══════════════════════════════════════════════════════════════════════════════
# 3. _batch_messages
# ═══════════════════════════════════════════════════════════════════════════════


def test_batch_messages_single():
    from horus.plugins.notifications.telegram.main import _batch_messages

    assert _batch_messages(["hello"]) == ["hello"]


def test_batch_messages_under_limit():
    from horus.plugins.notifications.telegram.main import _batch_messages

    result = _batch_messages(["a", "b", "c"])
    assert len(result) == 1
    assert "a" in result[0] and "b" in result[0] and "c" in result[0]


def test_batch_messages_over_limit():
    from horus.plugins.notifications.telegram.main import _batch_messages

    big = ["x" * 210 for _ in range(20)]
    result = _batch_messages(big, max_len=4000)
    assert len(result) > 1
    for batch in result:
        assert len(batch) <= 4000


def test_batch_messages_empty():
    from horus.plugins.notifications.telegram.main import _batch_messages

    assert _batch_messages([]) == []
