"""Notification dispatch — per-user event routing with mock Telegram API."""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

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


# ═══════════════════════════════════════════════════════════════════════════════
# 2. dispatch — per-user routing
# ═══════════════════════════════════════════════════════════════════════════════


def test_dispatch_sends_to_linked_user():
    _seed_linked, _, _cleanup = _fresh_db("d1")
    try:
        _seed_linked("alice", chat_id=42)
        from horus.notifications import dispatcher as dispatch_mod

        events = {
            "kev_new": [
                {"cve_id": "CVE-2026-1234", "cvss_score": 9.8, "cvss_severity": "CRITICAL"}
            ],
        }

        with (
            patch.object(dispatch_mod, "_get_token", return_value="fake-token"),
            patch("horus.notifications.dispatcher.TelegramAPI") as MockAPI,
        ):
            api_instance = MagicMock()
            MockAPI.return_value = api_instance
            dispatch_mod.dispatch(events)

        api_instance.send_message.assert_called_once()
        assert api_instance.send_message.call_args[0][0] == 42
        assert "NEW KEV ADDITION" in api_instance.send_message.call_args[0][1]
    finally:
        _cleanup()


def test_dispatch_skips_disabled_category():
    _seed_linked, _, _cleanup = _fresh_db("d2")
    try:
        uid = _seed_linked("alice", chat_id=42)
        from horus.notifications import dispatcher as dispatch_mod

        with _db.connect() as conn:
            conn.execute(
                "INSERT INTO notification_pref (user_id, kind, enabled) VALUES (?, ?, 0)",
                (uid, "kev_new"),
            )

        events = {
            "kev_new": [
                {"cve_id": "CVE-2026-1234", "cvss_score": 9.8, "cvss_severity": "CRITICAL"}
            ],
        }

        with (
            patch.object(dispatch_mod, "_get_token", return_value="fake-token"),
            patch("horus.notifications.dispatcher.TelegramAPI") as MockAPI,
        ):
            api_instance = MagicMock()
            MockAPI.return_value = api_instance
            dispatch_mod.dispatch(events)

        api_instance.send_message.assert_not_called()
    finally:
        _cleanup()


def test_dispatch_no_token_is_noop():
    _seed_linked, _, _cleanup = _fresh_db("d3")
    try:
        _seed_linked("alice", chat_id=42)
        from horus.notifications import dispatcher as dispatch_mod

        events = {"kev_new": [{"cve_id": "CVE-2026-1234"}]}

        with patch.object(dispatch_mod, "_get_token", return_value=None):
            dispatch_mod.dispatch(events)  # should not raise
    finally:
        _cleanup()


def test_dispatch_no_linked_users_is_noop():
    _, _seed_unlinked, _cleanup = _fresh_db("d4")
    try:
        _seed_unlinked("bob")
        from horus.notifications import dispatcher as dispatch_mod

        events = {"kev_new": [{"cve_id": "CVE-2026-1234"}]}

        with (
            patch.object(dispatch_mod, "_get_token", return_value="fake-token"),
            patch("horus.notifications.dispatcher.TelegramAPI") as MockAPI,
        ):
            api_instance = MagicMock()
            MockAPI.return_value = api_instance
            dispatch_mod.dispatch(events)

        api_instance.send_message.assert_not_called()
    finally:
        _cleanup()


def test_dispatch_multiple_events_batched():
    _seed_linked, _, _cleanup = _fresh_db("d5")
    try:
        _seed_linked("alice", chat_id=42)
        from horus.notifications import dispatcher as dispatch_mod

        events = {
            "kev_new": [
                {"cve_id": "CVE-2026-1001", "cvss_score": 9.8, "cvss_severity": "CRITICAL"},
                {"cve_id": "CVE-2026-1002", "cvss_score": 7.5, "cvss_severity": "HIGH"},
            ],
        }

        with (
            patch.object(dispatch_mod, "_get_token", return_value="fake-token"),
            patch("horus.notifications.dispatcher.TelegramAPI") as MockAPI,
        ):
            api_instance = MagicMock()
            MockAPI.return_value = api_instance
            dispatch_mod.dispatch(events)

        api_instance.send_message.assert_called_once()
        msg = api_instance.send_message.call_args[0][1]
        assert "CVE-2026-1001" in msg
        assert "CVE-2026-1002" in msg
    finally:
        _cleanup()


def test_dispatch_skips_empty_event_lists():
    _seed_linked, _, _cleanup = _fresh_db("d6")
    try:
        _seed_linked("alice", chat_id=42)
        from horus.notifications import dispatcher as dispatch_mod

        events = {"kev_new": [], "critical_cve": []}

        with (
            patch.object(dispatch_mod, "_get_token", return_value="fake-token"),
            patch("horus.notifications.dispatcher.TelegramAPI") as MockAPI,
        ):
            api_instance = MagicMock()
            MockAPI.return_value = api_instance
            dispatch_mod.dispatch(events)

        api_instance.send_message.assert_not_called()
    finally:
        _cleanup()


def test_dispatch_telegram_error_is_caught():
    _seed_linked, _, _cleanup = _fresh_db("d7")
    try:
        _seed_linked("alice", chat_id=42)
        _seed_linked("bob", chat_id=99)
        from horus.bot.api import TelegramError
        from horus.notifications import dispatcher as dispatch_mod

        events = {
            "kev_new": [
                {"cve_id": "CVE-2026-1234", "cvss_score": 9.8, "cvss_severity": "CRITICAL"}
            ],
        }

        with (
            patch.object(dispatch_mod, "_get_token", return_value="fake-token"),
            patch("horus.notifications.dispatcher.TelegramAPI") as MockAPI,
        ):
            api_instance = MagicMock()
            api_instance.send_message.side_effect = [TelegramError("network"), MagicMock()]
            MockAPI.return_value = api_instance
            dispatch_mod.dispatch(events)

        assert api_instance.send_message.call_count == 2
    finally:
        _cleanup()


# ═══════════════════════════════════════════════════════════════════════════════
# 3. _batch_messages
# ═══════════════════════════════════════════════════════════════════════════════


def test_batch_messages_single():
    from horus.notifications.dispatcher import _batch_messages

    assert _batch_messages(["hello"]) == ["hello"]


def test_batch_messages_under_limit():
    from horus.notifications.dispatcher import _batch_messages

    result = _batch_messages(["a", "b", "c"])
    assert len(result) == 1
    assert "a" in result[0] and "b" in result[0] and "c" in result[0]


def test_batch_messages_over_limit():
    from horus.notifications.dispatcher import _batch_messages

    big = ["x" * 210 for _ in range(20)]
    result = _batch_messages(big, max_len=4000)
    assert len(result) > 1
    for batch in result:
        assert len(batch) <= 4000


def test_batch_messages_empty():
    from horus.notifications.dispatcher import _batch_messages

    assert _batch_messages([]) == []
