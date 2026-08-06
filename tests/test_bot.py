"""Telegram bot — token consumption, command parsing, message formatting."""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import MagicMock

# ── We manage DB isolation manually since horus.storage.db uses module-level
# DB_PATH. Each helper below patches it to a fresh temp DB for the test.
from horus.storage import db as _db

_SCHEMA_PATH = Path(__file__).resolve().parent.parent / "horus" / "storage" / "schema.sql"


def _fresh_db(suffix=""):
    """Create a fresh isolated in-memory-like DB, return (seed_fn, db_path)."""
    tmp = Path(tempfile.mkdtemp(prefix="horus-bot-"))
    db_path = tmp / "horus.db"
    old = _db.DB_PATH
    _db.DB_PATH = db_path

    def _seed():
        u = f"u{suffix}"
        with _db.connect() as conn:
            conn.executescript(_SCHEMA_PATH.read_text())
            conn.execute("INSERT OR IGNORE INTO role (name) VALUES ('admin')")
            conn.execute("INSERT OR IGNORE INTO role (name) VALUES ('analyst')")
            conn.execute("INSERT OR IGNORE INTO role (name) VALUES ('viewer')")
            conn.execute(
                "INSERT INTO user (username, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (u, f"{u}@example.com", "x", "2026-01-01T00:00:00Z"),
            )
            uid = conn.execute("SELECT id FROM user WHERE username = ?", (u,)).fetchone()[0]
            rid = conn.execute("SELECT id FROM role WHERE name = 'analyst'").fetchone()[0]
            conn.execute("INSERT INTO user_role (user_id, role_id) VALUES (?, ?)", (uid, rid))
            token = f"tok-{u}"
            conn.execute(
                "INSERT INTO telegram_link_token (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
                (token, uid, "2026-01-01T00:00:00Z", "2099-01-01T00:00:00Z"),
            )
        return uid, token

    def _cleanup():
        _db.DB_PATH = old

    return _seed, _cleanup


# ═══════════════════════════════════════════════════════════════════════════════
# 1. Token consumption
# ═══════════════════════════════════════════════════════════════════════════════


def test_start_consumes_valid_token():
    _seed, _cleanup = _fresh_db("a")
    try:
        uid, token = _seed()
        from horus.bot.telegram import _handle_start

        api = MagicMock()
        _handle_start(api, chat_id=100, username="a_tg", text=f"/start {token}")

        with _db.connect() as conn:
            row = conn.execute(
                "SELECT used_at FROM telegram_link_token WHERE token = ?", (token,)
            ).fetchone()
            assert row[0] is not None
            urow = conn.execute("SELECT telegram_chat_id FROM user WHERE id = ?", (uid,)).fetchone()
            assert urow[0] == 100

        api.send_message.assert_called_once()
        assert "linked successfully" in api.send_message.call_args[0][1]
    finally:
        _cleanup()


def test_start_rejects_invalid_token():
    _seed, _cleanup = _fresh_db("b")
    try:
        _seed()
        from horus.bot.telegram import _handle_start

        api = MagicMock()
        _handle_start(api, chat_id=101, username="b_tg", text="/start bad-token")

        api.send_message.assert_called_once()
        assert "Invalid or expired" in api.send_message.call_args[0][1]
    finally:
        _cleanup()


def test_start_rejects_expired_token():
    _seed, _cleanup = _fresh_db("c")
    try:
        uid, _ = _seed()
        from horus.bot.telegram import _handle_start

        with _db.connect() as conn:
            conn.execute(
                "INSERT INTO telegram_link_token (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
                ("expired-tok", uid, "2020-01-01T00:00:00Z", "2020-01-02T00:00:00Z"),
            )

        api = MagicMock()
        _handle_start(api, chat_id=102, username="c_tg", text="/start expired-tok")

        api.send_message.assert_called_once()
        assert "Invalid or expired" in api.send_message.call_args[0][1]
    finally:
        _cleanup()


def test_start_rejects_already_used_token():
    _seed, _cleanup = _fresh_db("d")
    try:
        uid, _ = _seed()
        from horus.bot.telegram import _handle_start

        with _db.connect() as conn:
            conn.execute(
                "INSERT INTO telegram_link_token (token, user_id, created_at, expires_at, used_at) VALUES (?, ?, ?, ?, ?)",
                (
                    "used-tok",
                    uid,
                    "2026-01-01T00:00:00Z",
                    "2099-01-01T00:00:00Z",
                    "2026-06-01T00:00:00Z",
                ),
            )

        api = MagicMock()
        _handle_start(api, chat_id=103, username="d_tg", text="/start used-tok")

        api.send_message.assert_called_once()
        assert "Invalid or expired" in api.send_message.call_args[0][1]
    finally:
        _cleanup()


def test_start_no_token_provided():
    _seed, _cleanup = _fresh_db("e")
    try:
        _seed()
        from horus.bot.telegram import _handle_start

        api = MagicMock()
        _handle_start(api, chat_id=104, username="e_tg", text="/start")

        api.send_message.assert_called_once()
        assert "No token provided" in api.send_message.call_args[0][1]
    finally:
        _cleanup()


# ═══════════════════════════════════════════════════════════════════════════════
# 2. Command parsing
# ═══════════════════════════════════════════════════════════════════════════════


def _make_update(text: str, chat_id: int = 42, username: str = "tg") -> dict:
    return {
        "update_id": 1,
        "message": {
            "chat": {"id": chat_id},
            "text": text,
            "from": {"username": username},
        },
    }


def test_process_update_routes_help():
    _seed, _cleanup = _fresh_db("help")
    try:
        _seed()
        from horus.bot.telegram import _process_update

        api = MagicMock()
        _process_update(api, _make_update("/help"))
        api.send_message.assert_called_once()
        assert "Horus CVE Intelligence Bot" in api.send_message.call_args[0][1]
    finally:
        _cleanup()


def test_process_update_routes_start():
    _seed, _cleanup = _fresh_db("strt")
    try:
        _, token = _seed()
        from horus.bot.telegram import _process_update

        api = MagicMock()
        _process_update(api, _make_update(f"/start {token}"))
        api.send_message.assert_called_once()
        assert "linked successfully" in api.send_message.call_args[0][1]
    finally:
        _cleanup()


def test_process_update_unknown_command():
    _seed, _cleanup = _fresh_db("unk")
    try:
        _, token = _seed()
        from horus.bot.telegram import _process_update

        api = MagicMock()
        _process_update(api, _make_update(f"/start {token}"))
        api.reset_mock()

        _process_update(api, _make_update("/foobar"))
        api.send_message.assert_called_once()
        assert "Unknown command" in api.send_message.call_args[0][1]
    finally:
        _cleanup()


def test_process_update_not_linked_gets_restricted():
    _seed, _cleanup = _fresh_db("unlinked")
    try:
        _seed()
        from horus.bot.telegram import _process_update

        api = MagicMock()
        _process_update(api, _make_update("/status"))
        api.send_message.assert_called_once()
        assert "Access restricted" in api.send_message.call_args[0][1]
    finally:
        _cleanup()


def test_process_update_strips_botname_suffix():
    _seed, _cleanup = _fresh_db("botname")
    try:
        _, token = _seed()
        from horus.bot.telegram import _process_update

        api = MagicMock()
        _process_update(api, _make_update(f"/start {token}"))
        api.reset_mock()

        with _db.connect() as conn:
            conn.execute(
                "INSERT INTO cve (id, description, cvss_score, cvss_severity, first_seen, last_seen) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    "CVE-2026-1234",
                    "Test RCE",
                    9.8,
                    "CRITICAL",
                    "2026-01-01T00:00:00Z",
                    "2026-01-01T00:00:00Z",
                ),
            )

        _process_update(api, _make_update("/cve@CVEHorusbot CVE-2026-1234"))
        api.send_message.assert_called_once()
        assert "CVE-2026-1234" in api.send_message.call_args[0][1]
    finally:
        _cleanup()


def test_process_update_ignores_non_message_updates():
    _seed, _cleanup = _fresh_db("nomsg")
    try:
        _seed()
        from horus.bot.telegram import _process_update

        api = MagicMock()
        _process_update(api, {"update_id": 1, "edited_message": {}})
        api.send_message.assert_not_called()
    finally:
        _cleanup()


def test_process_update_ignores_empty_text():
    _seed, _cleanup = _fresh_db("empty")
    try:
        _seed()
        from horus.bot.telegram import _process_update

        api = MagicMock()
        _process_update(api, {"update_id": 1, "message": {"chat": {"id": 42}, "text": "   "}})
        api.send_message.assert_not_called()
    finally:
        _cleanup()


# ═══════════════════════════════════════════════════════════════════════════════
# 3. Message formatting (bot helpers)
# ═══════════════════════════════════════════════════════════════════════════════


def test_md_escape():
    from horus.bot.telegram import _md_escape

    assert _md_escape("hello_world") == r"hello\_world"
    assert _md_escape("a*b") == r"a\*b"
    assert _md_escape("code `here`") == r"code \`here\`"
    assert _md_escape("[link](url)") == r"\[link](url)"
    assert _md_escape("plain") == "plain"


def test_fmt_cve_row_full():
    from horus.bot.telegram import _fmt_cve_row

    cve = {
        "id": "CVE-2026-1234",
        "cvss_score": 9.8,
        "cvss_severity": "CRITICAL",
        "epss_score": 0.95,
        "kev": 1,
        "description": "Remote code execution in FooApp",
    }
    result = _fmt_cve_row(cve)
    assert "CVE-2026-1234" in result
    assert "CVSS 9.8" in result
    assert "CRIT" in result
    assert "EPSS 95.0%" in result
    assert "KEV" in result
    assert "Remote code execution" in result


def test_fmt_cve_row_minimal():
    from horus.bot.telegram import _fmt_cve_row

    cve = {"id": "CVE-2026-0001"}
    result = _fmt_cve_row(cve)
    assert "CVE-2026-0001" in result


def test_fmt_cve_row_long_description_truncated():
    from horus.bot.telegram import _fmt_cve_row

    cve = {"id": "CVE-2026-0001", "description": "A" * 300}
    result = _fmt_cve_row(cve)
    assert "…" in result
    assert "A" * 200 not in result


def test_handle_help_message():
    from horus.bot.telegram import _handle_help

    api = MagicMock()
    _handle_help(api, chat_id=42)
    api.send_message.assert_called_once()
    msg = api.send_message.call_args[0][1]
    assert "/start" in msg
    assert "/cve" in msg
    assert "/kev" in msg
    assert "/top" in msg
    assert "/poc" in msg
    assert "/whoami" in msg
    assert "/unlink" in msg


def test_handle_whoami():
    _seed, _cleanup = _fresh_db("whoami")
    try:
        _, token = _seed()
        from horus.bot.telegram import _process_update

        api = MagicMock()
        _process_update(api, _make_update(f"/start {token}"))
        api.reset_mock()

        _process_update(api, _make_update("/whoami"))
        api.send_message.assert_called_once()
        msg = api.send_message.call_args[0][1]
        assert "uwhoami" in msg
        assert "Identity" in msg
    finally:
        _cleanup()


def test_handle_unlink():
    _seed, _cleanup = _fresh_db("unlink")
    try:
        _, token = _seed()
        from horus.bot.telegram import _process_update

        api = MagicMock()
        _process_update(api, _make_update(f"/start {token}"))
        api.reset_mock()

        _process_update(api, _make_update("/unlink"))
        api.send_message.assert_called_once()
        msg = api.send_message.call_args[0][1]
        assert "disconnect" in msg.lower()

        with _db.connect() as conn:
            row = conn.execute(
                "SELECT telegram_chat_id FROM user WHERE username = ?",
                ("uunlink",),
            ).fetchone()
            assert row[0] is None
    finally:
        _cleanup()


def test_handle_status():
    _seed, _cleanup = _fresh_db("status")
    try:
        _, token = _seed()
        from horus.bot.telegram import _process_update

        api = MagicMock()
        _process_update(api, _make_update(f"/start {token}"))
        api.reset_mock()

        _process_update(api, _make_update("/status"))
        api.send_message.assert_called_once()
        msg = api.send_message.call_args[0][1]
        assert "Notification Preferences" in msg
    finally:
        _cleanup()


def test_handle_cve_no_results():
    _seed, _cleanup = _fresh_db("cve_none")
    try:
        _, token = _seed()
        from horus.bot.telegram import _process_update

        api = MagicMock()
        _process_update(api, _make_update(f"/start {token}"))
        api.reset_mock()

        _process_update(api, _make_update("/cve nonexistent"))
        api.send_message.assert_called_once()
        msg = api.send_message.call_args[0][1]
        assert "No CVEs match" in msg
    finally:
        _cleanup()


def test_handle_poc_no_results():
    _seed, _cleanup = _fresh_db("poc_none")
    try:
        _, token = _seed()
        from horus.bot.telegram import _process_update

        api = MagicMock()
        _process_update(api, _make_update(f"/start {token}"))
        api.reset_mock()

        _process_update(api, _make_update("/poc nonexistent"))
        api.send_message.assert_called_once()
        msg = api.send_message.call_args[0][1]
        assert "No PoCs match" in msg
    finally:
        _cleanup()


def test_handle_poc_with_results():
    _seed, _cleanup = _fresh_db("poc_hit")
    try:
        _, token = _seed()
        from horus.bot.telegram import _process_update

        api = MagicMock()
        _process_update(api, _make_update(f"/start {token}"))
        api.reset_mock()

        with _db.connect() as conn:
            conn.execute(
                "INSERT INTO poc (url, source, stars, description, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    "https://github.com/poc/repo",
                    "github",
                    100,
                    "Test PoC",
                    "2026-01-01T00:00:00Z",
                    "2026-01-01T00:00:00Z",
                ),
            )

        _process_update(api, _make_update("/poc github"))
        api.send_message.assert_called_once()
        msg = api.send_message.call_args[0][1]
        assert "PoC search" in msg
        assert "github" in msg
    finally:
        _cleanup()


def test_handle_kev_no_results():
    _seed, _cleanup = _fresh_db("kev_none")
    try:
        _, token = _seed()
        from horus.bot.telegram import _process_update

        api = MagicMock()
        _process_update(api, _make_update(f"/start {token}"))
        api.reset_mock()

        _process_update(api, _make_update("/kev"))
        api.send_message.assert_called_once()
        msg = api.send_message.call_args[0][1]
        assert "No KEV-tagged CVEs" in msg
    finally:
        _cleanup()


def test_handle_kev_with_results():
    _seed, _cleanup = _fresh_db("kev_hit")
    try:
        _, token = _seed()
        from horus.bot.telegram import _process_update

        api = MagicMock()
        _process_update(api, _make_update(f"/start {token}"))
        api.reset_mock()

        with _db.connect() as conn:
            conn.execute(
                "INSERT INTO cve (id, description, cvss_score, cvss_severity, first_seen, last_seen, kev) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    "CVE-2026-5678",
                    "Test RCE",
                    9.8,
                    "CRITICAL",
                    "2026-01-01T00:00:00Z",
                    "2026-01-01T00:00:00Z",
                    1,
                ),
            )

        _process_update(api, _make_update("/kev"))
        api.send_message.assert_called_once()
        msg = api.send_message.call_args[0][1]
        assert "Known Exploited" in msg
        assert "CVE-2026-5678" in msg
    finally:
        _cleanup()


def test_handle_top_no_results():
    _seed, _cleanup = _fresh_db("top_none")
    try:
        _, token = _seed()
        from horus.bot.telegram import _process_update

        api = MagicMock()
        _process_update(api, _make_update(f"/start {token}"))
        api.reset_mock()

        _process_update(api, _make_update("/top"))
        api.send_message.assert_called_once()
        msg = api.send_message.call_args[0][1]
        assert "No EPSS data" in msg
    finally:
        _cleanup()


def test_handle_cve_usage_error():
    """/cve without argument shows usage."""
    _seed, _cleanup = _fresh_db("cve_usage")
    try:
        _, token = _seed()
        from horus.bot.telegram import _process_update

        api = MagicMock()
        _process_update(api, _make_update(f"/start {token}"))
        api.reset_mock()

        _process_update(api, _make_update("/cve"))
        api.send_message.assert_called_once()
        msg = api.send_message.call_args[0][1]
        assert "Usage:" in msg
    finally:
        _cleanup()


def test_handle_cve_with_results():
    """/cve with matching CVE returns results."""
    _seed, _cleanup = _fresh_db("cve_hit")
    try:
        _, token = _seed()
        from horus.bot.telegram import _process_update

        api = MagicMock()
        _process_update(api, _make_update(f"/start {token}"))
        api.reset_mock()

        with _db.connect() as conn:
            conn.execute(
                "INSERT INTO cve (id, description, cvss_score, cvss_severity, first_seen, last_seen, epss_score, kev) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "CVE-2026-9999",
                    "Test vulnerability",
                    8.5,
                    "HIGH",
                    "2026-01-01T00:00:00Z",
                    "2026-01-01T00:00:00Z",
                    0.75,
                    1,
                ),
            )

        _process_update(api, _make_update("/cve CVE-2026-9999"))
        api.send_message.assert_called_once()
        msg = api.send_message.call_args[0][1]
        assert "CVE-2026-9999" in msg
        assert "Test vulnerability" in msg
    finally:
        _cleanup()


def test_handle_top_with_results():
    """/top with EPSS data returns results."""
    _seed, _cleanup = _fresh_db("top_hit")
    try:
        _, token = _seed()
        from horus.bot.telegram import _process_update

        api = MagicMock()
        _process_update(api, _make_update(f"/start {token}"))
        api.reset_mock()

        with _db.connect() as conn:
            conn.execute(
                "INSERT INTO cve (id, description, cvss_score, cvss_severity, first_seen, last_seen, epss_score, kev) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "CVE-2026-1111",
                    "High EPSS vuln",
                    9.0,
                    "CRITICAL",
                    "2026-01-01T00:00:00Z",
                    "2026-01-01T00:00:00Z",
                    0.95,
                    1,
                ),
            )

        _process_update(api, _make_update("/top"))
        api.send_message.assert_called_once()
        msg = api.send_message.call_args[0][1]
        assert "Top by EPSS" in msg
        assert "CVE-2026-1111" in msg
    finally:
        _cleanup()
