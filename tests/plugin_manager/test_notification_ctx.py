"""Telegram notification plugin — ctx.send + per-user prefs routing."""

from __future__ import annotations

from horus.core.plugin_types import NotificationContext
from horus.plugins.notifications.telegram.main import notify


def test_telegram_notify_uses_ctx_send():
    sent: list[tuple[str, str]] = []
    ctx = NotificationContext(
        token="t",
        users=[(1, "alice", "chat123")],
        prefs={
            1: {
                "kev_new": True,
                "epss_jump": False,
                "critical_cve": True,
                "watchlist_match": True,
                "poc_new": True,
            }
        },
        send=lambda ch, m: sent.append((ch, m)),
    )
    events = {"kev_new": [{"cve_id": "CVE-2026-1", "cvss_score": 9.8, "cvss_severity": "CRITICAL"}]}
    notify(events, ctx)
    assert sent and sent[0][0] == "chat123"


def test_telegram_notify_respects_per_user_disabled_kind():
    """A user who disabled a kind must not receive it even if another enabled it."""
    sent: list[tuple[str, str]] = []
    events = {"poc_new": [{"cve_id": "CVE-2026-1", "url": "https://x", "source": "github"}]}
    ctx = NotificationContext(
        token="t",
        users=[(1, "alice", "chat1"), (2, "bob", "chat2")],
        prefs={
            1: {"poc_new": True},
            2: {"poc_new": False},
        },
        send=lambda ch, m: sent.append((ch, m)),
    )
    notify(events, ctx)
    # Only alice's chat receives poc_new.
    assert [ch for ch, _ in sent] == ["chat1"]


def test_telegram_notify_missing_user_prefs_defaults_off():
    sent: list[tuple[str, str]] = []
    events = {"epss_jump": [{"cve_id": "CVE-2026-1", "epss_score": 0.9}]}
    ctx = NotificationContext(
        token="t",
        users=[(1, "alice", "chat1")],
        prefs={},  # no prefs row for the user
        send=lambda ch, m: sent.append((ch, m)),
    )
    notify(events, ctx)
    assert sent == []
