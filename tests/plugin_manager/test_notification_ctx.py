from __future__ import annotations

from horus.core.plugin_types import NotificationContext
from horus.plugins.notifications.telegram.main import notify


def test_telegram_notify_uses_ctx_send():
    sent: list[tuple[str, str]] = []
    ctx = NotificationContext(
        token="t",
        users=[(1, "alice", "chat123")],
        prefs={
            "kev_new": True,
            "epss_jump": False,
            "critical_cve": True,
            "watchlist_match": True,
            "poc_new": True,
        },
        send=lambda ch, m: sent.append((ch, m)),
    )
    events = {"kev_new": [{"cve_id": "CVE-2026-1", "cvss_score": 9.8, "cvss_severity": "CRITICAL"}]}
    notify(events, ctx)
    assert sent and sent[0][0] == "chat123"
