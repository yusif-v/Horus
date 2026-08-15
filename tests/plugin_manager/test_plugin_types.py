"""Plugin type contracts — kinds, manifest, NotificationContext."""

from __future__ import annotations

from horus.core.plugin_types import NotificationContext, PluginKind, PluginManifest


def test_plugin_kind_values():
    assert PluginKind.SOURCE == "source"
    assert PluginKind.ENRICHER == "enricher"
    assert PluginKind.NOTIFICATION == "notification"


def test_manifest_parses_minimal():
    m = PluginManifest(
        name="github",
        type=PluginKind.SOURCE,
        version="1.0.0",
        entrypoint="main",
        enabled_by_default=True,
        interval_seconds=3600,
        config_schema={},
    )
    assert m.name == "github"
    assert m.interval_seconds == 3600


def test_notification_context_has_send_callable():
    sent: list[tuple[str, str]] = []

    def fake_send(channel: str, message: str) -> None:
        sent.append((channel, message))

    ctx = NotificationContext(token="x", users=[], prefs={}, send=fake_send)
    ctx.send("chat", "hi")
    assert sent == [("chat", "hi")]
