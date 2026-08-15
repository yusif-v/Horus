"""Plugin type contracts shared by PluginManager and the pipeline."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class PluginKind(str, Enum):
    SOURCE = "source"
    ENRICHER = "enricher"
    NOTIFICATION = "notification"


@dataclass
class PluginManifest:
    name: str
    type: PluginKind
    version: str
    entrypoint: str = "main"
    enabled_by_default: bool = True
    interval_seconds: int = 3600
    config_schema: dict[str, Any] = field(default_factory=dict)
    requires: list[str] = field(default_factory=list)


@dataclass
class NotificationContext:
    """Inputs to a notification plugin's `notify(events, ctx)` call.

    `send` is a helper the plugin calls instead of talking to a transport
    directly, so the same plugin contract works for Telegram/Slack/email.

    `prefs` is keyed by user id: ``prefs[user_id]`` is that user's
    per-kind enabled map (defaults already merged). This keeps per-user
    opt-outs intact — a user who disabled a kind must not receive it
    just because someone else enabled it.
    """

    token: str | None
    users: list[Any]
    prefs: dict[Any, dict[str, bool]]
    send: Callable[[str, str], None]


@dataclass
class Plugin:
    """A resolved, enabled plugin: manifest + loaded module + merged config."""

    name: str
    kind: PluginKind
    manifest: PluginManifest
    module: Any
    config: dict[str, Any] = field(default_factory=dict)
    # Source folder the plugin was loaded from (bundled or external).
    path: Path | None = None
    # Explicit enabled override from horus.yaml (None = use manifest default).
    enabled_override: bool | None = None
    # Display/metadata kept from the module for backward-compatible ordering.
    display_name: str = ""
    plugin_kind_tag: str = ""  # module KIND attribute ("cve"/"poc")
    provides: list[str] = field(default_factory=list)
    consumes: list[str] = field(default_factory=list)

    def run(self, ctx: Any) -> dict[str, Any]:
        return self.module.run(ctx)  # type: ignore[no-any-return]

    def enrich(self, ctx: Any) -> None:
        return self.module.enrich(ctx)  # type: ignore[no-any-return]

    def notify(self, events: dict[str, list[dict[str, Any]]], ctx: NotificationContext) -> None:
        return self.module.notify(events, ctx)  # type: ignore[no-any-return]
