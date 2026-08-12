"""Single loader for all plugin kinds (sources / enrichers / notifications).

Discovers plugins from bundled `horus/plugins/<type>/` and each external
`plugin_dirs` entry. Bundled and user plugins load identically. A broken
plugin (bad manifest, missing entrypoint export, import error) is recorded in
`.broken` and skipped — never aborts the run.
"""

from __future__ import annotations

import importlib.util
import logging
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .core.plugin_types import Plugin, PluginKind, PluginManifest

logger = logging.getLogger(__name__)

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised only on 3.10
    import tomli as tomllib

_KIND_DIRS = {
    PluginKind.SOURCE: "sources",
    PluginKind.ENRICHER: "enrichers",
    PluginKind.NOTIFICATION: "notifications",
}
_EXPORT = {
    PluginKind.SOURCE: "run",
    PluginKind.ENRICHER: "enrich",
    PluginKind.NOTIFICATION: "notify",
}


def _load_toml(path: Path) -> dict[str, Any]:
    with path.open("rb") as fh:
        return tomllib.load(fh)


class PluginManager:
    def __init__(self, bundled_root: Path, external_dirs: list[Path]):
        self.bundled_root = Path(bundled_root)
        self.external_dirs = [Path(d) for d in external_dirs]
        self._plugins: dict[str, Plugin] = {}
        self.broken: list[tuple[str, str]] = []
        self.discover()

    # ── discovery ──────────────────────────────────────────────────────
    def discover(self) -> None:
        self._plugins.clear()
        self.broken.clear()
        for kind, sub in _KIND_DIRS.items():
            # Bundled first, then external (external overrides on collision).
            for base in [self.bundled_root, *self.external_dirs]:
                root = base / sub
                if not root.is_dir():
                    continue
                for entry in root.iterdir():
                    if not entry.is_dir() or entry.name.startswith("_"):
                        continue
                    toml_path = entry / "plugin.toml"
                    if not toml_path.exists():
                        continue
                    try:
                        data = _load_toml(toml_path)
                    except Exception as e:
                        self.broken.append((entry.name, f"toml: {e}"))
                        continue
                    try:
                        plugin = self._build(kind, entry, data)
                    except Exception as e:
                        self.broken.append((entry.name, str(e)))
                        continue
                    self._plugins[plugin.name] = plugin

    def _load_module(self, entry: Path, entrypoint: str) -> Any:
        mod_path = entry / f"{entrypoint}.py"
        if not mod_path.exists():
            raise ValueError(f"entrypoint {entrypoint}.py not found")
        spec = importlib.util.spec_from_file_location(
            f"_horus_plugin_{entry.name}_{entrypoint}", mod_path
        )
        assert spec and spec.loader
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def _build(self, kind: PluginKind, entry: Path, data: dict[str, Any]) -> Plugin:
        p = data.get("plugin", {})
        name = p.get("name") or entry.name
        ptype = p.get("type")
        if ptype not in (kind.value, _KIND_DIRS[kind]):
            raise ValueError(f"type '{ptype}' != dir '{kind.value}'")
        entrypoint = p.get("entrypoint", "main")
        mod = self._load_module(entry, entrypoint)
        export = _EXPORT[kind]
        if not hasattr(mod, export) or not callable(getattr(mod, export)):
            raise ValueError(f"missing export '{export}'")
        sched = data.get("schedule", {})
        manifest = PluginManifest(
            name=name,
            type=kind,
            version=str(p.get("version", "0.0.0")),
            entrypoint=entrypoint,
            enabled_by_default=bool(p.get("enabled_by_default", True)),
            interval_seconds=int(sched.get("interval_seconds", 3600)),
            config_schema=data.get("config", {}),
            requires=p.get("requires", []),
        )
        return Plugin(
            name=name,
            kind=kind,
            manifest=manifest,
            module=mod,
            display_name=getattr(mod, "NAME", name),
            plugin_kind_tag=getattr(mod, "KIND", ""),
            provides=getattr(mod, "PROVIDES", []),
            consumes=getattr(mod, "CONSUMES", []),
        )

    # ── accessors ─────────────────────────────────────────────────────
    def apply_config(self, plugins_cfg: dict[str, dict[str, Any]]) -> None:
        """Merge enable/interval/config overrides from horus.yaml `plugins:`."""
        for name, over in plugins_cfg.items():
            p = self._plugins.get(name)
            if p is None:
                continue
            if "interval_seconds" in over and over["interval_seconds"] is not None:
                p.manifest.interval_seconds = int(over["interval_seconds"])
            if "config" in over and isinstance(over["config"], dict):
                p.config = dict(over["config"])
            # enabled is handled at accessor time via get_enabled()
            if "enabled" in over:
                p._override_enabled = bool(over["enabled"])  # type: ignore[attr-defined]

    def is_enabled(self, name: str) -> bool:
        p = self._plugins.get(name)
        if p is None:
            return False
        if hasattr(p, "_override_enabled"):
            return p._override_enabled  # type: ignore[no-any-return]
        return p.manifest.enabled_by_default

    def _by_kind(self, kind: PluginKind) -> dict[str, Plugin]:
        return {n: p for n, p in self._plugins.items() if p.kind == kind and self.is_enabled(n)}

    def due_sources(self, now_epoch: float, last_run_getter: Callable[[str], float]) -> list[str]:
        out = []
        for name, p in self.sources().items():
            last = last_run_getter(name) or 0.0
            if now_epoch - last >= p.manifest.interval_seconds:
                out.append(name)
        return out

    def sources(self) -> dict[str, Plugin]:
        return self._by_kind(PluginKind.SOURCE)

    def enrichers(self) -> dict[str, Plugin]:
        return self._by_kind(PluginKind.ENRICHER)

    def notifications(self) -> dict[str, Plugin]:
        return self._by_kind(PluginKind.NOTIFICATION)

    def get(self, name: str) -> Plugin | None:
        return self._plugins.get(name)
