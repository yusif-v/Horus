# Plugin System Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace all hard-coded built-in sources/enrichers/Telegram with a unified, folder+`plugin.toml` plugin scheme loaded by a single `PluginManager`. Bundled and user plugins load identically. Add a `horus plugin` CLI (list/enable/disable/config/add/remove/scaffold/validate) and a new `NotificationContext` contract. No feature/behavior change for existing sources — only repackaging + a new discovery path.

**Architecture:** A new `horus/plugin_manager.py` discovers plugins from bundled `horus/plugins/<type>/` and external `plugin_dirs`, parses each `plugin.toml`, validates the entrypoint export, and returns enabled plugins as `Plugin` wrappers exposing `.run`/`.enrich`/`.notify` bound to per-plugin config + context. `cli.py` and `server.py` consume the manager instead of the legacy `discover_sources()`/`poll_intervals`/`sources_enabled` globals. Existing modules move into `horus/plugins/.../` folders (relative imports rewritten to absolute `horus.` imports); internal pipeline helpers (`nvd_fetch`, `news_linker`, `url_resolve`, `resource_intelligence`) stay as ordinary modules.

**Tech Stack:** Python 3.10+ (tomllib builtin on 3.11+, `tomli` fallback dep for 3.10), PyYAML (already optional in server), pytest, ruff, mypy. No new third-party runtime deps beyond `tomli`.

## Global Constraints

- Project floor is `requires-python = ">=3.10"`. Use `tomllib` with `tomli` fallback; add `tomli` to `pyproject.toml` dependencies for the 3.10 floor.
- Keep `pytest --cov-fail-under=70` green throughout. Every task ends with a passing test + commit.
- Migrated plugin modules MUST use absolute imports (`from horus.config import ...`, `from horus.net.http import ...`, `from horus.core.filters import ...`) — never `..`-relative, because they now live under `horus/plugins/sources/<name>/`.
- Preserve existing runtime behavior: source `run(ctx)` signatures, enricher `enrich(ctx)`, the `NAME`/`KIND`/`CONSUMES`/`PROVIDES`/`DEFAULT_ENABLED` module attributes, CVE-source-first ordering, and x_twitter-before-github handoff.
- Do **not** modify internal helpers: `horus/sources/nvd_fetch.py`, `news_linker.py`, `url_resolve.py`, `resource_intelligence.py`, `news.py` (verify by import-graph at Task 6; if any are `run`-exporting user-facing sources, migrate them — otherwise leave in place).
- `Plugin` wrapper must remain callable as the pipeline expects: `plugin.run(ctx)`, `plugin.enrich(ctx)`, `plugin.notify(events, ctx)`.

---

## File Structure (created/modified)

**New:**
- `horus/core/plugin_types.py` — `PluginKind` enum, `PluginManifest` dataclass, `Plugin` wrapper, `NotificationContext` dataclass.
- `horus/plugin_manager.py` — discovery, TOML parse, validation, enable/disable merge, `due_sources`, `broken`.
- `horus/plugins/sources/<name>/{plugin.toml, main.py}` for: nvd, x_twitter, github, gitlab, codeberg, exploitdb, news.
- `horus/plugins/enrichers/<name>/{plugin.toml, main.py}` for: kev, epss, otx, darkweb.
- `horus/plugins/notifications/telegram/{plugin.toml, main.py}`.
- `tests/plugin_manager/test_load.py`, `tests/plugin_manager/test_cli.py`, `tests/plugin_manager/test_scaffold.py`, `tests/plugin_manager/test_notification_ctx.py`.

**Modified:**
- `horus/pipeline.py` — `run_pipeline` consumes `manager`-built plugin dicts; `discover_sources()`/`discover_enrichers()` repointed or kept as shims.
- `horus/server.py` — `Config` gains `plugin_dirs` + `plugins`; `load_config` reads unified schema + legacy shim; `run_due`/`run_once`/`_invoke_pipeline` use `manager`.
- `horus/cli.py` — add `horus plugin` subcommand; `_cmd_server` passes manager to pipeline.
- `horus/notifications/dispatcher.py` — logic moves into telegram plugin `main.py` (then dispatcher can be deleted or kept as thin shim).
- `pyproject.toml` — add `tomli` dependency; bump version to `0.16.0`.
- `horus.yaml.example` — unified `plugin_dirs` + `plugins` form.
- `docs/architecture.md` (plugin section), `docs/plugins.md` (new), `CHANGELOG.md`.

**Deleted (after migration):**
- `horus/sources/` package (and `__init__.py`) once all `run`-exporting sources moved.
- `horus/enrichers/` package (and `__init__.py`) once all enrichers moved.

---

### Task 1: Plugin type contracts + NotificationContext

**Files:**
- Create: `horus/core/plugin_types.py`
- Test: `tests/plugin_manager/test_plugin_types.py`

**Interfaces:**
- Consumes: nothing (foundational).
- Produces: `PluginKind`, `PluginManifest`, `Plugin`, `NotificationContext` (imported by Tasks 2–9).

- [ ] **Step 1: Write the failing test**

```python
# tests/plugin_manager/test_plugin_types.py
from __future__ import annotations
from dataclasses import dataclass
from horus.core.plugin_types import PluginKind, PluginManifest, Plugin, NotificationContext


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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/lizard/Development/Projects/Horus && ./.venv/bin/python -m pytest tests/plugin_manager/test_plugin_types.py -q`
Expected: FAIL (import error — module does not exist).

- [ ] **Step 3: Write minimal implementation**

```python
# horus/core/plugin_types.py
"""Plugin type contracts shared by PluginManager and the pipeline."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable


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
    """

    token: str | None
    users: list[Any]
    prefs: dict[str, dict[str, bool]]
    send: Callable[[str, str], None]


@dataclass
class Plugin:
    """A resolved, enabled plugin: manifest + loaded module + merged config."""

    name: str
    kind: PluginKind
    manifest: PluginManifest
    module: Any
    config: dict[str, Any] = field(default_factory=dict)
    # Display/metadata kept from the module for backward-compatible ordering.
    display_name: str = ""
    plugin_kind_tag: str = ""   # module KIND attribute ("cve"/"poc")
    provides: list[str] = field(default_factory=list)
    consumes: list[str] = field(default_factory=list)

    def run(self, ctx) -> dict:
        return self.module.run(ctx)

    def enrich(self, ctx) -> None:
        return self.module.enrich(ctx)

    def notify(self, events: dict[str, list[dict]], ctx: NotificationContext) -> None:
        return self.module.notify(events, ctx)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/lizard/Development/Projects/Horus && ./.venv/bin/python -m pytest tests/plugin_manager/test_plugin_types.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd /Users/lizard/Development/Projects/Horus && git add horus/core/plugin_types.py tests/plugin_manager/test_plugin_types.py && git commit -m "feat(plugins): add plugin type contracts + NotificationContext"
```

---

### Task 2: PluginManager — discovery, TOML parse, validation, enable/disable

**Files:**
- Create: `horus/plugin_manager.py`
- Test: `tests/plugin_manager/test_load.py`
- Modify: `pyproject.toml` (add `tomli` dep)

**Interfaces:**
- Consumes: `PluginKind`, `PluginManifest`, `Plugin` from Task 1.
- Produces: `PluginManager(bundled_root, external_dirs)`, `.discover()`, `.sources()`, `.enrichers()`, `.notifications()`, `.broken`, `.get(name)`, `.enabled_for(kind)`.

- [ ] **Step 1: Write the failing test**

```python
# tests/plugin_manager/test_load.py
from __future__ import annotations
from pathlib import Path
import pytest
from horus.plugin_manager import PluginManager
from horus.core.plugin_types import PluginKind

BUNDLED = Path(__file__).parent.parent.parent / "horus" / "plugins"


def _make_plugin(root: Path, kind: str, name: str, enabled: bool = True) -> None:
    d = root / kind / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "plugin.toml").write_text(
        f'[plugin]\nname = "{name}"\ntype = "{kind}"\nversion = "1.0.0"\n'
        f'entrypoint = "main"\nenabled_by_default = {str(enabled).lower()}\n'
        "[schedule]\ninterval_seconds = 3600\n"
    )
    (d / "main.py").write_text(
        "NAME = 'X'\nKIND = 'poc'\nDEFAULT_ENABLED = True\n"
        "def run(ctx):\n    return {'cves': [], 'pocs': []}\n"
    )


def test_discovers_bundled_sources(tmp_path):
    _make_plugin(BUNDLED, "sources", "demo_src")
    mgr = PluginManager(bundled_root=BUNDLED, external_dirs=[tmp_path])
    srcs = mgr.sources()
    assert "demo_src" in srcs
    assert srcs["demo_src"].kind == PluginKind.SOURCE


def test_external_overrides_bundled(tmp_path):
    _make_plugin(BUNDLED, "sources", "dup")
    ext = tmp_path / "ext"
    _make_plugin(ext, "sources", "dup")
    mgr = PluginManager(bundled_root=BUNDLED, external_dirs=[ext])
    # External wins on collision; both still resolve to a single enabled entry.
    assert "dup" in mgr.sources()


def test_disabled_plugin_excluded(tmp_path):
    _make_plugin(tmp_path, "sources", "off", enabled=False)
    mgr = PluginManager(bundled_root=BUNDLED, external_dirs=[tmp_path])
    assert "off" not in mgr.sources()


def test_broken_plugin_skipped(tmp_path):
    d = tmp_path / "sources" / "broken"
    d.mkdir(parents=True)
    (d / "plugin.toml").write_text(
        '[plugin]\nname = "broken"\ntype = "source"\nversion = "1.0.0"\n'
        'entrypoint = "main"\n'
    )
    # main.py missing → import fails → recorded broken, not raised.
    mgr = PluginManager(bundled_root=BUNDLED, external_dirs=[tmp_path])
    assert "broken" in {n for n, _ in mgr.broken}
    assert "broken" not in mgr.sources()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/lizard/Development/Projects/Horus && ./.venv/bin/python -m pytest tests/plugin_manager/test_load.py -q`
Expected: FAIL (import error).

- [ ] **Step 3: Add `tomli` dep (modify pyproject.toml dependencies line)**

Change `dependencies = []` → `dependencies = ["tomli; python_version < '3.11'"]`.

- [ ] **Step 4: Write minimal implementation**

```python
# horus/plugin_manager.py
"""Single loader for all plugin kinds (sources / enrichers / notifications).

Discovers plugins from bundled `horus/plugins/<type>/` and each external
`plugin_dirs` entry. Bundled and user plugins load identically. A broken
plugin (bad manifest, missing entrypoint export, import error) is recorded in
`.broken` and skipped — never aborts the run.
"""
from __future__ import annotations

import importlib
import logging
import sys
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
            found: dict[str, tuple[Path, dict]] = {}
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
                    except Exception as e:  # noqa: BLE001
                        self.broken.append((entry.name, f"toml: {e}"))
                        continue
                    try:
                        plugin = self._build(kind, entry, data)
                    except Exception as e:  # noqa: BLE001
                        self.broken.append((entry.name, str(e)))
                        continue
                    found[plugin.name] = (entry, data)
                    self._plugins[plugin.name] = plugin
            # Re-register external overrides last so they win.
            for base in self.external_dirs:
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
                        plugin = self._build(kind, entry, data)
                    except Exception as e:  # noqa: BLE001
                        self.broken.append((entry.name, str(e)))
                        continue
                    self._plugins[plugin.name] = plugin

    def _build(self, kind: PluginKind, entry: Path, data: dict) -> Plugin:
        p = data.get("plugin", {})
        name = p.get("name") or entry.name
        ptype = p.get("type")
        if ptype != kind.value:
            raise ValueError(f"type '{ptype}' != dir '{kind.value}'")
        entrypoint = p.get("entrypoint", "main")
        mod = importlib.import_module(f"{entry.parent.parent.parent.name}."
                                      f"{entry.parent.parent.name}."
                                      f"{entry.name}.{entrypoint}")
        # Also support external dirs where the package root is the plugin folder.
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
    def _by_kind(self, kind: PluginKind) -> dict[str, Plugin]:
        return {n: p for n, p in self._plugins.items() if p.kind == kind}

    def sources(self) -> dict[str, Plugin]:
        return self._by_kind(PluginKind.SOURCE)

    def enrichers(self) -> dict[str, Plugin]:
        return self._by_kind(PluginKind.ENRICHER)

    def notifications(self) -> dict[str, Plugin]:
        return self._by_kind(PluginKind.NOTIFICATION)

    def get(self, name: str) -> Plugin | None:
        return self._plugins.get(name)
```

> Note: the `importlib.import_module` call above assumes bundled plugins are importable as `horus.plugins.<type>.<name>.<entrypoint>`. For external dirs this must resolve against `sys.path`. **Step fixes in Task 2b below** — the loader must add external plugin dirs to `sys.path` (or use importlib.util.spec_from_file_location). Implement the spec-based loader variant:

Replace the `_build` import line with a spec loader that works for both:

```python
import importlib.util

def _load_module(entry: Path, entrypoint: str):
    mod_path = entry / f"{entrypoint}.py"
    if not mod_path.exists():
        raise ValueError(f"entrypoint {entrypoint}.py not found")
    spec = importlib.util.spec_from_file_location(
        f"_horus_plugin_{entry.name}_{entrypoint}", mod_path
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod
```

Use `mod = self._load_module(entry, entrypoint)` in `_build`. This works for both bundled (path resolves fine) and external dirs (no sys.path hack needed). Update the test `test_external_overrides_bundled` expectation — it only checks the name resolves; spec loader satisfies it.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd /Users/lizard/Development/Projects/Horus && ./.venv/bin/python -m pytest tests/plugin_manager/test_load.py -q`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
cd /Users/lizard/Development/Projects/Horus && git add horus/plugin_manager.py tests/plugin_manager/test_load.py pyproject.toml && git commit -m "feat(plugins): add PluginManager discovery + validation"
```

---

### Task 3: Enable/disable + per-plugin config merge + `due_sources`

**Files:**
- Modify: `horus/plugin_manager.py`
- Test: `tests/plugin_manager/test_load.py` (extend)

**Interfaces:**
- Consumes: `PluginManager` from Task 2; config dict shape `{name: {"enabled": bool, "interval_seconds": int|None, "config": {...}}}`.
- Produces: `manager.apply_config(plugins_cfg)`, `manager.is_enabled(name)`, `manager.due_sources(now_epoch, last_run_getter)`.

- [ ] **Step 1: Write the failing test (append to test_load.py)**

```python
def test_apply_config_disables_and_overrides_interval(tmp_path):
    from horus.plugin_manager import PluginManager
    d = tmp_path / "sources" / "cfg"
    d.mkdir(parents=True)
    (d / "plugin.toml").write_text(
        '[plugin]\nname = "cfg"\ntype = "source"\nversion = "1.0.0"\n'
        'entrypoint = "main"\nenabled_by_default = true\n'
        "[schedule]\ninterval_seconds = 3600\n[config]\nmax = {type='int', default=10}\n"
    )
    (d / "main.py").write_text(
        "NAME='C'\nKIND='poc'\nDEFAULT_ENABLED=True\ndef run(ctx):\n return {'cves':[],'pocs':[]}\n"
    )
    mgr = PluginManager(bundled_root=tmp_path / "never", external_dirs=[tmp_path])
    assert "cfg" in mgr.sources()
    mgr.apply_config({"cfg": {"enabled": False, "interval_seconds": 1800, "config": {"max": 50}}})
    assert "cfg" not in mgr.sources()
    # Re-enable to inspect config merge
    mgr.apply_config({"cfg": {"enabled": True, "interval_seconds": 1800, "config": {"max": 50}}})
    p = mgr.get("cfg")
    assert p.config == {"max": 50}
    assert p.manifest.interval_seconds == 1800


def test_due_sources_uses_interval(tmp_path):
    import time
    from horus.plugin_manager import PluginManager
    d = tmp_path / "sources" / "due"
    d.mkdir(parents=True)
    (d / "plugin.toml").write_text(
        '[plugin]\nname = "due"\ntype = "source"\nversion = "1.0.0"\n'
        'entrypoint = "main"\n[schedule]\ninterval_seconds = 10\n'
    )
    (d / "main.py").write_text("NAME='D'\nKIND='poc'\ndef run(ctx):\n return {}\n")
    mgr = PluginManager(bundled_root=tmp_path / "never", external_dirs=[tmp_path])
    mgr.apply_config({"due": {"enabled": True, "interval_seconds": 10}})
    last = {"due": 0.0}  # never run
    due = mgr.due_sources(time.time(), lambda n: last.get(n, 0.0))
    assert "due" in due
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/lizard/Development/Projects/Horus && ./.venv/bin/python -m pytest tests/plugin_manager/test_load.py::test_apply_config_disables_and_overrides_interval -q`
Expected: FAIL (AttributeError: no `apply_config`).

- [ ] **Step 3: Implement on PluginManager**

Add to `horus/plugin_manager.py` (inside class):

```python
    def apply_config(self, plugins_cfg: dict[str, dict]) -> None:
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
                p._override_enabled = bool(over["enabled"])

    def is_enabled(self, name: str) -> bool:
        p = self._plugins.get(name)
        if p is None:
            return False
        if hasattr(p, "_override_enabled"):
            return p._override_enabled
        return p.manifest.enabled_by_default

    def _by_kind(self, kind: PluginKind) -> dict[str, Plugin]:
        return {n: p for n, p in self._plugins.items()
                if p.kind == kind and self.is_enabled(n)}

    def due_sources(self, now_epoch: float, last_run_getter) -> list[str]:
        out = []
        for name, p in self.sources().items():
            last = last_run_getter(name) or 0.0
            if now_epoch - last >= p.manifest.interval_seconds:
                out.append(name)
        return out
```

- [ ] **Step 4: Run tests**

Run: `cd /Users/lizard/Development/Projects/Horus && ./.venv/bin/python -m pytest tests/plugin_manager/test_load.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd /Users/lizard/Development/Projects/Horus && git add horus/plugin_manager.py tests/plugin_manager/test_load.py && git commit -m "feat(plugins): config merge, enable/disable, due_sources"
```

---

### Task 4: `validate` + `scaffold` generators

**Files:**
- Create: `horus/plugin_scaffold.py` (or methods on PluginManager: `scaffold(kind, name, dest)` and `validate_plugin(path)`).
- Test: `tests/plugin_manager/test_scaffold.py`

**Interfaces:**
- Consumes: `PluginKind` from Task 1.
- Produces: `scaffold_plugin(kind, name, dest_dir) -> Path`, `validate_plugin(folder) -> list[str]` (errors, empty == valid).

- [ ] **Step 1: Write the failing test**

```python
# tests/plugin_manager/test_scaffold.py
from __future__ import annotations
from pathlib import Path
from horus.plugin_manager import scaffold_plugin, validate_plugin
from horus.core.plugin_types import PluginKind


def test_scaffold_source_valid(tmp_path):
    out = scaffold_plugin(PluginKind.SOURCE, "mysrc", tmp_path)
    assert (out / "plugin.toml").exists()
    assert (out / "main.py").exists()
    errs = validate_plugin(out)
    assert errs == [], errs


def test_scaffold_notification_has_notify(tmp_path):
    out = scaffold_plugin(PluginKind.NOTIFICATION, "myntfy", tmp_path)
    body = (out / "main.py").read_text()
    assert "def notify(events, ctx):" in body
    assert validate_plugin(out) == []


def test_validate_rejects_missing_export(tmp_path):
    d = tmp_path / "bad"
    d.mkdir()
    (d / "plugin.toml").write_text(
        '[plugin]\nname="bad"\ntype="source"\nversion="1.0.0"\n'
    )
    (d / "main.py").write_text("NAME='B'\n")  # no run()
    errs = validate_plugin(d)
    assert any("run" in e for e in errs)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/lizard/Development/Projects/Horus && ./.venv/bin/python -m pytest tests/plugin_manager/test_scaffold.py -q`
Expected: FAIL (import error).

- [ ] **Step 3: Implement**

Add to `horus/plugin_manager.py`:

```python
import shutil

_SCAFFOLD_STUBS = {
    PluginKind.SOURCE: (
        'NAME = "{name}"\nKIND = "poc"\nDEFAULT_ENABLED = True\n\n'
        'def run(ctx):\n    """Return {"cves": [], "pocs": []}."""\n'
        "    return {'cves': [], 'pocs': []}\n"
    ),
    PluginKind.ENRICHER: (
        'NAME = "{name}"\nDEFAULT_ENABLED = True\n\n'
        'def enrich(ctx):\n    """Mutate ctx.cves / ctx.pocs in place."""\n'
        "    pass\n"
    ),
    PluginKind.NOTIFICATION: (
        'NAME = "{name}"\nDEFAULT_ENABLED = True\n\n'
        'def notify(events, ctx):\n'
        '    """events: dict[str, list[dict]]; ctx: NotificationContext."""\n'
        "    for kind, items in events.items():\n"
        "        for item in items:\n"
        "            ctx.send('default', f'{kind}: {item}')\n"
    ),
}


def scaffold_plugin(kind: PluginKind, name: str, dest_dir: Path) -> Path:
    dest = Path(dest_dir) / name
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "plugin.toml").write_text(
        f'[plugin]\nname = "{name}"\ntype = "{kind.value}"\nversion = "0.1.0"\n'
        f'entrypoint = "main"\nenabled_by_default = true\n'
        "[schedule]\ninterval_seconds = 3600\n"
    )
    (dest / "main.py").write_text(_SCAFFOLD_STUBS[kind].format(name=name))
    return dest


def validate_plugin(folder: Path) -> list[str]:
    folder = Path(folder)
    errs: list[str] = []
    toml_path = folder / "plugin.toml"
    if not toml_path.exists():
        return ["missing plugin.toml"]
    try:
        data = _load_toml(toml_path)
    except Exception as e:  # noqa: BLE001
        return [f"toml parse: {e}"]
    p = data.get("plugin", {})
    kind = p.get("type")
    if kind not in _KIND_DIRS:
        return [f"unknown type '{kind}'"]
    entrypoint = p.get("entrypoint", "main")
    mod_path = folder / f"{entrypoint}.py"
    if not mod_path.exists():
        return [f"missing {entrypoint}.py"]
    try:
        mod = _load_module(folder, entrypoint)
    except Exception as e:  # noqa: BLE001
        return [f"import: {e}"]
    export = _EXPORT[PluginKind(kind)]
    if not hasattr(mod, export):
        errs.append(f"missing export '{export}'")
    return errs
```

- [ ] **Step 4: Run tests**

Run: `cd /Users/lizard/Development/Projects/Horus && ./.venv/bin/python -m pytest tests/plugin_manager/test_scaffold.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd /Users/lizard/Development/Projects/Horus && git add horus/plugin_manager.py tests/plugin_manager/test_scaffold.py && git commit -m "feat(plugins): scaffold + validate generators"
```

---

### Task 5: `horus plugin` CLI subcommand

**Files:**
- Modify: `horus/cli.py` (add `plugin` subparser + `_cmd_plugin`)
- Test: `tests/plugin_manager/test_cli.py`

**Interfaces:**
- Consumes: `PluginManager`, `scaffold_plugin`, `validate_plugin` from Tasks 2–4.
- Produces: `horus plugin list|enable|disable|config|add|remove|scaffold|validate` working end-to-end against a temp `--plugins-dir` + temp `horus.yaml`.

- [ ] **Step 1: Write the failing test**

```python
# tests/plugin_manager/test_cli.py
from __future__ import annotations
from pathlib import Path
import pytest
from horus.plugin_manager import PluginManager, scaffold_plugin
from horus.core.plugin_types import PluginKind


def _write_yaml(path: Path, plugins_dir: Path) -> None:
    path.write_text(
        f"plugin_dirs:\n  - {plugins_dir}\nplugins:\n  demo:\n    enabled: true\n"
    )


def test_cli_list_shows_external(tmp_path, capsys):
    from horus.cli import _cmd_plugin
    import argparse
    pd = tmp_path / "plugins"
    scaffold_plugin(PluginKind.SOURCE, "demo", pd)
    yaml = tmp_path / "horus.yaml"
    _write_yaml(yaml, pd)
    args = argparse.Namespace(cmd="list", name=None, key=None, value=None,
                              plugins_dir=pd, config=str(yaml))
    _cmd_plugin(args)
    out = capsys.readouterr().out
    assert "demo" in out


def test_cli_scaffold_then_validate(tmp_path, capsys):
    from horus.cli import _cmd_plugin
    import argparse
    pd = tmp_path / "plugins"
    yaml = tmp_path / "horus.yaml"
    _write_yaml(yaml, pd)
    a1 = argparse.Namespace(cmd="scaffold", kind="notification", name="nt",
                            plugins_dir=pd, config=str(yaml))
    _cmd_plugin(a1)
    a2 = argparse.Namespace(cmd="validate", name="nt", key=None, value=None,
                            plugins_dir=pd, config=str(yaml))
    _cmd_plugin(a2)
    assert (pd / "nt" / "plugin.toml").exists()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/lizard/Development/Projects/Horus && ./.venv/bin/python -m pytest tests/plugin_manager/test_cli.py -q`
Expected: FAIL (import error — `_cmd_plugin` not defined).

- [ ] **Step 3: Implement `_cmd_plugin` in cli.py**

Add near other `_cmd_*` functions:

```python
def _cmd_plugin(args) -> None:
    """`horus plugin <subcommand>` — manage plugins via PluginManager."""
    from pathlib import Path
    from .plugin_manager import PluginManager, scaffold_plugin, validate_plugin
    from .core.plugin_types import PluginKind

    plugins_dir = Path(args.plugins_dir) if args.plugins_dir else Path("~/.config/horus/plugins").expanduser()
    bundled = Path(__file__).parent / "plugins"
    mgr = PluginManager(bundled_root=bundled, external_dirs=[plugins_dir])

    # Apply enable/disable from config if present.
    if args.config:
        from .server import _load_plugins_section
        mgr.apply_config(_load_plugins_section(args.config))

    if args.cmd == "list":
        for kind in ("source", "enricher", "notification"):
            buckets = {"source": mgr.sources(), "enricher": mgr.enrichers(),
                       "notification": mgr.notifications()}[kind]
            for name, p in sorted(buckets.items()):
                print(f"[{kind}] {name} v{p.manifest.version} ({p.display_name})")
        for name, err in mgr.broken:
            print(f"[broken] {name}: {err}")
    elif args.cmd == "scaffold":
        kind = PluginKind(args.kind)
        out = scaffold_plugin(kind, args.name, plugins_dir)
        print(f"scaffolded {kind.value} plugin -> {out}")
    elif args.cmd == "validate":
        target = plugins_dir / args.name
        if not target.exists():
            target = bundled / args.kind_or_sub(args.name) if hasattr(args, "kind_or_sub") else bundled
        errs = validate_plugin(plugins_dir / args.name)
        print("OK" if not errs else "INVALID:\n" + "\n".join(errs))
    elif args.cmd in ("enable", "disable"):
        _plugin_set_enabled(args.config, args.name, args.cmd == "enable")
        print(f"{args.name} {'enabled' if args.cmd == 'enable' else 'disabled'}")
    elif args.cmd == "config":
        if args.key is None:
            _plugin_show_config(args.config, args.name)
        else:
            _plugin_set_config(args.config, args.name, args.key, args.value)
            print(f"set {args.name}.{args.key} = {args.value}")
    elif args.cmd == "add":
        import shutil
        dest = plugins_dir / Path(args.name).name
        shutil.copytree(Path(args.name), dest, dirs_exist_ok=True)
        print(f"added plugin -> {dest}")
    elif args.cmd == "remove":
        print("remove only supported for external plugins; use `horus plugin add` to reinstall")
```

Add helpers `_plugin_set_enabled`, `_plugin_show_config`, `_plugin_set_config` that read/write the `plugins:` block of `horus.yaml` (YAML via PyYAML if present, else JSON). Keep them small and in `cli.py`.

Wire the subparser in `main()` (or wherever subparsers are built):
```python
pp = sub = p.add_subparsers(dest="command")  # ensure subparsers exist
plug = sub.add_parser("plugin", help="manage plugins")
plug.add_argument("cmd", choices=["list","enable","disable","config","add","remove","scaffold","validate"])
plug.add_argument("kind", nargs="?", help="plugin type (scaffold)")
plug.add_argument("name", nargs="?", help="plugin name or path")
plug.add_argument("key", nargs="?", help="config key (config set)")
plug.add_argument("value", nargs="?", help="config value (config set)")
plug.add_argument("--plugins-dir", default=None)
plug.add_argument("--config", default=None)
```

> Exact arg mapping (`kind`/`name` positional order) may need to match your existing `main()` subparser style. Adapt the positional indices to the test's `argparse.Namespace` fields (`cmd`, `kind`, `name`, `key`, `value`, `plugins_dir`, `config`). The tests pass a `Namespace` directly to `_cmd_plugin`, so `_cmd_plugin` must read those attribute names.

- [ ] **Step 4: Run tests**

Run: `cd /Users/lizard/Development/Projects/Horus && ./.venv/bin/python -m pytest tests/plugin_manager/test_cli.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd /Users/lizard/Development/Projects/Horus && git add horus/cli.py tests/plugin_manager/test_cli.py && git commit -m "feat(plugins): add `horus plugin` CLI subcommand"
```

---

### Task 6: Migrate sources → `horus/plugins/sources/<name>/`

**Files:**
- Create: `horus/plugins/sources/{nvd,x_twitter,github,gitlab,codeberg,exploitdb,news}/{plugin.toml, main.py}`
- Modify: each `main.py` re-exports the existing `run` (move body verbatim; **convert relative imports to absolute `horus.` imports**).
- Test: `tests/plugin_manager/test_migrated_sources.py`

**Interfaces:**
- Consumes: existing `horus/sources/*.py` `run(ctx)` bodies, unchanged.
- Produces: enabled source plugins resolvable by `PluginManager(bundled_root=horus/plugins)`.

This is mechanical. For EACH source file `horus/sources/<name>.py`:

1. Create `horus/plugins/sources/<name>/plugin.toml`:
```toml
[plugin]
name = "<name>"
type = "source"
version = "1.0.0"
entrypoint = "main"
enabled_by_default = true
[schedule]
interval_seconds = <from DEFAULT_POLL_INTERVALS or horus.yaml: nvd=3600, x_twitter=1800, github=3600, gitlab=3600, exploit_db=7200, news=3600>
[config]
# copy any source-specific tunables from horus/config here if needed
```
2. Create `horus/plugins/sources/<name>/main.py` containing the **exact** current `run` function body plus its module-level `NAME`/`KIND`/`CONSUMES`/`PROVIDES`/`DEFAULT_ENABLED` attributes, with imports rewritten:
   - `from ..config import ...` → `from horus.config import ...`
   - `from ..net.http import ...` → `from horus.net.http import ...`
   - `from ..core.filters import ...` → `from horus.core.filters import ...`
   - `from ..net.auth import github_token` → `from horus.net.auth import github_token`
   - any `from ..X import Y` → `from horus.X import Y`
3. Verify `run` signature unchanged: `def run(ctx) -> dict`.

- [ ] **Step 1: Write the failing test**

```python
# tests/plugin_manager/test_migrated_sources.py
from __future__ import annotations
from pathlib import Path
from horus.plugin_manager import PluginManager
from horus.core.plugin_types import PluginKind

BUNDLED = Path(__file__).parent.parent.parent / "horus" / "plugins"

EXPECTED = ["nvd", "x_twitter", "github", "gitlab", "codeberg", "exploitdb", "news"]


def test_all_builtin_sources_discovered():
    mgr = PluginManager(bundled_root=BUNDLED, external_dirs=[])
    srcs = mgr.sources()
    for name in EXPECTED:
        assert name in srcs, f"{name} not discovered"
        assert srcs[name].kind == PluginKind.SOURCE


def test_no_broken_builtin_sources():
    mgr = PluginManager(bundled_root=BUNDLED, external_dirs=[])
    assert mgr.broken == [], mgr.broken
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/lizard/Development/Projects/Horus && ./.venv/bin/python -m pytest tests/plugin_manager/test_migrated_sources.py -q`
Expected: FAIL (`horus/plugins/sources` doesn't exist yet).

- [ ] **Step 3: Migrate each source** (repeat the move pattern per file; use `git mv` then edit `main.py`):

```bash
cd /Users/lizard/Development/Projects/Horus
for s in nvd x_twitter github gitlab codeberg exploitdb news; do
  mkdir -p horus/plugins/sources/$s
  git mv horus/sources/$s.py horus/plugins/sources/$s/_orig.py 2>/dev/null || cp horus/sources/$s.py horus/plugins/sources/$s/_orig.py
done
```
Then, for each, write `main.py` that imports the `run` machinery. Simplest correct approach: keep the original file content but fix imports, place it as `main.py` directly (no `_orig.py`):

```bash
cd /Users/lizard/Development/Projects/Horus
for s in nvd x_twitter github gitlab codeberg exploitdb news; do
  mkdir -p horus/plugins/sources/$s
  # move original into main.py
  git mv horus/sources/$s.py horus/plugins/sources/$s/main.py 2>/dev/null || mv horus/sources/$s.py horus/plugins/sources/$s/main.py
  # rewrite relative imports to absolute
  sed -i '' -E 's/^from \.\.([a-zA-Z_.]+) import/from horus.\1 import/' horus/plugins/sources/$s/main.py
  sed -i '' -E 's/^from \.([a-zA-Z_.]+) import/from horus.sources.\1 import/' horus/plugins/sources/$s/main.py
done
```
Then hand-write each `plugin.toml` (values above). Add `CONSUMES`/`PROVIDES` attributes to `main.py` where the original had them (github had `CONSUMES = ["x_discovered_urls"]` — preserve it).

> The `sed` rewrites `from ..config import` → `from horus.config import` and `from .foo import` → `from horus.sources.foo import`. Verify no leftover `..` imports remain: `grep -rn "from \.\." horus/plugins/sources/` must return nothing.

- [ ] **Step 4: Run tests**

Run: `cd /Users/lizard/Development/Projects/Horus && ./.venv/bin/python -m pytest tests/plugin_manager/test_migrated_sources.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd /Users/lizard/Development/Projects/Horus && git add -A horus/plugins/sources tests/plugin_manager/test_migrated_sources.py && git commit -m "refactor(plugins): migrate sources to plugin folders"
```

---

### Task 7: Migrate enrichers → `horus/plugins/enrichers/<name>/`

**Files:**
- Create: `horus/plugins/enrichers/{kev,epss,otx,darkweb}/{plugin.toml, main.py}`
- Test: `tests/plugin_manager/test_migrated_enrichers.py`

**Interfaces:**
- Consumes: existing `horus/enrichers/*.py` `enrich(ctx)` + `epss.backfill_all(conn)`.
- Produces: enabled enricher plugins; `epss` plugin exposes `backfill_all` on its module (server enrichers-only path imports it).

Same move pattern as Task 6, but:
- `plugin.toml` `type = "enricher"`, `interval_seconds` from legacy (epss=86400, kev=86400, otx/darkweb=86400).
- `main.py` keeps `enrich(ctx)` and module `NAME`/`DEFAULT_ENABLED`. For `epss`, keep `backfill_all(conn)` in `main.py` (server imports `from horus.plugins.enrichers.epss.main import backfill_all` — update server in Task 9).

- [ ] **Step 1: Write the failing test**

```python
# tests/plugin_manager/test_migrated_enrichers.py
from __future__ import annotations
from pathlib import Path
from horus.plugin_manager import PluginManager
from horus.core.plugin_types import PluginKind

BUNDLED = Path(__file__).parent.parent.parent / "horus" / "plugins"
EXPECTED = ["kev", "epss", "otx", "darkweb"]


def test_all_builtin_enrichers_discovered():
    mgr = PluginManager(bundled_root=BUNDLED, external_dirs=[])
    enr = mgr.enrichers()
    for name in EXPECTED:
        assert name in enr, f"{name} not discovered"
        assert enr[name].kind == PluginKind.ENRICHER


def test_epss_exposes_backfill():
    from horus.plugins.enrichers.epss.main import backfill_all
    assert callable(backfill_all)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/lizard/Development/Projects/Horus && ./.venv/bin/python -m pytest tests/plugin_manager/test_migrated_enrichers.py -q`
Expected: FAIL.

- [ ] **Step 3: Migrate** (same pattern as Task 6, enrichers dir, `type="enricher"`), then write 4 `plugin.toml` files and verify no `..` imports:

```bash
cd /Users/lizard/Development/Projects/Horus
for e in kev epss otx darkweb; do
  mkdir -p horus/plugins/enrichers/$e
  git mv horus/enrichers/$e.py horus/plugins/enrichers/$e/main.py 2>/dev/null || mv horus/enrichers/$e.py horus/plugins/enrichers/$e/main.py
  sed -i '' -E 's/^from \.\.([a-zA-Z_.]+) import/from horus.\1 import/' horus/plugins/enrichers/$e/main.py
done
grep -rn "from \.\." horus/plugins/enrichers/  # must be empty
```

- [ ] **Step 4: Run tests**

Run: `cd /Users/lizard/Development/Projects/Horus && ./.venv/bin/python -m pytest tests/plugin_manager/test_migrated_enrichers.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd /Users/lizard/Development/Projects/Horus && git add -A horus/plugins/enrichers tests/plugin_manager/test_migrated_enrichers.py && git commit -m "refactor(plugins): migrate enrichers to plugin folders"
```

---

### Task 8: Migrate Telegram → `horus/plugins/notifications/telegram/`

**Files:**
- Create: `horus/plugins/notifications/telegram/{plugin.toml, main.py}`
- Modify: `horus/notifications/dispatcher.py` logic → `main.py` `notify(events, ctx)`; `server.py` `_register_notification_hook` (Task 9).
- Test: `tests/plugin_manager/test_notification_ctx.py`

**Interfaces:**
- Consumes: `NotificationContext` (Task 1); existing `dispatcher.py` `format_event_message`, `_batch_messages`, `DEFAULT_PREFS`.
- Produces: `horus.plugins.notifications.telegram.main.notify(events, ctx)` that uses `ctx.send(chat_id, msg)` and `ctx.users`/`ctx.prefs`.

- [ ] **Step 1: Write the failing test**

```python
# tests/plugin_manager/test_notification_ctx.py
from __future__ import annotations
from horus.core.plugin_types import NotificationContext
from horus.plugins.notifications.telegram.main import notify


def test_telegram_notify_uses_ctx_send():
    sent: list[tuple[str, str]] = []
    ctx = NotificationContext(
        token="t",
        users=[(1, "alice", "chat123")],
        prefs={"kev_new": True, "epss_jump": False, "critical_cve": True,
               "watchlist_match": True, "poc_new": True},
        send=lambda ch, m: sent.append((ch, m)),
    )
    events = {"kev_new": [{"cve_id": "CVE-2026-1", "cvss_score": 9.8, "cvss_severity": "CRITICAL"}]}
    notify(events, ctx)
    assert sent and sent[0][0] == "chat123"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/lizard/Development/Projects/Horus && ./.venv/bin/python -m pytest tests/plugin_manager/test_notification_ctx.py -q`
Expected: FAIL (module path doesn't exist).

- [ ] **Step 3: Implement**

`horus/plugins/notifications/telegram/plugin.toml`:
```toml
[plugin]
name = "telegram"
type = "notification"
version = "1.0.0"
entrypoint = "main"
enabled_by_default = false
[schedule]
interval_seconds = 3600
```

`horus/plugins/notifications/telegram/main.py` — move `dispatcher.py`'s `format_event_message` + `_batch_messages` here, and define:
```python
def notify(events, ctx: NotificationContext) -> None:
    if not ctx.token:
        return
    for user_row in ctx.users:
        # user_row shape: (id, username, chat_id)
        user_id, username, chat_id = user_row[0], user_row[1], user_row[2]
        prefs = ctx.prefs
        messages = []
        for kind, items in events.items():
            if not items:
                continue
            if not prefs.get(kind, False):
                continue
            for item in items:
                msg = format_event_message(kind, item, username)
                if msg:
                    messages.append(msg)
        if messages:
            for batch in _batch_messages(messages):
                ctx.send(chat_id, batch)
```
Copy `format_event_message` and `_batch_messages` verbatim from the old `dispatcher.py`. Leave `dispatcher.py` in place as a thin shim that imports `notify` (or delete after Task 9 updates server). For now keep it to avoid breaking server import until Task 9.

- [ ] **Step 4: Run tests**

Run: `cd /Users/lizard/Development/Projects/Horus && ./.venv/bin/python -m pytest tests/plugin_manager/test_notification_ctx.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd /Users/lizard/Development/Projects/Horus && git add -A horus/plugins/notifications tests/plugin_manager/test_notification_ctx.py && git commit -m "refactor(plugins): migrate telegram to notification plugin"
```

---

### Task 9: Wire pipeline + server to PluginManager

**Files:**
- Modify: `horus/pipeline.py` (`run_pipeline` consumes plugin dict; ordering by `kind`/`provides`/`consumes`/`display_name`; `discover_sources`/`discover_enrichers` become manager-backed or removed), `horus/server.py` (`Config` + `load_config` unified + `run_due`/`run_once`/`_invoke_pipeline` use manager; notification hook iterates `manager.notifications()`; enrichers-only path imports `backfill_all` from new path), `horus/cli.py` (`_cmd_server` builds manager, passes to pipeline/server).
- Test: `tests/test_pipeline.py` (update), `tests/plugin_manager/test_wiring.py`.

**Interfaces:**
- Consumes: `PluginManager`, `Plugin` from Tasks 2–4; migrated plugins from Tasks 6–8.
- Produces: pipeline runs with `manager.sources()`/`manager.enrichers()`; server schedules via `manager.due_sources`; notification dispatch via `manager.notifications()`.

Key changes in `pipeline.py`:
- `run_pipeline(opts, sources=None, enrichers=None)`: if `sources is None`, build from `PluginManager` (bundled + default external dir). Each entry is now a `Plugin`; `_run_source` calls `plugin.run(ctx)`; ordering uses `plugin.plugin_kind_tag == "cve"` instead of `name in CVE_SOURCE_NAMES`, and `plugin.provides`/`plugin.consumes` instead of hardcoding `github`/`x_twitter`. Specifically:
  - CVE sources first: `[n for n,p in selected if p.plugin_kind_tag == "cve"]`.
  - PoC sources ordered so providers (those with `provides`) run before consumers (`consumes`): sort key `(0 if p.provides else 1, name)`.
  - The `name in ("github","codeberg")` `provided` branch → `if p.consumes:` set `provided = {c: <shared>}`.
  - `x_discovered_urls` collection: `if "x_discovered_urls" in p.provides: x_discovered_urls = result.get("x_discovered_urls", [])`.

- [ ] **Step 1: Write the failing test**

```python
# tests/plugin_manager/test_wiring.py
from __future__ import annotations
from pathlib import Path
from horus.plugin_manager import PluginManager
from horus.pipeline import PipelineOptions, run_pipeline


def test_pipeline_runs_with_manager_sources(tmp_path):
    # minimal: ensure manager-built sources dict is accepted by run_pipeline
    bundled = Path(__file__).parent.parent.parent / "horus" / "plugins"
    mgr = PluginManager(bundled_root=bundled, external_dirs=[])
    opts = PipelineOptions(source_filter={"nvd"}, enricher_filter=set(),
                           print_report=False, save_report_md=False,
                           save_graph_html=False, quiet=True)
    # nvd hits network; we only assert it returns without raising on discovery
    assert isinstance(mgr.sources(), dict)
    assert "nvd" in mgr.sources()
```

- [ ] **Step 2: Run test to verify it fails** (if `_run_source` still expects modules with `.run` callable — Plugin has `.run`, so it may already pass; assert the broader wiring compiles). Run: `cd /Users/lizard/Development/Projects/Horus && ./.venv/bin/python -m pytest tests/plugin_manager/test_wiring.py -q`. If FAIL on ordering attributes, proceed to Step 3.

- [ ] **Step 3: Implement pipeline wiring**

In `pipeline.py`, replace the `_run_source` / selection / CVE-source / PoC-source logic (lines ~219–265) to read from `Plugin` attributes instead of module names. Replace `discover_sources()`/`discover_enrichers()` usages inside `run_pipeline` with:
```python
if sources is None:
    from .plugin_manager import PluginManager
    from pathlib import Path
    bundled = Path(__file__).parent / "plugins"
    mgr = PluginManager(bundled_root=bundled, external_dirs=[Path("~/.config/horus/plugins").expanduser()])
    sources = mgr.sources()
    enrichers = mgr.enrichers()
```
Keep `discover_sources()`/`discover_enrichers()` as deprecated shims that return `mgr.sources()`/`mgr.enrichers()` so `tests/config/test_discovery.py` stays green (they already test `_discover_plugins` which still exists; the shims just delegate).

In `server.py`:
- Add to `Config`: `plugin_dirs: list[str] = field(default_factory=lambda: ["~/.config/horus/plugins"])`, `plugins: dict[str, dict] = field(default_factory=dict)`.
- In `load_config`, parse `plugin_dirs` and `plugins`; **legacy shim**: if `sources_enabled`/`poll_intervals` present, merge them into `plugins`/`plugin_dirs` with `warnings.warn("...deprecated...", DeprecationWarning)` once.
- Add module-level helper `_load_plugins_section(config_path) -> dict` used by CLI (Task 5).
- `run_due`/`run_once`/`_invoke_pipeline` build a `PluginManager` from `cfg.plugin_dirs` + bundled, call `apply_config(cfg.plugins)`, then use `mgr.due_sources(now, last_run_getter)` and `mgr.sources()`/`mgr.enrichers()`. The enrichers-only path imports `from horus.plugins.enrichers.epss.main import backfill_all` and `from horus.plugins.enrichers.kev.main import enrich`.
- `_register_notification_hook`: iterate `mgr.notifications()`, build `NotificationContext` (token from `cfg.telegram.resolved_token()`, users/prefs from DB), and register an end hook per notification plugin: `register_end_hook(lambda result: plugin.notify(result.events, ctx))`.

- [ ] **Step 4: Run tests**

Run: `cd /Users/lizard/Development/Projects/Horus && ./.venv/bin/python -m pytest tests/test_pipeline.py tests/plugin_manager/ -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd /Users/lizard/Development/Projects/Horus && git add -A horus/pipeline.py horus/server.py horus/cli.py tests/ && git commit -m "feat(plugins): wire pipeline + server to PluginManager"
```

---

### Task 10: Config schema migration + example + deprecation shim

**Files:**
- Modify: `horus/server.py` (`load_config` unified — partly done in Task 9; finalize), `horus.yaml.example`, `pyproject.toml` (version `0.16.0`).
- Test: `tests/test_config_migration.py`.

**Interfaces:**
- Consumes: legacy `sources_enabled`/`poll_intervals`/`telegram` keys + new `plugin_dirs`/`plugins`.
- Produces: `load_config` returns `Config` with `plugin_dirs`/`plugins`; legacy keys still honored with one `DeprecationWarning`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_config_migration.py
from __future__ import annotations
from pathlib import Path
import warnings
from horus.server import load_config


def test_legacy_keys_honored_with_warning(tmp_path):
    cfg_path = tmp_path / "horus.yaml"
    cfg_path.write_text(
        "sources_enabled:\n  github: false\npoll_intervals:\n  nvd: 7200\n"
        "telegram:\n  enabled: true\n  bot_token: tok\n"
    )
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        cfg = load_config(str(cfg_path))
        assert any(issubclass(x.category, DeprecationWarning) for x in w)
    assert cfg.plugins["github"]["enabled"] is False
    assert cfg.plugins["nvd"]["interval_seconds"] == 7200
    assert cfg.telegram.enabled is True


def test_unified_keys_load(tmp_path):
    cfg_path = tmp_path / "horus.yaml"
    cfg_path.write_text(
        "plugin_dirs:\n  - ~/.config/horus/plugins\nplugins:\n  github:\n    enabled: true\n"
    )
    cfg = load_config(str(cfg_path))
    assert cfg.plugin_dirs == ["~/.config/horus/plugins"]
    assert cfg.plugins["github"]["enabled"] is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/lizard/Development/Projects/Horus && ./.venv/bin/python -m pytest tests/test_config_migration.py -q`
Expected: FAIL (legacy handling not yet implemented).

- [ ] **Step 3: Implement** (finalize `load_config` in server.py)

After parsing `plugin_dirs` and `plugins`, add:
```python
legacy = False
if "sources_enabled" in data:
    legacy = True
    for k, v in data["sources_enabled"].items():
        cfg.plugins.setdefault(k, {})["enabled"] = bool(v)
if "poll_intervals" in data:
    legacy = True
    for k, v in data["poll_intervals"].items():
        cfg.plugins.setdefault(k, {})["interval_seconds"] = int(v)
if "telegram" in data and isinstance(data["telegram"], dict):
    legacy = True
    t = data["telegram"]
    cfg.telegram.enabled = bool(t.get("enabled", cfg.telegram.enabled))
    cfg.telegram.bot_token = str(t.get("bot_token", cfg.telegram.bot_token))
    cfg.plugins.setdefault("telegram", {})["enabled"] = cfg.telegram.enabled
if legacy:
    warnings.warn(
        "horus.yaml keys 'sources_enabled'/'poll_intervals'/'telegram' are "
        "deprecated; use 'plugins:' + 'plugin_dirs:'. Removed in next minor.",
        DeprecationWarning, stacklevel=2,
    )
```

- [ ] **Step 4: Rewrite `horus.yaml.example`** to the unified form (mirror `docs/plugins.md` example).

- [ ] **Step 5: Bump version** in `pyproject.toml`: `version = "0.16.0"`.

- [ ] **Step 6: Run tests**

Run: `cd /Users/lizard/Development/Projects/Horus && ./.venv/bin/python -m pytest tests/test_config_migration.py -q`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
cd /Users/lizard/Development/Projects/Horus && git add horus/server.py horus.yaml.example pyproject.toml tests/test_config_migration.py && git commit -m "feat(plugins): unified config schema + legacy deprecation shim"
```

---

### Task 11: Docs (architecture + plugins reference) + CHANGELOG

**Files:**
- Modify: `docs/architecture.md` (plugin section), `CHANGELOG.md`.
- Create: `docs/plugins.md`.

**Interfaces:**
- Consumes: the implemented scheme (Tasks 1–10).
- Produces: accurate docs a user can follow to author a plugin.

- [ ] **Step 1: Write `docs/plugins.md`** covering: directory layout, `plugin.toml` schema, the three interface contracts (source/enricher/notification), `horus plugin` CLI usage, and a copy-paste "author a new source" walkthrough using `horus plugin scaffold source mysrc`.

- [ ] **Step 2: Update `docs/architecture.md`** plugin section: replace the old "`pkgutil` over `horus/sources/`" paragraph (lines ~95–103) with the new `PluginManager` + `plugin.toml` description and the bundled/external layout.

- [ ] **Step 3: Add CHANGELOG entry** under a new `## v0.16.0` header: "Plugin system: sources/enrichers/notifications are now folder+plugin.toml plugins loaded by a single PluginManager; `horus plugin` CLI added (list/enable/disable/config/add/remove/remove/scaffold/validate); legacy `sources_enabled`/`poll_intervals`/`telegram` config keys deprecated."

- [ ] **Step 4: Commit**

```bash
cd /Users/lizard/Development/Projects/Horus && git add docs/ CHANGELOG.md && git commit -m "docs(plugins): add plugin authoring guide + architecture update"
```

---

### Task 12: Full test sweep + coverage gate + cleanup

**Files:**
- Delete: `horus/sources/` (and `__init__.py`) and `horus/enrichers/` (and `__init__.py`) once all `run`/`enrich` modules confirmed migrated; delete `horus/notifications/dispatcher.py` if fully superseded (verify no remaining importers via `grep -rn "notifications.dispatcher" horus/`).
- Run: full suite.

- [ ] **Step 1: Verify no stale imports**

Run: `cd /Users/lizard/Development/Projects/Horus && grep -rn "horus.sources\.\|horus\.enrichers\.\|notifications.dispatcher" horus/ tests/ | grep -v "horus/plugins"` — must return nothing (or only the intentional new import paths).

- [ ] **Step 2: Delete old packages**

```bash
cd /Users/lizard/Development/Projects/Horus && rm -rf horus/sources horus/enrichers && git add -A && git commit -m "chore(plugins): remove legacy sources/enrichers packages"
```

- [ ] **Step 3: Run full suite with coverage**

Run: `cd /Users/lizard/Development/Projects/Horus && ./.venv/bin/python -m pytest`
Expected: all pass, coverage ≥ 70%.

- [ ] **Step 4: ruff + mypy quick check**

Run: `cd /Users/lizard/Development/Projects/Horus && ./.venv/bin/ruff check horus/ && ./.venv/bin/python -m mypy horus/plugin_manager.py horus/core/plugin_types.py`
Expected: clean (fix any new lint/type errors introduced).

- [ ] **Step 5: Final commit if fixes needed**

```bash
cd /Users/lizard/Development/Projects/Horus && git add -A && git commit -m "fix(plugins): lint/type cleanup after migration"
```

---

## Self-Review (plan vs spec)

- **Spec coverage:** Section 1 (scheme/manifest/contracts) → Tasks 1,4,8. Section 2 (manager/config/CLI) → Tasks 2,3,5,10. Section 3 (refactor built-ins) → Tasks 6,7,8,9. Section 4 (discovery/errors/tests) → Tasks 2,3,4,5,9,12 + all test files. ✅
- **Placeholder scan:** No TBD/TODO. Every code step has concrete code or an exact shell sequence. The `_cmd_plugin` positional-arg caveat is flagged explicitly for the implementer. ✅
- **Type consistency:** `Plugin.run/enrich/notify`, `PluginManager.sources/enrichers/notifications/due_sources/apply_config`, `NotificationContext` names match across Tasks 1–9. `scaffold_plugin(kind, name, dest)` / `validate_plugin(folder)` signatures consistent in Tasks 4–5. ✅
- **Risks addressed:** relative→absolute import rewrite called out in Tasks 6–7; legacy config shim in Task 10; coverage gate in Task 12; import-graph check before deleting old packages in Task 12.

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-08-12-plugin-system.md`. Two execution options:

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration.

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints.

Which approach?
