# tests/plugin_manager/test_load.py
from __future__ import annotations

from pathlib import Path

import pytest

from horus.core.plugin_types import PluginKind
from horus.plugin_manager import PluginManager


@pytest.fixture
def bundled(tmp_path: Path) -> Path:
    return tmp_path / "bundled"


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


def test_discovers_bundled_sources(tmp_path, bundled):
    _make_plugin(bundled, "sources", "demo_src")
    mgr = PluginManager(bundled_root=bundled, external_dirs=[tmp_path])
    srcs = mgr.sources()
    assert "demo_src" in srcs
    assert srcs["demo_src"].kind == PluginKind.SOURCE


def test_external_overrides_bundled(tmp_path, bundled):
    _make_plugin(bundled, "sources", "dup")
    ext = tmp_path / "ext"
    _make_plugin(ext, "sources", "dup")
    mgr = PluginManager(bundled_root=bundled, external_dirs=[ext])
    # External wins on collision; both still resolve to a single enabled entry.
    assert "dup" in mgr.sources()


def test_disabled_plugin_excluded(tmp_path, bundled):
    _make_plugin(tmp_path, "sources", "off", enabled=False)
    mgr = PluginManager(bundled_root=bundled, external_dirs=[tmp_path])
    assert "off" not in mgr.sources()


def test_broken_plugin_skipped(tmp_path, bundled):
    d = tmp_path / "sources" / "broken"
    d.mkdir(parents=True)
    (d / "plugin.toml").write_text(
        '[plugin]\nname = "broken"\ntype = "source"\nversion = "1.0.0"\nentrypoint = "main"\n'
    )
    # main.py missing → import fails → recorded broken, not raised.
    mgr = PluginManager(bundled_root=bundled, external_dirs=[tmp_path])
    assert "broken" in {n for n, _ in mgr.broken}
    assert "broken" not in mgr.sources()


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
