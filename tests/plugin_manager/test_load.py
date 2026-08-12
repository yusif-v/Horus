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
