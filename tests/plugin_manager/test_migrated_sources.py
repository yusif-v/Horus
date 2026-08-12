# tests/plugin_manager/test_migrated_sources.py
from __future__ import annotations

from pathlib import Path

from horus.core.plugin_types import PluginKind
from horus.plugin_manager import PluginManager

BUNDLED = Path(__file__).parent.parent.parent / "horus" / "plugins"

EXPECTED = [
    "nvd",
    "x_twitter",
    "github",
    "gitlab",
    "codeberg",
    "exploitdb",
    "news",
    "resource_intelligence",
]


def test_all_builtin_sources_discovered():
    mgr = PluginManager(bundled_root=BUNDLED, external_dirs=[])
    srcs = mgr.sources()
    for name in EXPECTED:
        assert name in srcs, f"{name} not discovered"
        assert srcs[name].kind == PluginKind.SOURCE


def test_no_broken_builtin_sources():
    mgr = PluginManager(bundled_root=BUNDLED, external_dirs=[])
    assert mgr.broken == [], mgr.broken
