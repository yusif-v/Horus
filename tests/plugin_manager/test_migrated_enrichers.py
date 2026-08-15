"""Migrated bundled enrichers still discover through the manager."""

from __future__ import annotations

from pathlib import Path

from horus.core.plugin_types import PluginKind
from horus.plugin_manager import PluginManager

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
