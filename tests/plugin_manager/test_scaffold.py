"""Scaffold generator produces plugins that pass validation."""

from __future__ import annotations

from horus.core.plugin_types import PluginKind
from horus.plugin_manager import scaffold_plugin, validate_plugin


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
    (d / "plugin.toml").write_text('[plugin]\nname="bad"\ntype="source"\nversion="1.0.0"\n')
    (d / "main.py").write_text("NAME='B'\n")  # no run()
    errs = validate_plugin(d)
    assert any("run" in e for e in errs)
