# tests/plugin_manager/test_cli.py
from __future__ import annotations

from pathlib import Path

from horus.core.plugin_types import PluginKind
from horus.plugin_manager import scaffold_plugin


def _write_yaml(path: Path, plugins_dir: Path) -> None:
    path.write_text(f"plugin_dirs:\n  - {plugins_dir}\nplugins:\n  demo:\n    enabled: true\n")


def test_cli_list_shows_external(tmp_path, capsys):
    import argparse

    from horus.cli import _cmd_plugin

    pd = tmp_path / "plugins"
    scaffold_plugin(PluginKind.SOURCE, "demo", pd)
    yaml = tmp_path / "horus.yaml"
    _write_yaml(yaml, pd)
    args = argparse.Namespace(
        cmd="list", name=None, key=None, value=None, plugins_dir=pd, config=str(yaml)
    )
    _cmd_plugin(args)
    out = capsys.readouterr().out
    assert "demo" in out


def test_cli_scaffold_then_validate(tmp_path, capsys):
    import argparse

    from horus.cli import _cmd_plugin

    pd = tmp_path / "plugins"
    yaml = tmp_path / "horus.yaml"
    _write_yaml(yaml, pd)
    a1 = argparse.Namespace(
        cmd="scaffold", kind="notification", name="nt", plugins_dir=pd, config=str(yaml)
    )
    _cmd_plugin(a1)
    a2 = argparse.Namespace(
        cmd="validate", name="nt", key=None, value=None, plugins_dir=pd, config=str(yaml)
    )
    _cmd_plugin(a2)
    assert (pd / "notifications" / "nt" / "plugin.toml").exists()


def test_cli_remove_deletes_external_plugin(tmp_path, capsys):
    import argparse

    import horus.cli as cli_mod
    from horus.cli import _cmd_plugin

    pd = tmp_path / "plugins"
    scaffold_plugin(PluginKind.SOURCE, "demo", pd)
    bundled = Path(cli_mod.__file__).parent / "plugins"
    yaml = tmp_path / "horus.yaml"
    _write_yaml(yaml, pd)
    args = argparse.Namespace(
        cmd="remove", name="demo", key=None, value=None, plugins_dir=pd, config=str(yaml)
    )
    _cmd_plugin(args)
    assert not (pd / "sources" / "demo").exists()
    assert not (bundled / "sources" / "demo").exists()
