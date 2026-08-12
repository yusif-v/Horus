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


def _ns(cmd, name, *, key=None, value=None, config=None, plugins_dir=None):
    import argparse

    return argparse.Namespace(
        cmd=cmd,
        kind=None,
        name=name,
        key=key,
        value=value,
        plugins_dir=plugins_dir,
        config=config,
    )


def test_cli_enable_persists_plugins_block(tmp_path, capsys):
    from horus.cli import _cmd_plugin, _plugin_read_config

    yaml = tmp_path / "horus.yaml"
    yaml.write_text("web:\n  port: 9000\nplugins:\n  other:\n    enabled: false\n")

    _cmd_plugin(_ns("enable", "demo", config=str(yaml), plugins_dir=tmp_path / "plugins"))

    doc = _plugin_read_config(str(yaml))
    assert doc["plugins"]["demo"]["enabled"] is True
    assert doc["plugins"]["other"]["enabled"] is False  # unrelated plugin untouched
    assert doc["web"]["port"] == 9000  # unrelated top-level key preserved
    assert "demo enabled" in capsys.readouterr().out


def test_cli_disable_persists_plugins_block(tmp_path, capsys):
    from horus.cli import _cmd_plugin, _plugin_read_config

    yaml = tmp_path / "horus.yaml"
    yaml.write_text("plugins:\n  demo:\n    enabled: true\n")

    _cmd_plugin(_ns("disable", "demo", config=str(yaml), plugins_dir=tmp_path / "plugins"))

    doc = _plugin_read_config(str(yaml))
    assert doc["plugins"]["demo"]["enabled"] is False
    assert "demo disabled" in capsys.readouterr().out


def test_cli_config_set_and_show(tmp_path, capsys):
    from horus.cli import _cmd_plugin, _plugin_read_config

    yaml = tmp_path / "horus.yaml"
    yaml.write_text("web:\n  host: 0.0.0.0\nplugins:\n  demo:\n    enabled: true\n")

    _cmd_plugin(
        _ns(
            "config",
            "demo",
            key="api_key",
            value="abc123",
            config=str(yaml),
            plugins_dir=tmp_path / "plugins",
        )
    )
    assert "set demo.api_key = abc123" in capsys.readouterr().out

    doc = _plugin_read_config(str(yaml))
    assert doc["plugins"]["demo"]["api_key"] == "abc123"
    assert doc["plugins"]["demo"]["enabled"] is True  # existing key preserved

    _cmd_plugin(_ns("config", "demo", config=str(yaml), plugins_dir=tmp_path / "plugins"))
    assert "api_key: abc123" in capsys.readouterr().out


def test_cli_config_write_json_fallback(tmp_path, monkeypatch):
    import builtins

    from horus.cli import _plugin_read_config, _plugin_set_config

    json_path = tmp_path / "horus.json"
    json_path.write_text('{"web": {"port": 8081}, "plugins": {"demo": {"enabled": true}}}')

    real_import = builtins.__import__

    def no_yaml(name, *args, **kwargs):
        if name == "yaml":
            raise ImportError("yaml unavailable")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_yaml)

    ok = _plugin_set_config(str(json_path), "demo", "api_key", "xyz")
    assert ok is True

    doc = _plugin_read_config(str(json_path))
    assert doc["plugins"]["demo"]["api_key"] == "xyz"
    assert doc["plugins"]["demo"]["enabled"] is True  # existing key preserved
    assert doc["web"]["port"] == 8081  # unrelated top-level key preserved


def test_cli_enable_without_config_does_not_claim_success(tmp_path, capsys):
    from horus.cli import _cmd_plugin

    _cmd_plugin(_ns("enable", "demo", plugins_dir=tmp_path / "plugins"))

    out = capsys.readouterr().out
    assert "no config file; nothing persisted" in out
    assert "demo enabled" not in out


def test_cli_config_set_without_config_does_not_claim_success(tmp_path, capsys):
    from horus.cli import _cmd_plugin

    _cmd_plugin(_ns("config", "demo", key="k", value="v", plugins_dir=tmp_path / "plugins"))

    out = capsys.readouterr().out
    assert "no config file; nothing persisted" in out
    assert "set demo.k = v" not in out
