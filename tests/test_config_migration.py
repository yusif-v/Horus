from __future__ import annotations

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
