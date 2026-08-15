"""Shared config-file parsing (YAML if PyYAML is present, else JSON).

`load_config_document` is used by `horus.server.load_config`,
`horus.server._load_plugins_section`, and `horus.cli._plugin_read_config`
so the PyYAML-else-JSON fallback lives in exactly one place.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def parse_config_text(raw: str) -> dict[str, Any]:
    """Parse YAML-or-JSON text into a dict.

    Raises ValueError when PyYAML is missing and the content is not valid JSON.
    """
    try:
        import yaml

        data = yaml.safe_load(raw) or {}
    except ImportError:
        try:
            data = json.loads(raw) or {}
        except json.JSONDecodeError as e:
            raise ValueError(f"PyYAML missing and config is not JSON ({e})") from e
    return data if isinstance(data, dict) else {}


def load_config_document(path: str | None) -> dict[str, Any]:
    """Read and parse a config file into a dict.

    Returns {} when the path is missing/unparseable so callers can fall
    back to defaults safely.
    """
    if not path:
        return {}
    p = Path(path).expanduser()
    if not p.exists():
        return {}
    try:
        return parse_config_text(p.read_text())
    except ValueError:
        return {}
