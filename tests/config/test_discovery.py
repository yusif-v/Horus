"""Unit tests for horus plugin discovery logic.

Tests the _discover_plugins() function from horus.pipeline using mocks
to isolate filesystem discovery from actual package structure.
"""

from __future__ import annotations

import importlib
import pkgutil
import sys
import types
import warnings
from unittest.mock import patch

from horus.pipeline import _discover_plugins


class FakePluginDef:
    """Holds info about a fake plugin to be discovered."""

    def __init__(self, name: str, has_run: bool = False, has_enrich: bool = False):
        self.name = name
        self.has_run = has_run
        self.has_enrich = has_enrich


def _build_module(name: str, pkg_name: str, has_run: bool, has_enrich: bool) -> types.ModuleType:
    """Build a mock module, register it in sys.modules, and return it."""
    mod = types.ModuleType(f"horus.{pkg_name}.{name}")
    mod.__file__ = f"/fake/horus/{pkg_name}/{name}.py"
    if has_run:
        mod.run = lambda: None
    if has_enrich:
        mod.enrich = lambda: None
    sys.modules[f"horus.{pkg_name}.{name}"] = mod
    return mod


def _cleanup_modules(pkg_name: str, names: list[str]) -> None:
    """Remove fake modules from sys.modules."""
    for name in names:
        sys.modules.pop(f"horus.{pkg_name}.{name}", None)


def _make_import_fn(modules: dict[str, types.ModuleType]):
    """Create a fake import_module that returns from modules dict."""

    def fake_import(name, package=None):
        # Relative ".name" + package "horus.pkg" → "horus.pkg.name"
        if name.startswith("."):
            full = f"{package}{name}"
        else:
            full = name
        if full in modules:
            return modules[full]
        raise ModuleNotFoundError(f"No module named '{full}'")

    return fake_import


# ── Unit tests with mocked discovery ──────────────────────────────────────────


def test_discover_finds_module_with_run(tmp_path, monkeypatch):
    """Modules that export a callable `run` should be discovered."""
    plugins = [FakePluginDef("nvd", has_run=True)]
    pkg_name = "fake_src_a"
    iter_result = [(None, p.name, False) for p in plugins]
    mod = _build_module("nvd", pkg_name, True, False)
    modules = {f"horus.{pkg_name}.nvd": mod}

    with (
        patch.object(pkgutil, "iter_modules", return_value=iter_result),
        patch.object(importlib, "import_module", side_effect=_make_import_fn(modules)),
    ):
        result = _discover_plugins(pkg_name, required_export="run")

    assert "nvd" in result
    assert callable(result["nvd"].run)
    _cleanup_modules(pkg_name, ["nvd"])


def test_discover_skips_modules_starting_with_underscore(tmp_path, monkeypatch):
    """Modules whose names start with '_' should be skipped."""
    plugins = [
        FakePluginDef("_private", has_run=True),
        FakePluginDef("public", has_run=True),
    ]
    pkg_name = "fake_src_b"
    iter_result = [(None, p.name, False) for p in plugins]
    mods = {
        f"horus.{pkg_name}._private": _build_module("_private", pkg_name, True, False),
        f"horus.{pkg_name}.public": _build_module("public", pkg_name, True, False),
    }

    with (
        patch.object(pkgutil, "iter_modules", return_value=iter_result),
        patch.object(importlib, "import_module", side_effect=_make_import_fn(mods)),
    ):
        result = _discover_plugins(pkg_name, required_export="run")

    assert "_private" not in result
    assert "public" in result
    _cleanup_modules(pkg_name, ["_private", "public"])


def test_discover_skips_modules_without_required_export(tmp_path, monkeypatch):
    """Modules that do not export the required attribute should be skipped."""
    plugins = [
        FakePluginDef("has_run", has_run=True),
        FakePluginDef("no_run", has_run=False),
    ]
    pkg_name = "fake_src_c"
    iter_result = [(None, p.name, False) for p in plugins]
    # no_run gets a module without run()
    no_run_mod = _build_module("no_run", pkg_name, False, False)
    mods = {
        f"horus.{pkg_name}.has_run": _build_module("has_run", pkg_name, True, False),
        f"horus.{pkg_name}.no_run": no_run_mod,
    }

    with (
        patch.object(pkgutil, "iter_modules", return_value=iter_result),
        patch.object(importlib, "import_module", side_effect=_make_import_fn(mods)),
    ):
        result = _discover_plugins(pkg_name, required_export="run")

    assert "has_run" in result
    assert "no_run" not in result
    _cleanup_modules(pkg_name, ["has_run", "no_run"])


def test_discover_skips_only_underscore_modules(tmp_path, monkeypatch):
    """Only underscore-prefixed modules are skipped; similar names are not."""
    plugins = [
        FakePluginDef("_hidden", has_run=True),
        FakePluginDef("__dunder__", has_run=True),
        FakePluginDef("valid_mod", has_run=True),
    ]
    pkg_name = "fake_src_d"
    iter_result = [(None, p.name, False) for p in plugins]
    mods = {
        f"horus.{pkg_name}._hidden": _build_module("_hidden", pkg_name, True, False),
        f"horus.{pkg_name}.__dunder__": _build_module("__dunder__", pkg_name, True, False),
        f"horus.{pkg_name}.valid_mod": _build_module("valid_mod", pkg_name, True, False),
    }

    with (
        patch.object(pkgutil, "iter_modules", return_value=iter_result),
        patch.object(importlib, "import_module", side_effect=_make_import_fn(mods)),
    ):
        result = _discover_plugins(pkg_name, required_export="run")

    assert "_hidden" not in result
    assert "__dunder__" not in result
    assert "valid_mod" in result
    _cleanup_modules(pkg_name, ["_hidden", "__dunder__", "valid_mod"])


def test_discover_empty_package(tmp_path, monkeypatch):
    """An empty package (no plugins) should return an empty dict."""
    pkg_name = "fake_src_e"
    iter_result: list = []

    with (
        patch.object(pkgutil, "iter_modules", return_value=iter_result),
        patch.object(importlib, "import_module", side_effect=_make_import_fn({})),
    ):
        result = _discover_plugins(pkg_name, required_export="run")

    assert result == {}


def test_discover_plugins_with_enricher_required(tmp_path, monkeypatch):
    """discover_enrichers uses 'enrich' as the required export."""
    plugins = [
        FakePluginDef("epss", has_enrich=True),
        FakePluginDef("no_enrich", has_enrich=False),
    ]
    pkg_name = "fake_enrich_f"
    iter_result = [(None, p.name, False) for p in plugins]
    no_enrich_mod = _build_module("no_enrich", pkg_name, False, False)
    mods = {
        f"horus.{pkg_name}.epss": _build_module("epss", pkg_name, False, True),
        f"horus.{pkg_name}.no_enrich": no_enrich_mod,
    }

    with (
        patch.object(pkgutil, "iter_modules", return_value=iter_result),
        patch.object(importlib, "import_module", side_effect=_make_import_fn(mods)),
    ):
        result = _discover_plugins(pkg_name, required_export="enrich")

    assert "epss" in result
    assert "no_enrich" not in result
    _cleanup_modules(pkg_name, ["epss", "no_enrich"])


def test_discover_returns_modules_not_names(tmp_path, monkeypatch):
    """The returned dict values should be actual module objects with attributes."""
    plugins = [FakePluginDef("mymod", has_run=True)]
    pkg_name = "fake_src_g"
    iter_result = [(None, p.name, False) for p in plugins]
    mod = _build_module("mymod", pkg_name, True, False)
    mod.VALUE = 42
    mods = {f"horus.{pkg_name}.mymod": mod}

    with (
        patch.object(pkgutil, "iter_modules", return_value=iter_result),
        patch.object(importlib, "import_module", side_effect=_make_import_fn(mods)),
    ):
        result = _discover_plugins(pkg_name, required_export="run")

    assert "mymod" in result
    assert hasattr(result["mymod"], "VALUE")
    assert result["mymod"].VALUE == 42
    _cleanup_modules(pkg_name, ["mymod"])


def test_discover_handles_import_errors(tmp_path, monkeypatch):
    """Modules that raise ImportError during load should be skipped gracefully."""

    def fake_import(name, package=None):
        if ".broken" in name:
            raise ImportError(f"mocked:{package}.broken")
        full = f"{package}{name}"
        if full in sys.modules:
            return sys.modules[full]
        raise ImportError(full)

    plugins = [
        FakePluginDef("broken", has_run=True),
        FakePluginDef("working", has_run=True),
    ]
    pkg_name = "fake_src_h"
    iter_result = [(None, p.name, False) for p in plugins]
    _build_module("working", pkg_name, True, False)

    with (
        patch.object(pkgutil, "iter_modules", return_value=iter_result),
        patch.object(importlib, "import_module", side_effect=fake_import),
        warnings.catch_warnings(),
    ):
        warnings.simplefilter("ignore", DeprecationWarning)
        result = _discover_plugins(pkg_name, required_export="run")

    assert "working" in result
    assert "broken" not in result
    _cleanup_modules(pkg_name, ["working"])
