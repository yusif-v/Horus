"""Server mode — config loading + cycle scheduling (no real daemon)."""

from __future__ import annotations

import json
from pathlib import Path

from horus import server

# ── Config dataclasses ───────────────────────────────────────────────────


def test_config_defaults():
    cfg = server.Config()
    assert cfg.check_every_seconds == 60
    assert cfg.web.enabled is True
    assert cfg.web.port == 8080
    assert cfg.web.workers == 2
    # Interval falls back to DEFAULT_POLL_INTERVALS
    assert cfg.interval("nvd") == server.DEFAULT_POLL_INTERVALS["nvd"]
    # Unknown source → default fallback (3600)
    assert cfg.interval("never-heard-of-it") == 3600
    # Sources default to enabled when not present in the dict
    assert cfg.enabled("nvd") is True
    assert cfg.enabled("exploit_db") is True


def test_config_enabled_respects_explicit_false():
    cfg = server.Config(sources_enabled={"nvd": False})
    assert cfg.enabled("nvd") is False
    assert cfg.enabled("github") is True


# ── load_config ──────────────────────────────────────────────────────────


def test_load_config_none_returns_defaults():
    cfg = server.load_config(None)
    assert isinstance(cfg, server.Config)
    assert cfg.check_every_seconds == 60


def test_load_config_missing_path_returns_defaults(tmp_path: Path):
    cfg = server.load_config(str(tmp_path / "no-such-file.yaml"))
    assert cfg.check_every_seconds == 60


def test_load_config_parses_full_yaml_or_json(tmp_path: Path):
    """JSON is a subset of YAML, so this works whether PyYAML is installed or not."""
    config_path = tmp_path / "horus.json"
    config_path.write_text(
        json.dumps(
            {
                "poll_intervals": {"nvd": 7200},
                "sources_enabled": {"github": False},
                "check_every_seconds": 30,
                "web": {
                    "enabled": False,
                    "host": "0.0.0.0",
                    "port": 9999,
                    "workers": 8,
                    "allow_dev_fallback": False,
                },
            }
        )
    )
    cfg = server.load_config(str(config_path))
    assert cfg.interval("nvd") == 7200
    # Default-preserved for keys not in the file
    assert cfg.interval("github") == server.DEFAULT_POLL_INTERVALS["github"]
    assert cfg.enabled("github") is False
    assert cfg.enabled("nvd") is True
    assert cfg.check_every_seconds == 30
    assert cfg.web.enabled is False
    assert cfg.web.host == "0.0.0.0"
    assert cfg.web.port == 9999
    assert cfg.web.workers == 8
    assert cfg.web.allow_dev_fallback is False


def test_load_config_bad_json_without_yaml_returns_defaults(tmp_path: Path, monkeypatch):
    """If PyYAML isn't installed AND content isn't valid JSON, fall through to defaults."""
    config_path = tmp_path / "bad.yaml"
    config_path.write_text("not: valid: yaml: [[[")
    # Force the yaml ImportError branch
    import sys

    monkeypatch.setitem(sys.modules, "yaml", None)
    cfg = server.load_config(str(config_path))
    assert cfg.check_every_seconds == 60  # defaults


# ── _last_run_epoch ──────────────────────────────────────────────────────


def test_last_run_epoch_returns_zero_when_never_run(monkeypatch):
    monkeypatch.setattr(server.db, "get_last_run", lambda conn, name: None)
    assert server._last_run_epoch(None, "nvd") == 0.0


def test_last_run_epoch_parses_iso_with_z_suffix(monkeypatch):
    monkeypatch.setattr(server.db, "get_last_run", lambda conn, name: "2026-06-13T12:00:00Z")
    epoch = server._last_run_epoch(None, "nvd")
    assert epoch > 0


def test_last_run_epoch_handles_malformed_iso(monkeypatch):
    monkeypatch.setattr(server.db, "get_last_run", lambda conn, name: "not-an-iso")
    assert server._last_run_epoch(None, "nvd") == 0.0


# ── Server.run_due / run_once ────────────────────────────────────────────


class _StubConn:
    """Minimal context-manager stand-in for db.connect()."""

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_run_once_invokes_pipeline_with_all_enabled_sources(monkeypatch):
    monkeypatch.setattr(server.db, "initialize", lambda: (0, 0))
    captured = {}

    def fake_invoke(self, sources, enrichers):
        captured["sources"] = set(sources)
        captured["enrichers"] = set(enrichers)

    monkeypatch.setattr(server.Server, "_invoke_pipeline", fake_invoke)

    cfg = server.Config(sources_enabled={"exploit_db": False})
    server.Server(cfg).run_once()

    assert "nvd" in captured["sources"]
    assert "exploit_db" not in captured["sources"]
    assert captured["enrichers"] == {"epss", "kev"}


def test_run_due_skips_sources_not_yet_elapsed(monkeypatch):
    """A source whose last_run is recent (< interval) should not be invoked."""
    import time

    now = time.time()
    monkeypatch.setattr(server.time, "time", lambda: now)
    monkeypatch.setattr(server.db, "connect", lambda: _StubConn())
    monkeypatch.setattr(server.db, "mark_run", lambda *a, **kw: None)
    # All sources just ran → none due
    monkeypatch.setattr(server, "_last_run_epoch", lambda conn, name: now)

    called = {"n": 0}

    def fake_invoke(self, sources, enrichers):
        called["n"] += 1

    monkeypatch.setattr(server.Server, "_invoke_pipeline", fake_invoke)

    server.Server(server.Config()).run_due()
    assert called["n"] == 0


def test_run_due_invokes_pipeline_for_elapsed_sources(monkeypatch):
    """Sources whose last_run is older than the interval are scheduled."""
    import time

    now = time.time()
    monkeypatch.setattr(server.time, "time", lambda: now)
    monkeypatch.setattr(server.db, "connect", lambda: _StubConn())
    monkeypatch.setattr(server.db, "mark_run", lambda *a, **kw: None)
    # All sources are very stale
    monkeypatch.setattr(server, "_last_run_epoch", lambda conn, name: 0.0)

    captured = {}

    def fake_invoke(self, sources, enrichers):
        captured["sources"] = set(sources)
        captured["enrichers"] = set(enrichers)

    monkeypatch.setattr(server.Server, "_invoke_pipeline", fake_invoke)

    server.Server(server.Config()).run_due()
    assert server.SOURCE_KEYS.issubset(captured["sources"])
    assert server.ENRICHER_KEYS.issubset(captured["enrichers"])


# ── main entry point ─────────────────────────────────────────────────────


def test_main_once_path_runs_single_cycle(monkeypatch):
    called = {"once": False, "start": False}

    def fake_run_once(self):
        called["once"] = True

    def fake_start(self):
        called["start"] = True

    monkeypatch.setattr(server.Server, "run_once", fake_run_once)
    monkeypatch.setattr(server.Server, "start", fake_start)

    server.main(["--once"])
    assert called["once"] is True
    assert called["start"] is False


def test_main_default_path_starts_daemon(monkeypatch):
    called = {"once": False, "start": False}
    monkeypatch.setattr(server.Server, "run_once", lambda self: called.__setitem__("once", True))
    monkeypatch.setattr(server.Server, "start", lambda self: called.__setitem__("start", True))

    server.main([])
    assert called["start"] is True
    assert called["once"] is False


# ── signal handler ───────────────────────────────────────────────────────


def test_on_signal_flips_running_flag():
    srv = server.Server(server.Config())
    srv._running = True
    srv._on_signal(15, None)
    assert srv._running is False
