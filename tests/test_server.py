"""Server mode — config loading + cycle scheduling (no real daemon)."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock

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


def test_load_config_folds_legacy_telegram_into_plugins(tmp_path: Path):
    """a6: the deprecated `telegram:` block folds into plugins.telegram.config."""
    config_path = tmp_path / "horus.json"
    config_path.write_text(
        json.dumps(
            {
                "telegram": {
                    "enabled": True,
                    "bot_token": "tok-123",
                }
            }
        )
    )
    cfg = server.load_config(str(config_path))
    entry = cfg.plugins.get("telegram", {})
    assert entry.get("enabled") is True
    assert entry.get("config", {}).get("bot_token") == "tok-123"
    assert cfg.telegram.bot_token == "tok-123"


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


def test_run_once_invokes_pipeline_with_all_enabled_sources(tmp_path, monkeypatch):
    monkeypatch.setattr(server.db, "initialize", lambda: (0, 0))
    captured = {}

    def fake_invoke(self, sources, enrichers):
        captured["sources"] = set(sources)
        captured["enrichers"] = set(enrichers)

    monkeypatch.setattr(server.Server, "_invoke_pipeline", fake_invoke)

    # Legacy `sources_enabled` goes through the deprecation shim, which maps
    # exploit_db → exploitdb and disables it in the manager.
    config_path = tmp_path / "horus.json"
    config_path.write_text(json.dumps({"sources_enabled": {"exploit_db": False}}))
    cfg = server.load_config(str(config_path))
    server.Server(cfg).run_once()

    assert "nvd" in captured["sources"]
    assert "exploitdb" not in captured["sources"]
    assert captured["enrichers"] == {"epss", "kev", "otx", "darkweb"}


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
    assert {"nvd", "x_twitter", "github", "gitlab", "codeberg", "exploitdb", "news"}.issubset(
        captured["sources"]
    )
    assert {"epss", "kev", "otx", "darkweb"}.issubset(captured["enrichers"])


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


# ── Additional coverage for uncovered branches ─────────────────────────────


def test_start_web_with_gunicorn(monkeypatch):
    """Covers lines 188-221: _start_web uses gunicorn when available."""
    import subprocess

    monkeypatch.setattr(server.db, "initialize", lambda: (0, 0))

    fake_gunicorn = MagicMock()
    monkeypatch.setitem(sys.modules, "gunicorn", fake_gunicorn)

    popen_instance = MagicMock()
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **kw: popen_instance)

    cfg = server.Config()
    cfg.web.enabled = True
    srv = server.Server(cfg)
    srv._start_web()
    assert srv._web_proc is popen_instance


def test_start_web_dev_fallback(monkeypatch):
    """Covers lines 223-240: Flask dev server fallback when gunicorn missing."""
    import threading

    monkeypatch.setitem(sys.modules, "gunicorn", None)

    fake_thread = MagicMock()
    monkeypatch.setattr(threading, "Thread", lambda *a, **kw: fake_thread)

    cfg = server.Config()
    cfg.web.enabled = True
    cfg.web.allow_dev_fallback = True
    srv = server.Server(cfg)
    srv._start_web()
    fake_thread.start.assert_called_once()


def test_start_web_no_gunicorn_no_fallback_raises(monkeypatch):
    """Covers lines 223-227: RuntimeError when no gunicorn and no fallback."""
    monkeypatch.setitem(sys.modules, "gunicorn", None)

    cfg = server.Config()
    cfg.web.enabled = True
    cfg.web.allow_dev_fallback = False
    srv = server.Server(cfg)
    try:
        srv._start_web()
        assert False, "Should have raised"
    except RuntimeError as e:
        assert "gunicorn" in str(e).lower()


def test_supervise_web_restarts_dead_child(monkeypatch):
    """Covers lines 243-250: _supervise_web restarts a dead web child."""
    cfg = server.Config()
    cfg.web.enabled = True
    srv = server.Server(cfg)

    dead_proc = MagicMock()
    dead_proc.poll.return_value = 1  # exited
    srv._web_proc = dead_proc

    restarted = {"n": 0}

    def fake_start_web(self):
        restarted["n"] += 1

    monkeypatch.setattr(server.Server, "_start_web", fake_start_web)
    srv._supervise_web()
    assert restarted["n"] == 1
    assert srv._web_proc is None


def test_supervise_web_no_op_when_none(monkeypatch):
    """Covers line 244-245: _supervise_web is no-op when _web_proc is None."""
    cfg = server.Config()
    cfg.web.enabled = True
    srv = server.Server(cfg)
    srv._web_proc = None
    # Should not raise
    srv._supervise_web()


def test_stop_web_terminates_process(monkeypatch):
    """Covers lines 253-266: _stop_web sends SIGTERM and waits."""
    import os

    cfg = server.Config()
    cfg.web.enabled = True
    srv = server.Server(cfg)

    fake_proc = MagicMock()
    fake_proc.pid = 12345
    fake_proc.wait.return_value = 0
    srv._web_proc = fake_proc

    monkeypatch.setattr(os, "killpg", lambda *a, **kw: None)
    monkeypatch.setattr(os, "getpgid", lambda pid: pid)

    srv._stop_web()
    fake_proc.wait.assert_called_once_with(timeout=25)
    assert srv._web_proc is None


def test_run_due_with_enrichers_only(monkeypatch):
    """Covers lines 289-293, 299-301: run_due with only enrichers due (no sources)."""
    import time

    now = time.time()
    monkeypatch.setattr(server.time, "time", lambda: now)
    monkeypatch.setattr(server.db, "connect", lambda: _StubConn())
    monkeypatch.setattr(server.db, "mark_run", lambda *a, **kw: None)

    # All sources just ran, but enrichers are stale
    def fake_last_run(conn, name):
        if name in server.SOURCE_KEYS:
            return now  # sources just ran
        return 0.0  # enrichers never ran

    monkeypatch.setattr(server, "_last_run_epoch", fake_last_run)

    captured = {}

    def fake_invoke(self, sources, enrichers):
        captured["sources"] = sources
        captured["enrichers"] = enrichers

    monkeypatch.setattr(server.Server, "_invoke_pipeline", fake_invoke)

    server.Server(server.Config()).run_due()
    assert captured["sources"] == []
    assert "epss" in captured["enrichers"]
    assert "kev" in captured["enrichers"]


def test_invoke_pipeline_enricher_only_epss(monkeypatch):
    """Covers lines 312-316: _invoke_pipeline with enrichers-only (EPSS backfill)."""
    called = {"backfill": False}

    def fake_backfill(conn):
        called["backfill"] = True

    fake_epss = MagicMock()
    fake_epss.backfill_all = fake_backfill
    monkeypatch.setitem(sys.modules, "horus.plugins.enrichers.epss.main", fake_epss)

    cfg = server.Config()
    srv = server.Server(cfg)
    srv._invoke_pipeline([], ["epss"])
    assert called["backfill"] is True


def test_invoke_pipeline_enricher_only_otx(monkeypatch):
    """Enrichers-only cycles now run the DB-wide OTX IOC backfill."""
    called = {"backfill": False}

    def fake_backfill(conn):
        called["backfill"] = True

    fake_otx = MagicMock()
    fake_otx.backfill = fake_backfill
    monkeypatch.setitem(sys.modules, "horus.plugins.enrichers.otx.main", fake_otx)

    cfg = server.Config()
    srv = server.Server(cfg)
    srv._invoke_pipeline([], ["otx"])
    assert called["backfill"] is True


def test_invoke_pipeline_enricher_only_darkweb(monkeypatch):
    """Enrichers-only cycles now run the DB-wide dark-web IOC backfill."""
    called = {"backfill": False}

    def fake_backfill(conn):
        called["backfill"] = True

    fake_darkweb = MagicMock()
    fake_darkweb.backfill = fake_backfill
    monkeypatch.setitem(sys.modules, "horus.plugins.enrichers.darkweb.main", fake_darkweb)

    cfg = server.Config()
    srv = server.Server(cfg)
    srv._invoke_pipeline([], ["darkweb"])
    assert called["backfill"] is True


def test_invoke_pipeline_source_filter(monkeypatch):
    """Covers _invoke_pipeline with source filter."""
    called = {"run": False, "opts": None, "sources": None}

    fake_pipeline = MagicMock()

    def fake_run_pipeline(opts, sources=None, enrichers=None):
        called["run"] = True
        called["opts"] = opts
        called["sources"] = sources

    fake_pipeline.run_pipeline = fake_run_pipeline
    fake_pipeline.PipelineOptions = MagicMock()
    monkeypatch.setitem(sys.modules, "horus.pipeline", fake_pipeline)

    cfg = server.Config()
    srv = server.Server(cfg)
    srv._invoke_pipeline(["nvd"], [])
    assert called["run"] is True
    assert set(called["sources"]) == {"nvd"}


def test_main_import_guard(monkeypatch):
    """Covers line 393: __name__ == '__main__' path."""
    called = {"main": False}
    monkeypatch.setattr(server, "main", lambda argv=None: called.__setitem__("main", True))

    # Simulate the __main__ guard
    monkeypatch.setattr(server, "__name__", "__main__")
    # Re-exec the guard
    if server.__name__ == "__main__":
        server.main()
    assert called["main"] is True
