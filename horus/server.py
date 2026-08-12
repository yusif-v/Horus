"""24/7 server mode for Horus.

Long-running daemon that polls each source on its own interval. The
shared `cli.main` pipeline (sources → merge → enrich → persist) is
re-used per cycle by feeding it an argv that restricts which sources run
this round. Last-run timestamps live in the existing `meta` table via
`db.mark_run` so they survive restarts.

Config file (YAML if PyYAML is installed; JSON also accepted):

    poll_intervals:
      nvd: 3600
      x_twitter: 1800
      github: 3600
      gitlab: 3600
      exploit_db: 7200
      epss: 86400
      kev: 86400
    sources_enabled:
      nvd: true
      x_twitter: true
      github: true
      gitlab: true
      exploit_db: false
    check_every_seconds: 60
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .storage import db

logger = logging.getLogger(__name__)

DEFAULT_POLL_INTERVALS: dict[str, int] = {
    "nvd": 3600,  # 1h    — NVD updates roughly every 2h
    "x_twitter": 1800,  # 30m   — social moves fast
    "github": 3600,  # 1h    — search API rate-limited
    "gitlab": 3600,  # 1h    — search API rate-limited
    "exploit_db": 7200,  # 2h    — slower moving
    "epss": 86400,  # 24h   — daily CSV
    "kev": 86400,  # 24h   — daily catalog
}

# Sources are run by the main pipeline (CVE/PoC discovery); enrichers
# are scheduled but applied to the current batch + DB backfill.
SOURCE_KEYS = {"nvd", "x_twitter", "github", "gitlab", "exploit_db"}
ENRICHER_KEYS = {"epss", "kev"}


@dataclass
class WebConfig:
    enabled: bool = True
    host: str = field(default_factory=lambda: os.environ.get("HORUS_WEB_HOST", "0.0.0.0"))
    port: int = field(default_factory=lambda: int(os.environ.get("HORUS_WEB_PORT", "8080")))
    workers: int = 2
    # If True and gunicorn isn't installed, fall back to Flask's dev server
    # with a loud warning. Set False in prod to fail-fast instead.
    allow_dev_fallback: bool = True


@dataclass
class TelegramConfig:
    enabled: bool = False
    bot_token: str = ""  # or TELEGRAM_BOT_TOKEN env var

    def resolved_token(self) -> str | None:
        return self.bot_token or os.environ.get("TELEGRAM_BOT_TOKEN") or None


@dataclass
class Config:
    poll_intervals: dict[str, int] = field(default_factory=lambda: dict(DEFAULT_POLL_INTERVALS))
    sources_enabled: dict[str, bool] = field(default_factory=dict)
    check_every_seconds: int = 60
    web: WebConfig = field(default_factory=WebConfig)
    telegram: TelegramConfig = field(default_factory=TelegramConfig)

    def interval(self, name: str) -> int:
        return self.poll_intervals.get(name, DEFAULT_POLL_INTERVALS.get(name, 3600))

    def enabled(self, name: str) -> bool:
        return self.sources_enabled.get(name, True)


def load_config(path: str | None) -> Config:
    """Load YAML/JSON config; return defaults if path is None or missing."""
    cfg = Config()
    if not path:
        return cfg
    p = Path(path).expanduser()
    if not p.exists():
        logger.warning("config not found at %s, using defaults", p)
        return cfg
    raw = p.read_text()
    data: dict
    try:
        import yaml  # type: ignore

        data = yaml.safe_load(raw) or {}
    except ImportError:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            print(
                f"  [WARN] PyYAML missing and config is not JSON ({e}); using defaults",
                file=sys.stderr,
            )
            return cfg
    if "poll_intervals" in data and isinstance(data["poll_intervals"], dict):
        cfg.poll_intervals.update({k: int(v) for k, v in data["poll_intervals"].items()})
    if "sources_enabled" in data and isinstance(data["sources_enabled"], dict):
        cfg.sources_enabled.update({k: bool(v) for k, v in data["sources_enabled"].items()})
    if "check_every_seconds" in data:
        cfg.check_every_seconds = int(data["check_every_seconds"])
    if "web" in data and isinstance(data["web"], dict):
        w = data["web"]
        cfg.web.enabled = bool(w.get("enabled", cfg.web.enabled))
        cfg.web.host = str(w.get("host", cfg.web.host))
        cfg.web.port = int(w.get("port", cfg.web.port))
        cfg.web.workers = int(w.get("workers", cfg.web.workers))
        cfg.web.allow_dev_fallback = bool(w.get("allow_dev_fallback", cfg.web.allow_dev_fallback))
    # Env-var overrides (useful in Docker where yaml bakes 127.0.0.1 but compose sets 0.0.0.0)
    if os.environ.get("HORUS_WEB_HOST"):
        cfg.web.host = os.environ["HORUS_WEB_HOST"]
    if os.environ.get("HORUS_WEB_PORT"):
        cfg.web.port = int(os.environ["HORUS_WEB_PORT"])
    if "telegram" in data and isinstance(data["telegram"], dict):
        t = data["telegram"]
        cfg.telegram.enabled = bool(t.get("enabled", cfg.telegram.enabled))
        cfg.telegram.bot_token = str(t.get("bot_token", cfg.telegram.bot_token))
    return cfg


def _load_plugins_section(config_path: str | None) -> dict[str, Any]:
    """Return the `plugins:` block of a YAML/JSON config file ({} if absent).

    Shares load_config's parsing strategy: PyYAML if present, else JSON.
    """
    if not config_path:
        return {}
    p = Path(config_path).expanduser()
    if not p.exists():
        return {}
    raw = p.read_text()
    data: dict[str, Any]
    try:
        import yaml

        data = yaml.safe_load(raw) or {}
    except ImportError:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return {}
    if not isinstance(data, dict):
        return {}
    plugins = data.get("plugins", {})
    return plugins if isinstance(plugins, dict) else {}


def _last_run_epoch(conn, name: str) -> float:
    """Read last-run ISO timestamp for a source; return 0 if never run."""
    ts = db.get_last_run(conn, name)
    if not ts:
        return 0.0
    # ISO 8601 'Z' suffix
    try:
        # strptime can't handle 'Z' directly on older versions
        if ts.endswith("Z"):
            ts = ts[:-1] + "+00:00"
        return datetime.fromisoformat(ts).replace(tzinfo=timezone.utc).timestamp()
    except (ValueError, TypeError):
        return 0.0


class Server:
    """Polls each source on its own interval and runs the standard pipeline.

    When `cfg.web.enabled`, also supervises a gunicorn child serving
    `horus.web:app` for the duration of the server's lifetime.
    """

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._running = False
        self._web_proc: subprocess.Popen | None = None

    # ── notification hook ────────────────────────────────────────────────────

    def _register_notification_hook(self) -> None:
        """Register the pipeline end hook for Telegram notification dispatch."""
        token = self.cfg.telegram.resolved_token()
        if not token:
            self._log("[WARN] telegram enabled but no bot token; notifications disabled")
            return
        try:
            from .notifications.dispatcher import dispatch
            from .pipeline import register_end_hook

            register_end_hook(lambda result: dispatch(result.events, token))
            self._log("telegram notification dispatch registered")
        except Exception as e:
            self._log(f"[WARN] failed to register notification hook: {e}")

    def _start_bot(self) -> None:
        """Start the Telegram bot listener in a background thread."""
        token = self.cfg.telegram.resolved_token()
        if not token:
            return
        from .bot.telegram import run_listener

        t = threading.Thread(
            target=run_listener,
            args=(token,),
            kwargs={"poll_timeout": 30},
            daemon=True,
            name="horus-telegram-bot",
        )
        t.start()
        self._log("telegram bot listener started")

    # ── lifecycle ────────────────────────────────────────────────────────

    def start(self) -> None:
        self._running = True
        # Handle SIGTERM/SIGINT for clean shutdown under systemd / docker stop.
        signal.signal(signal.SIGTERM, self._on_signal)
        signal.signal(signal.SIGINT, self._on_signal)
        db.initialize()

        # Register notification dispatch hook
        if self.cfg.telegram.enabled:
            self._register_notification_hook()
            self._start_bot()

        if self.cfg.web.enabled:
            self._start_web()
        self._log(f"server started; check_every={self.cfg.check_every_seconds}s")
        try:
            while self._running:
                try:
                    self.run_due()
                except Exception as e:
                    logger.error("cycle failed: %s", e)
                # Supervise the web child: if it died, restart it once per cycle.
                if self.cfg.web.enabled:
                    self._supervise_web()
                # Sleep in small slices so SIGTERM is responsive.
                slept = 0
                while self._running and slept < self.cfg.check_every_seconds:
                    time.sleep(1)
                    slept += 1
        finally:
            self._stop_web()
        self._log("server stopped")

    def _on_signal(self, signum, frame) -> None:
        self._log(f"received signal {signum}, shutting down")
        self._running = False

    # ── web supervision ──────────────────────────────────────────────────

    def _start_web(self) -> None:
        host = self.cfg.web.host
        port = self.cfg.web.port
        workers = self.cfg.web.workers
        try:
            import gunicorn  # noqa: F401

            cmd = [
                sys.executable,
                "-m",
                "gunicorn",
                "horus.web:app",
                "--bind",
                f"{host}:{port}",
                "--workers",
                str(workers),
                "--worker-class",
                "sync",
                "--timeout",
                "60",
                "--access-logfile",
                "-",
                "--error-logfile",
                "-",
                "--log-level",
                "info",
                # Tie children to this group so SIGTERM kills the lot cleanly.
                "--graceful-timeout",
                "20",
            ]
            self._log(f"starting web (gunicorn {workers}w) on http://{host}:{port}")
            self._web_proc = subprocess.Popen(cmd, start_new_session=True)
            return
        except ImportError:
            pass

        if not self.cfg.web.allow_dev_fallback:
            raise RuntimeError(
                "gunicorn not installed and web.allow_dev_fallback=false. "
                'Install it: pip install -e ".[server]"'
            )
        # Dev-server fallback in a daemon thread. NOT for real production.

        from . import web as _web

        self._log(f"[WARN] gunicorn not installed; using Flask dev server on http://{host}:{port}")
        t = threading.Thread(
            target=_web.app.run,
            kwargs={"host": host, "port": port, "debug": False, "use_reloader": False},
            daemon=True,
            name="horus-web-dev",
        )
        t.start()

    def _supervise_web(self) -> None:
        proc = self._web_proc
        if proc is None:
            return
        rc = proc.poll()
        if rc is not None:
            self._log(f"[WARN] web child exited (rc={rc}); restarting")
            self._web_proc = None
            self._start_web()

    def _stop_web(self) -> None:
        proc = self._web_proc
        if proc is None:
            return
        self._log("stopping web child")
        with contextlib.suppress(ProcessLookupError, PermissionError):
            # SIGTERM the gunicorn process group; gunicorn forwards to workers.
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        try:
            proc.wait(timeout=25)
        except subprocess.TimeoutExpired:
            self._log("[WARN] web did not exit in 25s; killing")
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        self._web_proc = None

    # ── cycles ───────────────────────────────────────────────────────────

    def run_once(self) -> None:
        """Run all enabled sources/enrichers once, ignoring intervals."""
        db.initialize()
        self._invoke_pipeline(
            sources=[s for s in SOURCE_KEYS if self.cfg.enabled(s)],
            enrichers=[e for e in ENRICHER_KEYS if self.cfg.enabled(e)],
        )

    def run_due(self) -> None:
        """Run any sources/enrichers whose interval has elapsed."""
        now = time.time()
        due_sources: list[str] = []
        due_enrichers: list[str] = []
        with db.connect() as conn:
            for name in SOURCE_KEYS:
                if not self.cfg.enabled(name):
                    continue
                if now - _last_run_epoch(conn, name) >= self.cfg.interval(name):
                    due_sources.append(name)
            for name in ENRICHER_KEYS:
                if not self.cfg.enabled(name):
                    continue
                if now - _last_run_epoch(conn, name) >= self.cfg.interval(name):
                    due_enrichers.append(name)
        if not due_sources and not due_enrichers:
            return
        self._log(f"cycle: sources={due_sources or '∅'} enrichers={due_enrichers or '∅'}")
        self._invoke_pipeline(due_sources, due_enrichers)
        # Bump last_run for enrichers (pipeline only marks sources).
        with db.connect() as conn:
            for e in due_enrichers:
                db.mark_run(conn, e)

    # ── pipeline invocation ──────────────────────────────────────────────

    def _invoke_pipeline(self, sources: list[str], enrichers: list[str]) -> None:
        """Run the shared pipeline for the given source/enricher subset.

        No CLI gymnastics — server is a first-class pipeline consumer.
        """
        if not sources:
            # Enrichers-only cycle: backfill EPSS + run KEV against existing DB.
            with db.connect() as conn:
                if "epss" in enrichers:
                    from .enrichers.epss import backfill_all

                    backfill_all(conn)
                if "kev" in enrichers:
                    from .core.context import EnricherContext
                    from .core.model import CVE
                    from .enrichers.kev import enrich

                    # KEV needs CVE objects to mutate; fetch all from DB
                    rows = conn.execute(
                        "SELECT id, description, cvss_score, cvss_severity, published_at,"
                        " epss_score, kev, social_mentions, poc_source_count,"
                        " reputation_score, confidence"
                        " FROM cve"
                    ).fetchall()
                    cves = []
                    for r in rows:
                        cves.append(
                            CVE(
                                id=r[0],
                                description=r[1] or "",
                                cvss_score=r[2],
                                cvss_severity=r[3],
                                published_at=r[4],
                                epss_score=r[5],
                                kev=r[6],
                                social_mentions=r[7] or 0,
                                poc_source_count=r[8] or 0,
                                reputation_score=r[9] or 0.0,
                                confidence=r[10] or "high",
                            )
                        )
                    enrich(EnricherContext(cves=cves, pocs=[]))
                    # Persist KEV flags back
                    for cve in cves:
                        if cve.kev:
                            conn.execute("UPDATE cve SET kev = 1 WHERE id = ?", (cve.id,))
            return

        from .pipeline import PipelineOptions, run_pipeline

        run_pipeline(
            PipelineOptions(
                source_filter=set(sources),
                enricher_filter=set(enrichers) if enrichers else set(),
                quiet=True,
                save_report_md=False,
                save_graph_html=False,
                print_report=False,
                log=lambda m: self._log(m),
            )
        )

    # ── logging ──────────────────────────────────────────────────────────

    def _log(self, msg: str) -> None:
        logger.info(msg)


def main(argv: list[str] | None = None) -> None:
    """Entry point for `python3 -m horus.server`."""
    import argparse

    p = argparse.ArgumentParser(prog="horus.server", description="Horus 24/7 server mode")
    p.add_argument("--config", default=None, help="Path to YAML/JSON config file")
    p.add_argument("--once", action="store_true", help="Run a single cycle then exit")
    args = p.parse_args(argv)
    cfg = load_config(args.config)
    srv = Server(cfg)
    if args.once:
        srv.run_once()
    else:
        srv.start()


if __name__ == "__main__":
    main()
