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
      exploit_db: 7200
      epss: 86400
      kev: 86400
    sources_enabled:
      nvd: true
      x_twitter: true
      github: true
      exploit_db: false
    check_every_seconds: 60
"""

from __future__ import annotations

import json
import signal
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from .storage import db


DEFAULT_POLL_INTERVALS: dict[str, int] = {
    "nvd":         3600,    # 1h    — NVD updates roughly every 2h
    "x_twitter":   1800,    # 30m   — social moves fast
    "github":      3600,    # 1h    — search API rate-limited
    "exploit_db":  7200,    # 2h    — slower moving
    "epss":        86400,   # 24h   — daily CSV
    "kev":         86400,   # 24h   — daily catalog
}

# Sources are run by the main pipeline (CVE/PoC discovery); enrichers
# are scheduled but applied to the current batch + DB backfill.
SOURCE_KEYS = {"nvd", "x_twitter", "github", "exploit_db"}
ENRICHER_KEYS = {"epss", "kev"}


@dataclass
class Config:
    poll_intervals: dict[str, int] = field(default_factory=lambda: dict(DEFAULT_POLL_INTERVALS))
    sources_enabled: dict[str, bool] = field(default_factory=dict)
    check_every_seconds: int = 60

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
        print(f"  [WARN] config not found at {p}, using defaults", file=sys.stderr)
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
            print(f"  [WARN] PyYAML missing and config is not JSON ({e}); using defaults", file=sys.stderr)
            return cfg
    if "poll_intervals" in data and isinstance(data["poll_intervals"], dict):
        cfg.poll_intervals.update({k: int(v) for k, v in data["poll_intervals"].items()})
    if "sources_enabled" in data and isinstance(data["sources_enabled"], dict):
        cfg.sources_enabled.update({k: bool(v) for k, v in data["sources_enabled"].items()})
    if "check_every_seconds" in data:
        cfg.check_every_seconds = int(data["check_every_seconds"])
    return cfg


def _last_run_epoch(conn, name: str) -> float:
    """Read last-run ISO timestamp for a source; return 0 if never run."""
    ts = db.get_last_run(conn, name)
    if not ts:
        return 0.0
    # ISO 8601 'Z' suffix
    try:
        from datetime import datetime, timezone
        # strptime can't handle 'Z' directly on older versions
        if ts.endswith("Z"):
            ts = ts[:-1] + "+00:00"
        return datetime.fromisoformat(ts).replace(tzinfo=timezone.utc).timestamp()
    except (ValueError, TypeError):
        return 0.0


class Server:
    """Polls each source on its own interval and runs the standard pipeline."""

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._running = False

    # ── lifecycle ────────────────────────────────────────────────────────

    def start(self) -> None:
        self._running = True
        # Handle SIGTERM/SIGINT for clean shutdown under systemd / docker stop.
        signal.signal(signal.SIGTERM, self._on_signal)
        signal.signal(signal.SIGINT, self._on_signal)
        db.initialize()
        self._log(f"server started; check_every={self.cfg.check_every_seconds}s")
        while self._running:
            try:
                self.run_due()
            except Exception as e:
                print(f"  [ERROR] cycle failed: {e}", file=sys.stderr)
            # Sleep in small slices so SIGTERM is responsive.
            slept = 0
            while self._running and slept < self.cfg.check_every_seconds:
                time.sleep(1)
                slept += 1
        self._log("server stopped")

    def _on_signal(self, signum, frame) -> None:
        self._log(f"received signal {signum}, shutting down")
        self._running = False

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
        """Drive cli.main with a synthesized argv: quiet, no graph, no report file."""
        from .cli import main as cli_main
        argv: list[str] = ["--quiet", "--no-save", "--no-graph"]
        if sources:
            argv += ["--sources", ",".join(sources)]
        else:
            # No sources due — only enrichers. cli.main requires at least one
            # source to do anything; skip and just run enrichers via the
            # backfill path.
            if "epss" in enrichers:
                from .enrichers.epss import backfill_all
                with db.connect() as conn:
                    backfill_all(conn)
            return
        if enrichers:
            argv += ["--enrichers", ",".join(enrichers)]
        try:
            cli_main(argv)
        except SystemExit:
            # argparse may raise on bad combo — keep the server alive.
            pass

    # ── logging ──────────────────────────────────────────────────────────

    def _log(self, msg: str) -> None:
        from datetime import datetime
        ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        print(f"[{ts}] horus.server: {msg}", file=sys.stderr)


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
