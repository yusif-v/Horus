"""Persistent deduplication state and per-source last-run tracking."""

import json
from datetime import datetime

from .config import LAST_RUN_FILE, STATE_DIR, STATE_FILE


def load_seen() -> set[str]:
    if STATE_FILE.exists():
        try:
            return set(json.loads(STATE_FILE.read_text()))
        except (json.JSONDecodeError, OSError):
            return set()
    return set()


def save_seen(seen: set[str]) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(sorted(seen)))


def load_last_run() -> dict[str, str]:
    if LAST_RUN_FILE.exists():
        try:
            return json.loads(LAST_RUN_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def save_last_run(last_run: dict[str, str]) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    LAST_RUN_FILE.write_text(json.dumps(last_run, indent=2, sort_keys=True))


def mark_run(last_run: dict[str, str], source: str) -> None:
    last_run[source] = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
