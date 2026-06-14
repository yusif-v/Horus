"""Append-only audit log for security-relevant mutations.

Call `record(action, target_type, target_id, before=..., after=...)` from
any route that mutates state the operator should be able to reconstruct
later: user CRUD, role/team changes, watchlist edits.

The actor is pulled from `g.user` automatically. `actor_username` is
denormalized into each row so the log stays meaningful even after a user
is deleted (FK on actor_id is SET NULL on delete).

NEVER pass a password_hash through `before` / `after`. Sanitize callers
before recording.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from flask import g

from ..storage import db as _storage


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _serialize(payload: Any) -> str | None:
    if payload is None:
        return None
    return json.dumps(payload, sort_keys=True, default=str)


def record(
    action: str,
    target_type: str,
    target_id: Any = None,
    *,
    before: Any = None,
    after: Any = None,
) -> None:
    """Append one audit event. Best-effort: never raises into the request path."""
    actor_id = None
    actor_username = None
    user = getattr(g, "user", None)
    if user is not None:
        actor_id = user.get("id") if isinstance(user, dict) else None
        actor_username = user.get("username") if isinstance(user, dict) else None

    try:
        with _storage.connect() as conn:
            conn.execute(
                "INSERT INTO audit_event "
                "(ts, actor_id, actor_username, action, target_type, target_id, "
                " before_json, after_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    _now(),
                    actor_id,
                    actor_username,
                    action,
                    target_type,
                    str(target_id) if target_id is not None else None,
                    _serialize(before),
                    _serialize(after),
                ),
            )
    except Exception:
        # Audit is best-effort — never break the request because of a write
        # failure here. A future enhancement could log to stderr.
        pass
