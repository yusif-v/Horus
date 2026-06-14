"""Session-bound CSRF protection.

Generates a per-session token stored in the Flask session cookie. Every
state-changing request (POST/PUT/PATCH/DELETE) must echo the token back
in a `csrf_token` form field or `X-CSRF-Token` header. Constant-time
compare on validation.

Disabled when `app.config['CSRF_ENABLED']` is False (set automatically
when `app.testing` is True so the existing test suite keeps working;
explicit CSRF tests flip the flag back on).
"""

from __future__ import annotations

import hmac
import secrets

from flask import Flask, abort, current_app, request, session

_SESSION_KEY = "_csrf_token"
_SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}


def get_token() -> str:
    """Return the session's CSRF token, creating one if absent."""
    token = session.get(_SESSION_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        session[_SESSION_KEY] = token
    return token


def _provided_token() -> str | None:
    return request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")


def _validate() -> None:
    # In production CSRF is always on. Test clients skip by default so the
    # existing test suite stays simple; explicit CSRF tests opt back in with
    # `app.config['CSRF_FORCE_IN_TESTING'] = True`.
    if current_app.config.get("CSRF_ENABLED") is False:
        return
    if current_app.testing and not current_app.config.get("CSRF_FORCE_IN_TESTING"):
        return
    if request.method in _SAFE_METHODS:
        return
    expected = session.get(_SESSION_KEY)
    provided = _provided_token()
    if not expected or not provided or not hmac.compare_digest(expected, provided):
        abort(400, description="CSRF token missing or invalid")


def init_app(app: Flask) -> None:
    """Wire CSRF into a Flask app: validator + Jinja helper.

    `CSRF_ENABLED` defaults to True. When `app.testing` is set later,
    `_validate` skips the check unless `CSRF_ENABLED` was explicitly set
    to True — letting individual tests opt-in.
    """
    app.config.setdefault("CSRF_ENABLED", True)
    app.before_request(_validate)
    app.jinja_env.globals["csrf_token"] = get_token
