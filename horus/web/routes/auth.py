"""Authentication blueprint: login, logout, session management, and access control."""

from __future__ import annotations

import functools
import re
from datetime import datetime, timezone
from threading import Lock
from typing import Literal, get_args
from urllib.parse import urljoin, urlparse

from flask import (
    Blueprint,
    abort,
    current_app,
    g,
    redirect,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

from ...storage import db as _storage
from .._render import page

bp = Blueprint("auth", __name__)

# ─── Simple per-IP rate limiter (no external dependencies) ───────────────────
# Tracks login attempts per IP in-memory with a sliding window.
# Disabled when TESTING=True (pytest) to avoid cross-test interference.
_login_attempts: dict[str, list[datetime]] = {}
_login_lock = Lock()
_WINDOW_SECONDS = 300  # 5 minutes
_MAX_ATTEMPTS = 5


def _rate_limit_check(ip: str) -> bool:
    """Return True if request is OK to proceed, False if rate-limited."""
    now = datetime.now(timezone.utc)
    cutoff = now.timestamp() - _WINDOW_SECONDS
    with _login_lock:
        attempts = _login_attempts.get(ip, [])
        attempts = [t for t in attempts if t.timestamp() > cutoff]
        _login_attempts[ip] = attempts
        if len(attempts) >= _MAX_ATTEMPTS:
            return False
        attempts.append(now)
        return True


# Default roles seeded on first run
DEFAULT_ROLES = [
    ("admin", "Full access to all features and settings"),
    ("analyst", "Can view and analyze CVEs, create alerts and reports"),
    ("viewer", "Read-only access to CVE data"),
]

# Dummy hash for constant-time check when username not found (prevents timing attacks)
_DUMMY_HASH = "pbkdf2:sha256:600000$dummy$hash"

Team = Literal["red", "blue", "both", "none"]
TEAMS: tuple[str, ...] = get_args(Team)

# Zero-trust role aliases used in route decorators.
# READ_ALL — any authenticated user with a defined role may read.
# WRITE_ALL — analyst+admin: can mutate triage/annotation/watchlist state.
# ADMIN_ONLY — admin-only mutations (users, system config).
READ_ALL: tuple[str, ...] = ("viewer", "analyst", "admin")
WRITE_ALL: tuple[str, ...] = ("analyst", "admin")
ADMIN_ONLY: tuple[str, ...] = ("admin",)


def _is_safe_url(target: str) -> bool:
    """Validate that a redirect URL is safe (same host, not external)."""
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ("http", "https") and ref_url.netloc == test_url.netloc


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _seed_default_roles(conn) -> None:
    for name, description in DEFAULT_ROLES:
        conn.execute(
            "INSERT OR IGNORE INTO role (name, description) VALUES (?, ?)",
            (name, description),
        )


def _get_user(conn, username: str) -> dict | None:
    row = conn.execute(
        "SELECT id, username, email, password_hash, is_active, team FROM user WHERE username = ?",
        (username,),
    ).fetchone()
    return dict(row) if row else None


def _get_user_roles(conn, user_id: int) -> list[str]:
    rows = conn.execute(
        "SELECT r.name FROM role r JOIN user_role ur ON ur.role_id = r.id WHERE ur.user_id = ?",
        (user_id,),
    ).fetchall()
    return [r[0] for r in rows]


def _create_user(conn, username: str, email: str, password: str, roles: list[str]) -> int:
    pw_hash = generate_password_hash(password)
    cur = conn.execute(
        "INSERT INTO user (username, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
        (username, email, pw_hash, _now()),
    )
    user_id = cur.lastrowid
    for role_name in roles:
        role = conn.execute("SELECT id FROM role WHERE name = ?", (role_name,)).fetchone()
        if role:
            conn.execute(
                "INSERT OR IGNORE INTO user_role (user_id, role_id) VALUES (?, ?)",
                (user_id, role[0]),
            )
    return user_id


@bp.before_app_request
def load_user() -> None:
    """Load the current user from session into g.user before every request."""
    user_id = session.get("user_id")
    if user_id is None:
        g.user = None
        g.user_roles = []
        g.user_team = "none"
        return
    with _storage.connect() as conn:
        row = conn.execute(
            "SELECT id, username, email, is_active, team, telegram_chat_id,"
            " COALESCE(theme_preference, 'system') AS theme_preference"
            " FROM user WHERE id = ?",
            (user_id,),
        ).fetchone()
        if row is None or not row[3]:
            # User was deleted or deactivated — clear session
            session.clear()
            g.user = None
            g.user_roles = []
            g.user_team = "none"
            return
        g.user = dict(row)
        g.user_roles = _get_user_roles(conn, user_id)
        g.user_team = g.user.get("team") or "none"


def login_required(view):
    """Decorator: redirect to login if user is not authenticated."""

    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for("auth.login", next=request.url))
        return view(**kwargs)

    return wrapped_view


def role_required(*roles):
    """Decorator: abort 403 if user doesn't have at least one of the required roles."""

    def decorator(view):
        @functools.wraps(view)
        def wrapped_view(**kwargs):
            if g.user is None:
                return redirect(url_for("auth.login", next=request.url))
            if not any(r in g.user_roles for r in roles):
                abort(403)
            return view(**kwargs)

        return wrapped_view

    return decorator


def team_required(*teams: str):
    """Decorator: abort 403 unless user's team matches one of `teams`.

    `team='both'` satisfies any of red/blue. Admins always pass.
    """

    def decorator(view):
        @functools.wraps(view)
        def wrapped_view(**kwargs):
            if g.user is None:
                return redirect(url_for("auth.login", next=request.url))
            if "admin" in g.user_roles:
                return view(**kwargs)
            user_team = g.get("user_team") or "none"
            allowed = set(teams)
            if user_team in allowed or (user_team == "both" and allowed & {"red", "blue"}):
                return view(**kwargs)
            abort(403)

        return wrapped_view

    return decorator


# ─── Routes ───────────────────────────────────────────────────────────────────


@bp.route("/login", methods=["GET", "POST"])
def login():
    if g.user is not None:
        return redirect(url_for("dashboard.index"))

    if request.method == "POST":
        # Rate limit login attempts (5 per 5 minutes per IP)
        if not current_app.config.get("TESTING", False):
            client_ip = (
                request.headers.get("X-Forwarded-For", request.remote_addr or "unknown")
                .split(",")[0]
                .strip()
            )
            if not _rate_limit_check(client_ip):
                return page(
                    "login.html",
                    title="Login",
                    error="Too many login attempts. Please try again in 5 minutes.",
                    username=request.form.get("username", "").strip(),
                ), 429

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        with _storage.connect() as conn:
            user = _get_user(conn, username)

        # Constant-time check: always run check_password_hash to prevent
        # timing attacks that could enumerate valid usernames.
        if user:
            valid = check_password_hash(user["password_hash"], password)
        else:
            check_password_hash(_DUMMY_HASH, password)
            valid = False

        if valid:
            session.clear()
            session["user_id"] = user["id"]
            try:
                with _storage.connect() as conn:
                    conn.execute(
                        "UPDATE user SET last_login = ? WHERE id = ?",
                        (_now(), user["id"]),
                    )
            except Exception:
                pass  # Non-critical — don't block login if this fails
            next_url = request.args.get("next", "")
            if not next_url or not _is_safe_url(next_url):
                next_url = url_for("dashboard.index")
            return redirect(next_url)

        return page(
            "login.html",
            title="Login",
            error="Invalid username or password",
            username=username,
        ), 401

    return page("login.html", title="Login")


@bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("auth.login"))


@bp.route("/register", methods=["GET", "POST"])
def register():
    if g.user is not None:
        return redirect(url_for("dashboard.index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        password_confirm = request.form.get("password_confirm", "")

        errors = []
        if not username or len(username) < 3:
            errors.append("Username must be at least 3 characters.")
        if not email or not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            errors.append("A valid email is required.")
        if not password or len(password) < 8:
            errors.append("Password must be at least 8 characters.")
        if password != password_confirm:
            errors.append("Passwords do not match.")

        if errors:
            return page(
                "register.html",
                title="Register",
                error=" ".join(errors),
                username=username,
                email=email,
            ), 400

        with _storage.connect() as conn:
            _seed_default_roles(conn)
            existing = conn.execute(
                "SELECT 1 FROM user WHERE username = ? OR email = ?",
                (username, email),
            ).fetchone()
            if existing:
                return page(
                    "register.html",
                    title="Register",
                    error="Username or email already taken.",
                    username=username,
                    email=email,
                ), 409

            # First user gets admin role; subsequent users get viewer
            user_count = conn.execute("SELECT COUNT(*) FROM user").fetchone()[0]
            assigned_roles = ["admin"] if user_count == 0 else ["viewer"]
            _create_user(conn, username, email, password, assigned_roles)

        return redirect(url_for("auth.login"))

    return page("register.html", title="Register")
