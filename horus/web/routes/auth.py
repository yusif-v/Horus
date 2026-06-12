"""Authentication blueprint: login, logout, session management, and access control."""

from __future__ import annotations

import functools
from datetime import datetime, timezone

from flask import (
    Blueprint,
    abort,
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

# Default roles seeded on first run
DEFAULT_ROLES = [
    ("admin", "Full access to all features and settings"),
    ("analyst", "Can view and analyze CVEs, create alerts and reports"),
    ("viewer", "Read-only access to CVE data"),
]


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
        "SELECT id, username, email, password_hash, is_active FROM user WHERE username = ?",
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
        return
    with _storage.connect() as conn:
        row = conn.execute(
            "SELECT id, username, email, is_active FROM user WHERE id = ?",
            (user_id,),
        ).fetchone()
        if row is None or not row[3]:
            # User was deleted or deactivated — clear session
            session.clear()
            g.user = None
            g.user_roles = []
            return
        g.user = dict(row)
        g.user_roles = _get_user_roles(conn, user_id)


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


# ─── Routes ───────────────────────────────────────────────────────────────────


@bp.route("/login", methods=["GET", "POST"])
def login():
    if g.user is not None:
        return redirect(url_for("dashboard.index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        with _storage.connect() as conn:
            user = _get_user(conn, username)

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            conn = _storage.connect().__enter__()
            try:
                conn.execute(
                    "UPDATE user SET last_login = ? WHERE id = ?",
                    (_now(), user["id"]),
                )
                conn.commit()
            except Exception:
                pass
            finally:
                conn.close()
            next_url = request.args.get("next", url_for("dashboard.index"))
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
        if not email or "@" not in email:
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
