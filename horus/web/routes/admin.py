"""Admin blueprint: user management (list, create, edit, deactivate)."""

from __future__ import annotations

import re
from datetime import datetime, timezone

from flask import Blueprint, abort, g, redirect, request, url_for
from werkzeug.security import generate_password_hash

from ...storage import db as _storage
from .._render import page
from .auth import TEAMS, role_required

bp = Blueprint("admin", __name__, url_prefix="/admin")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _all_roles(conn) -> list[dict]:
    rows = conn.execute("SELECT id, name, description FROM role ORDER BY name").fetchall()
    return [dict(r) for r in rows]


def _list_users(conn) -> list[dict]:
    rows = conn.execute(
        """
        SELECT u.id, u.username, u.email, u.is_active, u.team,
               u.created_at, u.last_login,
               COALESCE(GROUP_CONCAT(r.name, ','), '') AS roles
        FROM user u
        LEFT JOIN user_role ur ON ur.user_id = u.id
        LEFT JOIN role r ON r.id = ur.role_id
        GROUP BY u.id
        ORDER BY u.username
        """
    ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["roles"] = [x for x in d["roles"].split(",") if x] if d["roles"] else []
        out.append(d)
    return out


def _get_user(conn, user_id: int) -> dict | None:
    row = conn.execute(
        "SELECT id, username, email, is_active, team, created_at, last_login "
        "FROM user WHERE id = ?",
        (user_id,),
    ).fetchone()
    if row is None:
        return None
    d = dict(row)
    role_rows = conn.execute(
        "SELECT r.name FROM role r JOIN user_role ur ON ur.role_id = r.id WHERE ur.user_id = ?",
        (user_id,),
    ).fetchall()
    d["roles"] = [r[0] for r in role_rows]
    return d


def _set_user_roles(conn, user_id: int, role_names: list[str]) -> None:
    conn.execute("DELETE FROM user_role WHERE user_id = ?", (user_id,))
    for name in role_names:
        row = conn.execute("SELECT id FROM role WHERE name = ?", (name,)).fetchone()
        if row:
            conn.execute(
                "INSERT OR IGNORE INTO user_role (user_id, role_id) VALUES (?, ?)",
                (user_id, row[0]),
            )


def _admin_count(conn, exclude_user_id: int | None = None) -> int:
    sql = (
        "SELECT COUNT(DISTINCT u.id) FROM user u "
        "JOIN user_role ur ON ur.user_id = u.id "
        "JOIN role r ON r.id = ur.role_id "
        "WHERE r.name = 'admin' AND u.is_active = 1"
    )
    params: tuple = ()
    if exclude_user_id is not None:
        sql += " AND u.id != ?"
        params = (exclude_user_id,)
    return conn.execute(sql, params).fetchone()[0]


# ─── Routes ───────────────────────────────────────────────────────────────────


@bp.route("/users")
@role_required("admin")
def users_list():
    with _storage.connect() as conn:
        users = _list_users(conn)
    return page(
        "admin_users.html",
        title="Users",
        active="admin",
        users=users,
        teams=TEAMS,
        flash=request.args.get("flash", ""),
    )


@bp.route("/users/new", methods=["GET", "POST"])
@role_required("admin")
def users_new():
    with _storage.connect() as conn:
        roles = _all_roles(conn)

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        team = request.form.get("team", "none")
        selected_roles = request.form.getlist("roles")

        errors = []
        if not username or len(username) < 3:
            errors.append("Username must be at least 3 characters.")
        if not email or not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            errors.append("A valid email is required.")
        if not password or len(password) < 8:
            errors.append("Password must be at least 8 characters.")
        if team not in TEAMS:
            errors.append("Invalid team.")

        if errors:
            return page(
                "admin_user_edit.html",
                title="New user",
                active="admin",
                mode="new",
                user={"username": username, "email": email, "team": team, "roles": selected_roles},
                roles=roles,
                teams=TEAMS,
                error=" ".join(errors),
            ), 400

        with _storage.connect() as conn:
            existing = conn.execute(
                "SELECT 1 FROM user WHERE username = ? OR email = ?",
                (username, email),
            ).fetchone()
            if existing:
                return page(
                    "admin_user_edit.html",
                    title="New user",
                    active="admin",
                    mode="new",
                    user={
                        "username": username,
                        "email": email,
                        "team": team,
                        "roles": selected_roles,
                    },
                    roles=roles,
                    teams=TEAMS,
                    error="Username or email already taken.",
                ), 409

            cur = conn.execute(
                "INSERT INTO user (username, email, password_hash, team, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (username, email, generate_password_hash(password), team, _now()),
            )
            _set_user_roles(conn, cur.lastrowid, selected_roles)

        return redirect(url_for("admin.users_list", flash=f"Created {username}"))

    return page(
        "admin_user_edit.html",
        title="New user",
        active="admin",
        mode="new",
        user={"username": "", "email": "", "team": "none", "roles": []},
        roles=roles,
        teams=TEAMS,
    )


@bp.route("/users/<int:user_id>/edit", methods=["GET", "POST"])
@role_required("admin")
def users_edit(user_id: int):
    with _storage.connect() as conn:
        user = _get_user(conn, user_id)
        roles = _all_roles(conn)
    if user is None:
        abort(404)

    if request.method == "POST":
        email = request.form.get("email", "").strip()
        team = request.form.get("team", "none")
        is_active = 1 if request.form.get("is_active") == "on" else 0
        selected_roles = request.form.getlist("roles")
        new_password = request.form.get("password", "")

        errors = []
        if not email or not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            errors.append("A valid email is required.")
        if team not in TEAMS:
            errors.append("Invalid team.")
        if new_password and len(new_password) < 8:
            errors.append("Password must be at least 8 characters.")

        # Last-admin guard: don't allow removing the last active admin.
        with _storage.connect() as conn:
            removing_admin = "admin" in user["roles"] and "admin" not in selected_roles
            deactivating_admin = "admin" in user["roles"] and not is_active
            if (removing_admin or deactivating_admin) and _admin_count(
                conn, exclude_user_id=user_id
            ) == 0:
                errors.append("Cannot remove or deactivate the last admin.")

        if errors:
            user["email"] = email
            user["team"] = team
            user["is_active"] = is_active
            user["roles"] = selected_roles
            return page(
                "admin_user_edit.html",
                title=f"Edit {user['username']}",
                active="admin",
                mode="edit",
                user=user,
                roles=roles,
                teams=TEAMS,
                error=" ".join(errors),
            ), 400

        with _storage.connect() as conn:
            conn.execute(
                "UPDATE user SET email = ?, team = ?, is_active = ? WHERE id = ?",
                (email, team, is_active, user_id),
            )
            if new_password:
                conn.execute(
                    "UPDATE user SET password_hash = ? WHERE id = ?",
                    (generate_password_hash(new_password), user_id),
                )
            _set_user_roles(conn, user_id, selected_roles)

        return redirect(url_for("admin.users_list", flash=f"Updated {user['username']}"))

    return page(
        "admin_user_edit.html",
        title=f"Edit {user['username']}",
        active="admin",
        mode="edit",
        user=user,
        roles=roles,
        teams=TEAMS,
    )


@bp.route("/users/<int:user_id>/delete", methods=["POST"])
@role_required("admin")
def users_delete(user_id: int):
    if g.user and g.user["id"] == user_id:
        abort(400)  # Don't let admins delete themselves
    with _storage.connect() as conn:
        user = _get_user(conn, user_id)
        if user is None:
            abort(404)
        if "admin" in user["roles"] and _admin_count(conn, exclude_user_id=user_id) == 0:
            return redirect(url_for("admin.users_list", flash="Cannot delete the last admin"))
        conn.execute("DELETE FROM user WHERE id = ?", (user_id,))
    return redirect(url_for("admin.users_list", flash=f"Deleted {user['username']}"))
