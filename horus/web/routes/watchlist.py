"""Per-team watchlist blueprint (red/blue).

A watchlist entry is a (vendor, product) pin scoped to a team. The list
view joins to cve_product so newly-ingested CVEs touching a watched
vendor/product surface immediately.

Access policy:
- GET  /watchlist               READ_ALL  + team_required('red','blue')
- POST /watchlist/add           WRITE_ALL + team_required('red','blue')
- POST /watchlist/<id>/delete   WRITE_ALL + team_required('red','blue')

Admins always pass `team_required`. A user whose team is 'both' sees a
merged red+blue list; team='none' is denied entirely.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

from flask import Blueprint, abort, g, redirect, request, url_for

from ...storage import db as _storage
from .. import audit
from .._render import page
from .auth import READ_ALL, WRITE_ALL, role_required, team_required

bp = Blueprint("watchlist", __name__, url_prefix="/watchlist")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _user_team_scope() -> list[str]:
    """Which team rows the current user can see.

    admin       → both teams
    team='both' → both teams
    team='red'  → ['red']
    team='blue' → ['blue']
    """
    if "admin" in g.user_roles:
        return ["red", "blue"]
    team = g.get("user_team") or "none"
    if team == "both":
        return ["red", "blue"]
    if team in ("red", "blue"):
        return [team]
    return []


def _entries(conn, teams: list[str]) -> list[dict]:
    if not teams:
        return []
    placeholders = ",".join("?" for _ in teams)
    rows = conn.execute(
        f"""
        SELECT w.id, w.team, w.vendor, w.product, w.note,
               w.created_at, u.username AS created_by_name
        FROM team_watchlist w
        LEFT JOIN user u ON u.id = w.created_by
        WHERE w.team IN ({placeholders})
        ORDER BY w.team, w.vendor, w.product
        """,
        teams,
    ).fetchall()
    return [dict(r) for r in rows]


def _matching_cves(conn, teams: list[str], limit: int = 50) -> list[dict]:
    """CVEs that touch any (vendor[, product]) in the watchlist for `teams`."""
    if not teams:
        return []
    placeholders = ",".join("?" for _ in teams)
    rows = conn.execute(
        f"""
        SELECT DISTINCT c.id, c.cvss_score, c.cvss_severity, c.kev,
                        c.epss_score, c.published_at, c.description,
                        p.vendor, p.product
        FROM team_watchlist w
        JOIN product p
          ON p.vendor = w.vendor
         AND (w.product = '' OR p.product = w.product)
        JOIN cve_product cp ON cp.product_id = p.id
        JOIN cve c          ON c.id = cp.cve_id
        WHERE w.team IN ({placeholders})
        ORDER BY COALESCE(c.published_at, c.first_seen) DESC
        LIMIT ?
        """,
        (*teams, limit),
    ).fetchall()
    return [dict(r) for r in rows]


# ─── Routes ───────────────────────────────────────────────────────────────────


@bp.route("/")
@role_required(*READ_ALL)
@team_required("red", "blue")
def index():
    teams = _user_team_scope()
    with _storage.connect() as conn:
        entries = _entries(conn, teams)
        cves = _matching_cves(conn, teams)
    return page(
        "watchlist.html",
        title="Watchlist",
        active="watchlist",
        entries=entries,
        cves=cves,
        teams_visible=teams,
        flash=request.args.get("flash", ""),
    )


@bp.route("/add", methods=["POST"])
@role_required(*WRITE_ALL)
@team_required("red", "blue")
def add():
    team = request.form.get("team", "").strip().lower()
    vendor = request.form.get("vendor", "").strip()
    product = request.form.get("product", "").strip()
    note = request.form.get("note", "").strip() or None

    if team not in ("red", "blue"):
        abort(400, description="invalid team")
    if "admin" not in g.user_roles:
        allowed = _user_team_scope()
        if team not in allowed:
            abort(403, description="cannot add to a team you don't belong to")
    if not vendor:
        return redirect(url_for("watchlist.index", flash="Vendor required"))

    with _storage.connect() as conn:
        try:
            cur = conn.execute(
                "INSERT INTO team_watchlist (team, vendor, product, note, "
                "created_at, created_by) VALUES (?, ?, ?, ?, ?, ?)",
                (team, vendor, product, note, _now(), g.user["id"]),
            )
            new_id = cur.lastrowid
        except sqlite3.IntegrityError:
            return redirect(
                url_for("watchlist.index", flash=f"Already watching {vendor} {product}")
            )

    audit.record(
        "watchlist.add",
        "watchlist",
        new_id,
        after={"team": team, "vendor": vendor, "product": product, "note": note},
    )
    label = f"{vendor} {product}".strip()
    return redirect(url_for("watchlist.index", flash=f"Added {label}"))


@bp.route("/<int:entry_id>/delete", methods=["POST"])
@role_required(*WRITE_ALL)
@team_required("red", "blue")
def delete(entry_id: int):
    with _storage.connect() as conn:
        row = conn.execute(
            "SELECT team, vendor, product FROM team_watchlist WHERE id = ?",
            (entry_id,),
        ).fetchone()
        if row is None:
            abort(404)
        if "admin" not in g.user_roles:
            allowed = _user_team_scope()
            if row[0] not in allowed:
                abort(403)
        conn.execute("DELETE FROM team_watchlist WHERE id = ?", (entry_id,))

    audit.record(
        "watchlist.delete",
        "watchlist",
        entry_id,
        before={"team": row[0], "vendor": row[1], "product": row[2]},
    )
    label = f"{row[1]} {row[2]}".strip()
    return redirect(url_for("watchlist.index", flash=f"Removed {label}"))
