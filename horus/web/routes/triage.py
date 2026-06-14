"""Triage route — curated action queue with per-CVE status + analyst notes."""

from __future__ import annotations

from datetime import datetime, timezone

from flask import Blueprint, abort, g, redirect, request, url_for

from ...storage import db as _storage
from .. import audit
from .._render import error_page, page
from ..queries import PER_PAGE_DEFAULT, _rows_to_dicts, db_connect, safe_int
from .auth import READ_ALL, WRITE_ALL, role_required

bp = Blueprint("triage", __name__)

WHERE_BY_LENS = {
    "all": "(c.kev = 1 OR c.epss_score >= 0.5 OR (c.cvss_score >= 9 AND pc.cve_id IS NOT NULL))",
    "kev": "c.kev = 1",
    "imminent": "c.epss_score >= 0.5",
    "weaponized": "c.cvss_score >= 9 AND pc.cve_id IS NOT NULL",
}

STATUSES = ("new", "acknowledged", "working", "dismissed", "done")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _can_write() -> bool:
    return bool(g.user and any(r in g.user_roles for r in WRITE_ALL))


@bp.route("/triage")
@role_required(*READ_ALL)
def triage():
    pg = safe_int(request.args.get("page", "1"))
    lens = request.args.get("lens", "all")
    show_dismissed = request.args.get("show_dismissed") == "1"
    where = WHERE_BY_LENS.get(lens, WHERE_BY_LENS["all"])
    dismissed_clause = "" if show_dismissed else "AND COALESCE(t.status, 'new') != 'dismissed'"

    try:
        with db_connect() as conn:
            total = conn.execute(f"""
                SELECT COUNT(DISTINCT c.id) FROM cve c
                LEFT JOIN poc_cve pc ON pc.cve_id = c.id
                LEFT JOIN cve_triage t ON t.cve_id = c.id
                WHERE {where} {dismissed_clause}
            """).fetchone()[0]
            offset = (pg - 1) * PER_PAGE_DEFAULT
            rows = _rows_to_dicts(
                conn.execute(
                    f"""
                SELECT DISTINCT c.id, c.cvss_score, c.cvss_severity, c.description,
                       c.epss_score, c.kev, c.published_at,
                       (SELECT COUNT(*) FROM poc_cve WHERE cve_id = c.id) AS poc_count,
                       COALESCE(t.status, 'new') AS status,
                       u.username AS assigned_to_name,
                       t.note AS triage_note
                FROM cve c
                LEFT JOIN poc_cve pc ON pc.cve_id = c.id
                LEFT JOIN cve_triage t ON t.cve_id = c.id
                LEFT JOIN user u ON u.id = t.assigned_to
                WHERE {where} {dismissed_clause}
                ORDER BY c.kev DESC,
                         COALESCE(c.epss_score, 0) DESC,
                         COALESCE(c.cvss_score, 0) DESC
                LIMIT ? OFFSET ?
            """,
                    (PER_PAGE_DEFAULT, offset),
                ).fetchall()
            )
    except Exception as e:
        return error_page(f"Database Error: {e}", active="triage"), 500

    filters = [
        {"label": "All actionable", "url": "/triage", "active": lens == "all"},
        {"label": "KEV only", "url": "/triage?lens=kev", "active": lens == "kev"},
        {
            "label": "Imminent · EPSS≥0.5",
            "url": "/triage?lens=imminent",
            "active": lens == "imminent",
        },
        {
            "label": "Weaponized · CVSS≥9 + PoC",
            "url": "/triage?lens=weaponized",
            "active": lens == "weaponized",
        },
    ]
    qs_lens = f"lens={lens}&" if lens != "all" else ""
    dismissed_filters = [
        {
            "label": "Hide dismissed",
            "url": f"/triage?{qs_lens}",
            "active": not show_dismissed,
        },
        {
            "label": "Show dismissed",
            "url": f"/triage?{qs_lens}show_dismissed=1",
            "active": show_dismissed,
        },
    ]
    qs = f"&lens={lens}" if lens != "all" else ""
    if show_dismissed:
        qs += "&show_dismissed=1"

    return page(
        "triage.html",
        title="Triage queue",
        active="triage",
        eyebrow="Action queue · prioritised",
        subtitle="KEV, EPSS≥0.5, or critical CVEs with public PoC. Analysts can set "
        "status and assign work; dismissed rows are hidden by default.",
        rows=rows,
        total=total,
        page=pg,
        per_page=PER_PAGE_DEFAULT,
        filters=filters,
        dismissed_filters=dismissed_filters,
        statuses=STATUSES,
        can_write=_can_write(),
        prev_url=f"/triage?page={pg - 1}{qs}" if pg > 1 else None,
        next_url=f"/triage?page={pg + 1}{qs}" if pg * PER_PAGE_DEFAULT < total else None,
    )


@bp.route("/triage/<cve_id>/update", methods=["POST"])
@role_required(*WRITE_ALL)
def update(cve_id: str):
    status = request.form.get("status", "").strip().lower()
    note = request.form.get("note", "").strip() or None
    assign_self = request.form.get("assign_self") == "on"

    if status not in STATUSES:
        abort(400, description="invalid status")

    # Ensure the CVE exists before we upsert a triage row.
    with _storage.connect() as conn:
        if conn.execute("SELECT 1 FROM cve WHERE id = ?", (cve_id,)).fetchone() is None:
            abort(404)
        before_row = conn.execute(
            "SELECT status, assigned_to, note FROM cve_triage WHERE cve_id = ?",
            (cve_id,),
        ).fetchone()
        before = dict(before_row) if before_row else None

        assigned_to = g.user["id"] if assign_self else (before["assigned_to"] if before else None)
        conn.execute(
            """
            INSERT INTO cve_triage (cve_id, status, assigned_to, note,
                                    updated_at, updated_by)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(cve_id) DO UPDATE SET
                status      = excluded.status,
                assigned_to = excluded.assigned_to,
                note        = excluded.note,
                updated_at  = excluded.updated_at,
                updated_by  = excluded.updated_by
            """,
            (cve_id, status, assigned_to, note, _now(), g.user["id"]),
        )

    audit.record(
        "triage.update",
        "cve",
        cve_id,
        before=before,
        after={"status": status, "assigned_to": assigned_to, "note": note},
    )
    qs = request.form.get("return_qs", "")
    return redirect(url_for("triage.triage") + (f"?{qs}" if qs else ""))
