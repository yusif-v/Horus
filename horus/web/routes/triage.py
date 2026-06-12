"""Triage route — curated action queue (KEV or EPSS>=0.5 or critical-with-PoC)."""

from __future__ import annotations

from flask import Blueprint, request

from .._render import error_page, page
from ..queries import PER_PAGE_DEFAULT, _rows_to_dicts, db_connect, safe_int
from .auth import login_required

bp = Blueprint("triage", __name__)

WHERE_BY_LENS = {
    "all": "(c.kev = 1 OR c.epss_score >= 0.5 OR (c.cvss_score >= 9 AND pc.cve_id IS NOT NULL))",
    "kev": "c.kev = 1",
    "imminent": "c.epss_score >= 0.5",
    "weaponized": "c.cvss_score >= 9 AND pc.cve_id IS NOT NULL",
}


@bp.route("/triage")
@login_required
def triage():
    pg = safe_int(request.args.get("page", "1"))
    lens = request.args.get("lens", "all")
    where = WHERE_BY_LENS.get(lens, WHERE_BY_LENS["all"])

    try:
        with db_connect() as conn:
            total = conn.execute(f"""
                SELECT COUNT(DISTINCT c.id) FROM cve c
                LEFT JOIN poc_cve pc ON pc.cve_id = c.id
                WHERE {where}
            """).fetchone()[0]
            offset = (pg - 1) * PER_PAGE_DEFAULT
            rows = _rows_to_dicts(
                conn.execute(
                    f"""
                SELECT DISTINCT c.id, c.cvss_score, c.cvss_severity, c.description,
                       c.epss_score, c.kev, c.published_at,
                       (SELECT COUNT(*) FROM poc_cve WHERE cve_id = c.id) AS poc_count
                FROM cve c
                LEFT JOIN poc_cve pc ON pc.cve_id = c.id
                WHERE {where}
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
    columns = ["CVE", "CVSS", "Severity", "EPSS", "KEV", "PoCs", "Description"]
    cells = [
        {"type": "cve_link", "key": "id"},
        {"type": "score", "key": "cvss_score"},
        {"type": "badge", "key": "cvss_severity"},
        {"type": "epss", "key": "epss_score"},
        {"type": "kev", "key": "kev"},
        {"type": "plain", "key": "poc_count"},
        {"type": "truncate", "key": "description"},
    ]
    qs = f"&lens={lens}" if lens != "all" else ""

    return page(
        "list.html",
        title="Triage queue",
        active="triage",
        eyebrow="Action queue · prioritised",
        subtitle="Vulnerabilities you should look at first: anything in CISA KEV, "
        "anything with EPSS ≥ 0.5, or critical CVEs with public proof-of-concept. "
        "Ordered by KEV → EPSS → CVSS.",
        rows=rows,
        total=total,
        page=pg,
        per_page=PER_PAGE_DEFAULT,
        filters=filters,
        columns=columns,
        cells=cells,
        prev_url=f"/triage?page={pg - 1}{qs}" if pg > 1 else None,
        next_url=f"/triage?page={pg + 1}{qs}" if pg * PER_PAGE_DEFAULT < total else None,
    )
