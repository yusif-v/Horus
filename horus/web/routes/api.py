"""JSON API routes — for liveness probes and external consumers."""

from __future__ import annotations

from flask import Blueprint, jsonify, request

from ...storage import db as _storage
from ..queries import get_cve_detail, get_stats, search_cves
from .auth import READ_ALL, role_required

bp = Blueprint("api", __name__, url_prefix="/api")


@bp.route("/health")
def health():
    """Public health check endpoint (no auth required)."""
    try:
        with _storage.connect() as conn:
            conn.execute("SELECT 1")
            rows = _storage.get_source_health(conn)
    except Exception:
        return jsonify({"status": "degraded", "db": False}), 503

    sources = {
        r["source_name"]: {
            "status": r["last_status"],
            "last_run": r["last_run_at"],
            "consecutive_failures": r["consecutive_failures"],
        }
        for r in rows
    }
    degraded = any(r["last_status"] != "skipped" and r["consecutive_failures"] >= 3 for r in rows)
    status = "degraded" if degraded else "ok"
    return jsonify({"status": status, "db": True, "sources": sources})


@bp.route("/stats")
@role_required(*READ_ALL)
def stats():
    try:
        year = request.args.get("year", type=int)
        return jsonify(get_stats(year=year))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@bp.route("/cves")
@role_required(*READ_ALL)
def cves():
    """List CVEs, optionally filtered by year with pagination."""
    try:
        year = request.args.get("year", type=int)
        page = request.args.get("page", default=1, type=int)
        per_page = request.args.get("per_page", default=20, type=int)
        # Clamp per_page to a sane range
        per_page = max(1, min(per_page, 100))

        results, total = search_cves("", page=page, per_page=per_page)

        if year is not None:
            year_str = str(year)
            results = [r for r in results if r.get("published_at", "").startswith(year_str)]

        return jsonify(
            {
                "results": results,
                "total": total,
                "page": page,
                "per_page": per_page,
            }
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@bp.route("/cve/<cve_id>")
@role_required(*READ_ALL)
def cve(cve_id):
    try:
        data = get_cve_detail(cve_id)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    if not data:
        return jsonify({"error": "not found"}), 404
    return jsonify(data)
