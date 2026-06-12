"""JSON API routes — for liveness probes and external consumers."""

from __future__ import annotations

from flask import Blueprint, jsonify

from ..queries import get_cve_detail, get_stats
from .auth import login_required

bp = Blueprint("api", __name__, url_prefix="/api")


@bp.route("/stats")
@login_required
def stats():
    try:
        return jsonify(get_stats())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@bp.route("/cve/<cve_id>")
@login_required
def cve(cve_id):
    try:
        data = get_cve_detail(cve_id)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    if not data:
        return jsonify({"error": "not found"}), 404
    return jsonify(data)
