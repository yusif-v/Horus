"""Correlation clusters dashboard — /correlations."""

from __future__ import annotations

from flask import Blueprint, request

from .._render import error_page, page
from ..queries import cluster_members, correlation_clusters
from .auth import READ_ALL, role_required

bp = Blueprint("correlations", __name__)


def _cluster_tags(conn, cluster_id: int, limit: int = 5) -> list[str]:
    """Return the most common attack tags among cluster members."""
    rows = conn.execute(
        """
        SELECT cat.tag, COUNT(*) AS cnt
        FROM cve_cluster_member cm
        JOIN cve_attack_tag cat ON cat.cve_id = cm.cve_id
        WHERE cm.cluster_id = ?
        GROUP BY cat.tag
        ORDER BY cnt DESC
        LIMIT ?
        """,
        (cluster_id, limit),
    ).fetchall()
    return [r[0] for r in rows]


def _cluster_date_range(conn, cluster_id: int) -> tuple[str | None, str | None]:
    """Return (earliest, latest) publication dates for cluster members."""
    row = conn.execute(
        """
        SELECT MIN(c.published_at), MAX(c.published_at)
        FROM cve_cluster_member cm
        JOIN cve c ON c.id = cm.cve_id
        WHERE cm.cluster_id = ?
        """,
        (cluster_id,),
    ).fetchone()
    return (row[0], row[1]) if row else (None, None)


@bp.route("/correlations")
@role_required(*READ_ALL)
def index():
    try:
        limit = min(int(request.args.get("limit", 50)), 100)
        clusters_raw = correlation_clusters(limit=limit)
    except Exception as e:
        return error_page(f"Database Error: {e}", active="correlations"), 500

    clusters = []
    try:
        from ..queries import db_connect

        with db_connect() as conn:
            for c in clusters_raw:
                cid = c["id"]
                tags = _cluster_tags(conn, cid)
                earliest, latest = _cluster_date_range(conn, cid)
                clusters.append(
                    {
                        "id": cid,
                        "label": c.get("label"),
                        "centroid_cve": c.get("centroid_cve"),
                        "cve_count": c.get("cve_count", 0),
                        "created_at": c.get("created_at"),
                        "tags": tags,
                        "earliest": earliest[:10] if earliest else None,
                        "latest": latest[:10] if latest else None,
                    }
                )
    except Exception:
        clusters = [
            {
                "id": c["id"],
                "label": c.get("label"),
                "centroid_cve": c.get("centroid_cve"),
                "cve_count": c.get("cve_count", 0),
                "created_at": c.get("created_at"),
                "tags": [],
                "earliest": None,
                "latest": None,
            }
            for c in clusters_raw
        ]

    return page(
        "correlations.html",
        title="Correlation Clusters",
        active="correlations",
        clusters=clusters,
    )


@bp.route("/correlations/<int:cluster_id>")
@role_required(*READ_ALL)
def cluster_detail(cluster_id):
    try:
        members = cluster_members(cluster_id)
    except Exception as e:
        return error_page(f"Database Error: {e}", active="correlations"), 500

    return page(
        "correlations.html",
        title=f"Cluster {cluster_id}",
        active="correlations",
        clusters=[],
        viewing_cluster=cluster_id,
        members=members,
    )
