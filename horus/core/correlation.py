"""CVE correlation engine — structured signals + temporal proximity.

Computes pairwise correlations between CVEs based on shared signals
(PoC URLs, attack tags, CWEs, products) and temporal proximity, then
clusters correlated CVEs using a greedy approach.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import date, datetime, timedelta, timezone
from typing import Any

SIGNALS: dict[str, int] = {
    "shared_poc": 4,
    "shared_tag": 3,
    "shared_cwe": 3,
    "shared_product": 2,
    "temporal_proximity": 1,
    "same_vendor": 1,
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_date(val: str | None) -> date | None:
    if not val:
        return None
    try:
        return date.fromisoformat(val[:10])
    except ValueError:
        return None


def compute_correlations(conn: Any, days: int = 30, threshold: float = 3.0) -> int:
    """Compute pairwise correlations for CVEs published within ``days``.

    Returns the number of correlations found above ``threshold``.
    """
    cutoff = _now_iso()[:10]
    cutoff_d = date.fromisoformat(cutoff)
    window_start = (cutoff_d - timedelta(days=days)).isoformat()

    cves = conn.execute(
        "SELECT id, published_at FROM cve WHERE published_at >= ?",
        (window_start,),
    ).fetchall()

    if len(cves) < 2:
        return 0

    cve_ids = [row[0] for row in cves]
    published_map = {row[0]: row[1] for row in cves}

    tags_map: dict[str, set[str]] = defaultdict(set)
    cwes_map: dict[str, set[str]] = defaultdict(set)
    prods_map: dict[str, set[int]] = defaultdict(set)
    pocs_map: dict[str, set[str]] = defaultdict(set)
    vendors_map: dict[str, set[str]] = defaultdict(set)

    placeholders = ",".join("?" for _ in cve_ids)

    for row in conn.execute(
        f"SELECT cve_id, tag FROM cve_attack_tag WHERE cve_id IN ({placeholders})",
        cve_ids,
    ):
        tags_map[row[0]].add(row[1])

    for row in conn.execute(
        f"SELECT cve_id, cwe_id FROM cve_cwe WHERE cve_id IN ({placeholders})",
        cve_ids,
    ):
        cwes_map[row[0]].add(row[1])

    for row in conn.execute(
        f"SELECT cp.cve_id, p.id, p.vendor FROM cve_product cp "
        f"JOIN product p ON cp.product_id = p.id "
        f"WHERE cp.cve_id IN ({placeholders})",
        cve_ids,
    ):
        prods_map[row[0]].add(row[1])
        vendors_map[row[0]].add(row[2])

    for row in conn.execute(
        f"SELECT cve_id, poc_url FROM poc_cve WHERE cve_id IN ({placeholders})",
        cve_ids,
    ):
        pocs_map[row[0]].add(row[1])

    correlations: list[tuple[str, str, float, str]] = []

    for i in range(len(cve_ids)):
        a = cve_ids[i]
        a_tags = tags_map.get(a, set())
        a_cwes = cwes_map.get(a, set())
        a_prods = prods_map.get(a, set())
        a_pocs = pocs_map.get(a, set())
        a_vendors = vendors_map.get(a, set())
        a_pub = published_map[a]

        for j in range(i + 1, len(cve_ids)):
            b = cve_ids[j]
            b_tags = tags_map.get(b, set())
            b_cwes = cwes_map.get(b, set())
            b_prods = prods_map.get(b, set())
            b_pocs = pocs_map.get(b, set())
            b_vendors = vendors_map.get(b, set())
            b_pub = published_map[b]

            score, reasons = _compute_pair_score(
                a_tags,
                b_tags,
                a_cwes,
                b_cwes,
                a_prods,
                b_prods,
                a_pocs,
                b_pocs,
                a_pub,
                b_pub,
                a_vendors,
                b_vendors,
            )

            if score >= threshold:
                correlations.append((a, b, score, reasons))

    ts = _now_iso()
    conn.execute("DELETE FROM cve_correlation")
    for cve_id, related_id, score, reasons in correlations:
        conn.execute(
            "INSERT OR REPLACE INTO cve_correlation (cve_id, related_id, score, reasons, computed_at)"
            " VALUES (?, ?, ?, ?, ?)",
            (cve_id, related_id, score, reasons, ts),
        )

    return len(correlations)


def _compute_pair_score(
    a_tags: set[str],
    b_tags: set[str],
    a_cwes: set[str],
    b_cwes: set[str],
    a_prods: set[int],
    b_prods: set[int],
    a_pocs: set[str],
    b_pocs: set[str],
    a_published: str | None,
    b_published: str | None,
    a_vendors: set[str],
    b_vendors: set[str],
) -> tuple[float, str]:
    """Compute weighted score + reasons for a pair.

    Returns (score, reasons) where reasons is a comma-separated signal list.
    """
    score = 0.0
    reasons: list[str] = []

    if a_pocs & b_pocs:
        score += SIGNALS["shared_poc"]
        reasons.append("shared_poc")
    if a_tags & b_tags:
        score += SIGNALS["shared_tag"]
        reasons.append("shared_tag")
    if a_cwes & b_cwes:
        score += SIGNALS["shared_cwe"]
        reasons.append("shared_cwe")
    if a_prods & b_prods:
        score += SIGNALS["shared_product"]
        reasons.append("shared_product")

    a_date = _parse_date(a_published)
    b_date = _parse_date(b_published)
    if a_date and b_date:
        diff = abs((a_date - b_date).days)
        if diff <= 30:
            score += SIGNALS["temporal_proximity"]
            reasons.append("temporal_proximity")

    if a_vendors & b_vendors:
        score += SIGNALS["same_vendor"]
        reasons.append("same_vendor")

    return score, ",".join(reasons)


def build_clusters(conn: Any, max_clusters: int = 50) -> int:
    """Build clusters from the correlation graph using greedy assignment.

    Each CVE is assigned to the cluster whose centroid it has the highest
    correlation score with. Returns the number of clusters created.
    """
    rows = conn.execute(
        "SELECT cve_id, related_id, score FROM cve_correlation WHERE score >= 3.0"
        " ORDER BY score DESC",
    ).fetchall()

    if not rows:
        return 0

    adj: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))
    all_cves: set[str] = set()
    for cve_id, related_id, score in rows:
        adj[cve_id][related_id] = score
        adj[related_id][cve_id] = score
        all_cves.add(cve_id)
        all_cves.add(related_id)

    sorted_cves = sorted(all_cves, key=lambda c: sum(adj[c].values()), reverse=True)
    centroids: list[str] = []
    assigned: dict[str, int] = {}

    for cve in sorted_cves:
        if len(centroids) < max_clusters:
            has_centroid = any(adj[cve].get(c, 0.0) >= 3.0 for c in centroids)
            if not has_centroid:
                centroids.append(cve)
                assigned[cve] = len(centroids) - 1
                continue
        best_cluster = -1
        best_score = 0.0
        for ci, centroid in enumerate(centroids):
            s = adj[cve].get(centroid, 0.0)
            if s > best_score:
                best_score = s
                best_cluster = ci
        if best_cluster >= 0 and best_score >= 3.0:
            assigned[cve] = best_cluster

    if not assigned:
        return 0

    ts = _now_iso()
    conn.execute("DELETE FROM cve_cluster_member")
    conn.execute("DELETE FROM cve_cluster")

    cluster_map: dict[int, list[tuple[str, float]]] = defaultdict(list)
    for cve, ci in assigned.items():
        centroid = centroids[ci]
        score = adj[cve].get(centroid, 0.0)
        if cve == centroid:
            score = 0.0
        cluster_map[ci].append((cve, score))

    for ci, members in cluster_map.items():
        centroid = centroids[ci]
        label = f"cluster_{centroid}"
        conn.execute(
            "INSERT INTO cve_cluster (label, centroid_cve, cve_count, created_at)"
            " VALUES (?, ?, ?, ?)",
            (label, centroid, len(members), ts),
        )
        cluster_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        for cve_id, score in members:
            conn.execute(
                "INSERT OR IGNORE INTO cve_cluster_member (cluster_id, cve_id, membership_score)"
                " VALUES (?, ?, ?)",
                (cluster_id, cve_id, score),
            )

    return len(cluster_map)
