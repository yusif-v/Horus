"""Test GET /api/cve/<id>/correlations, /api/clusters, /api/clusters/<id> endpoints."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from horus.storage import db
from horus.web import app as flask_app


@pytest.fixture(scope="module", autouse=True)
def _init_db():
    db.initialize()


@pytest.fixture()
def client():
    flask_app.config.update(TESTING=True, SECRET_KEY="test-secret")
    with flask_app.test_client() as c:
        yield c


@pytest.fixture()
def auth_client(client):
    client.post(
        "/register",
        data={
            "username": "corruser",
            "email": "corr@example.com",
            "password": "password123",
            "password_confirm": "password123",
        },
        follow_redirects=True,
    )
    client.post(
        "/login",
        data={"username": "corruser", "password": "password123"},
        follow_redirects=True,
    )
    return client


def _seed_cve(conn, cve_id="CVE-2026-1001"):
    conn.execute(
        "INSERT OR IGNORE INTO cve (id, description, published_at, cvss_score, kev, cvss_severity, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            cve_id,
            f"Test CVE {cve_id}",
            "2026-01-01T00:00:00Z",
            7.5,
            0,
            "HIGH",
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:00:00Z",
        ),
    )


def _seed_correlation(conn, cve_id, related_id, score, reasons):
    conn.execute(
        "INSERT OR REPLACE INTO cve_correlation (cve_id, related_id, score, reasons, computed_at) VALUES (?, ?, ?, ?, ?)",
        (cve_id, related_id, score, reasons, datetime.now(timezone.utc).isoformat()),
    )


def _seed_cluster(conn, cluster_id, label, centroid_cve, cve_count):
    conn.execute(
        "INSERT OR REPLACE INTO cve_cluster (id, label, centroid_cve, cve_count, created_at) VALUES (?, ?, ?, ?, ?)",
        (cluster_id, label, centroid_cve, cve_count, datetime.now(timezone.utc).isoformat()),
    )


def _seed_cluster_member(conn, cluster_id, cve_id, membership_score):
    conn.execute(
        "INSERT OR REPLACE INTO cve_cluster_member (cluster_id, cve_id, membership_score) VALUES (?, ?, ?)",
        (cluster_id, cve_id, membership_score),
    )


class TestCorrelationsEndpoint:
    def test_correlations_empty(self, auth_client):
        with db.connect() as conn:
            _seed_cve(conn, "CVE-2026-EMPTY-CORR")
        r = auth_client.get("/api/cve/CVE-2026-EMPTY-CORR/correlations")
        assert r.status_code == 200
        body = json.loads(r.data)
        assert body["cve_id"] == "CVE-2026-EMPTY-CORR"
        assert body["correlations"] == []

    def test_correlations_with_data(self, auth_client):
        with db.connect() as conn:
            _seed_cve(conn, "CVE-2026-CORR-A")
            _seed_cve(conn, "CVE-2026-CORR-B")
            _seed_correlation(
                conn, "CVE-2026-CORR-A", "CVE-2026-CORR-B", 5.0, "shared_poc,shared_tag"
            )
        r = auth_client.get("/api/cve/CVE-2026-CORR-A/correlations")
        assert r.status_code == 200
        body = json.loads(r.data)
        assert body["cve_id"] == "CVE-2026-CORR-A"
        assert len(body["correlations"]) == 1
        assert body["correlations"][0]["id"] == "CVE-2026-CORR-B"
        assert body["correlations"][0]["score"] == 5.0
        assert "shared_poc" in body["correlations"][0]["reasons"]

    def test_correlations_limit(self, auth_client):
        with db.connect() as conn:
            _seed_cve(conn, "CVE-2026-LIMIT-A")
            _seed_cve(conn, "CVE-2026-LIMIT-B")
            _seed_cve(conn, "CVE-2026-LIMIT-C")
            _seed_correlation(conn, "CVE-2026-LIMIT-A", "CVE-2026-LIMIT-B", 5.0, "shared_poc")
            _seed_correlation(conn, "CVE-2026-LIMIT-A", "CVE-2026-LIMIT-C", 3.0, "shared_tag")
        r = auth_client.get("/api/cve/CVE-2026-LIMIT-A/correlations?limit=1")
        assert r.status_code == 200
        body = json.loads(r.data)
        assert len(body["correlations"]) == 1

    def test_correlations_invalid_limit(self, auth_client):
        r = auth_client.get("/api/cve/CVE-2026-TEST/correlations?limit=invalid")
        assert r.status_code == 500


class TestClustersEndpoint:
    def test_clusters_empty(self, auth_client):
        r = auth_client.get("/api/clusters")
        assert r.status_code == 200
        body = json.loads(r.data)
        assert "clusters" in body

    def test_clusters_with_data(self, auth_client):
        with db.connect() as conn:
            _seed_cluster(conn, 1, "cluster_test", "CVE-2026-CLUSTER-A", 2)
        r = auth_client.get("/api/clusters")
        assert r.status_code == 200
        body = json.loads(r.data)
        assert len(body["clusters"]) >= 1
        cluster = body["clusters"][0]
        assert "id" in cluster
        assert "label" in cluster
        assert "centroid_cve" in cluster
        assert "cve_count" in cluster

    def test_clusters_limit(self, auth_client):
        r = auth_client.get("/api/clusters?limit=5")
        assert r.status_code == 200
        body = json.loads(r.data)
        assert "clusters" in body


class TestClusterDetailEndpoint:
    def test_cluster_detail_not_found(self, auth_client):
        r = auth_client.get("/api/clusters/99999")
        assert r.status_code == 200
        body = json.loads(r.data)
        assert body["cluster_id"] == 99999
        assert body["members"] == []

    def test_cluster_detail_with_members(self, auth_client):
        with db.connect() as conn:
            _seed_cve(conn, "CVE-2026-MEMBER-A")
            _seed_cve(conn, "CVE-2026-MEMBER-B")
            _seed_cluster(conn, 42, "cluster_42", "CVE-2026-MEMBER-A", 2)
            _seed_cluster_member(conn, 42, "CVE-2026-MEMBER-A", 8.5)
            _seed_cluster_member(conn, 42, "CVE-2026-MEMBER-B", 6.0)
        r = auth_client.get("/api/clusters/42")
        assert r.status_code == 200
        body = json.loads(r.data)
        assert body["cluster_id"] == 42
        assert len(body["members"]) == 2
        members = body["members"]
        assert members[0]["id"] == "CVE-2026-MEMBER-A"
        assert members[0]["membership_score"] == 8.5
        assert members[1]["id"] == "CVE-2026-MEMBER-B"
        assert members[1]["membership_score"] == 6.0
