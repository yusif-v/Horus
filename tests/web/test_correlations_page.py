"""Test GET /correlations and /correlations/<id> pages."""

from __future__ import annotations

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
            "username": "corrpageuser",
            "email": "corrpage@example.com",
            "password": "password123",
            "password_confirm": "password123",
        },
        follow_redirects=True,
    )
    client.post(
        "/login",
        data={"username": "corrpageuser", "password": "password123"},
        follow_redirects=True,
    )
    return client


def _seed_cve(conn, cve_id="CVE-2026-2001"):
    conn.execute(
        "INSERT OR IGNORE INTO cve (id, description, published_at, cvss_score, kev, cvss_severity, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            cve_id,
            f"Test CVE {cve_id}",
            "2026-02-01T00:00:00Z",
            8.0,
            0,
            "HIGH",
            "2026-02-01T00:00:00Z",
            "2026-02-01T00:00:00Z",
        ),
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


class TestCorrelationsPage:
    def test_correlations_page_returns_200(self, auth_client):
        r = auth_client.get("/correlations")
        assert r.status_code == 200

    def test_correlations_page_empty(self, auth_client):
        r = auth_client.get("/correlations")
        assert r.status_code == 200
        assert b"Correlation Clusters" in r.data or b"No correlation clusters" in r.data

    def test_correlations_page_with_data(self, auth_client):
        with db.connect() as conn:
            _seed_cve(conn, "CVE-2026-CLUSTER-PAGE-A")
            _seed_cve(conn, "CVE-2026-CLUSTER-PAGE-B")
            _seed_cluster(conn, 77, "test_cluster_label", "CVE-2026-CLUSTER-PAGE-A", 2)
            _seed_cluster_member(conn, 77, "CVE-2026-CLUSTER-PAGE-A", 9.0)
            _seed_cluster_member(conn, 77, "CVE-2026-CLUSTER-PAGE-B", 7.5)
        r = auth_client.get("/correlations")
        assert r.status_code == 200
        assert b"test_cluster_label" in r.data or b"CVE-2026-CLUSTER-PAGE-A" in r.data

    def test_correlations_cluster_detail(self, auth_client):
        with db.connect() as conn:
            _seed_cve(conn, "CVE-2026-DETAIL-A")
            _seed_cve(conn, "CVE-2026-DETAIL-B")
            _seed_cluster(conn, 88, "detail_cluster", "CVE-2026-DETAIL-A", 2)
            _seed_cluster_member(conn, 88, "CVE-2026-DETAIL-A", 8.0)
            _seed_cluster_member(conn, 88, "CVE-2026-DETAIL-B", 6.0)
        r = auth_client.get("/correlations/88")
        assert r.status_code == 200
        assert b"CVE-2026-DETAIL-A" in r.data
        assert b"CVE-2026-DETAIL-B" in r.data

    def test_correlations_cluster_not_found(self, auth_client):
        r = auth_client.get("/correlations/99999")
        assert r.status_code == 200
        assert b"No members found" in r.data or b"Cluster" in r.data

    def test_cve_detail_shows_correlations(self, auth_client):
        with db.connect() as conn:
            _seed_cve(conn, "CVE-2026-DOSSIER-A")
            _seed_cve(conn, "CVE-2026-DOSSIER-B")
            conn.execute(
                "INSERT OR REPLACE INTO cve_correlation (cve_id, related_id, score, reasons, computed_at) VALUES (?, ?, ?, ?, ?)",
                (
                    "CVE-2026-DOSSIER-A",
                    "CVE-2026-DOSSIER-B",
                    7.5,
                    "shared_poc,shared_tag",
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
        r = auth_client.get("/cve/CVE-2026-DOSSIER-A")
        assert r.status_code == 200
        assert b"Correlated vulnerabilities" in r.data
        assert b"CVE-2026-DOSSIER-B" in r.data
