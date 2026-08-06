"""Test GET /api/cve/<id>/sources endpoint."""

from __future__ import annotations

import json

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
            "username": "testuser",
            "email": "test@example.com",
            "password": "password123",
            "password_confirm": "password123",
        },
        follow_redirects=True,
    )
    client.post(
        "/login",
        data={"username": "testuser", "password": "password123"},
        follow_redirects=True,
    )
    return client


def _seed_cve_and_article(conn, cve_id="CVE-2026-1234"):
    conn.execute(
        "INSERT OR IGNORE INTO cve (id, description, published_at, cvss_severity, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?)",
        (
            cve_id,
            "Test CVE",
            "2026-01-01T00:00:00Z",
            "HIGH",
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:00:00Z",
        ),
    )
    cur = conn.execute(
        "INSERT INTO news_article (title, url, source, tier, published_at, first_seen) VALUES (?, ?, ?, ?, ?, ?)",
        (
            "Test Article",
            "https://example.com/1",
            "hacker_news",
            1,
            "2026-01-02T00:00:00Z",
            "2026-01-01T00:00:00Z",
        ),
    )
    article_id = cur.lastrowid
    conn.execute(
        "INSERT INTO news_article_cve (article_id, cve_id, snippet, context, linked_at) VALUES (?, ?, ?, ?, ?)",
        (article_id, cve_id, "snippet text", "context text", "2026-01-01T00:00:00Z"),
    )


def test_cve_sources_endpoint(auth_client):
    with db.connect() as conn:
        _seed_cve_and_article(conn)
    r = auth_client.get("/api/cve/CVE-2026-1234/sources")
    assert r.status_code == 200
    body = json.loads(r.data)
    assert body["cve_id"] == "CVE-2026-1234"
    assert body["total"] == 1
    assert body["limit"] == 10
    assert body["offset"] == 0
    assert len(body["sources"]) == 1
    src = body["sources"][0]
    assert src["title"] == "Test Article"
    assert src["url"] == "https://example.com/1"
    assert src["source"] == "hacker_news"
    assert src["snippet"] == "snippet text"
    assert src["context"] == "context text"


def test_cve_sources_empty(auth_client):
    with db.connect() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO cve (id, description, published_at, cvss_severity, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?)",
            (
                "CVE-2026-9999",
                "No sources",
                "2026-01-01T00:00:00Z",
                "LOW",
                "2026-01-01T00:00:00Z",
                "2026-01-01T00:00:00Z",
            ),
        )
    r = auth_client.get("/api/cve/CVE-2026-9999/sources")
    assert r.status_code == 200
    body = json.loads(r.data)
    assert body["cve_id"] == "CVE-2026-9999"
    assert body["total"] == 0
    assert body["sources"] == []


def test_cve_sources_case_insensitive(auth_client):
    with db.connect() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO cve (id, description, published_at, cvss_severity, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?)",
            (
                "CVE-2026-ABCD",
                "Test",
                "2026-01-01T00:00:00Z",
                "HIGH",
                "2026-01-01T00:00:00Z",
                "2026-01-01T00:00:00Z",
            ),
        )
        cur = conn.execute(
            "INSERT INTO news_article (title, url, source, tier, published_at, first_seen) VALUES (?, ?, ?, ?, ?, ?)",
            (
                "Case Article",
                "https://example.com/case",
                "hacker_news",
                1,
                "2026-01-02T00:00:00Z",
                "2026-01-01T00:00:00Z",
            ),
        )
        conn.execute(
            "INSERT INTO news_article_cve (article_id, cve_id, snippet, context, linked_at) VALUES (?, ?, ?, ?, ?)",
            (cur.lastrowid, "CVE-2026-ABCD", "snip", "ctx", "2026-01-01T00:00:00Z"),
        )
    r = auth_client.get("/api/cve/cve-2026-abcd/sources")
    assert r.status_code == 200
    body = json.loads(r.data)
    assert body["cve_id"] == "CVE-2026-ABCD"
    assert body["total"] == 1


def test_cve_sources_pagination(auth_client):
    with db.connect() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO cve (id, description, published_at, cvss_severity, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?)",
            (
                "CVE-2026-5000",
                "Many sources",
                "2026-01-01T00:00:00Z",
                "HIGH",
                "2026-01-01T00:00:00Z",
                "2026-01-01T00:00:00Z",
            ),
        )
        for i in range(5):
            cur = conn.execute(
                "INSERT INTO news_article (title, url, source, tier, published_at, first_seen) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    f"Article {i}",
                    f"https://example.com/pag/{i}",
                    "cisa",
                    2,
                    f"2026-01-0{i + 1}T00:00:00Z",
                    "2026-01-01T00:00:00Z",
                ),
            )
            conn.execute(
                "INSERT INTO news_article_cve (article_id, cve_id, snippet, context, linked_at) VALUES (?, ?, ?, ?, ?)",
                (cur.lastrowid, "CVE-2026-5000", f"snippet {i}", "ctx", "2026-01-01T00:00:00Z"),
            )
    r = auth_client.get("/api/cve/CVE-2026-5000/sources?limit=2&offset=1")
    assert r.status_code == 200
    body = json.loads(r.data)
    assert body["total"] == 5
    assert body["limit"] == 2
    assert body["offset"] == 1
    assert len(body["sources"]) == 2


def test_cve_sources_limit_clamped(auth_client):
    r = auth_client.get("/api/cve/CVE-2026-1234/sources?limit=999")
    assert r.status_code == 200
    body = json.loads(r.data)
    assert body["limit"] == 50
