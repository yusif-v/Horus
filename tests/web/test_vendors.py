"""Coverage for the /vendors exposure dashboard route.

Seeds a couple of vendors with linked CVEs, then exercises the route's
sort / filter / pagination branches. The smoke suite never hit /vendors,
so this is the route's first real test.
"""

from __future__ import annotations

import pytest

from horus.storage import db
from horus.web import app as flask_app


@pytest.fixture(scope="module", autouse=True)
def _seed_db():
    db.initialize()
    with db.connect() as c:
        c.executemany(
            "INSERT OR REPLACE INTO cve"
            " (id, description, cvss_score, cvss_severity, published_at,"
            "  epss_score, kev, reputation_score, confidence,"
            "  first_seen, last_seen)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    "CVE-2026-0001",
                    "acme flaw",
                    9.8,
                    "CRITICAL",
                    "2026-05-01",
                    0.9,
                    1,
                    8.0,
                    "high",
                    "2026-05-01",
                    "2026-05-01",
                ),
                (
                    "CVE-2026-0002",
                    "globex flaw",
                    5.0,
                    "MEDIUM",
                    "2026-05-02",
                    0.1,
                    0,
                    4.0,
                    "low",
                    "2026-05-02",
                    "2026-05-02",
                ),
            ],
        )
        c.executemany(
            "INSERT OR REPLACE INTO product (id, vendor, product, category) VALUES (?, ?, ?, ?)",
            [(901, "acme", "widget", "web"), (902, "globex", "gadget", "os")],
        )
        c.executemany(
            "INSERT OR REPLACE INTO cve_product (cve_id, product_id, versions) VALUES (?, ?, ?)",
            [("CVE-2026-0001", 901, "1.0"), ("CVE-2026-0002", 902, "2.0")],
        )
        c.execute(
            "INSERT INTO team_watchlist"
            " (team, vendor, product, created_by, created_at)"
            " VALUES (?, ?, ?, ?, ?)",
            ("blue", "acme", "widget", None, "2026-05-01"),
        )
        c.commit()


@pytest.fixture()
def auth_client():
    flask_app.config.update(TESTING=True, SECRET_KEY="test-secret")
    with flask_app.test_client() as c:
        c.post(
            "/register",
            data={
                "username": "vendoruser",
                "email": "vendor@example.com",
                "password": "password123",
                "password_confirm": "password123",
            },
            follow_redirects=True,
        )
        c.post(
            "/login",
            data={"username": "vendoruser", "password": "password123"},
            follow_redirects=True,
        )
        yield c


def test_vendors_lists_seeded_vendors(auth_client):
    r = auth_client.get("/vendors")
    assert r.status_code == 200
    assert b"acme" in r.data
    assert b"globex" in r.data


@pytest.mark.parametrize("sort", ["count", "cvss", "epss", "name", "kev", "watchlist"])
def test_vendors_sort_variants(auth_client, sort):
    r = auth_client.get(f"/vendors?sort={sort}")
    assert r.status_code == 200


def test_vendors_invalid_sort_falls_back(auth_client):
    r = auth_client.get("/vendors?sort=bogus&dir=sideways")
    assert r.status_code == 200
    assert b"acme" in r.data


def test_vendors_category_filter(auth_client):
    r = auth_client.get("/vendors?category=web")
    assert r.status_code == 200
    assert b"acme" in r.data
    # globex is in the 'os' category and should be filtered out.
    assert b"globex" not in r.data


def test_vendors_watchlist_only(auth_client):
    r = auth_client.get("/vendors?watchlist=1")
    assert r.status_code == 200
    assert b"acme" in r.data
    assert b"globex" not in r.data


def test_vendors_watchlist_sort_asc(auth_client):
    r = auth_client.get("/vendors?sort=watchlist&dir=asc")
    assert r.status_code == 200


def test_vendors_pagination_page_two(auth_client):
    r = auth_client.get("/vendors?page=2")
    assert r.status_code == 200
