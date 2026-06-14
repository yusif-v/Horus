"""Per-team watchlist tests: team scoping, role gating, CVE matching."""

from __future__ import annotations

import pytest

from horus.storage import db
from horus.web import app as flask_app


@pytest.fixture(autouse=True)
def _reset():
    db.initialize()
    with db.connect() as conn:
        conn.execute("DELETE FROM team_watchlist")
        conn.execute("DELETE FROM user_role")
        conn.execute("DELETE FROM user")
        conn.execute("DELETE FROM cve_product")
        conn.execute("DELETE FROM product")
        conn.execute("DELETE FROM cve")


@pytest.fixture()
def client():
    flask_app.config.update(TESTING=True, SECRET_KEY="test-secret")
    with flask_app.test_client() as c:
        yield c


def _register(client, username):
    return client.post(
        "/register",
        data={
            "username": username,
            "email": f"{username}@example.com",
            "password": "password123",
            "password_confirm": "password123",
        },
        follow_redirects=True,
    )


def _login(client, username):
    return client.post(
        "/login",
        data={"username": username, "password": "password123"},
        follow_redirects=False,
    )


def _seed_admin_and_team_user(client, username, team, *, role="analyst"):
    """First-registered user becomes admin; create a teammate with `team`+`role`."""
    _register(client, "seed_admin")
    _register(client, username)
    with db.connect() as conn:
        conn.execute("UPDATE user SET team = ? WHERE username = ?", (team, username))
        # Replace default 'viewer' role with whatever the test wants.
        conn.execute(
            "DELETE FROM user_role WHERE user_id = (SELECT id FROM user WHERE username = ?)",
            (username,),
        )
        if role:
            conn.execute(
                "INSERT INTO user_role (user_id, role_id) "
                "SELECT u.id, r.id FROM user u, role r "
                "WHERE u.username = ? AND r.name = ?",
                (username, role),
            )
    _login(client, username)


def _add_cve_with_product(cve_id, vendor, product):
    with db.connect() as conn:
        conn.execute(
            "INSERT INTO cve (id, cvss_score, cvss_severity, kev, "
            "published_at, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (cve_id, 7.5, "HIGH", 0, "2026-06-01", "2026-06-01", "2026-06-01"),
        )
        cur = conn.execute(
            "INSERT INTO product (vendor, product, category) VALUES (?, ?, ?)",
            (vendor, product, "application"),
        )
        conn.execute(
            "INSERT INTO cve_product (cve_id, product_id) VALUES (?, ?)",
            (cve_id, cur.lastrowid),
        )


class TestAccessControl:
    def test_anon_redirected(self, client):
        r = client.get("/watchlist/", follow_redirects=False)
        assert r.status_code == 302
        assert "/login" in r.headers["Location"]

    def test_none_team_viewer_denied(self, client):
        # team default 'none' + viewer role
        _register(client, "admin1")
        _register(client, "no_team")
        _login(client, "no_team")
        r = client.get("/watchlist/")
        assert r.status_code == 403

    def test_red_analyst_can_view(self, client):
        _seed_admin_and_team_user(client, "red1", "red", role="analyst")
        r = client.get("/watchlist/")
        assert r.status_code == 200

    def test_blue_viewer_can_view(self, client):
        _seed_admin_and_team_user(client, "blue1", "blue", role="viewer")
        r = client.get("/watchlist/")
        assert r.status_code == 200


class TestAddMutation:
    def test_red_analyst_can_add(self, client):
        _seed_admin_and_team_user(client, "red1", "red", role="analyst")
        r = client.post(
            "/watchlist/add",
            data={"team": "red", "vendor": "acme", "product": "vpn"},
            follow_redirects=True,
        )
        assert r.status_code == 200
        with db.connect() as conn:
            row = conn.execute("SELECT team, vendor, product FROM team_watchlist").fetchone()
        assert tuple(row) == ("red", "acme", "vpn")

    def test_viewer_cannot_add(self, client):
        _seed_admin_and_team_user(client, "red_viewer", "red", role="viewer")
        r = client.post(
            "/watchlist/add",
            data={"team": "red", "vendor": "acme", "product": "vpn"},
        )
        assert r.status_code == 403

    def test_red_cannot_add_to_blue(self, client):
        _seed_admin_and_team_user(client, "red1", "red", role="analyst")
        r = client.post(
            "/watchlist/add",
            data={"team": "blue", "vendor": "acme", "product": "vpn"},
        )
        assert r.status_code == 403

    def test_admin_can_add_to_either_team(self, client):
        _register(client, "admin1")
        _login(client, "admin1")
        r = client.post(
            "/watchlist/add",
            data={"team": "blue", "vendor": "contoso", "product": ""},
            follow_redirects=True,
        )
        assert r.status_code == 200
        with db.connect() as conn:
            row = conn.execute("SELECT team FROM team_watchlist").fetchone()
        assert row[0] == "blue"

    def test_duplicate_add_does_not_double_insert(self, client):
        _seed_admin_and_team_user(client, "red1", "red", role="analyst")
        data = {"team": "red", "vendor": "acme", "product": "vpn"}
        client.post("/watchlist/add", data=data, follow_redirects=True)
        client.post("/watchlist/add", data=data, follow_redirects=True)
        with db.connect() as conn:
            count = conn.execute("SELECT COUNT(*) FROM team_watchlist").fetchone()[0]
        assert count == 1


class TestTeamScoping:
    def test_red_user_only_sees_red_pins(self, client):
        # Admin seeds entries for both teams.
        _register(client, "admin1")
        _login(client, "admin1")
        client.post(
            "/watchlist/add",
            data={"team": "red", "vendor": "acme", "product": "vpn"},
        )
        client.post(
            "/watchlist/add",
            data={"team": "blue", "vendor": "contoso", "product": "office"},
        )
        client.get("/logout")

        # Red analyst logs in — must see only red.
        _register(client, "red1")
        with db.connect() as conn:
            conn.execute("UPDATE user SET team = 'red' WHERE username = 'red1'")
            conn.execute(
                "DELETE FROM user_role WHERE user_id = "
                "(SELECT id FROM user WHERE username = 'red1')"
            )
            conn.execute(
                "INSERT INTO user_role (user_id, role_id) "
                "SELECT u.id, r.id FROM user u, role r "
                "WHERE u.username = 'red1' AND r.name = 'analyst'"
            )
        _login(client, "red1")
        r = client.get("/watchlist/")
        assert b"acme" in r.data
        assert b"contoso" not in r.data


class TestCVEMatching:
    def test_matching_cve_appears_in_list(self, client):
        _add_cve_with_product("CVE-2026-9999", "acme", "vpn")
        _seed_admin_and_team_user(client, "red1", "red", role="analyst")
        client.post(
            "/watchlist/add",
            data={"team": "red", "vendor": "acme", "product": "vpn"},
        )
        r = client.get("/watchlist/")
        assert b"CVE-2026-9999" in r.data

    def test_vendor_only_pin_matches_any_product(self, client):
        _add_cve_with_product("CVE-2026-1111", "acme", "router")
        _add_cve_with_product("CVE-2026-2222", "acme", "vpn")
        _seed_admin_and_team_user(client, "red1", "red", role="analyst")
        client.post(
            "/watchlist/add",
            data={"team": "red", "vendor": "acme", "product": ""},
        )
        r = client.get("/watchlist/")
        assert b"CVE-2026-1111" in r.data
        assert b"CVE-2026-2222" in r.data

    def test_other_team_cves_not_shown(self, client):
        _add_cve_with_product("CVE-2026-3333", "contoso", "office")
        _register(client, "admin1")
        _login(client, "admin1")
        client.post(
            "/watchlist/add",
            data={"team": "blue", "vendor": "contoso", "product": "office"},
        )
        client.get("/logout")
        # Red analyst sees no microsoft CVE because nothing pinned for red.
        _seed_admin_and_team_user(client, "red1", "red", role="analyst")
        r = client.get("/watchlist/")
        assert b"CVE-2026-3333" not in r.data


class TestDelete:
    def test_analyst_deletes_own_team_entry(self, client):
        _seed_admin_and_team_user(client, "red1", "red", role="analyst")
        client.post(
            "/watchlist/add",
            data={"team": "red", "vendor": "acme", "product": "vpn"},
        )
        with db.connect() as conn:
            entry_id = conn.execute("SELECT id FROM team_watchlist").fetchone()[0]
        r = client.post(f"/watchlist/{entry_id}/delete", follow_redirects=True)
        assert r.status_code == 200
        with db.connect() as conn:
            assert conn.execute("SELECT COUNT(*) FROM team_watchlist").fetchone()[0] == 0

    def test_other_team_cannot_delete(self, client):
        _register(client, "admin1")
        _login(client, "admin1")
        client.post(
            "/watchlist/add",
            data={"team": "blue", "vendor": "contoso", "product": "office"},
        )
        with db.connect() as conn:
            entry_id = conn.execute("SELECT id FROM team_watchlist").fetchone()[0]
        client.get("/logout")
        _seed_admin_and_team_user(client, "red1", "red", role="analyst")
        r = client.post(f"/watchlist/{entry_id}/delete")
        assert r.status_code == 403
