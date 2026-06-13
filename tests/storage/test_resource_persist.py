"""Tests for security resource persistence and queries."""

from __future__ import annotations

import pytest

from horus.core.model import Resource
from horus.storage import db


@pytest.fixture(autouse=True)
def fresh_db(tmp_path, monkeypatch):
    """Each test gets a fresh database."""
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "horus.db")
    db.initialize()
    yield
    # Cleanup: reset DB_PATH to avoid side effects
    db.DB_PATH = db.STATE_DIR / "horus.db"


def _resource(**overrides) -> Resource:
    base = dict(
        url="https://github.com/user/exploit-repo",
        resource_type="exploit",
        source="github",
        title="CVE-2026-0001 RCE Exploit",
        description="A working remote code execution exploit",
        source_url="https://x.com/hacker/status/123",
        source_author="hacker",
        engagement_score=42,
        tags=["rce", "kernel"],
        cve_refs=["CVE-2026-0001"],
        stars=None,
        repo_created_at=None,
    )
    base.update(overrides)
    return Resource(**base)


def _seed_data():
    """Seed test data into the current DB."""
    with db.connect() as conn:
        db.persist_resource(
            conn,
            _resource(
                url="https://github.com/a/1",
                resource_type="exploit",
                source="github",
                engagement_score=100,
                stars=50,
                tags=["rce"],
            ),
        )
        db.persist_resource(
            conn,
            _resource(
                url="https://github.com/b/2",
                resource_type="tool",
                source="github",
                engagement_score=200,
                stars=100,
                tags=["pentest"],
            ),
        )
        db.persist_resource(
            conn,
            _resource(
                url="https://example.com/3",
                resource_type="exploit",
                source="web",
                engagement_score=50,
                stars=None,
                tags=["bypass"],
            ),
        )


class TestPersistResource:
    def test_persist_and_read(self, fresh_db):
        r = _resource()
        with db.connect() as conn:
            db.persist_resource(conn, r)
            row = conn.execute(
                "SELECT url, resource_type, title, source, engagement_score FROM security_resource WHERE url = ?",
                ("https://github.com/user/exploit-repo",),
            ).fetchone()
        assert row[0] == "https://github.com/user/exploit-repo"
        assert row[1] == "exploit"
        assert row[2] == "CVE-2026-0001 RCE Exploit"
        assert row[3] == "github"
        assert row[4] == 42

    def test_persist_is_upsert(self, fresh_db):
        r1 = _resource(engagement_score=10)
        r2 = _resource(engagement_score=50, title="Updated Title")
        with db.connect() as conn:
            db.persist_resource(conn, r1)
            db.persist_resource(conn, r2)
            row = conn.execute(
                "SELECT engagement_score, title FROM security_resource WHERE url = ?",
                ("https://github.com/user/exploit-repo",),
            ).fetchone()
        assert row[0] == 50
        assert row[1] == "Updated Title"

    def test_persist_stores_json_fields(self, fresh_db):
        with db.connect() as conn:
            db.persist_resource(conn, _resource(tags=["rce", "kernel"], cve_refs=["CVE-2026-0001"]))
            row = conn.execute(
                "SELECT tags, cve_refs FROM security_resource WHERE url = ?",
                ("https://github.com/user/exploit-repo",),
            ).fetchone()
        import json

        assert json.loads(row[0]) == ["rce", "kernel"]
        assert json.loads(row[1]) == ["CVE-2026-0001"]

    def test_persist_multiple_resources(self, fresh_db):
        with db.connect() as conn:
            db.persist_resource(
                conn, _resource(url="https://github.com/a/1", resource_type="exploit")
            )
            db.persist_resource(conn, _resource(url="https://github.com/b/2", resource_type="tool"))
            db.persist_resource(
                conn, _resource(url="https://example.com/3", resource_type="advisory")
            )
            count = conn.execute("SELECT COUNT(*) FROM security_resource").fetchone()[0]
        assert count == 3


class TestListKnownResourceUrls:
    def test_empty(self, fresh_db):
        with db.connect() as conn:
            assert db.list_known_resource_urls(conn) == set()

    def test_returns_urls(self, fresh_db):
        with db.connect() as conn:
            db.persist_resource(conn, _resource())
            db.persist_resource(
                conn, _resource(url="https://example.com/other", resource_type="bypass")
            )
            urls = db.list_known_resource_urls(conn)
        assert "https://github.com/user/exploit-repo" in urls
        assert "https://example.com/other" in urls


class TestFetchResources:
    def test_fetch_all(self, fresh_db):
        _seed_data()
        rows, total = db.fetch_resources()
        assert total == 3
        assert len(rows) == 3

    def test_filter_by_type(self, fresh_db):
        _seed_data()
        rows, total = db.fetch_resources(resource_type_filter="exploit")
        assert total == 2
        assert all(r["resource_type"] == "exploit" for r in rows)

    def test_filter_by_source(self, fresh_db):
        _seed_data()
        rows, total = db.fetch_resources(source_filter="github")
        assert total == 2
        assert all(r["source"] == "github" for r in rows)

    def test_filter_by_tag(self, fresh_db):
        _seed_data()
        rows, total = db.fetch_resources(tag_filter="rce")
        assert total == 1
        assert rows[0]["url"] == "https://github.com/a/1"

    def test_sort_by_engagement(self, fresh_db):
        _seed_data()
        rows, _ = db.fetch_resources(sort="engagement")
        scores = [r["engagement_score"] for r in rows]
        assert scores == sorted(scores, reverse=True)

    def test_sort_by_stars(self, fresh_db):
        _seed_data()
        rows, _ = db.fetch_resources(sort="stars")
        assert rows[0]["stars"] is not None

    def test_sort_by_newest(self, fresh_db):
        _seed_data()
        rows, _ = db.fetch_resources(sort="newest")
        assert len(rows) > 0

    def test_pagination(self, fresh_db):
        _seed_data()
        rows, total = db.fetch_resources(page=1, per_page=2)
        assert len(rows) == 2
        assert total == 3
        rows2, _ = db.fetch_resources(page=2, per_page=2)
        assert len(rows2) == 1

    def test_tags_parsed_as_list(self, fresh_db):
        _seed_data()
        rows, _ = db.fetch_resources()
        for r in rows:
            assert isinstance(r["tags"], list)

    def test_cve_ids_parsed_as_list(self, fresh_db):
        _seed_data()
        rows, _ = db.fetch_resources()
        for r in rows:
            assert isinstance(r["cve_ids"], list)

    def test_empty_result(self, fresh_db):
        _seed_data()
        rows, total = db.fetch_resources(resource_type_filter="nonexistent")
        assert total == 0
        assert len(rows) == 0
