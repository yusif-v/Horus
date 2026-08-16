"""Tests for the /posts AI news-feed page."""

from __future__ import annotations

import pytest

from horus.storage import db
from horus.web import app as flask_app


@pytest.fixture(scope="module", autouse=True)
def _seed_db():
    db.initialize()
    with db.connect() as c:
        c.execute(
            "INSERT INTO news_article (title, url, source, tier, summary, first_seen,"
            " ai_score, ai_rationale, ai_headline, ai_summary, scored_at)"
            " VALUES ('Apache RCE', 'http://posts-a.test', 'hacker_news', 1, 's',"
            " '2026-08-01T00:00:00Z', 95, 'exploited', 'RCE Critical', 'Patch now',"
            " '2026-08-15T00:00:00Z')"
        )
        article_id = c.execute(
            "SELECT id FROM news_article WHERE url = 'http://posts-a.test'"
        ).fetchone()[0]
        c.execute(
            "INSERT INTO news_post (article_id, posted_at) VALUES (?, ?)",
            (article_id, "2026-08-15T00:00:00Z"),
        )
        c.commit()


@pytest.fixture()
def auth_client():
    flask_app.config.update(TESTING=True, SECRET_KEY="test-secret")
    with flask_app.test_client() as c:
        c.post(
            "/register",
            data={
                "username": "postuser",
                "email": "post@example.com",
                "password": "password123",
                "password_confirm": "password123",
            },
            follow_redirects=True,
        )
        c.post(
            "/login",
            data={"username": "postuser", "password": "password123"},
            follow_redirects=True,
        )
        yield c


def test_posts_page_renders_seeded_posts(auth_client):
    r = auth_client.get("/posts")
    assert r.status_code == 200
    assert b"RCE Critical" in r.data
    assert b"Apache RCE" in r.data
