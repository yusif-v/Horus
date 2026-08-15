"""Test isolation for news-feed tests.

The session shares a single temp DB (conftest.py sets one STATE_DIR for
the whole run) and news_article.url is UNIQUE. Seed-based tests use the
same default url, so wipe the news tables before AND after each test to
avoid cross-test and cross-file collisions.
"""

from __future__ import annotations

import pytest

from horus.storage import db


@pytest.fixture(autouse=True)
def _clean_news_tables():
    db.initialize()
    with db.connect() as conn:
        conn.execute("DELETE FROM news_post")
        conn.execute("DELETE FROM news_article")
    yield
    with db.connect() as conn:
        conn.execute("DELETE FROM news_post")
        conn.execute("DELETE FROM news_article")
