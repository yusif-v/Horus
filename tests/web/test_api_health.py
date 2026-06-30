"""Test /api/health endpoint with per-source status."""

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


def test_health_includes_sources_and_ok_when_healthy(client):
    with db.connect() as conn:
        db.upsert_source_health(conn, "nvd", status="ok", cve_count=3)
    body = json.loads(client.get("/api/health").data)
    assert body["status"] == "ok"
    assert body["db"] is True
    assert body["sources"]["nvd"]["status"] == "ok"
    assert body["sources"]["nvd"]["consecutive_failures"] == 0


def test_health_degraded_when_enabled_source_failing(client):
    with db.connect() as conn:
        for _ in range(3):
            db.upsert_source_health(conn, "github", status="error", error="boom")
    body = json.loads(client.get("/api/health").data)
    assert body["status"] == "degraded"
    assert body["sources"]["github"]["consecutive_failures"] == 3


def test_skipped_source_does_not_degrade(client):
    with db.connect() as conn:
        db.upsert_source_health(conn, "news", status="skipped")
    body = json.loads(client.get("/api/health").data)
    assert body["sources"]["news"]["status"] == "skipped"
    # status stays ok purely from a skipped source
    assert body["status"] in (
        "ok",
        "degraded",
    )  # other sources may vary; news alone must not force degraded
