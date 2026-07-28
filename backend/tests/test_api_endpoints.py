# ==============================================================================
# D7 — API-layer integration tests (FastAPI TestClient).
#
# Establishes the safety net the tech-debt register called out as missing for
# api/v1/hunter.py. These tests exercise the real route
# handlers and Pydantic contracts against an ISOLATED, per-test SQLite database
# (dependency-overridden), with all external side effects neutralized:
#   - Gemini AI calls are monkeypatched (no network).
#   - Background fuzzing jobs are monkeypatched to no-ops.
#
# We deliberately construct TestClient WITHOUT a `with` block so the app's real
# lifespan (which would create_all on the production engine) never runs; schema
# setup happens on the throwaway test engine instead.
# ==============================================================================

import os
import sys
import asyncio

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from sqlalchemy.pool import NullPool
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.core.database import Base, get_db


_VALID_RAW_TRAFFIC = (
    "POST /api/v1/user/profile HTTP/1.1\n"
    "Host: target.example.com\n"
    "Cookie: session=abc123\n"
    "Content-Type: application/json\n\n"
    '{"user_id": 1001}'
)

_VALID_PAYLOAD = {
    "phase": 1,
    "type": "BOLA",
    "location": "query_param",
    "target_param": "id",
    "payload_string": "2",
    "expected_match": "HTTP 200",
}

_PARSED_WITH_HOST = {
    "method": "GET",
    "path": "/api/x",
    "query_params": {},
    "headers": {"Host": "good.com"},
    "body": None,
}

_PARSED_NO_HOST = {
    "method": "GET",
    "path": "/api/x",
    "query_params": {},
    "headers": {},
    "body": None,
}


@pytest.fixture
def client(tmp_path, monkeypatch):
    """An isolated TestClient backed by a fresh per-test SQLite file."""
    db_file = tmp_path / "test_api.db"
    # Forward slashes so the URL is valid on Windows paths too.
    test_url = "sqlite+aiosqlite:///" + str(db_file).replace("\\", "/")

    # NullPool: never reuse a connection across event loops (setup loop vs the
    # loop TestClient drives per request) — avoids "future attached to a
    # different loop" errors with aiosqlite.
    test_engine = create_async_engine(
        test_url,
        connect_args={"check_same_thread": False},
        poolclass=NullPool,
    )
    test_sessionmaker = async_sessionmaker(
        bind=test_engine, class_=AsyncSession, expire_on_commit=False
    )

    async def _create_schema():
        async with test_engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    asyncio.run(_create_schema())

    async def _override_get_db():
        async with test_sessionmaker() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise
            finally:
                await session.close()

    app.dependency_overrides[get_db] = _override_get_db

    async def _noop(*args, **kwargs):
        return None

    # Neutralize all real side effects triggered by background tasks.
    monkeypatch.setattr("backend.app.api.v1.hunter.execute_differential_fuzzing", _noop)

    test_client = TestClient(app)
    try:
        yield test_client
    finally:
        app.dependency_overrides.clear()
        asyncio.run(test_engine.dispose())


# -----------------------------------------------------------------------------
# Diagnostics
# -----------------------------------------------------------------------------

def test_root_health_check(client):
    resp = client.get("/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "online"
    assert "version" in body


# -----------------------------------------------------------------------------
# Hunter · analyze (Gemini mocked)
# -----------------------------------------------------------------------------

def test_analyze_success_with_mocked_gemini(client, monkeypatch):
    async def _fake_hunt(parsed_data, auth_context_b=None):
        return {
            "report_markdown": "## 测试报告",
            "automation_payloads": [_VALID_PAYLOAD],
        }

    monkeypatch.setattr(
        "backend.app.api.v1.hunter._invoke_gemini_logic_hunt", _fake_hunt
    )

    resp = client.post(
        "/api/v1/hunter/analyze",
        json={"raw_traffic": _VALID_RAW_TRAFFIC},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "success"
    assert body["parsed_data"]["method"] == "POST"
    assert len(body["automation_payloads"]) == 1
    assert body["automation_payloads"][0]["type"] == "BOLA"


def test_analyze_rejects_too_short_traffic(client):
    # raw_traffic has min_length=10 → Pydantic 422 before any handler logic.
    resp = client.post("/api/v1/hunter/analyze", json={"raw_traffic": "hi"})
    assert resp.status_code == 422


# -----------------------------------------------------------------------------
# Hunter · findings (persist) + verify
# -----------------------------------------------------------------------------

def test_persist_finding_then_verifiable(client):
    resp = client.post(
        "/api/v1/hunter/findings",
        json={
            "parsed_data": _PARSED_WITH_HOST,
            "automation_payloads": [_VALID_PAYLOAD],
            "target_url": "https://good.com",
        },
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["status"] == "success"
    finding_id = body["finding_id"]
    assert isinstance(finding_id, int)

    # The row must be queryable: triggering verification proves persistence
    # (the background fuzzing job itself is a no-op here).
    verify = client.post(f"/api/v1/hunter/verify/{finding_id}")
    assert verify.status_code == 202
    assert verify.json()["finding_id"] == finding_id


def test_persist_finding_requires_payloads(client):
    # automation_payloads has min_length=1 → 422.
    resp = client.post(
        "/api/v1/hunter/findings",
        json={
            "parsed_data": _PARSED_WITH_HOST,
            "automation_payloads": [],
            "target_url": "https://good.com",
        },
    )
    assert resp.status_code == 422


def test_persist_finding_unresolvable_host_returns_422(client):
    # No target_url and no Host header → base URL cannot be derived → 422.
    resp = client.post(
        "/api/v1/hunter/findings",
        json={
            "parsed_data": _PARSED_NO_HOST,
            "automation_payloads": [_VALID_PAYLOAD],
        },
    )
    assert resp.status_code == 422


def test_verify_unknown_finding_returns_404(client):
    resp = client.post("/api/v1/hunter/verify/999999")
    assert resp.status_code == 404


def test_batch_verify_unknown_finding_returns_404(client):
    resp = client.post(
        "/api/v1/hunter/verify/batch",
        json={"finding_ids": [999999]},
    )
    assert resp.status_code == 404
