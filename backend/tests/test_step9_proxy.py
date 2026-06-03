# ==============================================================================
# Unit Tests — Step 9: Passive Traffic Ingestion Proxy Radar
#
# Covers: unified WriterService serialization, SSE hub fan-out + overflow,
# ingest backpressure, Tier-2 enrichment, ProxyManager state machine + token,
# and the internal-ingest endpoint guards (loopback / token / size / 503).
#
# No real network, subprocess, or DB writes. Async tests wrapped in asyncio.run.
# ==============================================================================

import sys
import os
import json
import asyncio

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from fastapi import HTTPException

from backend.app.core.config import settings
from backend.app.services.proxy_pipeline import (
    WriterService,
    SSEHub,
    ProxyIngestPipeline,
)
from backend.app.services.proxy_manager import ProxyManager
import backend.app.api.v1.hunter as hunter


# =============================================================================
# Test doubles
# =============================================================================
class FakeWriter:
    def __init__(self):
        self.jobs = []

    async def submit(self, job):
        self.jobs.append(job)


class FakeSession:
    def __init__(self):
        self.added = []

    def add(self, row):
        self.added.append(row)


class _FakeClient:
    def __init__(self, host):
        self.host = host


class FakeRequest:
    def __init__(self, host, headers=None, body=b"{}"):
        self.client = _FakeClient(host)
        self.headers = headers or {}
        self._body = body

    async def body(self):
        return self._body


# =============================================================================
# 1. WriterService — single consumer serializes jobs in submission order
# =============================================================================
def test_writer_service_serializes_jobs():
    async def inner():
        ws = WriterService()
        await ws.start()
        assert ws.is_running
        order = []
        for i in range(15):
            await ws.submit(lambda db, i=i: order.append(i))
        await ws.stop()
        assert ws.is_running is False
        assert order == list(range(15)), f"writer did not serialize jobs in order: {order}"

    asyncio.run(inner())


# =============================================================================
# 2. SSEHub — register/publish/unregister + drop-oldest overflow + capacity
# =============================================================================
def test_sse_hub_fanout_and_overflow():
    async def inner():
        hub = SSEHub()
        q = hub.register()
        assert hub.client_count == 1
        hub.publish({"event": "flow", "data": {"i": 1}})
        assert q.get_nowait()["data"]["i"] == 1
        hub.unregister(q)
        assert hub.client_count == 0

        # Overflow: a full per-client queue drops the OLDEST event (latest-wins).
        small = asyncio.Queue(maxsize=2)
        hub._clients.add(small)
        for i in (1, 2, 3):
            hub.publish({"event": "flow", "data": {"i": i}})
        a = small.get_nowait()["data"]["i"]
        b = small.get_nowait()["data"]["i"]
        assert (a, b) == (2, 3), f"expected oldest dropped, got {(a, b)}"

    asyncio.run(inner())


# =============================================================================
# 3. Ingest pipeline — bounded queue applies backpressure (returns False / drops)
# =============================================================================
def test_ingest_pipeline_backpressure():
    async def inner():
        pipe = ProxyIngestPipeline(FakeWriter(), SSEHub())
        pipe._queue = asyncio.Queue(maxsize=1)  # no processor — test enqueue only
        assert pipe.enqueue({"flow_id": "a"}) is True
        assert pipe.enqueue({"flow_id": "b"}) is False  # full
        assert pipe.dropped_flows == 1

    asyncio.run(inner())


# =============================================================================
# 4. Tier-2 enrichment — scores the flow, flags login, persists + publishes
# =============================================================================
def test_ingest_pipeline_handle_enriches_and_publishes():
    async def inner():
        hub = SSEHub()
        q = hub.register()
        writer = FakeWriter()
        pipe = ProxyIngestPipeline(writer, hub)

        flow = {
            "method": "POST",
            "scheme": "https",
            "host": "api.example.com",
            "port": 443,
            "path": "/api/login",
            "tier1": {"in_scope": True},
            "request": {"headers": {}, "query_params": {}, "body": "username=a&password=b"},
            "response": {"status_code": 200, "headers": {}, "body": "ok"},
        }
        await pipe._handle(flow)

        # Persistence routed through the (single) writer as a deferred job.
        assert len(writer.jobs) == 1
        sess = FakeSession()
        writer.jobs[0](sess)
        row = sess.added[0]
        assert row.exposure_score is not None
        assert row.is_login_candidate is True
        assert row.url == "https://api.example.com/api/login"

        # Live projection fanned out to subscribers.
        ev = q.get_nowait()
        assert ev["event"] == "flow"
        assert ev["data"]["is_login_candidate"] is True
        assert ev["data"]["exposure_score"] is not None

    asyncio.run(inner())


# =============================================================================
# 5. ProxyManager — FAILED when mitmdump missing; token + cert sanity
# =============================================================================
def test_proxy_manager_failed_without_mitmdump():
    async def inner():
        mgr = ProxyManager()
        mgr._resolve_mitmdump = lambda: None  # simulate missing binary
        st = await mgr.start(scope=["example.com"])
        assert st["state"] == "FAILED"
        assert "mitmdump" in (st["message"] or "").lower()

        # Token guard never accepts None / wrong values.
        assert mgr.verify_ingest_token(None) is False
        assert mgr.verify_ingest_token("definitely-not-the-token") is False

        # CA cert path is either an existing Path or None (never crashes).
        cp = ProxyManager.ca_cert_path()
        from pathlib import Path
        assert cp is None or isinstance(cp, Path)

    asyncio.run(inner())


# =============================================================================
# 6. internal-ingest endpoint — loopback + token + size + backpressure guards
# =============================================================================
def test_internal_ingest_guards():
    async def inner():
        mgr = hunter.get_proxy_manager()
        mgr._ingest_token = "tok123"
        pipe = hunter.get_ingest_pipeline()
        pipe._queue = asyncio.Queue(maxsize=1)
        pipe.dropped_flows = 0

        valid_body = json.dumps({
            "flow_id": "a", "host": "x", "method": "GET", "path": "/",
            "request": {}, "response": {},
        }).encode()

        # Non-loopback peer => 404 (fail closed, don't confirm route).
        r = FakeRequest("8.8.8.8", {"X-Ingest-Token": "tok123"}, valid_body)
        try:
            await hunter.proxy_internal_ingest(r)
            assert False, "expected 404 for non-loopback"
        except HTTPException as e:
            assert e.status_code == 404

        # Loopback but wrong token => 404.
        r = FakeRequest("127.0.0.1", {"X-Ingest-Token": "wrong"}, valid_body)
        try:
            await hunter.proxy_internal_ingest(r)
            assert False, "expected 404 for bad token"
        except HTTPException as e:
            assert e.status_code == 404

        # Loopback + good token + valid flow => 202 accepted.
        r = FakeRequest("127.0.0.1", {"X-Ingest-Token": "tok123"}, valid_body)
        res = await hunter.proxy_internal_ingest(r)
        assert res["status"] == "accepted"

        # Queue now full => 503 backpressure.
        r = FakeRequest("127.0.0.1", {"X-Ingest-Token": "tok123"}, valid_body)
        try:
            await hunter.proxy_internal_ingest(r)
            assert False, "expected 503 when queue saturated"
        except HTTPException as e:
            assert e.status_code == 503

        # Oversize body => 413 (checked before enqueue).
        pipe._queue = asyncio.Queue(maxsize=10)
        big = b"x" * (settings.PROXY_INGEST_MAX_BYTES + 1)
        r = FakeRequest("127.0.0.1", {"X-Ingest-Token": "tok123"}, big)
        try:
            await hunter.proxy_internal_ingest(r)
            assert False, "expected 413 for oversize body"
        except HTTPException as e:
            assert e.status_code == 413

        pipe._queue = None  # reset shared singleton

    asyncio.run(inner())


# =============================================================================
# 7. /proxy/cert — 404 when the CA has not been generated yet
# =============================================================================
def test_proxy_cert_404_when_absent():
    async def inner():
        mgr = hunter.get_proxy_manager()
        mgr.ca_cert_path = lambda: None  # force "not generated"
        try:
            await hunter.proxy_cert()
            assert False, "expected 404 when cert absent"
        except HTTPException as e:
            assert e.status_code == 404

    asyncio.run(inner())
