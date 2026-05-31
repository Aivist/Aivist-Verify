# ==============================================================================
# Unit Tests — Step 8: Parallel Fuzzing Engine, Single-Writer Consumer,
#                      Shared Auth Custody (single-flight, scope lock, re-auth cap)
#
# These tests avoid any real network or DB. httpx and the DB seam are mocked.
# Async tests are wrapped in asyncio.run() so no pytest-asyncio plugin is required.
# ==============================================================================

import sys
import os
import asyncio

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

import backend.app.services.fuzzer as fz
from backend.app.services.fuzzer import (
    AuthCustodyController,
    _execute_single_fuzz,
    _db_writer_consumer,
    _QUEUE_SENTINEL,
)


# =============================================================================
# Test doubles
# =============================================================================

class FakeResp:
    def __init__(self, status=200, text="ok", headers=None, json_data=None, content=None):
        self.status_code = status
        self.text = text
        self.content = content if content is not None else text.encode()
        self.headers = headers or {}
        self._json = json_data

    def json(self):
        if self._json is None:
            raise ValueError("no json")
        return self._json


def _make_fake_httpx(calls, resp_factory=None, raise_exc=None):
    """Returns a class usable as a drop-in for httpx.AsyncClient."""
    class _FakeClient:
        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def request(self, **kwargs):
            calls["n"] += 1
            # Model real network I/O suspension so the single-flight lock is held
            # across the await (a synchronous return would not yield the loop).
            await asyncio.sleep(0.02)
            if raise_exc is not None:
                raise raise_exc
            return resp_factory() if resp_factory else FakeResp()

    return _FakeClient


class _PatchHttpx:
    """Context manager that swaps fz.httpx.AsyncClient for a fake."""
    def __init__(self, fake_cls):
        self.fake_cls = fake_cls

    def __enter__(self):
        self._orig = fz.httpx.AsyncClient
        fz.httpx.AsyncClient = self.fake_cls
        return self

    def __exit__(self, *a):
        fz.httpx.AsyncClient = self._orig
        return False


def _anchor(url):
    return {"method": "POST", "url": url, "headers": {}, "body": {"u": "x"}}


# =============================================================================
# 1. Single-flight: concurrent triggers fire exactly ONE re-auth
# =============================================================================

def test_single_flight_one_reauth():
    async def _run():
        calls = {"n": 0}
        custody = AuthCustodyController(
            1, auth_refresh_request=_anchor("https://t.com/login"), approved_host="t.com"
        )
        custody.session_valid_event.clear()
        fake = _make_fake_httpx(calls, lambda: FakeResp(headers={"set-cookie": "sid=NEW; Path=/"}))
        with _PatchHttpx(fake):
            # 12 workers all detect auth-death and trigger concurrently
            await asyncio.gather(*[custody._refresh_session_and_resume() for _ in range(12)])
        assert calls["n"] == 1, f"expected exactly ONE re-auth, got {calls['n']}"
        assert custody.session_valid_event.is_set(), "barrier must reopen"
        assert custody.current_active_auth_value == "sid=NEW"
        assert custody.auth_kind == "cookie"

    asyncio.run(_run())


# =============================================================================
# 2. Domain scope lock: refuse to probe a third-party host
# =============================================================================

def test_scope_lock_blocks_thirdparty_reauth():
    async def _run():
        calls = {"n": 0}
        custody = AuthCustodyController(
            1, auth_refresh_request=_anchor("https://evil-stripe.com/login"), approved_host="good.com"
        )
        custody.session_valid_event.clear()
        fake = _make_fake_httpx(calls, lambda: FakeResp())
        with _PatchHttpx(fake):
            await custody._refresh_session_and_resume()
        assert calls["n"] == 0, "must NOT open a socket to an out-of-scope host"
        assert custody.refresh_failed is True
        assert custody.session_valid_event.is_set(), "barrier must dissolve even on scope refusal"

    asyncio.run(_run())


# =============================================================================
# 3. Circuit breaker + cap: repeated failures dissolve the barrier (no hang)
# =============================================================================

def test_reauth_cap_dissolves_barrier():
    async def _run():
        calls = {"n": 0}
        custody = AuthCustodyController(
            1, auth_refresh_request=_anchor("https://t.com/login"),
            approved_host="t.com", max_reauth_cycles=2,
        )
        fake = _make_fake_httpx(calls, raise_exc=RuntimeError("provider 500"))
        with _PatchHttpx(fake):
            # Cycle 1 + 2 actually attempt (3 retries each = 6 HTTP calls total)
            await custody._refresh_session_and_resume()
            assert custody.reauth_count == 1
            assert custody.session_valid_event.is_set()
            await custody._refresh_session_and_resume()
            assert custody.reauth_count == 2
            assert custody.session_valid_event.is_set()
            calls_at_cap = calls["n"]
            # Cycle 3 is over the cap → bail immediately, no new HTTP
            await custody._refresh_session_and_resume()
            assert calls["n"] == calls_at_cap, "capped cycle must not fire more probes"
        assert custody.refresh_failed is True
        assert custody.session_valid_event.is_set(), "gate must stay open so tasks fail fast"

    asyncio.run(_run())


# =============================================================================
# 4. Single-writer consumer drains all results from concurrent producers
# =============================================================================

def test_single_writer_drains_concurrent_producers():
    async def _run():
        persisted = []
        commits = {"n": 0}

        def _fake_persist(db, record_id, finding_id, payload_index, sent, received, status, diff):
            persisted.append((finding_id, payload_index))

        async def _fake_commit(db):
            commits["n"] += 1

        class _DummyDB:
            async def __aenter__(self):
                return self
            async def __aexit__(self, *a):
                return False

        orig = (fz._persist_record, fz._commit_with_retry, fz.async_session_factory)
        fz._persist_record = _fake_persist
        fz._commit_with_retry = _fake_commit
        fz.async_session_factory = lambda: _DummyDB()
        try:
            q: asyncio.Queue = asyncio.Queue()
            writer = asyncio.create_task(_db_writer_consumer(q))

            async def _producer(fid, n):
                for i in range(n):
                    await q.put({
                        "record_id": f"{fid}-{i}", "finding_id": fid, "payload_index": i,
                        "sent_request": "s", "received_response": "r",
                        "verification_status": "failed", "diff_details": {},
                    })

            # Two endpoints producing concurrently (simulates parallel workers)
            await asyncio.gather(_producer(1, 15), _producer(2, 15))
            await q.put(_QUEUE_SENTINEL)
            await asyncio.wait_for(writer, timeout=5)
        finally:
            fz._persist_record, fz._commit_with_retry, fz.async_session_factory = orig

        assert len(persisted) == 30, f"expected all 30 records persisted, got {len(persisted)}"
        assert commits["n"] >= 1

    asyncio.run(_run())


# =============================================================================
# 5. Worker end-to-end: auth-death → ONE re-auth → resume with fresh creds
# =============================================================================

def test_worker_detects_death_then_resumes():
    async def _run():
        refresh_calls = {"n": 0}

        # Passed-in client: 401 first, 200 after re-auth
        class _WorkerClient:
            def __init__(self):
                self.n = 0
            async def request(self, **kwargs):
                self.n += 1
                if self.n == 1:
                    return FakeResp(status=401, text="unauthorized")
                return FakeResp(status=200, text="welcome user data", content=b"welcome user data")

        custody = AuthCustodyController(
            1, auth_refresh_request=_anchor("https://good.com/login"), approved_host="good.com",
        )
        baseline = {"status_code": 200, "content_length": 5, "response_body": "base", "elapsed_ms": 10, "url": "https://good.com/x"}
        q: asyncio.Queue = asyncio.Queue()
        sem = asyncio.Semaphore(1)

        fake_refresh = _make_fake_httpx(refresh_calls, lambda: FakeResp(json_data={"access_token": "JWT9"}))
        with _PatchHttpx(fake_refresh):
            await _execute_single_fuzz(
                result_queue=q,
                client=_WorkerClient(),
                finding_id=1,
                payload_index=0,
                payload_instruction={"type": "BOLA", "location": "query_param", "target_param": "id", "payload_string": "2"},
                parsed_request={"method": "GET", "path": "/x", "query_params": {}, "headers": {}},
                base_url="https://good.com",
                baseline=baseline,
                semaphore=sem,
                custody=custody,
            )

        assert refresh_calls["n"] == 1, "exactly one re-auth should have fired"
        assert custody.current_active_auth_value == "JWT9"
        assert custody.auth_kind == "token"
        item = q.get_nowait()
        # The replayed (200) result was recorded — NOT a reauth_failed record
        assert item["finding_id"] == 1 and item["payload_index"] == 0
        assert item["diff_details"].get("error") != "reauth_failed"

    asyncio.run(_run())
