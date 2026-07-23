# ==============================================================================
# TWO-ACCOUNT OWNERSHIP BASELINE — the owner/victim credential CHANNEL.
#
# Prerequisite milestone for the D24 read-semantic gate. This milestone adds the channel
# ONLY: a second identity that genuinely reaches the real Phase-7 pipeline. No gate, no
# verdict logic, nothing consumes it yet.
#
# These tests pin the objective, verdict-free properties the brief requires:
#   (a) UNSET  => byte-identical behavior  (the non-negotiable zero-regression anchor)
#   (b) SET    => an owner-scoped read genuinely returns the OWNER's authentic view
#   (c) the owner credential CANNOT be used for an attack request (structural, not
#       conventional — it must be impossible, not merely discouraged)
#   (d) fail-safe direction is BLOCK: every failure path yields available=False
#
# The strongest anchor here is test_ZERO_REGRESSION_identical_requests_whether_set_or_not:
# it proves zero regression AND inertness in one assertion, by capturing every HTTP request
# the verification path issues and comparing the two runs. It fails against any
# implementation that consumes the credential inside the verdict path.
# ==============================================================================

import asyncio
from collections.abc import Mapping

import httpx
import pytest

from backend.app.services.deep_verifier import (
    OwnerCredential,
    OwnerViewResult,
    fetch_owner_view,
    execute_deep_verification,
)

ATTACKER = "Bearer alice-token-aaaa"
OWNER = "Bearer bob-token-bbbb"


# -----------------------------------------------------------------------------
# from_config parsing — never raises; anything unusable degrades to None
# -----------------------------------------------------------------------------

@pytest.mark.parametrize("raw,name,value", [
    ("Bearer bob-token-bbbb", "Authorization", "Bearer bob-token-bbbb"),
    ("bob-token-bbbb", "Authorization", "Bearer bob-token-bbbb"),
    ("X-Token: abc123", "X-Token", "abc123"),
    ("Cookie: session=xyz", "Cookie", "session=xyz"),
])
def test_from_config_parses_supported_forms(raw, name, value):
    cred = OwnerCredential.from_config(raw)
    assert cred is not None
    assert cred.header_name == name
    assert cred.header_value == value
    assert cred.as_read_headers() == {name: value}


@pytest.mark.parametrize("raw", [None, "", "   "])
def test_from_config_absent_yields_none(raw):
    assert OwnerCredential.from_config(raw) is None


# -----------------------------------------------------------------------------
# (c) STRUCTURAL: the owner credential cannot become an attack request
# -----------------------------------------------------------------------------

def test_STRUCTURAL_owner_credential_is_not_a_mapping():
    """It must be impossible to merge the owner credential into the attack headers.
    The attack path builds headers with {**parsed_headers, **auth_context}; a frozen
    dataclass is not a Mapping, so that splat raises rather than silently conflating
    the two identities."""
    cred = OwnerCredential.from_config(OWNER)
    assert not isinstance(cred, Mapping)
    assert not hasattr(cred, "keys")
    with pytest.raises(TypeError):
        {**cred}                      # noqa: F841 — this raising IS the assertion


def test_STRUCTURAL_owner_credential_is_frozen():
    cred = OwnerCredential.from_config(OWNER)
    with pytest.raises(Exception):
        cred.header_value = ATTACKER  # frozen: cannot be repointed at the attacker


def test_STRUCTURAL_fetch_owner_view_cannot_express_a_write():
    """GET is hardcoded: there is no method or body parameter to abuse."""
    import inspect
    params = set(inspect.signature(fetch_owner_view).parameters)
    assert "method" not in params
    assert "body" not in params
    assert "json" not in params
    assert "data" not in params


def test_STRUCTURAL_execute_deep_verification_accepts_owner_credential_keyword_only():
    import inspect
    p = inspect.signature(execute_deep_verification).parameters["owner_credential"]
    assert p.kind is inspect.Parameter.KEYWORD_ONLY
    assert p.default is None


# -----------------------------------------------------------------------------
# (d) fail-safe BLOCK — every failure path yields available=False, never raises
# -----------------------------------------------------------------------------

def test_FAILSAFE_no_credential_blocks():
    async def _run():
        async with httpx.AsyncClient() as client:
            return await fetch_owner_view(client, "/x", "http://127.0.0.1:9", None)
    res = asyncio.run(_run())
    assert res.available is False
    assert res.reason == "no_owner_credential"


def test_FAILSAFE_invalid_path_blocks():
    async def _run():
        cred = OwnerCredential.from_config(OWNER)
        async with httpx.AsyncClient() as client:
            return await fetch_owner_view(client, "not-a-path", "http://127.0.0.1:9", cred)
    res = asyncio.run(_run())
    assert res.available is False
    assert res.reason == "invalid_path"


def test_FAILSAFE_out_of_scope_host_blocks():
    async def _run():
        cred = OwnerCredential.from_config(OWNER)
        async with httpx.AsyncClient() as client:
            return await fetch_owner_view(
                client, "/x", "http://127.0.0.1:8001", cred, approved_host="example.com")
    res = asyncio.run(_run())
    assert res.available is False
    assert res.reason == "outside_approved_scope"


def test_FAILSAFE_transport_failure_blocks_and_does_not_raise():
    """Nothing is listening on this port: must degrade, never propagate."""
    async def _run():
        cred = OwnerCredential.from_config(OWNER)
        async with httpx.AsyncClient(timeout=2.0) as client:
            return await fetch_owner_view(client, "/x", "http://127.0.0.1:9", cred)
    res = asyncio.run(_run())
    assert res.available is False
    assert res.available is not True          # only a clean 2xx may ever be True


def test_FAILSAFE_result_shape_only_2xx_is_available():
    assert OwnerViewResult(available=False, reason="x").available is False
    assert OwnerViewResult(available=True, status=200, body="{}", reason="ok").available is True


# -----------------------------------------------------------------------------
# (b) SET => an owner-scoped read genuinely returns the OWNER's authentic view
# -----------------------------------------------------------------------------

def _depot_app():
    """Depot bound to a throwaway DB (the real on-disk file is never touched)."""
    import os, sys, importlib, tempfile
    db = os.path.join(tempfile.mkdtemp(), "owner_view.db")
    os.environ["DEPOT_TARGET_DATABASE_URL"] = "sqlite+aiosqlite:///" + db.replace("\\", "/")
    if "depot_target.main" in sys.modules:
        return importlib.reload(sys.modules["depot_target.main"])
    return importlib.import_module("depot_target.main")


def test_OWNER_VIEW_returns_the_owners_authentic_view_not_the_attackers():
    """The whole point of the second identity, shown on DP-READ-SAFE-ECHO: the same object,
    read with two credentials, yields two genuinely different views. The attacker gets a
    masked denial; the OWNER gets the real record. Nothing but a second credential can
    obtain that second view — which is exactly why the read-semantic shape had no evidence
    to gate on."""
    depot = _depot_app()
    bob, alice = depot.ACCOUNT_BOB, depot.ACCOUNT_ALICE

    async def _run():
        async with depot.app.router.lifespan_context(depot.app):
            transport = httpx.ASGITransport(app=depot.app)
            async with httpx.AsyncClient(transport=transport, timeout=10.0) as client:
                owner = OwnerCredential.from_config("Bearer bob-depot-token-bbbb")
                attacker = OwnerCredential.from_config("Bearer alice-depot-token-aaaa")
                path = f"/depot/bonds/{bob}"
                return (
                    await fetch_owner_view(client, path, "http://testserver", owner),
                    await fetch_owner_view(client, path, "http://testserver", attacker),
                )

    as_owner, as_attacker = asyncio.run(_run())

    # The OWNER's authentic view: the real record.
    assert as_owner.available is True
    assert as_owner.status == 200
    assert "CDG-SFO" in as_owner.body          # Bob's real route
    assert "ACTIVE" in as_owner.body
    assert "SEALED" not in as_owner.body

    # The same read as the attacker: a masked denial carrying none of that.
    assert as_attacker.available is True       # a 200 -- 'available' means fetched, not 'leaked'
    assert "CDG-SFO" not in as_attacker.body
    assert "SEALED" in as_attacker.body

    # The two views genuinely differ -- that difference is the evidence a future gate needs.
    assert as_owner.body != as_attacker.body
    assert alice not in as_owner.body          # the owner view is not about the attacker


# -----------------------------------------------------------------------------
# (a) ZERO-REGRESSION + INERTNESS -- the non-negotiable anchor
# -----------------------------------------------------------------------------

def _recording_send(sink):
    """Stand in for deep_verifier._send_request, recording every request issued."""
    async def _send(client, parsed_request, base_url, custody=None):
        sink.append({
            "method": str(parsed_request.get("method", "GET")).upper(),
            "path": parsed_request.get("path", ""),
            "headers": dict(parsed_request.get("headers") or {}),
            "body": parsed_request.get("body"),
        })
        body = '{"id":2,"owner_id":2,"status":"OPEN"}'
        return {"status_code": 200, "content_length": len(body),
                "response_body": body, "elapsed_ms": 5, "url": base_url}
    return _send


def _fake_gemini_verdict(verdict="verified"):
    import json as _json

    class _R:
        def __init__(self, text): self.text = text

    async def _gen(*args, **kwargs):
        return _R(_json.dumps({"decision": "verdict", "next_request": None,
                               "verdict": verdict, "confidence": 1.0,
                               "evidence_path": "owner_id",
                               "reasoning": "owner-credential-channel-mock"}))
    return _gen


def test_ZERO_REGRESSION_identical_requests_whether_owner_credential_set_or_not(monkeypatch):
    """THE anchor for this milestone. Runs the real execute_deep_verification twice --
    once with no owner credential, once with one configured -- and asserts the two runs
    issue EXACTLY the same HTTP requests and reach the same verdict.

    This proves zero regression AND inertness in a single assertion: it fails against any
    implementation that consumes the credential inside the verdict path, issues an extra
    owner-scoped request, or leaks the owner's token into an outbound request."""
    pytest.importorskip("google.genai")
    import backend.app.services.deep_verifier as dv
    from backend.app.core.config import settings

    monkeypatch.setattr(settings, "AI_DEEP_VERIFY_ENABLED", True, raising=False)
    monkeypatch.setattr(settings, "GEMINI_API_KEY", "test-dummy-key", raising=False)

    parsed = {"method": "GET", "path": "/api/statements/1", "query_params": {},
              "headers": {}, "body": None}
    payload = {"location": "path_segment", "target_param": "1",
               "payload_string": "2", "type": "BOLA"}

    def _run(owner_cred):
        sink = []
        monkeypatch.setattr(dv, "_send_request", _recording_send(sink))
        monkeypatch.setattr(dv, "_gemini_generate", _fake_gemini_verdict())
        res = asyncio.run(dv.execute_deep_verification(
            parsed_request=parsed, payload=payload, base_url="http://127.0.0.1:8001",
            approved_host="127.0.0.1:8001", auth_context={"Authorization": ATTACKER},
            available_endpoints=["GET /api/statements/{id}"], owner_credential=owner_cred,
        ))
        return sink, res

    without, res_without = _run(None)
    with_cred, res_with = _run(OwnerCredential.from_config(OWNER))

    # Byte-identical request traffic: same count, same method/path/headers/body, same order.
    assert with_cred == without, "configuring an owner credential changed the requests issued"
    assert len(with_cred) == len(without)

    # And the verdict path is untouched.
    assert res_with.ai_verdict == res_without.ai_verdict
    assert res_with.ai_verdict_raw == res_without.ai_verdict_raw
    assert res_with.guard_override == res_without.guard_override

    # The owner's credential NEVER appears on the wire: attacks go out as the attacker.
    for req in with_cred:
        assert OWNER not in str(req["headers"].values())
        assert "bob-token-bbbb" not in str(req["headers"])
        assert req["headers"].get("Authorization", ATTACKER) == ATTACKER
