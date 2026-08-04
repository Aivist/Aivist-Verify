# ==============================================================================
# Broken-for-all disclosure (opt-in `assert_owner_only`) — offline engine fixtures.
#
# GOAL: surface a broken-for-all authorization gap (every authenticated principal can read an
# owner-scoped resource; anonymous cannot) as a LOCKED-inconclusive conditional finding, WITHOUT
# ever emitting verified/confirmed. Drives the REAL execute_deep_verification with the socket and
# the model stubbed; ground truth = the canned responses each fixture defines. The model is pinned
# to 'verified' so only CODE can hold the line.
# ==============================================================================
import json
import asyncio

import pytest

pytest.importorskip("google.genai")

import backend.app.services.deep_verifier as dv
from backend.tests._llmstub import as_provider
from backend.app.core.config import settings
from backend.app.services.deep_verifier import (
    OwnerCredential, BROKEN_FOR_ALL_ASSERTION_REASON, PUBLIC_RESOURCE_NOT_BOLA_REASON,
)

ATTACKER, OWNER, BYSTANDER = "Bearer alice", "Bearer bob", "Bearer carol"
# Every AUTHENTICATED principal receives THIS (the owner's object) -> D30 would suppress.
OWNER_DATA = json.dumps({"order": {"id": 11, "user": {"email": "owner@example.com"}, "secret": "OWNER-CANARY"}})


@pytest.fixture(autouse=True)
def _enable(monkeypatch):
    monkeypatch.setattr(settings, "AI_DEEP_VERIFY_ENABLED", True, raising=False)
    monkeypatch.setattr(settings, "GEMINI_API_KEY", "test-dummy-key", raising=False)


def _resp(status, body):
    return {"status_code": status, "content_length": len(body or ""),
            "response_body": body, "elapsed_ms": 1.0, "url": "http://testserver/x"}


def _always_verified():
    class _R:
        def __init__(self, t): self.text = t
    async def _gen(*a, **k):
        return _R(json.dumps({"decision": "verdict", "next_request": None, "verdict": "verified",
                              "confidence": 1.0, "evidence_path": "order.id", "reasoning": "stub"}))
    return _gen


def _identity(req):
    auth = ""
    for k, v in (req.get("headers") or {}).items():
        if k.lower() == "authorization":
            auth = v
    if "bob" in auth:
        return "owner"
    if "carol" in auth:
        return "bystander"
    if "alice" in auth:
        return "attacker"
    return "anon"                       # no principal-auth header -> the anonymous probe


def _run(anon, *, assert_owner_only, with_bystander=True, capture=None):
    """Every authenticated principal (attacker/owner/bystander) receives OWNER_DATA (so D30 fires).
    `anon` is what the ANONYMOUS probe receives: (status, body) or ('raise',)."""
    monkeypatch = _run.mp

    async def _fake_send(client, req, base_url, custody=None, scope=None):
        ident = _identity(req)
        if capture is not None:
            capture.append(ident)
        if ident == "anon":
            if anon[0] == "raise":
                raise RuntimeError("anon probe transport failure")
            return _resp(anon[0], anon[1])
        return _resp(200, OWNER_DATA)   # attacker / owner / bystander all read the owner's object

    monkeypatch.setattr(dv, "_send_request", _fake_send, raising=True)
    monkeypatch.setattr(dv, "get_provider", as_provider(_always_verified()))
    parsed = {"method": "GET", "path": "/workshop/api/shop/orders/12", "query_params": {},
              "headers": {}, "body": None}

    async def _go():
        return await dv.execute_deep_verification(
            parsed_request=parsed, payload=None, base_url="http://testserver",
            approved_host="testserver", auth_context={"Authorization": ATTACKER},
            available_endpoints=["GET /workshop/api/shop/orders/12"],
            owner_credential=OwnerCredential.from_config(OWNER),
            bystander_credential=(OwnerCredential.from_config(BYSTANDER) if with_bystander else None),
            assert_owner_only=assert_owner_only,
        )
    return asyncio.run(_go())


@pytest.fixture(autouse=True)
def _bind(monkeypatch):
    _run.mp = monkeypatch
    yield


# (1) genuinely PUBLIC (anonymous corroborates owner data) + assert_owner_only -> SUPPRESSED, no finding
def test_public_resource_misasserted_is_plain_suppressed():
    res = _run((200, OWNER_DATA), assert_owner_only=True)
    assert res.ai_verdict == "inconclusive"
    assert res.guard_override == PUBLIC_RESOURCE_NOT_BOLA_REASON
    assert res.broken_for_all_suspected in (None, False)   # mis-assertion on a truly-public resource is caught


# (2) BROKEN-FOR-ALL (bystander corroborates; anonymous denied) + assert_owner_only -> conditional finding
def test_broken_for_all_is_locked_inconclusive_conditional_finding():
    res = _run((401, '{"message":"unauthorized"}'), assert_owner_only=True)
    assert res.ai_verdict == "inconclusive"                # LOCKED inconclusive
    assert res.ai_verdict != "verified"
    assert res.guard_override == BROKEN_FOR_ALL_ASSERTION_REASON
    assert res.broken_for_all_suspected is True
    assert res.owner_view_corroborated is False            # never promotable


# (3) shared-by-design, assert_owner_only NOT set -> suppressed exactly as today
def test_default_path_no_assertion_is_plain_d30_suppress():
    cap = []
    res = _run((401, "unauthorized"), assert_owner_only=False, capture=cap)
    assert res.ai_verdict == "inconclusive"
    assert res.guard_override == PUBLIC_RESOURCE_NOT_BOLA_REASON
    assert res.broken_for_all_suspected is None
    assert "anon" not in cap                               # (4) the anonymous probe is NOT even issued


# (5) ambiguous anonymous probe (timeout / 5xx / empty) + assert_owner_only -> PLAIN suppress, no finding
@pytest.mark.parametrize("anon,label", [
    (("raise",), "transport error / timeout"),
    ((500, "internal server error"), "5xx server error"),
    ((200, ""), "empty body"),
    ((200, "   "), "whitespace-only body"),
])
def test_ambiguous_anonymous_probe_is_plain_suppress(anon, label):
    res = _run(anon, assert_owner_only=True)
    assert res.ai_verdict == "inconclusive"
    assert res.guard_override == PUBLIC_RESOURCE_NOT_BOLA_REASON, label
    assert res.broken_for_all_suspected is None, label     # no finding without deterministic evidence


# (6) downgrade-only: this path NEVER yields verified under ANY input
@pytest.mark.parametrize("anon,assert_oo", [
    ((200, OWNER_DATA), True), ((401, "no"), True), ((404, "no"), True),
    ((500, "err"), True), ((200, ""), True), (("raise",), True),
    ((401, "no"), False), ((200, OWNER_DATA), False),
])
def test_broken_for_all_path_is_downgrade_only(anon, assert_oo):
    res = _run(anon, assert_owner_only=assert_oo)
    assert res.ai_verdict != "verified"
    assert res.ai_verdict == "inconclusive"


def test_anonymous_probe_is_unauthenticated_and_get_only():
    # The anonymous probe must carry NO principal-auth header (stripped) and be a GET.
    seen = {}
    async def _fake_send(client, req, base_url, custody=None, scope=None):
        if _identity(req) == "anon":
            seen["headers"] = dict(req.get("headers") or {})
            seen["method"] = req.get("method")
            seen["custody"] = custody
            return _resp(401, '{"message":"unauthorized"}')
        return _resp(200, OWNER_DATA)
    _run.mp.setattr(dv, "_send_request", _fake_send, raising=True)
    _run.mp.setattr(dv, "get_provider", as_provider(_always_verified()))
    parsed = {"method": "GET", "path": "/workshop/api/shop/orders/12", "query_params": {},
              "headers": {}, "body": None}
    asyncio.run(dv.execute_deep_verification(
        parsed_request=parsed, payload=None, base_url="http://testserver", approved_host="testserver",
        auth_context={"Authorization": ATTACKER},
        available_endpoints=["GET /workshop/api/shop/orders/12"],
        owner_credential=OwnerCredential.from_config(OWNER),
        bystander_credential=OwnerCredential.from_config(BYSTANDER), assert_owner_only=True))
    assert seen["method"] == "GET"
    assert seen["custody"] is None
    assert not any(k.lower() == "authorization" for k in seen["headers"])   # no auth token
