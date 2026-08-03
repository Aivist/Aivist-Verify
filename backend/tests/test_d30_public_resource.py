# ==============================================================================
# D30 — PUBLIC-RESOURCE DISCRIMINATION (the dangerous-direction false positive).
#
# The D24 owner-view gate confirms a read-semantic cross-user read when the attacker's
# response matches the owner's authentic view. On a PUBLIC / shared resource both identities
# legitimately receive the SAME bytes, so the gate corroborates for a benign reason and reports
# a FALSE POSITIVE (observed on crAPI's public community post). The D30 fix probes the SAME
# resource as a THIRD (bystander) identity with no ownership: if that identity ALSO receives it
# (2xx + corroborating content), the resource is public -> the read is NOT a BOLA -> SUPPRESS.
#
# These tests exercise the REAL code: only the model call and the network socket (_send_request)
# are stubbed. `fetch_control_view`, `_resource_is_public`, `_owner_view_corroborates`, the D24
# branch, and the scope check all run for real. INDEPENDENT GROUND TRUTH = the canned owner /
# bystander responses each scenario defines (a faithful public resource vs a faithful private
# BOLA vs an ambiguous/soft-deny probe) — never the function's own output.
#
# THE NON-NEGOTIABLES PROVEN HERE:
#   * known-public  -> SUPPRESSED (verified -> inconclusive)
#   * known-private -> STILL CONFIRMED (verified stands)
#   * ANY ambiguity (probe errors / non-2xx / empty / decoy / different body) -> FAILS SAFE to
#     private -> STILL CONFIRMED  (uncertainty == private; no ambiguous probe ever suppresses)
#   * DOWNGRADE-ONLY: the probe can only turn verified -> inconclusive, never manufacture verified
#   * custody-free / GET-only / scope-locked probe; no bystander configured -> byte-identical
# ==============================================================================

import json
import asyncio

import httpx
import pytest

pytest.importorskip("google.genai")

import backend.app.services.deep_verifier as dv
from backend.tests._llmstub import as_provider
from backend.app.core.config import settings
from backend.app.services.deep_verifier import (
    OwnerCredential,
    OwnerViewResult,
    fetch_control_view,
    _resource_is_public,
    PUBLIC_RESOURCE_NOT_BOLA_REASON,
    OWNER_VIEW_NOT_CORROBORATED_REASON,
)

# The victim's authentic object. In the CONFIRM setup the attacker's response is byte-identical
# (a genuine leak, as the pinned model claims), so the owner-view gate corroborates and — absent
# D30 — would stand `verified`. What separates public from private is ONLY what a THIRD identity
# with no ownership receives.
OWNER_BODY = json.dumps({
    "account_id": 7, "problem_details": "hydraulic press seized on unit 7",
    "vin": "1HGCM82633A004352", "internal_note": "escalate to supervisor",
})
# A different object (e.g. the bystander's OWN unrelated resource, or a denial stub) — must NOT
# corroborate the owner body, so it can never read as "public".
DIFFERENT_BODY = json.dumps({"account_id": 999, "problem_details": "unrelated: tyre rotation"})
DECOY_DENY_BODY = json.dumps({"error": "forbidden", "message": "access denied"})

ATTACKER = "Bearer alice-attacker-aaaa"
OWNER = "Bearer bob-owner-bbbb"
BYSTANDER = "Bearer carol-bystander-cccc"


@pytest.fixture(autouse=True)
def _enable_verifier(monkeypatch):
    monkeypatch.setattr(settings, "AI_DEEP_VERIFY_ENABLED", True, raising=False)
    monkeypatch.setattr(settings, "GEMINI_API_KEY", "test-dummy-key", raising=False)


def _always_verified():
    """Pin the model to a read-semantic `verified` with NO follow-up — reproducing the exact D30
    failure mode, so anything non-verified afterwards was held by CODE."""
    class _R:
        def __init__(self, text): self.text = text

    async def _gen(*a, **k):
        return _R(json.dumps({
            "decision": "verdict", "next_request": None, "verdict": "verified",
            "confidence": 1.0, "evidence_path": "account_id",
            "reasoning": "d30-test-mock: model asserts verified (the cross-user read succeeded)",
        }))
    return _gen


def _resp(status, body):
    return {"status_code": status, "content_length": len(body or ""),
            "response_body": body, "elapsed_ms": 1.0, "url": "http://testserver/x"}


def _identity(req):
    auth = ""
    for k, v in (req.get("headers") or {}).items():
        if k.lower() == "authorization":
            auth = v
    if "alice" in auth:
        return "attacker"
    if "bob" in auth:
        return "owner"
    if "carol" in auth:
        return "bystander"
    return "anon"


def _run(bystander_spec, *, with_bystander=True, attacker_body=OWNER_BODY,
         owner_body=OWNER_BODY, capture=None):
    """Drive the REAL read-semantic branch. `bystander_spec` is what the third identity receives:
      ("ok", body)          -> 200 with body
      ("status", code)      -> that status, empty body
      ("raise",)            -> the probe raises (transport error / timeout class)
    Only the model + the socket are stubbed; the D24 branch + fetch_control_view run for real."""
    monkeypatch = _run.monkeypatch

    async def _fake_send(client, req, base_url, custody=None, scope=None):
        if capture is not None:
            capture.append({"identity": _identity(req), "custody": custody,
                            "headers": dict(req.get("headers") or {}), "method": req.get("method")})
        ident = _identity(req)
        if ident == "owner":
            return _resp(200, owner_body)
        if ident == "bystander":
            kind = bystander_spec[0]
            if kind == "raise":
                raise RuntimeError("bystander probe transport failure")
            if kind == "status":
                return _resp(bystander_spec[1], bystander_spec[2] if len(bystander_spec) > 2 else "")
            return _resp(200, bystander_spec[1])   # ("ok", body)
        return _resp(200, attacker_body)           # attacker: baseline + attack

    monkeypatch.setattr(dv, "_send_request", _fake_send, raising=True)
    monkeypatch.setattr(dv, "get_provider", as_provider(_always_verified()))

    parsed = {"method": "GET", "path": "/community/api/v2/community/posts/abc123",
              "query_params": {}, "headers": {}, "body": None}

    async def _go():
        return await dv.execute_deep_verification(
            parsed_request=parsed,
            payload=None,                                   # read-semantic: baseline == attack
            base_url="http://testserver",
            approved_host="testserver",
            auth_context={"Authorization": ATTACKER},
            available_endpoints=["GET /community/api/v2/community/posts/abc123"],
            owner_credential=OwnerCredential.from_config(OWNER),
            bystander_credential=(OwnerCredential.from_config(BYSTANDER) if with_bystander else None),
        )
    return asyncio.run(_go())


@pytest.fixture(autouse=True)
def _bind_monkeypatch(monkeypatch):
    _run.monkeypatch = monkeypatch
    yield


# =============================================================================
# 1. KNOWN-PUBLIC resource -> SUPPRESSED  (the D30 fix; the crAPI public-post class)
# =============================================================================
def test_known_public_resource_is_suppressed():
    # The bystander (no ownership) ALSO reads the SAME object -> it is public/shared.
    res = _run(("ok", OWNER_BODY))
    assert res.ai_verdict_raw == "verified"                      # the model DID say verified ...
    assert res.ai_verdict == "inconclusive"                      # ... and CODE suppressed it (D30)
    assert res.guard_override == PUBLIC_RESOURCE_NOT_BOLA_REASON
    assert res.resource_is_public is True
    assert res.bystander_view_available is True
    assert res.owner_view_corroborated is False                 # so D19 can never promote it


# =============================================================================
# 2. KNOWN-PRIVATE BOLA -> STILL CONFIRMED  (the thing that already works must not break)
# =============================================================================
def test_known_private_bola_denied_to_bystander_still_confirmed():
    # A distinct third principal is correctly DENIED (403) -> not public -> real leak stands.
    res = _run(("status", 403))
    assert res.ai_verdict == "verified"
    assert res.guard_override != PUBLIC_RESOURCE_NOT_BOLA_REASON
    assert res.guard_override != OWNER_VIEW_NOT_CORROBORATED_REASON   # owner-view DID corroborate
    assert res.resource_is_public is False
    assert res.bystander_view_available is False
    assert res.owner_view_corroborated is True


def test_known_private_bola_bystander_sees_its_own_object_still_confirmed():
    # The bystander gets a 200 but a DIFFERENT object (its own) -> does not corroborate -> private.
    res = _run(("ok", DIFFERENT_BODY))
    assert res.ai_verdict == "verified"
    assert res.resource_is_public is False
    assert res.bystander_view_available is True                  # 2xx, but content does not match
    assert res.owner_view_corroborated is True


# =============================================================================
# 3. AMBIGUOUS / soft-deny -> FAILS SAFE to private -> STILL CONFIRMED
#    (uncertainty == private; NO ambiguous/failed probe may ever suppress a real confirmation)
# =============================================================================
@pytest.mark.parametrize("spec,label", [
    (("raise",),          "transport error / timeout"),
    (("status", 500),     "server error (non-2xx)"),
    (("status", 401),     "auth challenge (non-2xx)"),
    (("status", 404),     "not found (non-2xx)"),
    (("ok", ""),          "empty body"),
    (("ok", DECOY_DENY_BODY), "soft-deny 200 decoy body"),
])
def test_ambiguous_probe_fails_safe_to_private_still_confirmed(spec, label):
    res = _run(spec)
    assert res.ai_verdict == "verified", f"ambiguous probe ({label}) must NOT suppress a real BOLA"
    assert res.guard_override != PUBLIC_RESOURCE_NOT_BOLA_REASON
    assert res.resource_is_public is False
    assert res.owner_view_corroborated is True


# =============================================================================
# 4. Default OFF (no bystander) -> byte-identical to pre-D30 behavior
# =============================================================================
def test_no_bystander_configured_is_byte_identical():
    res = _run(("ok", OWNER_BODY), with_bystander=False)
    assert res.ai_verdict == "verified"                          # the pre-D30 verdict stands
    assert res.guard_override != PUBLIC_RESOURCE_NOT_BOLA_REASON
    assert res.resource_is_public is None                        # the probe never ran
    assert res.bystander_view_available is None


# =============================================================================
# 5. D30 is scoped to would-be CONFIRMATIONS: if the owner-view already blocks, the probe
#    must not even run (and the block reason stays the owner-view one, not the D30 one).
# =============================================================================
def test_probe_does_not_run_when_owner_view_already_blocks():
    # Attacker's response does NOT match the owner's authentic view -> owner-view gate blocks first.
    res = _run(("ok", OWNER_BODY), attacker_body=DIFFERENT_BODY)
    assert res.ai_verdict == "inconclusive"
    assert res.guard_override == OWNER_VIEW_NOT_CORROBORATED_REASON   # NOT the public-resource reason
    assert res.resource_is_public is None                        # D30 sub-block never evaluated
    assert res.bystander_view_available is None


# =============================================================================
# 6. The probe is CUSTODY-FREE and GET-only (the attacker session can never ride it)
# =============================================================================
def test_bystander_probe_is_custody_free_and_get_only():
    cap = []
    _run(("ok", OWNER_BODY), capture=cap)
    bystander_calls = [c for c in cap if c["identity"] == "bystander"]
    assert bystander_calls, "the bystander probe should have been issued"
    for c in bystander_calls:
        assert c["custody"] is None                              # custody deliberately omitted
        assert c["method"] == "GET"                              # GET only, structurally
        # the bystander header is present and is NOT the attacker's
        assert any("carol" in v for v in c["headers"].values())
        assert not any("alice" in v for v in c["headers"].values())


# =============================================================================
# 7. _resource_is_public — pure-predicate property tests (affirmative-certainty only)
# =============================================================================
def test_resource_is_public_true_only_on_available_2xx_plus_corroborating_body():
    # True ONLY when available AND the body corroborates the owner's.
    assert _resource_is_public(OwnerViewResult(available=True, status=200, body=OWNER_BODY), OWNER_BODY) is True


@pytest.mark.parametrize("cv,owner_body,expect", [
    (None,                                                        OWNER_BODY, False),  # no probe
    (OwnerViewResult(available=False, reason="non_2xx:403"),      OWNER_BODY, False),  # denied
    (OwnerViewResult(available=False, reason="transport_error"),  OWNER_BODY, False),  # errored
    (OwnerViewResult(available=True, status=200, body=""),        OWNER_BODY, False),  # empty body
    (OwnerViewResult(available=True, status=200, body=DIFFERENT_BODY), OWNER_BODY, False),  # different
    (OwnerViewResult(available=True, status=200, body=DECOY_DENY_BODY), OWNER_BODY, False),  # decoy
    (OwnerViewResult(available=True, status=200, body=OWNER_BODY), None,       False),  # no owner body
    (OwnerViewResult(available=True, status=200, body=OWNER_BODY), "",         False),  # empty owner
])
def test_resource_is_public_matrix_never_true_on_any_ambiguity(cv, owner_body, expect):
    assert _resource_is_public(cv, owner_body) is expect


def test_resource_is_public_is_a_plain_bool_cannot_manufacture_a_verdict():
    # Structural: the predicate returns a bool, never a verdict string; its only consumer uses it
    # to DOWNGRADE. It can neither create nor strengthen a verdict.
    out = _resource_is_public(OwnerViewResult(available=True, status=200, body=OWNER_BODY), OWNER_BODY)
    assert isinstance(out, bool)
    assert out != "verified"


# =============================================================================
# 8. fetch_control_view — scope-locked fail-closed, and unauthenticated when no credential
# =============================================================================
def test_fetch_control_view_refuses_out_of_scope_before_any_send(monkeypatch):
    # A probe whose host is not the approved host is refused BEFORE the socket opens.
    sent = []
    async def _boom(*a, **k):
        sent.append(1)
        return _resp(200, OWNER_BODY)
    monkeypatch.setattr(dv, "_send_request", _boom, raising=True)

    async def _go():
        async with httpx.AsyncClient() as client:
            return await fetch_control_view(
                client, "/x", "http://evil.example.com",
                OwnerCredential.from_config(BYSTANDER), approved_host="good.example.com",
            )
    res = asyncio.run(_go())
    assert res.available is False
    assert res.reason == "outside_approved_scope"
    assert sent == []                                            # never reached the send


def test_fetch_control_view_unauthenticated_sends_empty_auth_headers(monkeypatch):
    captured = {}
    async def _cap(client, req, base_url, custody=None, scope=None):
        captured["headers"] = dict(req.get("headers") or {})
        captured["custody"] = custody
        captured["method"] = req.get("method")
        return _resp(200, OWNER_BODY)
    monkeypatch.setattr(dv, "_send_request", _cap, raising=True)

    async def _go():
        async with httpx.AsyncClient() as client:
            return await fetch_control_view(client, "/x", "http://testserver", None,
                                            approved_host="testserver")
    res = asyncio.run(_go())
    assert res.available is True
    assert captured["method"] == "GET"
    assert captured["custody"] is None                          # custody-free
    # unauthenticated: no Authorization header injected
    assert not any(k.lower() == "authorization" for k in captured["headers"])
