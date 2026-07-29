# ==============================================================================
# M1.4 — MASS-ASSIGNMENT BOLA. The attacker writes to the VICTIM's object and sneaks in a field
# they must not be able to set (role / is_admin / tier).
#
# WHY THIS SHAPE NEEDS A NEW ANCHOR: the injected value is LOW-ENTROPY. M1.2's payload-causality
# assumes the injected value is effectively UNIQUE, so its mere PRESENCE proves the write landed.
# Here "the field reads admin" cannot distinguish "I set it" from "it was already admin". Decisive
# causality is a STATE JUMP: the field moved FROM a KNOWN pre-flight state TO the injected value.
#
# THE CRITICAL DISTINCTION (this is where the false positive hides):
#   MISSING = absent from a SUCCESSFUL (2xx, parseable) pre-flight  -> a VALID original state;
#             MISSING -> injected is a REAL hidden-field escalation and MUST be able to verify.
#   UNKNOWN = the pre-flight (or post read-back) failed / non-2xx / unparseable -> nothing may be
#             attributed to this attack, ever.
#
# HUMAN-OWNED GROUND TRUTH (implement + measure, do NOT redefine):
#   X-MASS-VULN (present-value jump AND missing->injected) -> verified
#   X-MASS-SAFE (stripped: unchanged, or still-missing)    -> NEVER verified
#   injected == pre-flight / failed pre-flight / failed-or-unparseable post read -> NEVER verified
#
# A `verified` on any SAFE/control shape here = false positive = the moat's core claim broken.
# Fix the gate, not the test. No live model, no network.
# ==============================================================================

import os
import sys
import json
import asyncio

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

import pytest

from backend.app.services.deep_verifier import (
    _apply_cross_resource_guard,
    _anchor_state_jump,
    _is_mass_assignment_payload,
    _anchor_caller_identity,
    _anchor_payload_causality,
    _written_values,
    CROSS_RESOURCE_OVERRIDE_REASON,
    STATE_READBACK_EXEMPTION_REASON,
    STATE_JUMP_EXEMPTION_REASON,
)
from backend.app.services.endpoint_catalog import select_object_state_endpoint

ATTACK_WRITE = "/api/users/2/membership"
STATE_READBACK = "/api/memberships/2"

_PRE_PRESENT = json.dumps({"id": 2, "owner_id": 2, "plan": "basic", "role": "member"})
_PRE_MISSING = json.dumps({"id": 2, "owner_id": 2, "plan": "basic"})          # role hidden (NULL)
_SENT = {"plan": "plan-unique-abc", "role": "admin"}


# =============================================================================
# 1. The state-jump anchor (pure) — the full truth table.
# =============================================================================

def test_jump_from_present_value():
    post = json.dumps({"id": 2, "owner_id": 2, "plan": "plan-unique-abc", "role": "admin"})
    assert _anchor_state_jump(200, _PRE_PRESENT, 200, post, _SENT) == "confirmed_jump"


def test_jump_from_missing_is_valid_causality():
    # MISSING -> injected is a REAL hidden-field escalation; it MUST be able to confirm.
    post = json.dumps({"id": 2, "owner_id": 2, "plan": "plan-unique-abc", "role": "admin"})
    assert _anchor_state_jump(200, _PRE_MISSING, 200, post, _SENT) == "confirmed_jump"


def test_no_jump_when_field_unchanged():
    # SAFE: the legit field landed, the privileged field was STRIPPED -> not all fields moved.
    post = json.dumps({"id": 2, "owner_id": 2, "plan": "plan-unique-abc", "role": "member"})
    assert _anchor_state_jump(200, _PRE_PRESENT, 200, post, _SENT) == "no_jump"


def test_no_jump_when_field_still_missing():
    # SAFE (hidden variant): missing -> still missing is NOT a jump.
    post = json.dumps({"id": 2, "owner_id": 2, "plan": "plan-unique-abc"})
    assert _anchor_state_jump(200, _PRE_MISSING, 200, post, _SENT) == "no_jump"


def test_no_jump_when_injected_equals_preflight_value():
    # THE LOW-ENTROPY TRAP: the field already held the injected value -> indistinguishable.
    sent = {"role": "member"}
    post = json.dumps({"id": 2, "owner_id": 2, "role": "member"})
    assert _anchor_state_jump(200, _PRE_PRESENT, 200, post, sent) == "no_jump"


@pytest.mark.parametrize("pre_status", [None, 500, 404, 403, 302])
def test_failed_or_non_2xx_preflight_is_UNKNOWN_not_missing(pre_status):
    # A failed pre-flight is NOT the MISSING state — the original value is unknown, so nothing
    # can be attributed to this attack even if the post read shows the injected value.
    post = json.dumps({"id": 2, "owner_id": 2, "plan": "plan-unique-abc", "role": "admin"})
    assert _anchor_state_jump(pre_status, None, 200, post, _SENT) == "preflight_unknown"


def test_unparseable_preflight_is_unknown():
    post = json.dumps({"id": 2, "owner_id": 2, "role": "admin"})
    assert _anchor_state_jump(200, "<html>not json</html>", 200, post, _SENT) == "preflight_unknown"


@pytest.mark.parametrize("post_status,post_body", [
    (None, None), (500, "{}"), (404, "{}"), (200, "<html>boom</html>"), (200, None),
])
def test_failed_or_unparseable_post_readback_degrades_no_crash(post_status, post_body):
    # Must degrade to a non-decisive value and NEVER raise.
    assert _anchor_state_jump(200, _PRE_PRESENT, post_status, post_body, _SENT) == "postread_unknown"


def test_no_sent_fields_and_garbage_never_raise():
    assert _anchor_state_jump(200, _PRE_PRESENT, 200, _PRE_PRESENT, None) == "no_sent_fields"
    assert _anchor_state_jump(200, _PRE_PRESENT, 200, _PRE_PRESENT, {}) == "no_sent_fields"
    # Deliberately hostile inputs — the contract is "never raises".
    for bad in (object(), [1, 2], "not-a-dict"):
        assert _anchor_state_jump(200, _PRE_PRESENT, 200, _PRE_PRESENT, bad) in (
            "no_sent_fields", "indeterminate", "no_jump", "confirmed_jump")


def test_type_coercion_on_low_entropy_values():
    # "1"/1 and True/"True" must compare equal so an int/bool flag still reads as a jump.
    assert _anchor_state_jump(
        200, json.dumps({"tier": 0}), 200, json.dumps({"tier": 1}), {"tier": "1"}
    ) == "confirmed_jump"


def test_payload_type_detection_is_generic():
    for t in ("MASS_ASSIGNMENT", "mass-assignment", "MassAssignment", "mass assignment",
              "overposting", "OverPost"):
        assert _is_mass_assignment_payload({"type": t}) is True, t
    for t in ("BOLA", "IDOR", "sqli", None, ""):
        assert _is_mass_assignment_payload({"type": t}) is False, t


# =============================================================================
# 2. Guard — the new mass_assignment channel.
# =============================================================================

def test_mass_exemption_keeps_verified_on_crosspath():
    final, reason = _apply_cross_resource_guard(
        "verified", ATTACK_WRITE, STATE_READBACK, follow_up_performed=True,
        state_jump_decisive=True)
    assert final == "verified"
    assert reason == STATE_JUMP_EXEMPTION_REASON


def test_mass_exemption_off_by_default_downgrades():
    final, reason = _apply_cross_resource_guard(
        "verified", ATTACK_WRITE, STATE_READBACK, follow_up_performed=True)
    assert final == "inconclusive"
    assert reason == CROSS_RESOURCE_OVERRIDE_REASON


def test_mass_exemption_only_verified_not_failed():
    final, reason = _apply_cross_resource_guard(
        "failed", ATTACK_WRITE, STATE_READBACK, follow_up_performed=True,
        state_jump_decisive=True)
    assert final == "inconclusive"


# =============================================================================
# 3. THE HAZARD: without the narrowing, M1.2's channel exempts a SECURE case.
# =============================================================================

def test_HAZARD_m12_causality_would_false_positive_on_mass_assignment_safe():
    """PROOF that narrowing the M1.2 channel was necessary, not cosmetic.

    On a SECURE allow-list target the LEGITIMATE field's unique value still lands while the
    PRIVILEGED field is stripped. M1.2's payload-causality only asks "did ANY value I wrote
    appear in the read-back", so it CONFIRMS — and caller-identity confirms too. Un-narrowed,
    that channel would exempt a SECURE case: a false positive.

    This test pins the hazard itself. If someone removes the `not _is_mass_attack` narrowing,
    the integrated SAFE tests below go red — this test explains why."""
    attack_req = {"method": "PATCH", "path": ATTACK_WRITE, "body": dict(_SENT)}
    safe_post = json.dumps(
        {"id": 2, "owner_id": 2, "plan": "plan-unique-abc", "role": "member"})   # role STRIPPED

    # Both M1.2 gate terms confirm on a case that is provably SECURE...
    assert _anchor_caller_identity(safe_post, "2", "1") == "confirmed"
    assert _anchor_payload_causality(
        safe_post, None, _written_values(attack_req)) == "confirmed_in_body"

    # ...so the un-narrowed M1.2 channel would have exempted it -> verified on a SECURE case.
    final, reason = _apply_cross_resource_guard(
        "verified", ATTACK_WRITE, STATE_READBACK, follow_up_performed=True,
        state_readback_decisive=True)
    assert final == "verified" and reason == STATE_READBACK_EXEMPTION_REASON

    # The state-jump anchor is what correctly refuses it.
    assert _anchor_state_jump(200, _PRE_PRESENT, 200, safe_post, _SENT) == "no_jump"


# =============================================================================
# 4. GENERICITY — a FOREIGN spec sharing no vocabulary with this target.
# =============================================================================

_FOREIGN = [
    "PATCH /v2/accounts/{account_id}/entitlement  [tags: entitlements]",
    "GET /v2/entitlements/{entitlement_id}  [tags: entitlements]",
    "PATCH /crm/clients/{client_id}/privilege",
    "GET /crm/privileges/{privilege_id}",
]


@pytest.mark.parametrize("attack_path,attacked_id,expected", [
    ("/v2/accounts/77/entitlement", "77", "/v2/entitlements/77"),
    ("/crm/clients/9/privilege", "9", "/crm/privileges/9"),
])
def test_resolver_finds_state_endpoint_on_foreign_spec(attack_path, attacked_id, expected):
    assert select_object_state_endpoint(
        _FOREIGN, attack_path, attacked_object_id=attacked_id) == expected


def test_state_jump_generic_on_foreign_field_names():
    pre = json.dumps({"entitlement_id": 5, "owner": 5, "grade": "standard"})
    post = json.dumps({"entitlement_id": 5, "owner": 5, "grade": "superuser"})
    assert _anchor_state_jump(200, pre, 200, post, {"grade": "superuser"}) == "confirmed_jump"
    assert _anchor_state_jump(200, pre, 200, pre, {"grade": "superuser"}) == "no_jump"


# =============================================================================
# 5. Integrated — REAL execute_deep_verification, mocked Gemini + transport.
# =============================================================================

pytest.importorskip("google.genai")

from vulnerable_target.main import app                                  # noqa: E402
from backend.app.core.config import settings                           # noqa: E402
import backend.app.services.deep_verifier as dv                        # noqa: E402
from backend.tests._llmstub import as_provider
from backend.app.services.endpoint_catalog import catalog_from_openapi  # noqa: E402

CATALOG = catalog_from_openapi(app.openapi())
BASE_URL = "http://127.0.0.1:8001"
APPROVED_HOST = "127.0.0.1:8001"
ALICE = "Bearer alice-token-aaaa"
PLAN = "plan-unique-abc"

_MASS_PAYLOAD = {"location": "path_segment", "target_param": "1", "payload_string": "2",
                 "type": "MASS_ASSIGNMENT"}


def _resp(status, body):
    return {"status_code": status, "content_length": len(body or ""),
            "response_body": body, "elapsed_ms": 5, "url": BASE_URL}


def _fake_send(state_path, pre_state, post_state):
    """PATCH -> opaque 200. The object-state GET returns `pre_state` on its FIRST call (the
    pre-flight) and `post_state` afterwards (the code-gathered AFTER read). Each is (status, body)."""
    calls = {"n": 0}

    async def _send(client, parsed_request, base_url, custody=None):
        method = str(parsed_request.get("method", "GET")).upper()
        path = parsed_request.get("path", "")
        if method in ("POST", "PUT", "PATCH", "DELETE"):
            return _resp(200, '{"status":"ok"}')
        if path == state_path:
            calls["n"] += 1
            st, body = pre_state if calls["n"] == 1 else post_state
            return _resp(st, body)
        return _resp(200, '{"events":[]}')          # the audit-log probe -> HALF-1 steps back
    return _send


def _fake_gemini(t1, t2):
    class _R:
        def __init__(self, text): self.text = text
    seq = iter([json.dumps(t1), json.dumps(t2)])

    async def _gen(*a, **k):
        return _R(next(seq))
    return _gen


def _verdict(v, ep=None):
    return {"decision": "verdict", "next_request": None, "verdict": v,
            "confidence": 1.0, "reasoning": f"m14-mock:{v}", "evidence_path": ep}


@pytest.fixture(autouse=True)
def _enable(monkeypatch):
    monkeypatch.setattr(settings, "AI_DEEP_VERIFY_ENABLED", True, raising=False)
    monkeypatch.setattr(settings, "GEMINI_API_KEY", "test-dummy-key", raising=False)


def _run(write_path, state_path, *, pre_state, post_state, turn2_verdict, monkeypatch,
         body=None, payload=None):
    parsed = {"method": "PATCH", "path": write_path, "query_params": {},
              "headers": {"Content-Type": "application/json"},
              "body": dict(body if body is not None else {"plan": PLAN, "role": "admin"})}
    monkeypatch.setattr(dv, "_send_request", _fake_send(state_path, pre_state, post_state))
    monkeypatch.setattr(dv, "get_provider", as_provider(_fake_gemini(_verdict("inconclusive"),
                                                             _verdict(turn2_verdict, "role"))))
    return asyncio.run(dv.execute_deep_verification(
        parsed_request=parsed, payload=payload or _MASS_PAYLOAD, base_url=BASE_URL,
        approved_host=APPROVED_HOST, auth_context={"Authorization": ALICE},
        available_endpoints=CATALOG))


_OK_PRESENT = (200, _PRE_PRESENT)
_OK_MISSING = (200, _PRE_MISSING)
_POST_ESCALATED = (200, json.dumps({"id": 2, "owner_id": 2, "plan": PLAN, "role": "admin"}))
_POST_STRIPPED = (200, json.dumps({"id": 2, "owner_id": 2, "plan": PLAN, "role": "member"}))
_POST_STILL_MISSING = (200, json.dumps({"id": 2, "owner_id": 2, "plan": PLAN}))


def test_vuln_present_value_jump_reaches_verified(monkeypatch):
    res = _run("/api/users/1/membership", "/api/memberships/2",
               pre_state=_OK_PRESENT, post_state=_POST_ESCALATED,
               turn2_verdict="verified", monkeypatch=monkeypatch)
    assert res.follow_up_request["path"] == "/api/memberships/2"
    assert res.pre_flight_status == 200
    assert res.state_jump_anchor == "confirmed_jump"
    assert res.caller_identity_anchor == "confirmed"
    assert res.ai_verdict == "verified"
    assert res.guard_override == STATE_JUMP_EXEMPTION_REASON


def test_vuln_missing_to_injected_reaches_verified(monkeypatch):
    # Hidden-field escalation MUST verify — this is the case a naive "must have a previous value"
    # rule would wrongly miss.
    res = _run("/api/users/1/membership", "/api/memberships/2",
               pre_state=_OK_MISSING, post_state=_POST_ESCALATED,
               turn2_verdict="verified", monkeypatch=monkeypatch)
    assert res.state_jump_anchor == "confirmed_jump"
    assert res.ai_verdict == "verified"
    assert res.guard_override == STATE_JUMP_EXEMPTION_REASON


def test_SAFE_stripped_field_stays_inconclusive_even_if_model_says_verified(monkeypatch):
    # THE COMMAND LINE. The legit field landed (so M1.2's causality WOULD confirm — see the
    # hazard test above), but the privileged field was stripped -> no jump -> no exemption.
    res = _run("/api/users/1/subscription", "/api/subscriptions/2",
               pre_state=_OK_PRESENT, post_state=_POST_STRIPPED,
               turn2_verdict="verified", monkeypatch=monkeypatch)
    assert res.state_jump_anchor == "no_jump"
    assert res.ai_verdict_raw == "verified"
    assert res.ai_verdict == "inconclusive"
    assert res.ai_verdict != "verified"
    assert res.guard_override == CROSS_RESOURCE_OVERRIDE_REASON


def test_SAFE_missing_stays_missing_is_inconclusive(monkeypatch):
    res = _run("/api/users/1/subscription", "/api/subscriptions/2",
               pre_state=_OK_MISSING, post_state=_POST_STILL_MISSING,
               turn2_verdict="verified", monkeypatch=monkeypatch)
    assert res.state_jump_anchor == "no_jump"
    assert res.ai_verdict != "verified"


def test_CONTROL_injected_equals_preflight_stays_inconclusive(monkeypatch):
    # Coincidence control: the field ALREADY held the injected value.
    res = _run("/api/users/1/membership", "/api/memberships/2",
               pre_state=_OK_PRESENT,
               post_state=(200, json.dumps({"id": 2, "owner_id": 2, "role": "member"})),
               turn2_verdict="verified", monkeypatch=monkeypatch,
               body={"role": "member"})
    assert res.state_jump_anchor == "no_jump"
    assert res.ai_verdict != "verified"


def test_CONTROL_failed_preflight_stays_inconclusive(monkeypatch):
    # Pre-flight 500 -> ORIGINAL STATE UNKNOWN -> never verified, even though post == injected.
    res = _run("/api/users/1/membership", "/api/memberships/2",
               pre_state=(500, '{"detail":"boom"}'), post_state=_POST_ESCALATED,
               turn2_verdict="verified", monkeypatch=monkeypatch)
    assert res.state_jump_anchor == "preflight_unknown"
    assert res.ai_verdict != "verified"


def test_CONTROL_unparseable_post_readback_degrades_without_crashing(monkeypatch):
    res = _run("/api/users/1/membership", "/api/memberships/2",
               pre_state=_OK_PRESENT, post_state=(200, "<html>gateway</html>"),
               turn2_verdict="verified", monkeypatch=monkeypatch)
    assert res.status == "completed"                 # degraded, NOT crashed
    assert res.state_jump_anchor == "postread_unknown"
    assert res.ai_verdict != "verified"


def test_state_jump_governs_any_write_with_a_preflight_even_if_typed_BOLA(monkeypatch):
    """M1.4(fix) ROUTING: the stricter state-jump gate governs ANY write that has a pre-flight
    baseline — it no longer depends on how the attack DECLARED its type. A plain BOLA write now
    routes through the state-jump channel (same verdict, stricter evidence)."""
    res = _run("/api/users/1/gizmo", "/api/gizmos/2",
               pre_state=(200, json.dumps({"id": 2, "owner_id": 2, "code": "old-value"})),
               post_state=(200, json.dumps({"id": 2, "owner_id": 2, "code": "zz-unique-1"})),
               turn2_verdict="verified", monkeypatch=monkeypatch,
               body={"code": "zz-unique-1"},
               payload={"location": "path_segment", "target_param": "1",
                        "payload_string": "2", "type": "BOLA"})
    assert res.pre_flight_status == 200                  # a baseline now exists for any write
    assert res.state_jump_anchor == "confirmed_jump"
    assert res.guard_override == STATE_JUMP_EXEMPTION_REASON
    assert res.ai_verdict == "verified"                  # verdict unchanged vs the M1.2 channel


def test_RESIDUAL_FIX_mass_assignment_mistyped_as_BOLA_safe_stays_inconclusive(monkeypatch):
    """THE RESIDUAL FIX. A mass-assignment attack MISTYPED as plain BOLA against a SECURELY
    stripped target. The legitimate co-submitted field still lands, so payload-causality confirms
    — before this fix the weaker M1.2 channel would have exempted it (a false positive on a SECURE
    case). Now the state-jump gate governs (a pre-flight baseline exists) and refuses: the
    privileged field never moved."""
    res = _run("/api/users/1/subscription", "/api/subscriptions/2",
               pre_state=_OK_PRESENT, post_state=_POST_STRIPPED,
               turn2_verdict="verified", monkeypatch=monkeypatch,
               payload={"location": "path_segment", "target_param": "1",
                        "payload_string": "2", "type": "BOLA"})   # <-- MISTYPED, not mass-assignment
    # payload-causality WOULD have confirmed (the legit field landed) ...
    assert res.payload_causality_anchor in ("confirmed_at_path", "confirmed_in_body")
    # ... but the stricter gate governs and refuses.
    assert res.state_jump_anchor == "no_jump"
    assert res.ai_verdict_raw == "verified"
    assert res.ai_verdict == "inconclusive"
    assert res.guard_override == CROSS_RESOURCE_OVERRIDE_REASON
