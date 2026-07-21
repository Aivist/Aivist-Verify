# ==============================================================================
# M1.3 — DELETE-shape BOLA. Confirmation is a NEGATIVE ASSERTION: the proof is a
# from-EXISTS-to-ABSENT jump, not a value appearing. Two mechanisms this shape needs:
#   (1) PRE-FLIGHT READ (the coincidence gate): "it vanished" only proves a delete if the
#       object provably EXISTED and was active BEFORE the attack. The code GETs the victim
#       object first; no pre-flight existence proof -> NEVER verified.
#   (2) DUAL-TRACK ABSENCE: the post-attack read-back is decisive whether the object is
#       PHYSICALLY gone (404/403) OR LOGICALLY soft-deleted (200 with a status/lifecycle field
#       flipped to a deleted value). 404 is NOT hardcoded as the only proof of vanishing.
#
# HUMAN-OWNED GROUND TRUTH (implement + measure, do NOT redefine):
#   X-DELETE-VULN (hard + soft) -> verified;  X-DELETE-SAFE (dropped) -> NEVER verified;
#   no pre-flight existence (object absent before) -> inconclusive even if the AFTER read 404s.
#
# A `verified` on the SAFE shape, or a `verified` without the pre-flight existence proof, is a
# FALSE POSITIVE = the integrity hole reopened. Fix the gate, not the test. No live model / net.
# ==============================================================================

import os
import sys
import json
import asyncio

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

import pytest

from backend.app.services.deep_verifier import (
    _apply_cross_resource_guard,
    _anchor_negative_assertion,
    _deletion_signal,
    _is_delete_method,
    CROSS_RESOURCE_OVERRIDE_REASON,
    STATE_READBACK_EXEMPTION_REASON,
    DELETE_READBACK_EXEMPTION_REASON,
)
from backend.app.services.endpoint_catalog import select_object_state_endpoint

ATTACK_DELETE = "/api/users/2/relic"       # a cross-user DELETE
STATE_READBACK = "/api/relics/2"           # the object's own state, a DIFFERENT path


# =============================================================================
# 1. Negative-assertion anchor (pure) — dual-track + the coincidence gate.
# =============================================================================

_PRE_ACTIVE_NO_STATUS = json.dumps({"id": 2, "owner_id": 2, "label": "relic_bob"})
_PRE_ACTIVE_STATUS = json.dumps({"id": 2, "owner_id": 2, "status": "active", "label": "b"})
_POST_SOFT_DELETED = json.dumps({"id": 2, "owner_id": 2, "status": "revoked", "label": "b"})
_POST_404_BODY = json.dumps({"detail": "Relic not found"})


def test_neg_assertion_confirmed_physical():
    # existed+active BEFORE, gone (404) AFTER -> physical deletion confirmed.
    assert _anchor_negative_assertion(200, _PRE_ACTIVE_NO_STATUS, 404, _POST_404_BODY) == "confirmed_physical"
    assert _anchor_negative_assertion(200, _PRE_ACTIVE_NO_STATUS, 403, "{}") == "confirmed_physical"


def test_neg_assertion_confirmed_logical():
    # existed+active BEFORE, still 200 AFTER but status flipped to a deleted value -> soft delete.
    assert _anchor_negative_assertion(200, _PRE_ACTIVE_STATUS, 200, _POST_SOFT_DELETED) == "confirmed_logical"


def test_neg_assertion_still_present_is_not_decisive():
    # existed+active BEFORE, still present & active AFTER -> the delete was dropped (SAFE).
    assert _anchor_negative_assertion(200, _PRE_ACTIVE_NO_STATUS, 200, _PRE_ACTIVE_NO_STATUS) == "still_present"
    assert _anchor_negative_assertion(200, _PRE_ACTIVE_STATUS, 200, _PRE_ACTIVE_STATUS) == "still_present"


def test_neg_assertion_coincidence_gate_no_preflight():
    # No pre-flight (or it did not return 200) -> existence unproven -> NOT decisive, even on a 404 AFTER.
    assert _anchor_negative_assertion(None, None, 404, _POST_404_BODY) == "no_preflight"
    assert _anchor_negative_assertion(500, None, 404, _POST_404_BODY) == "no_preflight"


def test_neg_assertion_coincidence_gate_preflight_absent():
    # Pre-flight showed the object did NOT exist -> nothing to prove was deleted -> NOT decisive.
    assert _anchor_negative_assertion(404, "{}", 404, _POST_404_BODY) == "preflight_absent"


def test_neg_assertion_preflight_already_deleted():
    # Pre-flight existed but was ALREADY soft-deleted -> can't attribute a later absence to us.
    assert _anchor_negative_assertion(200, _POST_SOFT_DELETED, 404, _POST_404_BODY) == "preflight_already_deleted"


def test_deletion_signal_variants():
    # generic dual detection: string status, boolean flags, timestamp markers.
    assert _deletion_signal(json.dumps({"status": "active"})) == "active"
    assert _deletion_signal(json.dumps({"status": "revoked"})) == "deleted"
    assert _deletion_signal(json.dumps({"state": "archived"})) == "deleted"
    assert _deletion_signal(json.dumps({"is_deleted": True})) == "deleted"
    assert _deletion_signal(json.dumps({"is_active": False})) == "deleted"
    assert _deletion_signal(json.dumps({"deleted_at": "2026-07-20T00:00:00Z"})) == "deleted"
    assert _deletion_signal(json.dumps({"deleted_at": None, "status": "active"})) == "active"
    assert _deletion_signal(json.dumps({"id": 2, "owner_id": 2, "label": "x"})) == "unknown"


# =============================================================================
# 2. Guard — the new delete_readback_decisive channel (pure, structural).
# =============================================================================

def test_delete_exemption_keeps_verified_on_crosspath():
    final, reason = _apply_cross_resource_guard(
        "verified", ATTACK_DELETE, STATE_READBACK, follow_up_performed=True,
        delete_readback_decisive=True,
    )
    assert final == "verified"
    assert reason == DELETE_READBACK_EXEMPTION_REASON


def test_delete_exemption_off_by_default_downgrades():
    final, reason = _apply_cross_resource_guard(
        "verified", ATTACK_DELETE, STATE_READBACK, follow_up_performed=True,
    )
    assert final == "inconclusive"
    assert reason == CROSS_RESOURCE_OVERRIDE_REASON


def test_delete_exemption_only_verified_not_failed():
    final, reason = _apply_cross_resource_guard(
        "failed", ATTACK_DELETE, STATE_READBACK, follow_up_performed=True,
        delete_readback_decisive=True,
    )
    assert final == "inconclusive"
    assert reason == CROSS_RESOURCE_OVERRIDE_REASON


def test_delete_exemption_untouched_on_same_path():
    final, reason = _apply_cross_resource_guard(
        "verified", ATTACK_DELETE, ATTACK_DELETE, follow_up_performed=True,
        delete_readback_decisive=True,
    )
    assert final == "verified"
    assert reason is None


def test_other_channels_still_work_alongside_delete_param():
    # The new param is additive: state-readback exemption still fires when set (delete off).
    final, reason = _apply_cross_resource_guard(
        "verified", ATTACK_DELETE, STATE_READBACK, follow_up_performed=True,
        state_readback_decisive=True, delete_readback_decisive=False,
    )
    assert final == "verified"
    assert reason == STATE_READBACK_EXEMPTION_REASON


# =============================================================================
# 3. GENERICITY — a FOREIGN spec sharing NO vocabulary with this target.
# =============================================================================

_FOREIGN = [
    "DELETE /v2/accounts/{account_id}/widget  [tags: widgets]",
    "GET /v2/widgets/{widget_id}  [tags: widgets]",
    "DELETE /shop/customers/{customer_id}/policy",
    "GET /shop/policies/{policy_id}",
]


@pytest.mark.parametrize("attack_path,attacked_id,expected", [
    ("/v2/accounts/77/widget", "77", "/v2/widgets/77"),
    ("/shop/customers/9/policy", "9", "/shop/policies/9"),
])
def test_resolver_finds_object_state_for_delete_on_foreign_spec(attack_path, attacked_id, expected):
    # The SAME resolver M1.2(B) uses locates the object's state endpoint for a DELETE too,
    # on a spec with no vocabulary shared with this target.
    assert select_object_state_endpoint(_FOREIGN, attack_path, attacked_object_id=attacked_id) == expected


def test_neg_assertion_generic_on_foreign_status_vocabulary():
    # foreign soft-delete field names/values still classify by the generic vocabulary.
    pre = json.dumps({"widget_id": 5, "owner": 5, "lifecycle": "published"})
    post = json.dumps({"widget_id": 5, "owner": 5, "lifecycle": "purged"})
    assert _anchor_negative_assertion(200, pre, 200, post) == "confirmed_logical"


# =============================================================================
# 4. Integrated — REAL execute_deep_verification, mocked Gemini + transport.
#    Pins BOTH ways + the coincidence gate end-to-end.
# =============================================================================

pytest.importorskip("google.genai")

from vulnerable_target.main import app                              # noqa: E402
from backend.app.core.config import settings                       # noqa: E402
import backend.app.services.deep_verifier as dv                    # noqa: E402
from backend.app.services.endpoint_catalog import catalog_from_openapi  # noqa: E402

CATALOG = catalog_from_openapi(app.openapi())
BASE_URL = "http://127.0.0.1:8001"
APPROVED_HOST = "127.0.0.1:8001"
ALICE = "Bearer alice-token-aaaa"


def _resp(status: int, body: str) -> dict:
    return {"status_code": status, "content_length": len(body),
            "response_body": body, "elapsed_ms": 5, "url": BASE_URL}


def _fake_send(state_path: str, pre_state, post_state):
    """Opaque 200 on the DELETE; the object-state GET returns `pre_state` on its FIRST call
    (the pre-flight) and `post_state` on later calls (the post-attack read). Each is a
    (status_code, body) pair. This models the object changing across the attack."""
    calls = {"n": 0}

    async def _send(client, parsed_request, base_url, custody=None):
        method = str(parsed_request.get("method", "GET")).upper()
        path = parsed_request.get("path", "")
        if method == "DELETE":
            return _resp(200, '{"status":"ok"}')
        if path == state_path:
            calls["n"] += 1
            st, body = pre_state if calls["n"] == 1 else post_state
            return _resp(st, body)
        return _resp(200, '{"ok":true}')
    return _send


def _fake_gemini(turn1: dict, turn2: dict):
    class _R:
        def __init__(self, text): self.text = text
    seq = iter([json.dumps(turn1), json.dumps(turn2)])

    async def _gen(*args, **kwargs):
        return _R(next(seq))
    return _gen


def _verdict_turn(verdict, evidence_path=None):
    return {"decision": "verdict", "next_request": None, "verdict": verdict,
            "confidence": 1.0, "reasoning": f"m13-mock:{verdict}", "evidence_path": evidence_path}


@pytest.fixture(autouse=True)
def _enable(monkeypatch):
    monkeypatch.setattr(settings, "AI_DEEP_VERIFY_ENABLED", True, raising=False)
    monkeypatch.setattr(settings, "GEMINI_API_KEY", "test-dummy-key", raising=False)


_BOLA = {"location": "path_segment", "target_param": "1", "payload_string": "2", "type": "BOLA"}


def _run(delete_path, state_path, *, pre_state, post_state, turn2_verdict, monkeypatch):
    parsed_request = {"method": "DELETE", "path": delete_path, "query_params": {},
                      "headers": {}, "body": None}
    monkeypatch.setattr(dv, "_send_request", _fake_send(state_path, pre_state, post_state))
    # The model asks for nothing (turn 1 verdict); the code force-gathers the state read anyway.
    monkeypatch.setattr(dv, "_gemini_generate",
                        _fake_gemini(_verdict_turn("inconclusive"), _verdict_turn(turn2_verdict)))
    return asyncio.run(dv.execute_deep_verification(
        parsed_request=parsed_request, payload=_BOLA, base_url=BASE_URL,
        approved_host=APPROVED_HOST, auth_context={"Authorization": ALICE},
        available_endpoints=CATALOG,
    ))


_VICTIM_ACTIVE = (200, json.dumps({"id": 2, "owner_id": 2, "label": "relic_bob"}))
_GONE_404 = (404, json.dumps({"detail": "Relic not found"}))
_SOFT_ACTIVE = (200, json.dumps({"id": 2, "owner_id": 2, "status": "active", "label": "b"}))
_SOFT_DELETED = (200, json.dumps({"id": 2, "owner_id": 2, "status": "revoked", "label": "b"}))


def test_vuln_hard_delete_reaches_verified(monkeypatch):
    res = _run("/api/users/1/relic", "/api/relics/2",
               pre_state=_VICTIM_ACTIVE, post_state=_GONE_404,
               turn2_verdict="verified", monkeypatch=monkeypatch)
    assert res.status == "completed"
    assert res.follow_up_request["path"] == "/api/relics/2"          # code-gathered AFTER read
    assert res.pre_flight_status == 200                              # existence anchored
    assert res.negative_assertion_anchor == "confirmed_physical"
    assert res.ai_verdict_raw == "verified"
    assert res.ai_verdict == "verified"
    assert res.guard_override == DELETE_READBACK_EXEMPTION_REASON


def test_surfaced_preflight_anchor_is_the_one_the_gate_used(monkeypatch):
    """AUDITABILITY (observe-only). The delete gate keys on caller-identity computed over the
    PRE-FLIGHT body. The AFTER read of a physical delete is a 404 with no owner, so the
    general-purpose `caller_identity_anchor` reads "owner_not_found" — surfacing only that would
    misrepresent the evidence chain. `preflight_caller_identity_anchor` exposes the value the gate
    ACTUALLY used. The exemption firing PROVES the gate saw "confirmed" (it is an AND term), so
    asserting both together pins the surfaced field to the gate's real input."""
    res = _run("/api/users/1/relic", "/api/relics/2",
               pre_state=_VICTIM_ACTIVE, post_state=_GONE_404,
               turn2_verdict="verified", monkeypatch=monkeypatch)
    # The exemption fired => the gate's AND held => its caller-identity term was "confirmed".
    assert res.guard_override == DELETE_READBACK_EXEMPTION_REASON
    assert res.preflight_caller_identity_anchor == "confirmed"       # what the gate used
    # ...and it is NOT the misleading AFTER-read value, which a 404 leaves unanchorable.
    assert res.caller_identity_anchor == "owner_not_found"
    assert res.preflight_caller_identity_anchor != res.caller_identity_anchor


def test_surfaced_preflight_anchor_confirms_on_safe_too(monkeypatch):
    """The pre-flight caller-identity CANNOT be the VULN/SAFE separator — it confirms for both
    (a dropped delete still leaves the victim's object owned by the victim). Only the negative
    assertion separates them. Surfacing it makes that visible in the transcript."""
    res = _run("/api/users/1/seal", "/api/seals/2",
               pre_state=_VICTIM_ACTIVE, post_state=_VICTIM_ACTIVE,
               turn2_verdict="verified", monkeypatch=monkeypatch)
    assert res.preflight_caller_identity_anchor == "confirmed"       # same as VULN...
    assert res.negative_assertion_anchor == "still_present"          # ...only THIS differs
    assert res.ai_verdict == "inconclusive"


def test_surfaced_preflight_anchor_when_object_never_existed(monkeypatch):
    # Pre-flight 404 -> nothing to anchor an owner on -> the transcript shows why, honestly.
    res = _run("/api/users/1/relic", "/api/relics/2",
               pre_state=_GONE_404, post_state=_GONE_404,
               turn2_verdict="verified", monkeypatch=monkeypatch)
    assert res.preflight_caller_identity_anchor == "owner_not_found"
    assert res.negative_assertion_anchor == "preflight_absent"
    assert res.ai_verdict != "verified"


def test_non_delete_shapes_have_no_preflight_anchor(monkeypatch):
    # The field is delete-only: a value-write shape never takes a pre-flight, so it stays None
    # (proving the new field cannot leak into the other shapes' evidence chains).
    parsed = {"method": "POST", "path": "/api/users/1/gizmo", "query_params": {},
              "headers": {"Content-Type": "application/json"}, "body": {"code": "zz-unique-1"}}
    monkeypatch.setattr(dv, "_send_request", _fake_send(
        "/api/gizmos/2",
        (200, json.dumps({"id": 2, "owner_id": 2, "code": "old-value"})),      # pre-flight
        (200, json.dumps({"id": 2, "owner_id": 2, "code": "zz-unique-1"})),    # post-attack
    ))
    monkeypatch.setattr(dv, "_gemini_generate",
                        _fake_gemini(_verdict_turn("inconclusive"), _verdict_turn("verified", "code")))
    res = asyncio.run(dv.execute_deep_verification(
        parsed_request=parsed, payload=_BOLA, base_url=BASE_URL,
        approved_host=APPROVED_HOST, auth_context={"Authorization": ALICE},
        available_endpoints=CATALOG,
    ))
    # M1.4(fix): every WRITE now takes a pre-flight baseline, so the stricter state-jump gate
    # governs this shape too. The DELETE-specific anchors stay None — channels remain disjoint.
    assert res.negative_assertion_anchor is None                     # delete anchor not computed
    assert res.preflight_caller_identity_anchor is None              # delete-only anchor
    assert res.ai_verdict == "verified"                              # verdict unchanged


def test_vuln_soft_delete_reaches_verified(monkeypatch):
    res = _run("/api/users/1/badge", "/api/badges/2",
               pre_state=_SOFT_ACTIVE, post_state=_SOFT_DELETED,
               turn2_verdict="verified", monkeypatch=monkeypatch)
    assert res.pre_flight_status == 200
    assert res.negative_assertion_anchor == "confirmed_logical"
    assert res.ai_verdict == "verified"
    assert res.guard_override == DELETE_READBACK_EXEMPTION_REASON


def test_safe_dropped_delete_stays_inconclusive_even_if_model_says_verified(monkeypatch):
    # THE SAFETY LINE. The delete was dropped -> the object is still present -> negative assertion
    # is 'still_present' -> no exemption -> inconclusive, EVEN THOUGH the model wrongly says verified.
    res = _run("/api/users/1/seal", "/api/seals/2",
               pre_state=_VICTIM_ACTIVE, post_state=_VICTIM_ACTIVE,   # unchanged
               turn2_verdict="verified", monkeypatch=monkeypatch)
    assert res.negative_assertion_anchor == "still_present"
    assert res.ai_verdict_raw == "verified"
    assert res.ai_verdict == "inconclusive"
    assert res.ai_verdict != "verified"                             # NEVER verified on SAFE
    assert res.guard_override == CROSS_RESOURCE_OVERRIDE_REASON


def test_coincidence_gate_no_preflight_existence_stays_inconclusive(monkeypatch):
    # THE COINCIDENCE GATE. The object did NOT exist before the attack (pre-flight 404). The AFTER
    # read is also 404, so a naive "it's gone" oracle would say verified — but there is nothing to
    # prove was deleted. Must stay inconclusive even though the model says verified and post is 404.
    res = _run("/api/users/1/relic", "/api/relics/2",
               pre_state=_GONE_404, post_state=_GONE_404,
               turn2_verdict="verified", monkeypatch=monkeypatch)
    assert res.pre_flight_status == 404
    assert res.negative_assertion_anchor == "preflight_absent"
    assert res.ai_verdict != "verified"
    assert res.guard_override == CROSS_RESOURCE_OVERRIDE_REASON
