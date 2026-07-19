# ==============================================================================
# M1.2(A) — STATE-READBACK EXEMPTION. A SECOND, separate exemption channel (distinct from
# B-1's write-record exemption) that lets a CORRECT cross-path OBJECT-STATE read-back stand
# as `verified` instead of being downgraded to `inconclusive` by the B-2.2 cross-resource
# guard — but ONLY when code structurally confirms ALL THREE, AND-ed:
#   (1) the read object IS the ATTACKED object   (owner id == attacked id), AND
#   (2) the actor differs from the owner         (caller id != owner id),
#         -> (1)+(2) == the caller-identity anchor being "confirmed"; AND
#   (3) PAYLOAD CAUSALITY: THIS attack's UNIQUE injected value appears in the read-back
#         -> the payload-causality anchor being "confirmed_at_path"/"confirmed_in_body".
#
# Condition (3) is the NON-NEGOTIABLE false-positive gate. (1) and (2) are True for BOTH a
# real leak (X-SILENT-VULN) and a securely-DROPPED write (X-SILENT-SAFE) — a dropped write
# still leaves the object owned by the victim and attacked by the caller. ONLY the unique
# value actually landing separates them. If (3) is not confirmed, the exemption must NOT
# fire and the verdict stays `inconclusive` — EVEN IF the model raw-says `verified`.
#
# THESE EXPECTED VALUES ARE HUMAN-OWNED GROUND TRUTH. They must NOT be relaxed to make a
# test pass. A `verified` on the SAFE shape is the integrity hole reopened — a RED, fix the
# gate, not the test. NO live model, NO network: the guard is asserted directly and the
# integrated flow runs the REAL execute_deep_verification with a mocked Gemini + transport.
# ==============================================================================

import os
import sys
import json
import asyncio

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

import pytest

from backend.app.services.deep_verifier import (
    _apply_cross_resource_guard,
    CROSS_RESOURCE_OVERRIDE_REASON,
    WRITE_RECORD_EXEMPTION_REASON,
    STATE_READBACK_EXEMPTION_REASON,
)

# Concrete paths mirroring the live X-SILENT shapes: a write with NO same-path GET, whose
# only observation is a cross-path STATE read on a DIFFERENT path.
ATTACK_WRITE = "/api/users/2/gizmo"          # the silent cross-user write
STATE_READBACK = "/api/gizmos/2"             # the object's OWN state, a DIFFERENT path
WRITE_RECORD_PATH = "/api/audit-log"         # B-1's channel (a record/log path)


# =============================================================================
# 1. Unit — the guard's new state_readback_decisive channel (asserted directly).
#    Mirrors test_d18_b22_guard.py: pure, structural, no model/network.
# =============================================================================

def test_state_exemption_keeps_verified_on_crosspath_state_readback():
    # verified + cross-path + state_readback_decisive=True -> verified (kept), state reason.
    final, reason = _apply_cross_resource_guard(
        "verified", ATTACK_WRITE, STATE_READBACK, follow_up_performed=True,
        state_readback_decisive=True,
    )
    assert final == "verified"
    assert reason == STATE_READBACK_EXEMPTION_REASON


def test_state_exemption_does_not_fire_when_not_decisive():
    # verified + cross-path + state_readback_decisive=False -> downgraded (the gate's default).
    final, reason = _apply_cross_resource_guard(
        "verified", ATTACK_WRITE, STATE_READBACK, follow_up_performed=True,
        state_readback_decisive=False,
    )
    assert final == "inconclusive"
    assert reason == CROSS_RESOURCE_OVERRIDE_REASON


def test_state_exemption_only_applies_to_verified_not_failed():
    # A "failed" cross-path read-back is NEVER exempted (a record/state proves presence, not
    # absence) -> stays downgraded even with state_readback_decisive=True.
    final, reason = _apply_cross_resource_guard(
        "failed", ATTACK_WRITE, STATE_READBACK, follow_up_performed=True,
        state_readback_decisive=True,
    )
    assert final == "inconclusive"
    assert reason == CROSS_RESOURCE_OVERRIDE_REASON


def test_state_exemption_untouched_on_same_path():
    # Same-resource read-back is already decisive; the guard never downgrades it, so the
    # exemption is a no-op there (reason None, not the exemption reason).
    final, reason = _apply_cross_resource_guard(
        "verified", ATTACK_WRITE, ATTACK_WRITE, follow_up_performed=True,
        state_readback_decisive=True,
    )
    assert final == "verified"
    assert reason is None


def test_state_exemption_untouched_with_no_followup():
    # No follow-up (a read-type/GET BOLA confirmed by the attack response) -> untouched.
    final, reason = _apply_cross_resource_guard(
        "verified", "/api/orders/2", None, follow_up_performed=False,
        state_readback_decisive=True,
    )
    assert final == "verified"
    assert reason is None


def test_write_record_exemption_takes_precedence_over_state():
    # If BOTH channels are (hypothetically) set, B-1's write-record exemption WINS — B-1's
    # behavior and reason are unchanged by the new channel.
    final, reason = _apply_cross_resource_guard(
        "verified", ATTACK_WRITE, WRITE_RECORD_PATH, follow_up_performed=True,
        write_record_decisive=True, state_readback_decisive=True,
    )
    assert final == "verified"
    assert reason == WRITE_RECORD_EXEMPTION_REASON


def test_guard_defaults_unchanged_without_the_new_param():
    # Backward-compatibility: omitting state_readback_decisive keeps the pre-change behavior
    # (a bare cross-path verified is downgraded). This is what every existing guard test relies on.
    final, reason = _apply_cross_resource_guard(
        "verified", ATTACK_WRITE, STATE_READBACK, follow_up_performed=True,
    )
    assert final == "inconclusive"
    assert reason == CROSS_RESOURCE_OVERRIDE_REASON


# =============================================================================
# 2. Integration — the REAL execute_deep_verification, mocked Gemini + transport.
#    Proves the AND-ed 3-condition gate BOTH ways end-to-end.
# =============================================================================

pytest.importorskip("google.genai")

from vulnerable_target.main import app                      # noqa: E402
from backend.app.core.config import settings               # noqa: E402
import backend.app.services.deep_verifier as dv            # noqa: E402
from backend.app.services.endpoint_catalog import (        # noqa: E402
    catalog_from_openapi,
    select_write_record_endpoint,
)

CATALOG = catalog_from_openapi(app.openapi())
RECORD_PATH = select_write_record_endpoint(CATALOG)         # the global write-record (audit-log)

BASE_URL = "http://127.0.0.1:8001"
APPROVED_HOST = "127.0.0.1:8001"
ALICE = "Bearer alice-token-aaaa"
UNIQUE = "m12a-state-9d41c7ef03a"                           # this attack's unique injected value


def _resp(status: int, body: str) -> dict:
    return {"status_code": status, "content_length": len(body),
            "response_body": body, "elapsed_ms": 5, "url": BASE_URL}


def _fake_send(state_path: str, state_body: str, record_body: str = '{"events":[]}'):
    """Silent opaque 200 on every write; the audit-log probe returns `record_body` (empty by
    default, so HALF-1 steps back); the object's own cross-path STATE read returns state_body."""
    async def _send(client, parsed_request, base_url, custody=None):
        method = str(parsed_request.get("method", "GET")).upper()
        path = parsed_request.get("path", "")
        if method in ("POST", "PUT", "PATCH", "DELETE"):
            return _resp(200, '{"status":"ok"}')             # opaque silent write (baseline + attack)
        if path == RECORD_PATH:
            return _resp(200, record_body)                   # HALF-1 object-scope probe
        if path == state_path:
            return _resp(200, state_body)                    # the cross-path STATE read-back
        return _resp(200, '{"ok":true}')
    return _send


def _fake_gemini(turn1: dict, turn2: dict):
    class _R:
        def __init__(self, text): self.text = text
    seq = iter([json.dumps(turn1), json.dumps(turn2)])

    async def _gen(*args, **kwargs):
        return _R(next(seq))
    return _gen


def _verdict_turn(verdict: str, evidence_path: str = None) -> dict:
    return {"decision": "verdict", "next_request": None, "verdict": verdict,
            "confidence": 1.0, "reasoning": f"m12a-mock:{verdict}", "evidence_path": evidence_path}


def _request_turn(path: str) -> dict:
    return {"decision": "request_more",
            "next_request": {"method": "GET", "path": path, "body": None, "reason": "m12a-mock"},
            "verdict": None, "confidence": 0.5, "reasoning": "m12a-mock:request_more"}


@pytest.fixture(autouse=True)
def _enable(monkeypatch):
    monkeypatch.setattr(settings, "AI_DEEP_VERIFY_ENABLED", True, raising=False)
    monkeypatch.setattr(settings, "GEMINI_API_KEY", "test-dummy-key", raising=False)


def _run(parsed_request, payload, *, state_path, state_body, turn1, turn2, monkeypatch,
         record_body='{"events":[]}'):
    monkeypatch.setattr(dv, "_send_request", _fake_send(state_path, state_body, record_body))
    monkeypatch.setattr(dv, "_gemini_generate", _fake_gemini(turn1, turn2))
    return asyncio.run(dv.execute_deep_verification(
        parsed_request=parsed_request, payload=payload, base_url=BASE_URL,
        approved_host=APPROVED_HOST, auth_context={"Authorization": ALICE},
        available_endpoints=CATALOG,
    ))


_BOLA = {"location": "path_segment", "target_param": "1", "payload_string": "2", "type": "BOLA"}
# Write paths with NO same-path GET in the real catalog -> HALF-1 fires, probes the audit-log,
# finds no caller write (empty) -> steps back -> the MODEL's own state read is the follow-up.
_GIZMO_WRITE = {"method": "POST", "path": "/api/users/1/gizmo", "query_params": {},
                "headers": {"Content-Type": "application/json"}, "body": {"code": UNIQUE}}
_SPROCKET_WRITE = {"method": "POST", "path": "/api/users/1/sprocket", "query_params": {},
                   "headers": {"Content-Type": "application/json"}, "body": {"code": UNIQUE}}


# ---- (VULN) all three anchors confirmed -> exemption fires -> verified STANDS -------------
def test_vuln_state_readback_exemption_fires_and_verified_stands(monkeypatch):
    # The cross-path STATE read shows the ATTACKED object (owner 2) now carries THIS attack's
    # UNIQUE value -> (1) owner==attacked, (2) caller!=owner, (3) causality confirmed.
    res = _run(
        _GIZMO_WRITE, _BOLA,
        state_path="/api/gizmos/2",
        state_body=json.dumps({"id": 2, "owner_id": 2, "code": UNIQUE}),
        turn1=_request_turn("/api/gizmos/2"),
        turn2=_verdict_turn("verified", evidence_path="code"),
        monkeypatch=monkeypatch,
    )
    assert res.status == "completed"
    # HALF-1 stepped back: the follow-up is the model's own state read, NOT the audit-log.
    assert res.follow_up_request["path"] == "/api/gizmos/2"
    assert res.follow_up_request["path"] != RECORD_PATH
    # All three AND-ed conditions visible:
    assert res.caller_identity_anchor == "confirmed"                       # (1)+(2)
    assert res.payload_causality_anchor in ("confirmed_at_path", "confirmed_in_body")  # (3)
    # THE FIX: a correct cross-path STATE confirmation now reaches verified.
    assert res.ai_verdict_raw == "verified"
    assert res.ai_verdict == "verified"
    assert res.guard_override == STATE_READBACK_EXEMPTION_REASON


# ---- (SAFE) payload absent -> (3) fails -> NOT exempt -> stays inconclusive ---------------
def test_safe_dropped_write_is_not_exempted_even_if_model_says_verified(monkeypatch):
    # THE COMMAND-LINE SAFETY CHECK. Same attack, but the write was silently DROPPED: the
    # cross-path STATE read shows the ORIGINAL value, the UNIQUE value is ABSENT. (1) and (2)
    # STILL hold (object still owned by victim 2, attacked by caller 1) — only (3) separates
    # VULN from SAFE. The model wrongly raw-says "verified"; the gate MUST refuse the exemption.
    res = _run(
        _SPROCKET_WRITE, _BOLA,
        state_path="/api/sprockets/2",
        state_body=json.dumps({"id": 2, "owner_id": 2, "code": "sprocket_bob_v0"}),
        turn1=_request_turn("/api/sprockets/2"),
        turn2=_verdict_turn("verified", evidence_path="code"),   # model is WRONG here
        monkeypatch=monkeypatch,
    )
    assert res.status == "completed"
    assert res.follow_up_request["path"] == "/api/sprockets/2"
    # (1)+(2) confirm for the SAFE case too — proving they cannot be the separator...
    assert res.caller_identity_anchor == "confirmed"
    # ...only causality does, and it is ABSENT (the unique value never landed).
    assert res.payload_causality_anchor == "absent"
    # THE INTEGRITY LINE: raw verified, but NOT exempted -> downgraded to inconclusive.
    assert res.ai_verdict_raw == "verified"
    assert res.ai_verdict == "inconclusive"
    assert res.ai_verdict != "verified"                          # NEVER verified on the SAFE shape
    assert res.guard_override == CROSS_RESOURCE_OVERRIDE_REASON


# ---- (guard) reading the caller's OWN object -> (2) fails -> NOT exempt -------------------
def test_reading_callers_own_object_is_not_exempted(monkeypatch):
    # The model reads the CALLER's own object (owner 1). The unique value IS there (Alice's own
    # baseline self-write landed), so causality would confirm — but caller==owner, so this is
    # not a cross-user leak. caller_identity must be "same_as_caller" -> (2) fails -> no exemption.
    res = _run(
        _GIZMO_WRITE, _BOLA,
        state_path="/api/gizmos/1",
        state_body=json.dumps({"id": 1, "owner_id": 1, "code": UNIQUE}),
        turn1=_request_turn("/api/gizmos/1"),
        turn2=_verdict_turn("verified", evidence_path="code"),
        monkeypatch=monkeypatch,
    )
    assert res.caller_identity_anchor == "same_as_caller"        # (2) fails
    assert res.ai_verdict != "verified"
    assert res.guard_override == CROSS_RESOURCE_OVERRIDE_REASON


# ---- (guard) read-back exposes no owner/subject field -> (1) fails -> NOT exempt ----------
def test_state_readback_without_owner_field_is_not_exempted(monkeypatch):
    # The state read exposes the written value but NO owner/subject field, so we cannot prove
    # the read object IS the attacked object. caller_identity -> "owner_not_found" -> (1) fails.
    res = _run(
        _GIZMO_WRITE, _BOLA,
        state_path="/api/gizmos/2",
        state_body=json.dumps({"id": 2, "code": UNIQUE}),        # no owner_id / subject key
        turn1=_request_turn("/api/gizmos/2"),
        turn2=_verdict_turn("verified", evidence_path="code"),
        monkeypatch=monkeypatch,
    )
    assert res.caller_identity_anchor == "owner_not_found"       # (1) fails
    assert res.payload_causality_anchor in ("confirmed_at_path", "confirmed_in_body")
    assert res.ai_verdict != "verified"
    assert res.guard_override == CROSS_RESOURCE_OVERRIDE_REASON
