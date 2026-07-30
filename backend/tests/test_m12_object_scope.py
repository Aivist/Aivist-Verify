# ==============================================================================
# M1.2 — HALF-1 OBJECT-SCOPE gate. B-1's HALF-1 used to force-gather the single global
# write-record endpoint (audit-log) for ANY silent write, even when that record is not
# about the attacked object — hijacking the follow-up before the model could read the
# object's own state. The gate now keeps the gather ONLY when the record endpoint records
# the caller's OWN (baseline, definitely-landed) write; otherwise HALF-1 steps back.
#
# Pinned BOTH ways:
#   (a) record IS about the attacked object (contains the caller's landed write) -> HALF-1
#       still gathers it (B-1 preserved).
#   (b) record is NOT about the attacked object (no caller write) -> HALF-1 steps back; the
#       model's own follow-up (the object's state read) is used. This is exactly what the
#       PRE-CHANGE code could not do — it always gathered the record (see the unit test that
#       proves the gate predicate is False here while select_write_record_endpoint still
#       returns the record the old code would have gathered).
#
# The gate reuses _write_record_content_match unchanged (with the CALLER's id); it does NOT
# touch the guard, the content-match logic, the rule oracle, or any verdict assignment.
# ==============================================================================

import os
import sys
import json
import asyncio

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

import pytest

pytest.importorskip("google.genai")

from vulnerable_target.main import app
from backend.app.core.config import settings
import backend.app.services.deep_verifier as dv
from backend.tests._llmstub import as_provider
from backend.app.services.endpoint_catalog import (
    catalog_from_openapi,
    select_write_record_endpoint,
)

CATALOG = catalog_from_openapi(app.openapi())
RECORD_PATH = select_write_record_endpoint(CATALOG)   # the global write-record (audit-log)

BASE_URL = "http://127.0.0.1:8001"
APPROVED_HOST = "127.0.0.1:8001"
ALICE = "Bearer alice-token-aaaa"
UNIQUE = "m12-obj-scope-3fa9c1e4b2d"   # a unique, fuzzer-style injected value


def _audit(rows) -> str:
    """rows: list of (event_id, user_id, new_value) -> the get_audit_log shape."""
    return json.dumps({"events": [
        {"id": eid, "event": "record.update", "user_id": uid, "new_value": val}
        for (eid, uid, val) in rows
    ]})


# =============================================================================
# 1. Unit — the gate predicate _record_is_relevant_to_write (BOTH ways).
#    This is precisely the check the PRE-CHANGE HALF-1 lacked.
# =============================================================================

def test_gate_true_when_record_holds_the_callers_own_write():
    # The global record DOES record the caller's (user 1) landed baseline write -> relevant.
    body = _audit([(1, 1, UNIQUE)])
    assert dv._record_is_relevant_to_write(body, "1", [UNIQUE]) is True


def test_gate_false_when_record_has_no_caller_write():
    # The record has only UNRELATED activity (a different owner) -> NOT about this write-type.
    body = _audit([(1, 9, "unrelated-value")])
    assert dv._record_is_relevant_to_write(body, "1", [UNIQUE]) is False


def test_gate_false_on_empty_record():
    # A resource whose writes are not audited at all -> the record is empty -> step back.
    assert dv._record_is_relevant_to_write('{"events":[]}', "1", [UNIQUE]) is False


def test_gate_false_when_ids_or_values_missing():
    body = _audit([(1, 1, UNIQUE)])
    assert dv._record_is_relevant_to_write(body, None, [UNIQUE]) is False
    assert dv._record_is_relevant_to_write(body, "1", []) is False
    assert dv._record_is_relevant_to_write(None, "1", [UNIQUE]) is False


def test_pre_change_would_have_gathered_this_record():
    # PROOF the (b) case regressed the old behavior: select_write_record_endpoint still returns
    # the global record (the old, ungated HALF-1 would gather it unconditionally), while the new
    # gate predicate is False -> the ONLY thing standing between "hijack" and "step back" is the
    # gate this task added.
    assert select_write_record_endpoint(CATALOG) == RECORD_PATH
    assert dv._record_is_relevant_to_write(_audit([(1, 9, "x")]), "1", [UNIQUE]) is False


# =============================================================================
# 2. Integration — the gate's observable effect on the follow-up (BOTH ways).
# =============================================================================
def _resp(status: int, body: str) -> dict:
    return {"status_code": status, "content_length": len(body),
            "response_body": body, "elapsed_ms": 5, "url": BASE_URL}


def _fake_send(record_body: str, state_path: str = None, state_body: str = '{"ok":true}'):
    async def _send(client, parsed_request, base_url, custody=None, scope=None):
        method = str(parsed_request.get("method", "GET")).upper()
        path = parsed_request.get("path", "")
        if method in ("POST", "PUT", "PATCH", "DELETE"):
            return _resp(200, '{"status":"ok"}')             # opaque silent write
        if path == RECORD_PATH:
            return _resp(200, record_body)                   # the probed / gathered record
        if state_path and path == state_path:
            return _resp(200, state_body)                    # the object's own state read
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
            "confidence": 1.0, "reasoning": f"m12-mock:{verdict}", "evidence_path": evidence_path}


def _request_turn(path: str) -> dict:
    return {"decision": "request_more",
            "next_request": {"method": "GET", "path": path, "body": None, "reason": "m12-mock"},
            "verdict": None, "confidence": 0.5, "reasoning": "m12-mock:request_more"}


@pytest.fixture(autouse=True)
def _enable(monkeypatch):
    monkeypatch.setattr(settings, "AI_DEEP_VERIFY_ENABLED", True, raising=False)
    monkeypatch.setattr(settings, "GEMINI_API_KEY", "test-dummy-key", raising=False)


def _run(parsed_request, payload, *, record_body, turn1, turn2, monkeypatch,
         state_path=None, state_body='{"ok":true}'):
    monkeypatch.setattr(dv, "_send_request", _fake_send(record_body, state_path, state_body))
    monkeypatch.setattr(dv, "get_provider", as_provider(_fake_gemini(turn1, turn2)))
    return asyncio.run(dv.execute_deep_verification(
        parsed_request=parsed_request, payload=payload, base_url=BASE_URL,
        approved_host=APPROVED_HOST, auth_context={"Authorization": ALICE},
        available_endpoints=CATALOG,
    ))


_BOLA = {"location": "path_segment", "target_param": "1", "payload_string": "2", "type": "BOLA"}
# A write path with NO same-path GET read-back in the real catalog -> HALF-1 fires.
_WRITE_REQ = {"method": "POST", "path": "/api/widgets/1/color", "query_params": {},
              "headers": {"Content-Type": "application/json"}, "body": {"color": UNIQUE}}


# ---- (a) record IS about the attacked object -> HALF-1 still gathers -------------------
def test_a_record_about_object_is_still_gathered(monkeypatch):
    # The global record holds the caller's landed write (user 1) -> gate passes -> HALF-1
    # OVERRIDES the model's choice and gathers the record, exactly like B-1.
    res = _run(
        _WRITE_REQ, _BOLA,
        record_body=_audit([(1, 1, UNIQUE), (2, 2, UNIQUE)]),  # caller row + attacked row
        turn1=_request_turn("/api/widgets/2"),                 # model's own (overridden) choice
        turn2=_verdict_turn("verified"),
        monkeypatch=monkeypatch,
    )
    assert res.status == "completed"
    assert res.follow_up_request["path"] == RECORD_PATH        # gathered, not the model's path
    assert res.ai_verdict == "verified"                        # B-1 chain intact (exemption fires)
    assert res.guard_override == dv.WRITE_RECORD_EXEMPTION_REASON


# ---- (b) record is NOT about the attacked object -> HALF-1 steps back ------------------
def test_b_unrelated_record_makes_half1_step_back(monkeypatch):
    # The global record does NOT hold the caller's widget write (widgets aren't audited) ->
    # gate is False -> HALF-1 steps back -> the MODEL's follow-up (the object's state read)
    # is used. This is the fix: pre-change, HALF-1 would have hijacked with the record.
    res = _run(
        _WRITE_REQ, _BOLA,
        record_body='{"events":[]}',                           # no caller write recorded
        turn1=_request_turn("/api/widgets/2"),                 # model reads the object's STATE
        turn2=_verdict_turn("verified", evidence_path="color"),
        monkeypatch=monkeypatch,
        state_path="/api/widgets/2",
        state_body=json.dumps({"id": 2, "owner_id": 2, "color": UNIQUE}),
    )
    assert res.status == "completed"
    # THE OBJECT-SCOPE FIX: the follow-up is the model's own state read, NOT the hijacked record.
    assert res.follow_up_request["path"] == "/api/widgets/2"
    assert res.follow_up_request["path"] != RECORD_PATH
    # The M1.2 anchors confirm the leak on the state read:
    assert res.caller_identity_anchor == "confirmed"           # owner 2 != caller 1
    assert res.payload_causality_anchor in ("confirmed_at_path", "confirmed_in_body")
    # M1.2(A) NOW CLOSES THE GAP this test used to document: with the state-readback exemption
    # in place, a correct cross-path STATE read-back (all three anchors confirmed) is no longer
    # downgraded — it stands as `verified`. (The full both-ways proof of that exemption, incl.
    # the SAFE shape staying inconclusive, lives in test_m12_state_readback_exemption.py.)
    assert res.ai_verdict_raw == "verified"
    assert res.ai_verdict == "verified"
    assert res.guard_override == dv.STATE_READBACK_EXEMPTION_REASON
