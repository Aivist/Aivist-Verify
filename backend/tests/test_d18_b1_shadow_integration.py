# ==============================================================================
# B-1 shadow-path INTEGRATION regression test (ROADMAP §4 "prove the shadow path";
# TECH_DEBT D22). Runs the REAL execute_deep_verification end-to-end with Gemini
# and the HTTP target MOCKED — no live API, no token cost, fully deterministic.
#
# Unlike test_d18_b1_write_record.py (which unit-tests the deterministic helpers in
# isolation), this exercises the actual control flow of execute_deep_verification:
# baseline -> attack -> HALF 1 code-gathered write-record follow-up -> HALF 2
# content-match -> cross-resource guard -> FINAL verdict. It locks in the milestone:
#
#   * X-CROSS (REAL): the CODE gathers the write-record read-back (overriding the
#     model's wrong same-named-field choice); when the audit record links the
#     ATTACKED id to the value THIS attack wrote, the exemption fires and FINAL=verified.
#   * X-SAFE (SECURE) — THE SAFETY ASSERTION, the point of this test: the write-record
#     is gathered, but the structural content match FAILS (no audit row for the attacked
#     id), so the exemption does NOT fire and FINAL stays inconclusive — NEVER verified,
#     even when the model wrongly says "verified".
#   * HALF 2 only PREVENTS a wrong downgrade; it never FABRICATES verified — when the
#     model hedges to inconclusive on X-CROSS, FINAL stays inconclusive.
#   * A same-path case (P0-PROFILE / P0-AVATAR): no code-gathering is triggered (a real
#     same-path GET read-back exists), and the verdict is the model's, unchanged.
#
# ANTI-CHEATING (mirrors the human-owned constraints):
#   - The audit-log read-back bodies below are NOT invented: they mirror the REAL
#     vulnerable_target behavior for ONE fresh baseline+attack (see vulnerable_target/
#     main.py::update_display_name / update_nickname / get_audit_log): a landed write
#     appends {id, event, user_id, new_value}; X-SAFE's cross-user write is DROPPED so
#     no row exists for the attacked id.
#   - The record path is resolved STRUCTURALLY from the real catalog via
#     select_write_record_endpoint(...) — the literal "/api/audit-log" is never written
#     here, so a target rename would be followed, not broken (no hardcoding).
#   - The test conforms to the code's real behavior; it never adjusts the gate.
# ==============================================================================

import os
import sys
import json
import asyncio

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

import pytest

# The real verifier needs the google-genai SDK importable to construct its (unused,
# because _gemini_generate is mocked) client; it is a hard project dependency. Skip
# rather than false-fail if a stripped env lacks it.
pytest.importorskip("google.genai")

from vulnerable_target.main import app
from backend.app.core.config import settings
import backend.app.services.deep_verifier as dv
from backend.tests._llmstub import as_provider
from backend.app.services.endpoint_catalog import (
    catalog_from_openapi,
    select_write_record_endpoint,
)

# The real attack-surface catalog, and the write-record path chosen STRUCTURALLY
# (no hardcoded "/api/audit-log" literal in this test).
CATALOG = catalog_from_openapi(app.openapi())
RECORD_PATH = select_write_record_endpoint(CATALOG)

BASE_URL = "http://127.0.0.1:8001"
APPROVED_HOST = "127.0.0.1:8001"
ALICE = "Bearer alice-token-aaaa"
WRITTEN = "b1_regtest_value"  # the value THIS attack writes (baseline body, path-mutated)


# -----------------------------------------------------------------------------
# Deterministic HTTP mock — mirrors the REAL target's per-finding behavior.
# -----------------------------------------------------------------------------
def _resp(status: int, body: str) -> dict:
    return {"status_code": status, "content_length": len(body),
            "response_body": body, "elapsed_ms": 5, "url": BASE_URL}


def _audit_body(rows) -> str:
    """rows: list of (event_id, user_id, new_value) -> the get_audit_log shape."""
    return json.dumps({"events": [
        {"id": eid, "event": "record.update", "user_id": uid, "new_value": val}
        for (eid, uid, val) in rows
    ]})


# X-CROSS (REAL): BOTH writes land + audit -> baseline self-write (user 1) and the
# cross-user attack (user 2). A record links the ATTACKED id (2) to the written value.
XCROSS_AUDIT = _audit_body([(1, 1, WRITTEN), (2, 2, WRITTEN)])
# X-SAFE (SECURE): ONLY the owner's self-write (user 1) is audited; the cross-user
# attack is silently dropped -> NO row for the attacked id (2).
XSAFE_AUDIT = _audit_body([(1, 1, WRITTEN)])


def _fake_send(record_body: str, readback_body: str = '{"ok":true}'):
    """Stand in for deep_verifier._send_request. Writes -> opaque 200 {"status":"ok"};
    a GET to the structurally-chosen record path -> the audit body; any other GET ->
    a generic same-path read-back body."""
    async def _send(client, parsed_request, base_url, custody=None, scope=None):
        method = str(parsed_request.get("method", "GET")).upper()
        path = parsed_request.get("path", "")
        if method in ("POST", "PUT", "PATCH", "DELETE"):
            return _resp(200, '{"status":"ok"}')
        if path == RECORD_PATH:
            return _resp(200, record_body)
        return _resp(200, readback_body)
    return _send


def _fake_gemini(turn1: dict, turn2: dict):
    """Stand in for deep_verifier._gemini_generate: return turn1 then turn2 as the
    model's verbatim JSON. No network, no key use."""
    class _R:
        def __init__(self, text): self.text = text
    seq = iter([json.dumps(turn1), json.dumps(turn2)])

    async def _gen(*args, **kwargs):
        return _R(next(seq))
    return _gen


def _verdict_turn(verdict: str) -> dict:
    return {"decision": "verdict", "next_request": None, "verdict": verdict,
            "confidence": 1.0, "reasoning": f"regression-mock:{verdict}"}


def _request_turn(path: str) -> dict:
    # The model's (possibly WRONG) same-named-field follow-up choice.
    return {"decision": "request_more",
            "next_request": {"method": "GET", "path": path, "body": None,
                             "reason": "regression-mock: model choice"},
            "verdict": None, "confidence": 0.5, "reasoning": "regression-mock:request_more"}


@pytest.fixture(autouse=True)
def _enable_verifier(monkeypatch):
    # Both gates on; a dummy key so the verifier reaches the (mocked) model step.
    monkeypatch.setattr(settings, "AI_DEEP_VERIFY_ENABLED", True, raising=False)
    monkeypatch.setattr(settings, "GEMINI_API_KEY", "test-dummy-key", raising=False)


def _run_deep_verify(parsed_request, payload, *, record_body, turn1, turn2, monkeypatch,
                     readback_body='{"ok":true}'):
    monkeypatch.setattr(dv, "_send_request", _fake_send(record_body, readback_body))
    monkeypatch.setattr(dv, "get_provider", as_provider(_fake_gemini(turn1, turn2)))
    return asyncio.run(dv.execute_deep_verification(
        parsed_request=parsed_request,
        payload=payload,
        base_url=BASE_URL,
        approved_host=APPROVED_HOST,
        auth_context={"Authorization": ALICE},
        available_endpoints=CATALOG,
    ))


# Cross-path write findings (NO same-path GET read-back exists for these).
_XCROSS_REQ = {"method": "POST", "path": "/api/users/1/display-name", "query_params": {},
               "headers": {"Content-Type": "application/json"}, "body": {"display_name": WRITTEN}}
_XSAFE_REQ = {"method": "POST", "path": "/api/users/1/nickname", "query_params": {},
              "headers": {"Content-Type": "application/json"}, "body": {"nickname": WRITTEN}}
# Same-path write findings (a real GET read-back on the SAME resource DOES exist).
_PROFILE_REQ = {"method": "POST", "path": "/api/users/1/profile", "query_params": {},
                "headers": {"Content-Type": "application/json"}, "body": {"display_name": WRITTEN}}
_AVATAR_REQ = {"method": "POST", "path": "/api/users/1/avatar", "query_params": {},
               "headers": {"Content-Type": "application/json"}, "body": {"avatar_url": WRITTEN}}
_BOLA = {"location": "path_segment", "target_param": "1", "payload_string": "2", "type": "BOLA"}


# -----------------------------------------------------------------------------
# X-CROSS — code gathers the write-record; matching record -> FINAL verified.
# -----------------------------------------------------------------------------
def test_xcross_code_gathers_record_and_reaches_verified(monkeypatch):
    res = _run_deep_verify(
        _XCROSS_REQ, _BOLA,
        record_body=XCROSS_AUDIT,
        # The model asks for the WRONG same-named-field endpoint; the CODE overrides it.
        turn1=_request_turn("/api/users/2/profile"),
        turn2=_verdict_turn("verified"),
        monkeypatch=monkeypatch,
    )
    assert res.status == "completed"
    # HALF 1: the follow-up actually performed is the CODE-gathered record path, not
    # the model's /profile choice.
    assert res.follow_up_request is not None
    assert res.follow_up_request["path"] == RECORD_PATH
    assert res.follow_up_request["path"] != "/api/users/2/profile"
    # HALF 2: exemption fires on the content match -> FINAL verified (raw preserved).
    assert res.ai_verdict_raw == "verified"
    assert res.ai_verdict == "verified"
    assert res.guard_override == dv.WRITE_RECORD_EXEMPTION_REASON


# -----------------------------------------------------------------------------
# X-CROSS — HALF 2 never FABRICATES verified: if the model hedges, FINAL hedges.
# -----------------------------------------------------------------------------
def test_xcross_model_hedge_is_not_upgraded_to_verified(monkeypatch):
    res = _run_deep_verify(
        _XCROSS_REQ, _BOLA,
        record_body=XCROSS_AUDIT,  # a matching record EXISTS...
        turn1=_request_turn("/api/users/2/profile"),
        turn2=_verdict_turn("inconclusive"),  # ...but the model does not commit.
        monkeypatch=monkeypatch,
    )
    assert res.status == "completed"
    assert res.follow_up_request["path"] == RECORD_PATH  # code still gathered it
    assert res.ai_verdict_raw == "inconclusive"
    # The exemption only keeps a model 'verified' decisive; it invents nothing.
    assert res.ai_verdict == "inconclusive"
    assert res.guard_override is None


# -----------------------------------------------------------------------------
# X-SAFE — THE SAFETY ASSERTION: content match FAILS -> never verified.
# -----------------------------------------------------------------------------
def test_xsafe_no_matching_record_stays_inconclusive_even_if_model_says_verified(monkeypatch):
    res = _run_deep_verify(
        _XSAFE_REQ, _BOLA,
        record_body=XSAFE_AUDIT,  # only the user-1 self-write; NO row for attacked id 2
        turn1=_request_turn("/api/users/2/profile"),
        turn2=_verdict_turn("verified"),  # ADVERSARIAL: model wrongly claims success
        monkeypatch=monkeypatch,
    )
    assert res.status == "completed"
    assert res.follow_up_request["path"] == RECORD_PATH  # the record WAS gathered
    assert res.ai_verdict_raw == "verified"
    # The structural content match fails (no record for the attacked id), so the
    # exemption does NOT fire and the cross-resource guard downgrades it.
    assert res.ai_verdict == "inconclusive"
    assert res.ai_verdict != "verified"  # the integrity hole stays shut
    assert res.guard_override == dv.CROSS_RESOURCE_OVERRIDE_REASON


# -----------------------------------------------------------------------------
# Same-path P0 reverse-guards — NO code-gathering; model verdict passes through.
# -----------------------------------------------------------------------------
def test_samepath_profile_no_code_gathering_verified(monkeypatch):
    res = _run_deep_verify(
        _PROFILE_REQ, _BOLA,
        record_body=XCROSS_AUDIT,  # present but must be IRRELEVANT for a same-path case
        turn1=_request_turn("/api/users/2/profile"),  # model's same-resource read-back
        turn2=_verdict_turn("verified"),
        monkeypatch=monkeypatch,
        readback_body='{"user_id":2,"display_name":"' + WRITTEN + '"}',
    )
    assert res.status == "completed"
    # A real same-path GET read-back exists, so the code does NOT gather a record; the
    # follow-up is the model's same-resource choice, not the write-record path.
    assert res.follow_up_request["path"] == "/api/users/2/profile"
    assert res.follow_up_request["path"] != RECORD_PATH
    assert res.ai_verdict_raw == "verified"
    assert res.ai_verdict == "verified"
    assert res.guard_override is None  # same-resource read-back is already decisive


def test_samepath_avatar_no_code_gathering_failed(monkeypatch):
    res = _run_deep_verify(
        _AVATAR_REQ, _BOLA,
        record_body=XSAFE_AUDIT,
        turn1=_request_turn("/api/users/2/avatar"),
        turn2=_verdict_turn("failed"),
        monkeypatch=monkeypatch,
        readback_body='{"user_id":2,"avatar_url":"https://avatars.local/bob.png"}',
    )
    assert res.status == "completed"
    assert res.follow_up_request["path"] == "/api/users/2/avatar"
    assert res.follow_up_request["path"] != RECORD_PATH
    assert res.ai_verdict_raw == "failed"
    assert res.ai_verdict == "failed"
    assert res.guard_override is None
