# ==============================================================================
# D29 END-TO-END — the query-string / non-path IDOR is now CONFIRMABLE, and the zero-FP
# code gate still holds on it.
#
# Drives the REAL execute_deep_verification against the REAL query_target lab (in-process
# ASGI; only the MODEL call is stubbed, pinned to `verified` on every case — so every HTTP
# request the engine issues, including the query-string attack and the D24 owner-view
# re-read, is genuinely executed). The object id lives in the QUERY STRING (?report_id= /
# ?note_id=): the baseline carries the attacker's own id, the payload swaps ONLY that query
# id for the attack, and the owner-view read must re-hit the SAME query id — the exact path
# D29 fixed in the assembly layer, proven here through the whole engine.
#
# The point is twofold, and both directions must hold:
#   * QS-READ-VULN (REAL): the attacker's cross-account read matches the owner's authentic
#     view, so the owner-view gate corroborates and the verdict stands `verified` — the
#     false negative D29 recorded (a REAL query-string IDOR returning REFUTED) is GONE.
#   * QS-READ-SAFE (SECURE): the soft-200 denial does NOT match the owner's view, so the
#     gate downgrades the model's `verified` — zero-FP is unchanged on the new addressing.
#
# The model is pinned to `verified` on BOTH, reproducing the failure mode, so anything that
# still comes out non-verified was held by CODE, not the model.
# ==============================================================================
import asyncio
import json

import httpx
import pytest

pytest.importorskip("google.genai")

import backend.app.services.deep_verifier as dv
from backend.tests._llmstub import as_provider
from backend.app.core.config import settings
from backend.app.services.deep_verifier import OwnerCredential, OWNER_VIEW_NOT_CORROBORATED_REASON

from query_target.main import (
    app as QUERY_APP,
    ALICE_TOKEN, BOB_TOKEN,
    REPORT_ALICE_ID, REPORT_BOB_ID, NOTE_ALICE_ID, NOTE_BOB_ID,
)

ATTACKER = f"Bearer {ALICE_TOKEN}"
OWNER = f"Bearer {BOB_TOKEN}"


@pytest.fixture(autouse=True)
def _enable_verifier(monkeypatch):
    monkeypatch.setattr(settings, "AI_DEEP_VERIFY_ENABLED", True, raising=False)
    monkeypatch.setattr(settings, "GEMINI_API_KEY", "test-dummy-key", raising=False)


def _always_verified():
    """Pin the model to `verified` on every case, so only CODE can hold the line."""
    class _R:
        def __init__(self, text): self.text = text

    async def _gen(*args, **kwargs):
        return _R(json.dumps({
            "decision": "verdict", "next_request": None, "verdict": "verified",
            "confidence": 1.0, "evidence_path": "problem_details",
            "reasoning": "d29-e2e mock: model asserts verified",
        }))
    return _gen


def _run(path, id_param, attacker_own_id, victim_id, endpoint, monkeypatch):
    """Run the query-string BOLA end-to-end: baseline carries the attacker's OWN query id,
    the payload swaps only that query param's value to the victim id."""
    monkeypatch.setattr(dv, "get_provider", as_provider(_always_verified()))
    parsed = {
        "method": "GET",
        "path": path,
        "query_params": {id_param: attacker_own_id},         # baseline carries the attacker's own id
        "headers": {},
        "body": None,
    }
    payload = {"location": "query_param", "target_param": id_param,
               "payload_string": victim_id, "type": "BOLA"}   # swap only the query id

    async def _go():
        async with QUERY_APP.router.lifespan_context(QUERY_APP):
            transport = httpx.ASGITransport(app=QUERY_APP)
            real_cls = httpx.AsyncClient

            def _patched(*a, **kw):
                kw.pop("verify", None)
                kw["transport"] = transport
                return real_cls(*a, **kw)

            monkeypatch.setattr(dv.httpx, "AsyncClient", _patched)
            return await dv.execute_deep_verification(
                parsed_request=parsed,
                payload=payload,
                base_url="http://testserver",
                approved_host="testserver",
                auth_context={"Authorization": ATTACKER},
                available_endpoints=[endpoint],
                owner_credential=OwnerCredential.from_config(OWNER),
            )
    return asyncio.run(_go())


def test_QS_READ_VULN_confirms_via_owner_view(monkeypatch):
    """REAL query-string IDOR: the false negative is gone — it CONFIRMS."""
    res = _run("/reports", "report_id", REPORT_ALICE_ID, REPORT_BOB_ID,
               "GET /reports", monkeypatch)
    assert res.ai_verdict_raw == "verified"
    assert res.ai_verdict == "verified"                 # confirmed end-to-end
    assert res.owner_view_corroborated is True          # via the query-carrying owner re-read
    assert res.guard_override is None                   # nothing downgraded it


def test_QS_READ_SAFE_is_downgraded_by_owner_view_gate(monkeypatch):
    """SECURE query-string read: the model says verified, CODE refuses — zero-FP unchanged."""
    res = _run("/notes", "note_id", NOTE_ALICE_ID, NOTE_BOB_ID,
               "GET /notes", monkeypatch)
    assert res.ai_verdict_raw == "verified"             # the model DID say verified ...
    assert res.ai_verdict != "verified"                 # ... and CODE refused it
    assert res.guard_override == OWNER_VIEW_NOT_CORROBORATED_REASON


def test_QS_no_owner_credential_does_not_manufacture_confirmation(monkeypatch):
    """Downgrade-only sanity: with no owner credential the gate cannot run, so the SAFE case
    is NOT confirmed by code inventing corroboration (behavior degrades to today's, and the
    read-semantic shape without an owner view is not promoted to a code-held `verified`)."""
    monkeypatch.setattr(dv, "get_provider", as_provider(_always_verified()))
    parsed = {"method": "GET", "path": "/notes", "query_params": {"note_id": NOTE_ALICE_ID},
              "headers": {}, "body": None}
    payload = {"location": "query_param", "target_param": "note_id",
               "payload_string": NOTE_BOB_ID, "type": "BOLA"}

    async def _go():
        async with QUERY_APP.router.lifespan_context(QUERY_APP):
            transport = httpx.ASGITransport(app=QUERY_APP)
            real_cls = httpx.AsyncClient
            monkeypatch.setattr(dv.httpx, "AsyncClient",
                                lambda *a, **kw: (kw.pop("verify", None),
                                                  real_cls(*a, transport=transport, **kw))[1])
            return await dv.execute_deep_verification(
                parsed_request=parsed, payload=payload, base_url="http://testserver",
                approved_host="testserver", auth_context={"Authorization": ATTACKER},
                available_endpoints=["GET /notes"], owner_credential=None)
    res = asyncio.run(_go())
    # owner_view gate never ran (no owner credential); the code did not fabricate corroboration.
    assert res.owner_view_corroborated is not True
