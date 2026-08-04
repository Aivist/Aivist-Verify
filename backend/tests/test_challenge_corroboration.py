# ==============================================================================
# WAF-robustness Part 2 — a 200-status CHALLENGE PAGE must NEVER corroborate (VERDICT BOUNDARY).
#
# The risk: a WAF block/challenge page can return HTTP 200. If the ATTACK response and the D24
# OWNER-VIEW fetch both receive the same 200 block page, they are byte-similar, so the owner-view
# corroboration gate reads them as "attacker saw the owner's data" -> a FALSE owner_view_corroborated
# -> a false [CONFIRMED], silently. Part 2 adds a downgrade-only guard IN FRONT of corroboration.
#
# Drives the REAL execute_deep_verification; only the model + the socket (_send_request) are stubbed.
# Ground truth = the canned attack / owner-view responses each case defines. The model is pinned to
# 'verified' so only CODE can hold the line.
# ==============================================================================
import json
import asyncio

import pytest

pytest.importorskip("google.genai")

import backend.app.services.deep_verifier as dv
from backend.tests._llmstub import as_provider
from backend.app.core.config import settings
from backend.app.services.deep_verifier import (
    OwnerCredential, _CHALLENGE_PAGE_REASON, OWNER_VIEW_NOT_CORROBORATED_REASON,
)

ATTACKER = "Bearer alice-attacker"
OWNER = "Bearer bob-owner"

# A WAF/challenge page that happens to return HTTP 200 (carries block-signature keywords).
BLOCK_200 = json.dumps({"message": "Access Denied by WAF", "status": "blocked", "ref": "captcha"})
# The victim's genuine object data (no block signature).
REAL_DATA = json.dumps({"account_id": 7, "problem_details": "hydraulic press seized on unit 7",
                        "vin": "1HGCM82633A004352"})


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
                              "confidence": 1.0, "evidence_path": "account_id", "reasoning": "stub"}))
    return _gen


def _identity(req):
    auth = ""
    for k, v in (req.get("headers") or {}).items():
        if k.lower() == "authorization":
            auth = v
    return "owner" if "bob" in auth else "attacker"


def _run(attack, owner, monkeypatch, *, with_owner=True):
    """attack/owner are (status, body). Attacker baseline+attack get `attack`; the owner-view
    fetch gets `owner`. Read-semantic (payload=None); model pinned 'verified'."""
    async def _fake_send(client, req, base_url, custody=None, scope=None):
        if _identity(req) == "owner":
            return _resp(*owner)
        return _resp(*attack)
    monkeypatch.setattr(dv, "_send_request", _fake_send, raising=True)
    monkeypatch.setattr(dv, "get_provider", as_provider(_always_verified()))
    parsed = {"method": "GET", "path": "/api/report/7", "query_params": {}, "headers": {}, "body": None}

    async def _go():
        return await dv.execute_deep_verification(
            parsed_request=parsed, payload=None, base_url="http://testserver",
            approved_host="testserver", auth_context={"Authorization": ATTACKER},
            available_endpoints=["GET /api/report/7"],
            owner_credential=(OwnerCredential.from_config(OWNER) if with_owner else None),
        )
    return asyncio.run(_go())


# =============================================================================
# THE FP CASE — identical 200 block pages on both sides must NOT corroborate
# =============================================================================
def test_identical_200_block_pages_become_notdata(monkeypatch):
    res = _run((200, BLOCK_200), (200, BLOCK_200), monkeypatch)
    assert res.status == "degraded"                       # NOT DATA
    assert res.ai_verdict is None                         # never a confirmation
    assert res.ai_verdict != "verified"
    assert res.degraded_reason == _CHALLENGE_PAGE_REASON
    assert res.owner_view_corroborated in (None, False)   # owner-view did NOT corroborate


def test_attack_is_200_block_page_is_not_a_confirmation(monkeypatch):
    # Attack response is a 200 WAF block page; the owner-view returns the victim's REAL data.
    # They are dissimilar -> corroboration would not fire anyway -> the guard is gated OFF and the
    # existing owner-view gate correctly REFUTES (byte-identical to today). Either way: not confirmed.
    res = _run((200, BLOCK_200), (200, REAL_DATA), monkeypatch)
    assert res.ai_verdict != "verified"
    assert res.ai_verdict == "inconclusive"
    assert res.guard_override == OWNER_VIEW_NOT_CORROBORATED_REASON
    assert res.status == "completed"                      # NOT wrongly NOT-DATA'd (gating preserved)


# =============================================================================
# TRUE POSITIVE PRESERVED — real victim data on both sides STILL confirms
# =============================================================================
def test_genuine_vuln_with_real_data_still_confirmed(monkeypatch):
    res = _run((200, REAL_DATA), (200, REAL_DATA), monkeypatch)
    assert res.ai_verdict == "verified"                   # true positive survives the guard
    assert res.owner_view_corroborated is True


# =============================================================================
# DOWNGRADE-ONLY — the guard can only weaken; it never yields 'verified'
# =============================================================================
@pytest.mark.parametrize("attack,owner", [
    ((200, BLOCK_200), (200, BLOCK_200)),                 # both block -> NOT DATA
    ((200, BLOCK_200), (200, REAL_DATA)),                 # dissimilar -> refuted
    ((429, "rate limit exceeded"), (200, REAL_DATA)),     # non-2xx attack
    ((200, REAL_DATA), (403, "Forbidden")),               # owner-view denied (non-2xx)
])
def test_guard_is_downgrade_only_never_verified(attack, owner, monkeypatch):
    res = _run(attack, owner, monkeypatch)
    assert res.ai_verdict != "verified"                   # a challenge on either side never confirms


def test_no_owner_credential_is_unaffected(monkeypatch):
    # With no owner credential the D24 gate (and this guard) do not run at all: the read-semantic
    # verdict is the model's, exactly as before Part 2 (byte-identical).
    res = _run((200, BLOCK_200), (200, BLOCK_200), monkeypatch, with_owner=False)
    assert res.status == "completed"
    assert res.degraded_reason != _CHALLENGE_PAGE_REASON
