# ==============================================================================
# WAF-robustness Part 1 — the run-level challenge CIRCUIT BREAKER (offline, downgrade-only).
#
# Drives the REAL execute_deep_verification with the socket (_send_request) and the model stubbed.
# Proves: a run that is systematically challenged/rate-limited ABORTS and is marked NOT DATA with
# the exact degraded_reason, BEFORE spending a model call; the breaker is DOWNGRADE-ONLY (never a
# verdict); a single transient challenge does NOT abort; and with challenge_break=False (the lab /
# measurement default) the breaker never counts or aborts — behavior is byte-identical.
# ==============================================================================
import json
import asyncio

import pytest

pytest.importorskip("google.genai")

import backend.app.services.deep_verifier as dv
from backend.app.core.config import settings
from backend.app.services.deep_verifier import (
    OwnerCredential, _is_challenge_response, _CHALLENGE_ABORT_REASON, _CHALLENGE_ABORT_THRESHOLD,
)


@pytest.fixture(autouse=True)
def _enable(monkeypatch):
    monkeypatch.setattr(settings, "AI_DEEP_VERIFY_ENABLED", True, raising=False)
    monkeypatch.setattr(settings, "GEMINI_API_KEY", "test-dummy-key", raising=False)


def _resp(status, body="{}"):
    return {"status_code": status, "content_length": len(body or ""),
            "response_body": body, "elapsed_ms": 1.0, "url": "http://testserver/x"}


def _provider(calls):
    class _P:
        default_model = "test-model"
        def is_configured(self): return True
        async def generate(self, **k):
            calls.append(1)
            return json.dumps({"decision": "verdict", "next_request": None, "verdict": "verified",
                               "confidence": 1.0, "evidence_path": None, "reasoning": "stub"})
    return lambda: _P()


def _run(responder, *, challenge_break, monkeypatch):
    """Drive a READ-semantic run (payload=None: baseline == attack). `responder(i)` returns the
    response dict for the i-th attacker-side send. Returns (result, provider_call_count)."""
    calls = []
    idx = {"i": 0}

    async def _fake_send(client, req, base_url, custody=None, scope=None):
        r = responder(idx["i"]); idx["i"] += 1
        return r

    monkeypatch.setattr(dv, "_send_request", _fake_send, raising=True)
    monkeypatch.setattr(dv, "get_provider", _provider(calls))
    parsed = {"method": "GET", "path": "/api/x/1", "query_params": {}, "headers": {}, "body": None}

    async def _go():
        return await dv.execute_deep_verification(
            parsed_request=parsed, payload=None, base_url="http://testserver",
            approved_host="testserver", auth_context={"Authorization": "Bearer atk"},
            available_endpoints=["GET /api/x/1"], challenge_break=challenge_break,
        )
    res = asyncio.run(_go())
    return res, len(calls)


# ---------------------------------------------------------------------------
# _is_challenge_response — the ONE shared detector (reuses fuzzer._BLOCK_KEYWORDS)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("status", [401, 403, 429])
def test_challenge_statuses_are_challenges(status):
    assert _is_challenge_response(status, "anything") is True


@pytest.mark.parametrize("body", [
    '{"error":"forbidden"}', "Access Denied", "request blocked by WAF",
    "please solve the captcha", "rate limit exceeded", "not authorized",
])
def test_200_with_block_signature_is_a_challenge(body):
    assert _is_challenge_response(200, body) is True


@pytest.mark.parametrize("status,body", [
    (200, '{"account_id": 7, "data": "real object"}'),   # clean 2xx real data -> NOT a challenge
    (201, '{"created": true}'),
    (500, "internal server error"),                       # a 5xx is not a challenge status
    (404, "not found"),
    (302, "redirect"),
])
def test_clean_or_other_responses_are_not_challenges(status, body):
    assert _is_challenge_response(status, body) is False


def test_challenge_detector_never_raises_on_bad_input():
    assert _is_challenge_response(None, None) is False
    assert _is_challenge_response("nan", None) is False
    assert _is_challenge_response(200, None) is False


# ---------------------------------------------------------------------------
# The breaker: abort -> NOT DATA, before the model call
# ---------------------------------------------------------------------------
def test_persistent_429_aborts_run_to_notdata_before_model(monkeypatch):
    res, provider_calls = _run(lambda i: _resp(429), challenge_break=True, monkeypatch=monkeypatch)
    assert res.status == "degraded"
    assert res.ai_verdict is None                          # downgrade-only: NEVER a verdict
    assert res.degraded_reason == _CHALLENGE_ABORT_REASON
    assert provider_calls == 0                             # aborted BEFORE spending a model call


def test_200_block_page_mid_sequence_aborts_to_notdata(monkeypatch):
    # A 200 whose body is a WAF block page counts as a challenge just like a 429.
    res, provider_calls = _run(lambda i: _resp(200, '{"message":"request blocked by WAF"}'),
                               challenge_break=True, monkeypatch=monkeypatch)
    assert res.status == "degraded"
    assert res.ai_verdict is None
    assert res.degraded_reason == _CHALLENGE_ABORT_REASON
    assert provider_calls == 0


def test_single_transient_challenge_does_not_abort(monkeypatch):
    # baseline challenged, attack clean -> count 1 < threshold (2) -> run proceeds to the model.
    responses = [_resp(429), _resp(200, '{"account_id": 7}')]
    res, provider_calls = _run(lambda i: responses[min(i, 1)], challenge_break=True, monkeypatch=monkeypatch)
    assert res.degraded_reason != _CHALLENGE_ABORT_REASON  # breaker did NOT fire
    assert provider_calls == 1                             # reached the model


def test_threshold_is_the_named_constant_not_inline_magic():
    assert _CHALLENGE_ABORT_THRESHOLD == 2


# ---------------------------------------------------------------------------
# Byte-identical: with challenge_break=False (lab/measurement default) the breaker never fires
# ---------------------------------------------------------------------------
def test_breaker_off_by_default_is_byte_identical(monkeypatch):
    # The SAME persistent-429 sequence that aborts above must NOT abort when the breaker is off;
    # the run proceeds to the model exactly as before this feature existed.
    res, provider_calls = _run(lambda i: _resp(429), challenge_break=False, monkeypatch=monkeypatch)
    assert res.degraded_reason != _CHALLENGE_ABORT_REASON  # breaker never counted / aborted
    assert provider_calls == 1                             # reached the model (byte-identical path)
