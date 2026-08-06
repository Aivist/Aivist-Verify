# ==============================================================================
# Cut B, commit 1 — record enrichment: flatten the engine's ALREADY-captured, truncated HTTP
# evidence into a record under "evidence", with the SECRET-LEAKAGE RED LINE enforced (every
# flattened byte passes the credential redactor; no live token / bearer / cookie / password may
# enter the record). The victim's data — the actual cross-user evidence — MUST survive intact.
# ==============================================================================
import os
import sys
import json
import types

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, _REPO_ROOT)

from backend.app.services.deep_verifier import flatten_evidence, redact_secrets
from backend.app.cli.external_verify import _record_from_result

# a realistic live token (JWT-shaped) used as the leakage canary
LIVE_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.SIG-abc123DEF456"
VICTIM_SSN = "999-11-2222"          # the victim's data == the EVIDENCE; must NEVER be redacted


def _res(**over):
    base = dict(
        baseline={
            "request": {"method": "GET", "url": "http://t/api/records/1",
                        "headers": {"Authorization": "Bearer " + LIVE_JWT}, "body": None},
            "response": {"status_code": 200, "content_length": 24,
                         "body": '{"id":1,"owner":"alice"}', "url": "http://t/api/records/1"}},
        attack={
            "request": {"method": "GET", "url": "http://t/api/records/2",
                        "headers": {"Authorization": "Bearer " + LIVE_JWT}, "body": None},
            "response": {"status_code": 200, "content_length": 42,
                         "body": '{"id":2,"owner":"bob","ssn":"' + VICTIM_SSN + '"}',
                         "url": "http://t/api/records/2"}},
        follow_up_request={"method": "GET", "path": "/api/records/2", "body": None, "reason": "read back"},
        follow_up_response={"status_code": 200, "content_length": 30,
                            "body": '{"id":2,"ssn":"' + VICTIM_SSN + '"}', "url": "http://t/api/records/2"},
        owner_view_status=200, owner_view_reason="ok", owner_view_corroborated=True,
        owner_view_body='{"id":2,"owner":"bob","ssn":"' + VICTIM_SSN + '"}',
    )
    base.update(over)
    return types.SimpleNamespace(**base)


# ------------------------------------------------------------------ enrichment
def test_flatten_evidence_has_all_four_sections():
    ev = flatten_evidence(_res())
    assert set(ev) >= {"baseline", "attack", "follow_up", "owner_view"}
    assert ev["attack"]["request"]["method"] == "GET"
    assert ev["attack"]["request"]["url"] == "http://t/api/records/2"
    assert ev["attack"]["response"]["status_code"] == 200
    assert ev["follow_up"]["request"]["method"] == "GET"          # follow-up uses `path` -> url
    assert ev["owner_view"]["status"] == 200 and ev["owner_view"]["corroborated"] is True


def test_flatten_evidence_none_when_no_exchange_captured():
    r = types.SimpleNamespace(baseline=None, attack=None, follow_up_request=None,
                              follow_up_response=None, owner_view_status=None, owner_view_body=None)
    assert flatten_evidence(r) is None                            # degraded -> renderer falls back to cut A


# ------------------------------------------------------------------ REDACTION (load-bearing)
def test_flatten_evidence_masks_auth_header_but_shows_victim_data():
    ev = flatten_evidence(_res())
    blob = json.dumps(ev)
    # THE RED LINE: no live token anywhere in the flattened record (header OR body)
    assert LIVE_JWT not in blob
    assert "***REDACTED***" in ev["attack"]["request"]["headers"]["Authorization"]
    # the victim's SSN — the actual proof of cross-user access — is shown, NOT over-redacted
    assert VICTIM_SSN in ev["attack"]["response"]["body"]
    assert VICTIM_SSN in ev["owner_view"]["body"]


def test_flatten_evidence_redacts_a_token_echoed_inside_a_response_body():
    # a token echoed INTO a response body (JWT + a "token": key) must not survive into the record.
    r = _res(attack={
        "request": {"method": "GET", "url": "http://t/x", "headers": {}, "body": None},
        "response": {"status_code": 200, "content_length": 80,
                     "body": '{"session_token":"' + LIVE_JWT + '","balance":4200}', "url": "http://t/x"}})
    ev = flatten_evidence(r)
    body = ev["attack"]["response"]["body"]
    assert LIVE_JWT not in body and "***REDACTED***" in body      # token masked ...
    assert "4200" in body                                         # ... non-secret data preserved


def test_record_from_result_carries_redacted_evidence_with_victim_data():
    op = {"method": "GET", "baseline_path": "/api/records/1", "shape": "read_semantic", "body": None}
    rec = _record_from_result(_res(ai_verdict="verified"), op, None)
    assert rec["evidence"] is not None
    blob = json.dumps(rec["evidence"])
    assert LIVE_JWT not in blob                                   # a shared record carries NO live secret
    assert VICTIM_SSN in blob                                     # the cross-user evidence is intact


def test_record_from_result_degraded_run_still_redacts_or_omits():
    op = {"method": "GET", "baseline_path": "/api/records/1", "shape": "read_semantic", "body": None}
    rec = _record_from_result(_res(), op, "timeout")             # degraded
    # evidence may still be present (a captured exchange) — but it must never leak a live token
    assert LIVE_JWT not in json.dumps(rec.get("evidence"))


# ------------------------------------------------------------------ the redactor itself
def test_redact_secrets_targets_credentials_not_victim_data():
    assert redact_secrets("Authorization: Bearer " + LIVE_JWT) == "Authorization: Bearer ***REDACTED***"
    assert LIVE_JWT not in redact_secrets('{"token":"' + LIVE_JWT + '"}')
    assert redact_secrets('"password":"hunter2"') == '"password":"***REDACTED***"'
    assert redact_secrets("client_secret=csecretval") == "client_secret=***REDACTED***"
    # victim / business data is NOT a credential -> preserved perfectly (the evidence must show)
    assert redact_secrets('{"ssn":"' + VICTIM_SSN + '","balance":4200}') \
        == '{"ssn":"' + VICTIM_SSN + '","balance":4200}'
    assert redact_secrets(None) is None and redact_secrets("") == ""
