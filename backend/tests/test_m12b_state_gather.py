# ==============================================================================
# M1.2(B) — DETERMINISTIC OBJECT-STATE READ-BACK GATHER.
#
# WHY: the state-readback exemption (M1.2(A)) is proven safe but got NO inputs live —
# gemini-2.5-pro never fetches the attacked object's own state via its OTHER path (0/5; it
# tried the same path -> 405, or the empty audit-log). That is B-1's wall (decisive endpoint
# chosen 0/20 unaided). B-1 solved it by CODE-GATHERING the write-record; this mirrors it for
# the object's own STATE. Code fetches the evidence; the model still does the irreplaceable
# part — semantically reading that state.
#
# THE RESOLVER IS ONLY A FETCHER. It never decides a verdict. If it fetches the wrong object,
# the exemption's three-AND gate (owner==attacked AND caller!=owner AND payload-causality)
# simply fails to confirm and the verdict stays "inconclusive" — the SAFE direction.
#
# HUMAN-OWNED GROUND TRUTH: the SAFE shape (dropped write -> unique value ABSENT) must NEVER
# reach `verified`. Do not relax payload-causality to make anything green. A `verified` on the
# SAFE shape is the integrity hole reopened — fix the gate, not the test.
#
# No live model, no network: the resolver is asserted directly, and the integrated flow runs
# the REAL execute_deep_verification with a mocked Gemini + transport.
# ==============================================================================

import os
import sys
import json
import asyncio

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

import pytest

from backend.app.services.endpoint_catalog import (
    catalog_from_openapi,
    select_object_state_endpoint,
    select_write_record_endpoint,
    attacked_resource_noun,
)

from vulnerable_target.main import app                              # noqa: E402

CATALOG = catalog_from_openapi(app.openapi())
RECORD_PATH = select_write_record_endpoint(CATALOG)                  # the global write-record


# =============================================================================
# 1. Resolver — picks the attacked object's OWN state endpoint (unit, pure).
# =============================================================================

def test_resolver_picks_the_objects_own_state_endpoint():
    # write POST /api/users/2/gizmo -> the object's state lives at the DIFFERENT path
    # GET /api/gizmos/{gizmo_id}; the resolver binds the attacked id.
    assert select_object_state_endpoint(
        CATALOG, "/api/users/2/gizmo", attacked_object_id="2"
    ) == "/api/gizmos/2"


def test_resolver_picks_state_endpoint_for_the_secure_mirror_too():
    # The resolver is verdict-blind: it resolves the SAFE mirror identically. (Whether the
    # write landed is decided later, by payload-causality — not by the fetcher.)
    assert select_object_state_endpoint(
        CATALOG, "/api/users/2/sprocket", attacked_object_id="2"
    ) == "/api/sprockets/2"


def test_resolver_returns_none_when_no_state_endpoint_exists():
    # X-CROSS / X-SAFE (display-name / nickname) have NO state read-back anywhere — those are
    # confirmed via the write-record (B-1). The resolver must NOT fabricate one.
    assert select_object_state_endpoint(
        CATALOG, "/api/users/2/display-name", attacked_object_id="2"
    ) is None
    assert select_object_state_endpoint(
        CATALOG, "/api/users/2/nickname", attacked_object_id="2"
    ) is None


def test_resolver_rejects_the_attacks_own_path():
    # A candidate that resolves to the attack's OWN path is not a cross-path state read.
    entries = ["POST /api/gizmos/{gizmo_id}", "GET /api/gizmos/{gizmo_id}"]
    assert select_object_state_endpoint(
        entries, "/api/gizmos/2", attacked_object_id="2"
    ) is None


def test_resolver_skips_write_record_endpoints():
    # A record/log endpoint carrying the noun is B-1's channel — the two gathers stay DISJOINT.
    entries = ["GET /api/gizmo-history/{gizmo_id}  [tags: history]"]
    assert select_object_state_endpoint(
        entries, "/api/users/2/gizmo", attacked_object_id="2"
    ) is None


def test_resolver_requires_object_scoping():
    # A bare collection GET (no {id}) cannot target ONE object -> not decisive, not chosen.
    entries = ["GET /api/gizmos"]
    assert select_object_state_endpoint(
        entries, "/api/users/2/gizmo", attacked_object_id="2"
    ) is None


def test_resolver_returns_none_without_an_attacked_id():
    # Nothing to bind the template to -> no concrete path -> no fabrication.
    assert select_object_state_endpoint(
        CATALOG, "/api/users/2/gizmo", attacked_object_id=None
    ) is None


def test_resolver_prefers_the_canonical_object_read():
    # Both mention the noun; the CANONICAL "<noun>/{id}" object read wins over an incidental one.
    entries = [
        "GET /api/tenants/{tenant_id}/gizmo-summary",
        "GET /api/gizmos/{gizmo_id}",
    ]
    assert select_object_state_endpoint(
        entries, "/api/users/2/gizmo", attacked_object_id="2"
    ) == "/api/gizmos/2"


def test_noun_extraction_ignores_ids():
    assert attacked_resource_noun("/api/users/2/gizmo", "2") == "gizmo"
    assert attacked_resource_noun("/api/gizmos/2", "2") == "gizmo"          # flat write
    assert attacked_resource_noun("/api/users/{user_id}/gizmo", None) == "gizmo"


# =============================================================================
# 2. GENERICITY — a FOREIGN spec sharing NO vocabulary with this target.
#    (Mirrors B-1's genericity proof: the rule is structural, not memorized.)
# =============================================================================

_FOREIGN = [
    "POST /v2/accounts/{account_id}/widget  [tags: widgets]",
    "GET /v2/widgets/{widget_id}  [tags: widgets]",
    "GET /v2/accounts/{account_id}  [tags: accounts]",
    "POST /shop/customers/{customer_id}/policy  [tags: policies]",
    "GET /shop/policies/{policy_id}  [tags: policies]",
    "GET /shop/audit-trail  [tags: audit]",
    "POST /erp/orgs/{org_id}/dispatch-box",
    "GET /erp/dispatch-boxes/{box_id}",
]


@pytest.mark.parametrize("attack_path,attacked_id,expected", [
    ("/v2/accounts/77/widget", "77", "/v2/widgets/77"),
    ("/shop/customers/9/policy", "9", "/shop/policies/9"),      # 'policies' -> 'policy'
    ("/erp/orgs/5/dispatch-box", "5", "/erp/dispatch-boxes/5"),  # 'boxes' -> 'box'
])
def test_resolver_generalizes_to_a_foreign_spec(attack_path, attacked_id, expected):
    # No path, field, tag or noun of THIS target appears in the foreign spec; the resolver
    # still finds each object's own state endpoint by structure + plural morphology alone.
    assert select_object_state_endpoint(
        _FOREIGN, attack_path, attacked_object_id=attacked_id
    ) == expected


def test_foreign_spec_write_record_is_not_mistaken_for_state():
    # The foreign audit trail must never be chosen as an object-state read.
    assert select_object_state_endpoint(
        _FOREIGN, "/shop/customers/9/policy", attacked_object_id="9"
    ) != "/shop/audit-trail"


# =============================================================================
# 3. Integrated — the REAL execute_deep_verification, mocked Gemini + transport.
#    Proves the CODE-GATHER feeds the (unchanged) exemption, BOTH ways.
# =============================================================================

pytest.importorskip("google.genai")

from backend.app.core.config import settings                        # noqa: E402
import backend.app.services.deep_verifier as dv                     # noqa: E402
from backend.app.services.deep_verifier import (                    # noqa: E402
    STATE_READBACK_EXEMPTION_REASON,
    WRITE_RECORD_EXEMPTION_REASON,
    CROSS_RESOURCE_OVERRIDE_REASON,
)

BASE_URL = "http://127.0.0.1:8001"
APPROVED_HOST = "127.0.0.1:8001"
ALICE = "Bearer alice-token-aaaa"
UNIQUE = "m12b-gather-4be21c9f70"


def _resp(status: int, body: str) -> dict:
    return {"status_code": status, "content_length": len(body),
            "response_body": body, "elapsed_ms": 5, "url": BASE_URL}


def _fake_send(routes: dict, record_body: str = '{"events":[]}'):
    """Opaque 200 on every write; the audit-log probe returns `record_body`; `routes` maps a
    concrete GET path -> body. Anything else returns a body with no owner/value (useless)."""
    async def _send(client, parsed_request, base_url, custody=None):
        method = str(parsed_request.get("method", "GET")).upper()
        path = parsed_request.get("path", "")
        if method in ("POST", "PUT", "PATCH", "DELETE"):
            return _resp(200, '{"status":"ok"}')
        if path == RECORD_PATH:
            return _resp(200, record_body)
        if path in routes:
            return _resp(200, routes[path])
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
            "confidence": 1.0, "reasoning": f"m12b-mock:{verdict}", "evidence_path": evidence_path}


def _request_turn(path: str) -> dict:
    return {"decision": "request_more",
            "next_request": {"method": "GET", "path": path, "body": None, "reason": "m12b-mock"},
            "verdict": None, "confidence": 0.5, "reasoning": "m12b-mock:request_more"}


@pytest.fixture(autouse=True)
def _enable(monkeypatch):
    monkeypatch.setattr(settings, "AI_DEEP_VERIFY_ENABLED", True, raising=False)
    monkeypatch.setattr(settings, "GEMINI_API_KEY", "test-dummy-key", raising=False)


def _run(parsed_request, payload, *, routes, turn1, turn2, monkeypatch,
         record_body='{"events":[]}'):
    monkeypatch.setattr(dv, "_send_request", _fake_send(routes, record_body))
    monkeypatch.setattr(dv, "_gemini_generate", _fake_gemini(turn1, turn2))
    return asyncio.run(dv.execute_deep_verification(
        parsed_request=parsed_request, payload=payload, base_url=BASE_URL,
        approved_host=APPROVED_HOST, auth_context={"Authorization": ALICE},
        available_endpoints=CATALOG,
    ))


_BOLA = {"location": "path_segment", "target_param": "1", "payload_string": "2", "type": "BOLA"}
_GIZMO_WRITE = {"method": "POST", "path": "/api/users/1/gizmo", "query_params": {},
                "headers": {"Content-Type": "application/json"}, "body": {"code": UNIQUE}}
_SPROCKET_WRITE = {"method": "POST", "path": "/api/users/1/sprocket", "query_params": {},
                   "headers": {"Content-Type": "application/json"}, "body": {"code": UNIQUE}}
_DISPLAY_NAME_WRITE = {"method": "POST", "path": "/api/users/1/display-name", "query_params": {},
                       "headers": {"Content-Type": "application/json"},
                       "body": {"display_name": UNIQUE}}


# ---- VULN: code gathers the state, value present -> exemption fires -> verified ------------
def test_vuln_code_gathered_state_feeds_the_exemption_to_verified(monkeypatch):
    # The model delivers a verdict in turn 1 WITHOUT asking for anything (the live failure mode:
    # it cannot find the state path). M1.2(B) gathers it anyway, so the model still gets to judge
    # real state evidence in turn 2.
    res = _run(
        _GIZMO_WRITE, _BOLA,
        routes={"/api/gizmos/2": json.dumps({"id": 2, "owner_id": 2, "code": UNIQUE})},
        turn1=_verdict_turn("inconclusive"),                   # model asks for nothing
        turn2=_verdict_turn("verified", evidence_path="code"),
        monkeypatch=monkeypatch,
    )
    assert res.status == "completed"
    # The CODE gathered the object's own state (the model never asked for it).
    assert res.ai_requested_follow_up is True
    assert res.follow_up_request["path"] == "/api/gizmos/2"
    assert "code-gathered object-state read-back" in res.follow_up_request["reason"]
    # All three AND-ed anchors confirm on the gathered state.
    assert res.caller_identity_anchor == "confirmed"                                    # (1)+(2)
    assert res.payload_causality_anchor in ("confirmed_at_path", "confirmed_in_body")   # (3)
    # -> the already-proven exemption finally has inputs.
    assert res.ai_verdict_raw == "verified"
    assert res.ai_verdict == "verified"
    assert res.guard_override == STATE_READBACK_EXEMPTION_REASON


# ---- SAFE: code gathers the state, value ABSENT -> NOT exempt -> inconclusive --------------
def test_safe_code_gathered_state_without_the_value_stays_inconclusive(monkeypatch):
    # THE SAFETY LINE. Identical gather, but the write was silently DROPPED so the unique value
    # is ABSENT from the state. (1)+(2) still confirm (the object is still the victim's, still
    # attacked by the caller) — ONLY payload-causality separates VULN from SAFE. The model is
    # WRONG here (raw "verified"); the gate must refuse the exemption anyway.
    res = _run(
        _SPROCKET_WRITE, _BOLA,
        routes={"/api/sprockets/2": json.dumps(
            {"id": 2, "owner_id": 2, "code": "sprocket_bob_v0"})},   # original value, not ours
        turn1=_verdict_turn("inconclusive"),
        turn2=_verdict_turn("verified", evidence_path="code"),       # model is WRONG
        monkeypatch=monkeypatch,
    )
    assert res.follow_up_request["path"] == "/api/sprockets/2"       # gathered all the same
    assert res.caller_identity_anchor == "confirmed"                 # (1)+(2) cannot separate
    assert res.payload_causality_anchor == "absent"                  # (3) FAILS -> no exemption
    assert res.ai_verdict_raw == "verified"
    assert res.ai_verdict == "inconclusive"
    assert res.ai_verdict != "verified"                              # NEVER verified on SAFE
    assert res.guard_override == CROSS_RESOURCE_OVERRIDE_REASON


# ---- B-1 precedence preserved: a RELEVANT write-record still wins the gather ---------------
def test_b1_write_record_still_takes_precedence_over_state_gather(monkeypatch):
    # When the record DOES hold the caller's own landed write, HALF-1 gathers the record exactly
    # as before — M1.2(B) never runs. B-1 is untouched.
    audit = json.dumps({"events": [
        {"id": 1, "event": "display_name.update", "user_id": 1, "new_value": UNIQUE},
        {"id": 2, "event": "display_name.update", "user_id": 2, "new_value": UNIQUE},
    ]})
    res = _run(
        _DISPLAY_NAME_WRITE, _BOLA,
        routes={},
        turn1=_verdict_turn("inconclusive"),
        turn2=_verdict_turn("verified", evidence_path="events[1].new_value"),
        monkeypatch=monkeypatch,
        record_body=audit,
    )
    assert res.follow_up_request["path"] == RECORD_PATH              # the record, not a state read
    assert res.ai_verdict == "verified"
    assert res.guard_override == WRITE_RECORD_EXEMPTION_REASON       # B-1's channel, unchanged


# ---- No fabrication: nothing resolvable -> the model's own choice stands -------------------
def test_no_state_endpoint_resolvable_means_no_fabrication(monkeypatch):
    # display-name has NO state read-back and (here) an EMPTY audit log -> neither gather fires.
    # The engine must not invent a follow-up; the model's own choice is used.
    res = _run(
        _DISPLAY_NAME_WRITE, _BOLA,
        routes={},
        turn1=_request_turn("/api/users/2/profile"),                 # the model's own choice
        turn2=_verdict_turn("failed", evidence_path="display_name"),
        monkeypatch=monkeypatch,
        record_body='{"events":[]}',
    )
    assert res.follow_up_request["path"] == "/api/users/2/profile"   # untouched by the engine
    assert res.follow_up_request["path"] != RECORD_PATH
    assert res.ai_verdict != "verified"                              # cross-path failed -> downgraded


# ---- The carve-out did NOT over-generalize: a MODEL-CHOSEN cross-path read stays inconclusive ---
def test_model_chosen_crosspath_read_without_causality_stays_inconclusive(monkeypatch):
    # M1.2(C) guard-rail. Neither gather fires, so this follow-up is the MODEL'S OWN choice on an
    # unrelated resource. It happens to expose an owner field for the victim, so (1)+(2) CONFIRM —
    # but our attack's unique value is NOWHERE in it, so payload-causality is ABSENT and the
    # exemption must NOT fire. Even with the model raw-saying "verified", the verdict stays
    # inconclusive. This is what stops the prompt carve-out from becoming a general licence to
    # conclude from any different path.
    res = _run(
        _DISPLAY_NAME_WRITE, _BOLA,
        routes={"/api/users/2/profile": json.dumps({"user_id": 2, "display_name": "Bob"})},
        turn1=_request_turn("/api/users/2/profile"),        # the MODEL's own pick, not gathered
        turn2=_verdict_turn("verified", evidence_path="user_id"),   # model over-claims
        monkeypatch=monkeypatch,
        record_body='{"events":[]}',
    )
    assert res.follow_up_request["path"] == "/api/users/2/profile"
    assert "code-gathered" not in res.follow_up_request.get("reason", "")   # NOT system-gathered
    assert res.caller_identity_anchor == "confirmed"        # (1)+(2) hold — cannot separate
    assert res.payload_causality_anchor == "absent"         # (3) FAILS -> no exemption
    assert res.ai_verdict_raw == "verified"
    assert res.ai_verdict == "inconclusive"
    assert res.guard_override == CROSS_RESOURCE_OVERRIDE_REASON
