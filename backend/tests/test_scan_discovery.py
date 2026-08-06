# ==============================================================================
# scan v1, commit 1 — AI discovery + the CODE FENCE. AI proposes candidates; code vets them; the
# unchanged engine judges. These tests prove: a valid candidate is accepted and produces the exact
# flat op schema; an INVALID AI candidate/op (path not in catalog, target_param not in baseline_path,
# bad method) is DROPPED and never runnable. Zero API cost — the provider is stubbed.
# ==============================================================================
import os
import sys
import json
import asyncio

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, _REPO_ROOT)

from backend.tests._llmstub import as_provider
from backend.app.cli.console.targets import build_op, Target
from backend.app.cli import scan_discovery as sd

_CATALOG = [
    "GET /workshop/api/mechanic/mechanic_report  [operationId: getReport]",
    "GET /api/users/{user_id}/profile",
    "POST /api/users/{user_id}/gizmo",
]


def _stub_provider(candidates):
    async def gen():
        class _R:
            text = json.dumps({"candidates": candidates})
        return _R()
    return as_provider(gen)


# ------------------------------------------------------------------ op-gen reuse (build_op)
def test_build_op_matches_target_to_op_and_schema():
    # build_op is the ONE op-gen path: Target.to_op delegates to it (byte-identical).
    t = Target(name="c", base_url="", spec_path="", method="GET",
               path_template="/workshop/api/mechanic/mechanic_report", id_location="query",
               id_param="report_id", attacker_id="7", victim_id="6")
    assert t.to_op() == build_op("GET", "/workshop/api/mechanic/mechanic_report", "query",
                                 "report_id", "7", "6", shape="console:c")
    op = build_op("GET", "/api/users/{user_id}/profile", "path", "user_id", "1", "2",
                  shape="path_segment_bola")
    assert op["baseline_path"] == "/api/users/1/profile"
    assert op["payload"] == {"location": "path_segment", "target_param": "1",
                             "payload_string": "2", "type": "BOLA"}


# ------------------------------------------------------------------ AI proposal (stubbed provider)
def test_propose_candidates_returns_model_list():
    cands = [{"method": "GET", "path_template": "/api/users/{user_id}/profile",
              "id_location": "path", "id_param": "user_id", "reason": "user object"}]
    got = asyncio.run(sd.propose_candidates(_CATALOG, provider_factory=_stub_provider(cands)))
    assert got == cands


def test_propose_candidates_graceful_when_no_provider():
    assert asyncio.run(sd.propose_candidates(_CATALOG, provider_factory=lambda: None)) == []
    assert asyncio.run(sd.propose_candidates([], provider_factory=_stub_provider([]))) == []


# ------------------------------------------------------------------ CODE FENCE: validate_candidate
def test_validate_candidate_accepts_valid_and_assigns_known_shape():
    q = sd.validate_candidate(
        {"method": "get", "path_template": "/workshop/api/mechanic/mechanic_report",
         "id_location": "query", "id_param": "report_id"}, _CATALOG)
    assert q == {"method": "GET", "path_template": "/workshop/api/mechanic/mechanic_report",
                 "id_location": "query", "id_param": "report_id", "shape": "query_string_idor"}
    p = sd.validate_candidate(
        {"method": "GET", "path_template": "/api/users/{user_id}/profile",
         "id_location": "path", "id_param": "user_id", "shape": "TOTALLY-MADE-UP"}, _CATALOG)
    # the AI's shape is NEVER trusted — code assigns a known shape from the id location
    assert p["shape"] == "path_segment_bola" and p["shape"] in sd._KNOWN_SHAPES


def test_validate_candidate_drops_invalid():
    # path not in the catalog -> dropped
    assert sd.validate_candidate(
        {"method": "GET", "path_template": "/api/secret/{id}", "id_location": "path",
         "id_param": "id"}, _CATALOG) is None
    # id_param is not a real template var in the path -> dropped
    assert sd.validate_candidate(
        {"method": "GET", "path_template": "/api/users/{user_id}/profile", "id_location": "path",
         "id_param": "order_id"}, _CATALOG) is None
    # unknown method -> dropped
    assert sd.validate_candidate(
        {"method": "CONNECT", "path_template": "/api/users/{user_id}/profile",
         "id_location": "path", "id_param": "user_id"}, _CATALOG) is None
    # query id param that is a template (braces) -> dropped
    assert sd.validate_candidate(
        {"method": "GET", "path_template": "/workshop/api/mechanic/mechanic_report",
         "id_location": "query", "id_param": "{report_id}"}, _CATALOG) is None


def test_discover_candidate_parts_splits_accepted_and_dropped():
    raw = [
        {"method": "GET", "path_template": "/api/users/{user_id}/profile",
         "id_location": "path", "id_param": "user_id"},                       # valid
        {"method": "GET", "path_template": "/api/secret/{id}",
         "id_location": "path", "id_param": "id"},                            # invalid (not in catalog)
        "not-even-a-dict",                                                     # invalid
    ]
    accepted, dropped = sd.discover_candidate_parts(_CATALOG, raw)
    assert len(accepted) == 1 and accepted[0]["path_template"] == "/api/users/{user_id}/profile"
    assert len(dropped) == 2


# ------------------------------------------------------------------ CODE FENCE: validate_op (final gate)
def test_validate_op_accepts_valid_concrete_op():
    op = build_op("GET", "/api/users/{user_id}/profile", "path", "user_id", "1", "2",
                  shape="path_segment_bola")
    assert sd.validate_op(op, _CATALOG) is True
    qop = build_op("GET", "/workshop/api/mechanic/mechanic_report", "query", "report_id", "7", "6",
                   shape="query_string_idor")
    assert sd.validate_op(qop, _CATALOG) is True


def test_validate_op_drops_op_whose_target_param_not_in_baseline_path():
    # a mis-built op: target_param "999" does not appear in baseline_path -> DROPPED, never run
    bad = {"method": "GET", "baseline_path": "/api/users/1/profile", "body": None,
           "payload": {"location": "path_segment", "target_param": "999",
                       "payload_string": "2", "type": "BOLA"}, "shape": "path_segment_bola"}
    assert sd.validate_op(bad, _CATALOG) is False


def test_validate_op_drops_op_whose_path_not_in_catalog():
    bad = {"method": "GET", "baseline_path": "/api/secret/1", "body": None,
           "payload": {"location": "path_segment", "target_param": "1",
                       "payload_string": "2", "type": "BOLA"}, "shape": "path_segment_bola"}
    assert sd.validate_op(bad, _CATALOG) is False
