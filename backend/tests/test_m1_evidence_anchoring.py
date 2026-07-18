# ==============================================================================
# M1.1 — offline unit tests for evidence anchoring (the CODE half of "AI makes the
# semantic call, CODE anchors it against ground truth"). NO network, NO model.
#
# These pin the deterministic anchoring contract used observe-only by the deep
# verifier: given the model's cited evidence_path and the attacked victim's runtime
# id, the code structurally checks the path resolves in the read-back and points at
# that id. Robustness (type coercion, hallucinated paths, non-JSON) is required by the
# task's execution guardrails, so it is tested here rather than discovered live.
# ==============================================================================

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

import json
import pytest

from backend.app.services.deep_verifier import (
    _resolve_json_path,
    _anchor_evidence,
    _build_provider_config,
)


# -----------------------------------------------------------------------------
# _resolve_json_path — dotted / bracket / list-index, leading $ tolerated
# -----------------------------------------------------------------------------

def test_resolve_simple_key():
    assert _resolve_json_path({"owner_id": 2}, "owner_id") == 2


def test_resolve_nested_dotted():
    assert _resolve_json_path({"data": {"owner_id": 2}}, "data.owner_id") == 2


def test_resolve_list_bracket_index():
    obj = {"results": [{"owner_id": 9}, {"owner_id": 2}]}
    assert _resolve_json_path(obj, "results[1].owner_id") == 2


def test_resolve_bare_numeric_key_on_list():
    assert _resolve_json_path({"items": [{"owner_id": 2}]}, "items.0.owner_id") == 2


def test_resolve_leading_dollar_and_root_tolerated():
    assert _resolve_json_path({"owner_id": 2}, "$.owner_id") == 2
    assert _resolve_json_path({"owner_id": 2}, "root.owner_id") == 2


def test_resolve_missing_key_raises():
    with pytest.raises((KeyError, TypeError, IndexError, ValueError)):
        _resolve_json_path({"owner_id": 2}, "nope.deeper")


# -----------------------------------------------------------------------------
# _anchor_evidence — the observe-only structural check
# -----------------------------------------------------------------------------

VULN_BODY = json.dumps(
    {"id": 2, "owner_id": 2, "account_ref": "22222222-2222-2222-2222-222222222222",
     "period": "2026-Q1", "status": "OPEN"}
)
# SAFE soft-200 denial: carries NO victim identity (id/owner_id zeroed).
SAFE_BODY = json.dumps(
    {"id": 0, "owner_id": 0, "account_ref": "00000000-0000-0000-0000-000000000000",
     "period": "2026-Q1", "status": "DENY"}
)


def test_anchor_confirmed_on_leaked_owner_id():
    # The read-back's owner_id == the attacked victim id -> confirmed.
    assert _anchor_evidence(VULN_BODY, "owner_id", "2") == "confirmed"


def test_anchor_type_coercion_string_vs_int():
    # payload id is the string "2"; JSON yields int 2 -> still confirmed.
    assert _anchor_evidence(VULN_BODY, "owner_id", "2") == "confirmed"
    # and the reverse framing: a body carrying a string id.
    body = json.dumps({"owner_id": "2"})
    assert _anchor_evidence(body, "owner_id", "2") == "confirmed"


def test_anchor_value_mismatch_when_field_is_not_the_victim():
    # SAFE denial: owner_id is 0, not the attacked victim id 2 -> mismatch (no anchor).
    assert _anchor_evidence(SAFE_BODY, "owner_id", "2") == "value_mismatch"


def test_anchor_failed_path_not_found_on_hallucinated_path():
    # The AI cites a path that does not exist -> failed_path_not_found (never crashes).
    assert _anchor_evidence(VULN_BODY, "data.victim.email", "2") == "failed_path_not_found"


def test_anchor_container_or_null_is_not_a_scalar_anchor():
    body = json.dumps({"owner": {"id": 2}, "note": None})
    assert _anchor_evidence(body, "owner", "2") == "failed_path_not_found"   # dict, not scalar
    assert _anchor_evidence(body, "note", "2") == "failed_path_not_found"    # null, not scalar
    # but the scalar inside the container anchors fine
    assert _anchor_evidence(body, "owner.id", "2") == "confirmed"


def test_anchor_unparsable_read_back():
    assert _anchor_evidence("not json at all", "owner_id", "2") == "unparsable_read_back"


def test_anchor_no_read_back():
    assert _anchor_evidence(None, "owner_id", "2") == "no_read_back"
    assert _anchor_evidence("", "owner_id", "2") == "no_read_back"


def test_anchor_no_path():
    assert _anchor_evidence(VULN_BODY, None, "2") == "no_path"
    assert _anchor_evidence(VULN_BODY, "", "2") == "no_path"


def test_anchor_never_raises_on_weird_input():
    # Defensive: odd path shapes must degrade to a status string, never raise.
    for p in ("[0]", "a[b]", "...", "a.b.c.d.e"):
        out = _anchor_evidence(VULN_BODY, p, "2")
        assert out in {
            "confirmed", "value_mismatch", "failed_path_not_found",
            "unparsable_read_back", "no_read_back", "no_path",
        }


# -----------------------------------------------------------------------------
# provider seam — JSON mode is enforced at the API layer, not by prompt alone
# -----------------------------------------------------------------------------

class _FakeConfig:
    def __init__(self, **kw):
        self.__dict__.update(kw)


class _FakeTypes:
    GenerateContentConfig = _FakeConfig


def test_provider_config_enforces_json_mode():
    cfg = _build_provider_config(_FakeTypes, "SYS")
    assert cfg.response_mime_type == "application/json"
    assert cfg.system_instruction == "SYS"
    assert cfg.temperature == 0.4
