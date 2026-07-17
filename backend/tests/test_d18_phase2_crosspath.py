# ==============================================================================
# Human-owned test for the D18 Phase-2 CROSS-PATH cases (X-CROSS / X-SAFE).
#
# THE EXPECTED VALUES ARE HUMAN-OWNED GROUND TRUTH (from
# vulnerable_target/benchmark/RESULTS.md §"Phase-2 cross-path additions"). They must
# NOT be authored, relaxed, or "corrected" here to make a test pass. If an assertion
# fails, that is a SIGNAL to report — not something to fix here.
#
# This file is OFFLINE and deterministic: it touches NO network and NO live target.
#   * K2-rule-XCROSS / K2-rule-XSAFE — feed the real differential oracle
#     (_differential_verdict) the realistic byte-identical opaque-200 pair these two
#     silent cross-path writes produce, and assert the rule verdict is "suspicious".
#   * K2-catalog-reach — the placeholder _shadow_endpoint_catalog (no source) offers
#     ONLY the finding's own path, so it can NEVER reach the cross-path read-back
#     GET /api/audit-log; the REAL catalog (the OpenAPI surface, passed as the
#     build_catalog descriptor {"kind": "openapi", "spec": app.openapi()}) DOES.
#
# The live-pipeline X-CROSS/X-SAFE proof (K2-shadow, Phase 7, observe-only) is run by
# the throwaway driver scripts/audit/shadow_d18_phase2_run.py — it needs a live target
# + Gemini, so it is intentionally NOT a unit test here (same split as the P0 run).
# ==============================================================================

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

import pytest

from vulnerable_target.main import app
from backend.app.services.fuzzer import _differential_verdict, _shadow_endpoint_catalog


# -----------------------------------------------------------------------------
# Human-owned fixtures. Verbatim from the maintainer / RESULTS.md; do not edit.
# -----------------------------------------------------------------------------
XCROSS_FINDING = {"method": "POST", "path": "/api/users/{user_id}/display-name"}
XSAFE_FINDING = {"method": "POST", "path": "/api/users/{user_id}/nickname"}

# Both cross-path writes return the SAME opaque, byte-identical 200 {"status":"ok"}
# for a self-write and a cross-user write (the side effect is observable only via the
# cross-path GET /api/audit-log). content_length 15 == len('{"status":"ok"}').
_OPAQUE_OK = '{"status":"ok"}'

# Deterministic BOLA payload: flip the path id 1 -> 2 (the same shape the benchmark
# drivers use). The vuln_type drives Rule 2 of the oracle.
_BOLA_PAYLOAD = {
    "location": "path_segment",
    "target_param": "1",
    "payload_string": "2",
    "type": "BOLA",
}

AUDIT_LOG_ENTRY = "GET /api/audit-log"
_OPENAPI_SOURCE = {"kind": "openapi", "spec": app.openapi()}


def _offers_audit_log(catalog) -> bool:
    """True iff the catalog offers GET /api/audit-log. Entries now LEAD with
    'METHOD /path' and may carry a trailing '  [tags: ...; operationId: ...]'
    annotation (B-1 Step 1), so match the leading 'METHOD /path' rather than the
    whole string."""
    return any(e == AUDIT_LOG_ENTRY or e.startswith(AUDIT_LOG_ENTRY + "  [") for e in catalog)


def _opaque_ok_response() -> dict:
    """The realistic response both endpoints return for self AND cross-user writes."""
    return {
        "status_code": 200,
        "content_length": len(_OPAQUE_OK),
        "response_body": _OPAQUE_OK,
        "elapsed_ms": 5,
    }


# -----------------------------------------------------------------------------
# K2-rule — the single-shot differential oracle on the silent cross-path pair
# -----------------------------------------------------------------------------

def test_K2_rule_XCROSS_pair_is_suspicious():
    # X-CROSS (REAL): POST /api/users/{user_id}/display-name. Baseline self-write vs.
    # mutated cross-user write are byte-identical opaque 200s, so the rule oracle has
    # no signal to escalate and stalls at "suspicious".
    baseline = _opaque_ok_response()
    test_result = _opaque_ok_response()
    out = _differential_verdict(baseline, test_result, _BOLA_PAYLOAD)
    assert out["verdict"] == "suspicious"


def test_K2_rule_XSAFE_pair_is_suspicious():
    # X-SAFE (SECURE): POST /api/users/{user_id}/nickname returns the SAME opaque 200
    # {"status":"ok"} as X-CROSS, so the single-shot oracle produces the identical
    # "suspicious" verdict — it cannot tell the REAL hole from the SECURE control.
    baseline = _opaque_ok_response()
    test_result = _opaque_ok_response()
    out = _differential_verdict(baseline, test_result, _BOLA_PAYLOAD)
    assert out["verdict"] == "suspicious"


# -----------------------------------------------------------------------------
# K2-catalog-reach — placeholder cannot reach the cross-path read-back; real can
# -----------------------------------------------------------------------------

@pytest.mark.parametrize("finding", [XCROSS_FINDING, XSAFE_FINDING], ids=["XCROSS", "XSAFE"])
def test_K2_catalog_reach_no_source_excludes_audit_log(finding):
    catalog = _shadow_endpoint_catalog(finding)
    assert not _offers_audit_log(catalog)


@pytest.mark.parametrize("finding", [XCROSS_FINDING, XSAFE_FINDING], ids=["XCROSS", "XSAFE"])
def test_K2_catalog_reach_with_openapi_source_includes_audit_log(finding):
    catalog = _shadow_endpoint_catalog(finding, _OPENAPI_SOURCE)
    assert _offers_audit_log(catalog)
