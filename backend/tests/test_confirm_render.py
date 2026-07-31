# ==============================================================================
# Offline test for the CLI confirmer's PURE renderer (backend/app/cli/confirm_render.py).
# Zero API cost, no engine, no network: driven by rows read from the COMMITTED golden
# record (scripts/measure/results/sweep_highN.jsonl) plus a few synthetic records.
#
# Proves: render_tree renders every golden row without raising; the outcome tracks the
# ENGINE's verdict field (never ground_truth); the renderer structurally cannot manufacture
# `verified`; credentials are redacted; and exit_code_for gives 0/1/2 correctly.
# ==============================================================================
import os
import sys
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from backend.app.cli.confirm_render import render_tree, case_outcome, exit_code_for

_GOLDEN = os.path.join(os.path.dirname(__file__), "..", "..",
                       "scripts", "measure", "results", "sweep_highN.jsonl")


def _golden_rows():
    with open(_GOLDEN, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def test_golden_corpus_renders_and_outcome_tracks_engine_verdict():
    rows = _golden_rows()
    assert rows, "golden record is empty"
    for r in rows:
        out = render_tree(r)                       # must never raise
        assert isinstance(out, str) and out
        expected = "confirmed" if r["final_verdict"] == "verified" else "refuted"
        assert case_outcome(r) == expected
        assert ("[CONFIRMED]" in out) == (expected == "confirmed")
        assert ("[REFUTED]" in out) == (expected == "refuted")
    # the golden record contains verified rows -> the corpus exit code is 1
    assert exit_code_for(rows) == 1


def test_confirmed_row_shows_channel_and_evidence():
    r = next(x for x in _golden_rows() if x["final_verdict"] == "verified" and x["shape"] == "delete")
    out = render_tree(r)
    assert "[CONFIRMED]" in out
    assert "verified" in out
    assert r["guard_override"] in out                  # the exemption channel
    assert "Evidence chain" in out
    assert "negative-assertion anchor" in out          # delete-shape anchor from real fields


def test_read_semantic_safe_is_refuted_with_owner_view_reason():
    r = next(x for x in _golden_rows()
             if x["shape"] == "read_semantic" and x["ground_truth"] != "REAL")
    out = render_tree(r)
    assert "[REFUTED]" in out
    assert "owner-view" in out
    assert "no cross-user effect confirmed" in out


def test_notdata_row_renders_and_is_notdata():
    r = {"shape": "silent_write", "ground_truth": "REAL", "final_verdict": None,
         "status": "degraded", "degraded": True, "degraded_reason": "Gemini turn-1 error"}
    out = render_tree(r)
    assert "[NOT DATA]" in out
    assert case_outcome(r) == "notdata"


def test_renderer_cannot_manufacture_verified_from_ground_truth():
    # Lab says REAL (vuln) but the ENGINE said 'failed': must render REFUTED, never CONFIRMED.
    # This is the self-grading guard — ground_truth may only drive the [lab oracle] line.
    r = {"shape": "write_record", "ground_truth": "REAL", "final_verdict": "failed",
         "guard_override": None, "status": "completed", "degraded": False}
    out = render_tree(r)
    assert "[REFUTED]" in out
    assert "[CONFIRMED]" not in out
    assert "DIVERGES" in out                            # lab-oracle line notes the divergence
    assert case_outcome(r) == "refuted"


def test_exit_codes():
    confirmed = {"final_verdict": "verified", "shape": "x", "ground_truth": "REAL", "degraded": False}
    refuted = {"final_verdict": "failed", "shape": "x", "ground_truth": "SECURE", "degraded": False}
    notdata = {"final_verdict": None, "shape": "x", "ground_truth": "REAL",
               "degraded": True, "status": "degraded"}
    assert exit_code_for([refuted]) == 0
    assert exit_code_for([confirmed]) == 1
    assert exit_code_for([notdata]) == 2
    assert exit_code_for([refuted, confirmed]) == 1     # any confirmed -> 1
    assert exit_code_for([refuted, notdata]) == 2       # any not-data (no confirmed) -> 2


def test_credentials_are_redacted():
    r = {"shape": "write_record", "ground_truth": "REAL", "final_verdict": "verified",
         "guard_override": "write_record_readback_decisive", "status": "completed", "degraded": False,
         "method": "POST", "baseline_path": "/x", "attack_path": "/x",
         "body": {"a": "Bearer aaa-secret-111", "b": "authorization=bbb-secret-222"}}
    out = render_tree(r)
    assert "aaa-secret-111" not in out
    assert "bbb-secret-222" not in out
    assert "***REDACTED***" in out
