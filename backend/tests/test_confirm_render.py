# ==============================================================================
# Offline test for the CLI confirmer's PURE renderer (backend/app/cli/confirm_render.py).
# Zero API cost, no engine, no network: driven by rows read from the COMMITTED golden
# record (scripts/measure/results/sweep_highN.jsonl) plus a few synthetic records.
#
# Proves: render_tree renders every golden row without raising; the outcome tracks the
# ENGINE's verdict field (never ground_truth); the renderer structurally cannot manufacture
# `verified`; the plain-language layer TRANSLATES channels/anchors while keeping the raw
# engine token visible; color is opt-in and off by default (deterministic when pinned);
# credentials are redacted; exit_code_for gives 0/1/2 correctly; and render_tally counts
# strictly from the engine verdict.
# ==============================================================================
import os
import sys
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from backend.app.cli.confirm_render import (
    render_tree, render_tally, case_outcome, exit_code_for,
)

_GOLDEN = os.path.join(os.path.dirname(__file__), "..", "..",
                       "scripts", "measure", "results", "sweep_highN.jsonl")

_ESC = "\033["


def _golden_rows():
    with open(_GOLDEN, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def test_golden_corpus_renders_and_outcome_tracks_engine_verdict():
    rows = _golden_rows()
    assert rows, "golden record is empty"
    for r in rows:
        out = render_tree(r, color=False)             # must never raise
        assert isinstance(out, str) and out
        expected = "confirmed" if r["final_verdict"] == "verified" else "refuted"
        assert case_outcome(r) == expected
        assert ("[CONFIRMED]" in out) == (expected == "confirmed")
        assert ("[REFUTED]" in out) == (expected == "refuted")
    # the golden record contains verified rows -> the corpus exit code is 1
    assert exit_code_for(rows) == 1


def test_confirmed_row_shows_channel_and_evidence():
    r = next(x for x in _golden_rows() if x["final_verdict"] == "verified" and x["shape"] == "delete")
    out = render_tree(r, color=False)
    assert "[CONFIRMED]" in out
    assert "verified" in out
    assert r["guard_override"] in out                  # the raw exemption channel token is kept
    assert "What the engine proved" in out
    assert "Evidence chain" in out
    assert r["negative_assertion"] in out              # delete-shape anchor raw token from real fields


def test_translation_layer_reads_plainly_but_keeps_the_raw_token():
    # A write-record CONFIRMED row: the tree must explain what physically happened in plain
    # language AND still surface the raw engine tokens (translate, don't replace).
    r = next(x for x in _golden_rows()
             if x["final_verdict"] == "verified" and x["shape"] == "write_record")
    out = render_tree(r, color=False)
    # plain language
    assert "read the object back" in out
    assert "the write was attributed to the attacker's own identity" in out
    # raw tokens still present
    assert "write_record_readback_decisive" in out
    assert f"caller_identity={r['caller_identity']}" in out
    # no invented competitor commentary
    assert "scanner" not in out.lower()


def test_read_semantic_safe_is_refuted_with_owner_view_reason():
    r = next(x for x in _golden_rows()
             if x["shape"] == "read_semantic" and x["ground_truth"] != "REAL")
    out = render_tree(r, color=False)
    assert "[REFUTED]" in out
    assert "owner-view" in out
    assert "no cross-user effect confirmed" in out


def test_notdata_row_renders_and_is_notdata():
    r = {"shape": "silent_write", "ground_truth": "REAL", "final_verdict": None,
         "status": "degraded", "degraded": True, "degraded_reason": "Gemini turn-1 error"}
    out = render_tree(r, color=False)
    assert "[NOT DATA]" in out
    assert case_outcome(r) == "notdata"


def test_renderer_cannot_manufacture_verified_from_ground_truth():
    # Lab says REAL (vuln) but the ENGINE said 'failed': must render REFUTED, never CONFIRMED.
    # This is the self-grading guard — ground_truth may only drive the [lab oracle] line.
    r = {"shape": "write_record", "ground_truth": "REAL", "final_verdict": "failed",
         "guard_override": None, "status": "completed", "degraded": False}
    out = render_tree(r, color=False)
    assert "[REFUTED]" in out
    assert "[CONFIRMED]" not in out
    assert "DIVERGES" in out                            # lab-oracle line notes the divergence
    assert case_outcome(r) == "refuted"


def test_color_is_opt_in_and_off_by_default_when_pinned():
    r = next(x for x in _golden_rows() if x["final_verdict"] == "verified")
    plain = render_tree(r, color=False)
    colored = render_tree(r, color=True)
    assert _ESC not in plain                            # no ANSI when color is off
    assert _ESC in colored                              # ANSI present when color is on
    # the structural tags survive colorization (codes wrap, never split, the tag)
    assert "[CONFIRMED]" in plain and "[CONFIRMED]" in colored


def test_plain_output_is_windows_console_safe():
    # The director flagged em-dash mangling on the Windows console; keep output ASCII-safe.
    for r in _golden_rows()[:50]:
        out = render_tree(r, color=False)
        assert "—" not in out                      # no em-dash
        assert _ESC not in out                          # no stray ANSI when color off


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
    out = render_tree(r, color=False)
    assert "aaa-secret-111" not in out
    assert "bbb-secret-222" not in out
    assert "***REDACTED***" in out


def test_render_tally_counts_strictly_from_the_engine_verdict():
    records = [
        {"final_verdict": "verified", "shape": "x", "ground_truth": "REAL", "degraded": False},
        {"final_verdict": "inconclusive", "shape": "x", "ground_truth": "SECURE", "degraded": False},
        {"final_verdict": "verified", "shape": "x", "ground_truth": "REAL", "degraded": False},
        {"final_verdict": "failed", "shape": "x", "ground_truth": "SECURE", "degraded": False},
    ]
    out = render_tally(records, color=False)
    assert "4 candidate(s) checked" in out
    assert "2 confirmed exploitable" in out
    assert "2 refuted" in out
    assert "scanner" not in out.lower()                 # no competitor claims


def test_render_tally_ignores_ground_truth():
    # ground_truth REAL but the engine did NOT verify -> counts as refuted, never confirmed.
    records = [{"final_verdict": "failed", "shape": "x", "ground_truth": "REAL", "degraded": False}]
    out = render_tally(records, color=False)
    assert "0 confirmed exploitable" in out
    assert "1 refuted" in out
