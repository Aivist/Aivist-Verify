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

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from backend.app.cli.confirm_render import (
    render_tree, render_tally, case_outcome, exit_code_for, _claim_tier, _CODE_CONFIRMED_CHANNELS,
    _BROKEN_FOR_ALL_REASON,
)
# Test files MAY import the engine (the renderer module must not). The drift-guards anchor the
# renderer's channel set + render output to deep_verifier's OWN exemption-reason constants.
from backend.app.services.deep_verifier import (
    WRITE_RECORD_EXEMPTION_REASON, STATE_READBACK_EXEMPTION_REASON,
    DELETE_READBACK_EXEMPTION_REASON, STATE_JUMP_EXEMPTION_REASON,
    BROKEN_FOR_ALL_ASSERTION_REASON,
)

_FOUR_CHANNELS = (WRITE_RECORD_EXEMPTION_REASON, STATE_READBACK_EXEMPTION_REASON,
                  DELETE_READBACK_EXEMPTION_REASON, STATE_JUMP_EXEMPTION_REASON)

_GOLDEN = os.path.join(os.path.dirname(__file__), "..", "..",
                       "scripts", "measure", "results", "sweep_highN.jsonl")

_ESC = "\033["


def _golden_rows():
    with open(_GOLDEN, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


_TIER_TAG = {"code_confirmed": "[CONFIRMED]", "signal": "[SIGNAL",
             "refuted": "[REFUTED]", "not_data": "[NOT DATA]"}
_TIER_OUTCOME = {"code_confirmed": "confirmed", "signal": "signal",
                 "refuted": "refuted", "not_data": "notdata"}


def test_golden_corpus_renders_and_header_matches_tier():
    rows = _golden_rows()
    assert rows, "golden record is empty"
    for r in rows:
        out = render_tree(r, color=False)             # must never raise
        assert isinstance(out, str) and out
        tier = _claim_tier(r)                          # from engine fields only, never ground_truth
        assert _TIER_TAG[tier] in out                 # header matches the tier
        assert case_outcome(r) == _TIER_OUTCOME[tier]  # outcome maps the tier consistently
    # the golden record contains verified rows (code_confirmed + signal) -> corpus exit code is 1
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
    # Pick a CODE_CONFIRMED row explicitly: a plain `verified` may be a signal row (now [SIGNAL]).
    r = next(x for x in _golden_rows() if _claim_tier(x) == "code_confirmed")
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
        # code_confirmed (channel) and code_confirmed (owner-view) -> the confirmed (code-gated) count
        {"final_verdict": "verified", "guard_override": WRITE_RECORD_EXEMPTION_REASON,
         "shape": "x", "ground_truth": "REAL", "degraded": False},
        {"final_verdict": "inconclusive", "shape": "x", "ground_truth": "SECURE", "degraded": False},
        {"final_verdict": "verified", "owner_view_corroborated": True,
         "shape": "x", "ground_truth": "REAL", "degraded": False},
        {"final_verdict": "failed", "shape": "x", "ground_truth": "SECURE", "degraded": False},
        # verified but NO code channel -> broken out as an unconfirmed signal, NOT confirmed
        {"final_verdict": "verified", "guard_override": None, "shape": "x",
         "ground_truth": "REAL", "degraded": False},
    ]
    out = render_tally(records, color=False)
    assert "5 candidate(s) checked" in out
    assert "2 confirmed (code-gated)" in out            # only the code-gated ones are the red count
    assert "1 unconfirmed signal(s)" in out             # the model-opinion verified is a signal
    assert "2 refuted" in out
    assert "scanner" not in out.lower()                 # no competitor claims


def test_render_tally_ignores_ground_truth():
    # ground_truth REAL but the engine did NOT verify -> counts as refuted, never confirmed.
    records = [{"final_verdict": "failed", "shape": "x", "ground_truth": "REAL", "degraded": False}]
    out = render_tally(records, color=False)
    assert "0 confirmed (code-gated)" in out
    assert "1 refuted" in out


# ==============================================================================
# CLAIM TIER (cut A) - a code-authorized verdict wears a different badge than a model-opinion one.
# ==============================================================================
@pytest.mark.parametrize("ch", _FOUR_CHANNELS)
def test_verified_with_each_exemption_channel_is_code_confirmed(ch):
    r = {"shape": "write_record", "ground_truth": "REAL", "final_verdict": "verified",
         "guard_override": ch, "ai_verdict_raw": "verified", "status": "completed", "degraded": False}
    assert _claim_tier(r) == "code_confirmed"
    out = render_tree(r, color=False)
    assert "[CONFIRMED]" in out
    assert "[SIGNAL" not in out
    assert "deterministic code gate" in out             # the explicit Basis line


def test_verified_with_owner_view_corroborated_is_code_confirmed():
    r = {"shape": "read_semantic", "ground_truth": "REAL", "final_verdict": "verified",
         "guard_override": None, "owner_view_corroborated": True,
         "ai_verdict_raw": "verified", "status": "completed", "degraded": False}
    assert _claim_tier(r) == "code_confirmed"
    out = render_tree(r, color=False)
    assert "[CONFIRMED]" in out and "[SIGNAL" not in out


def test_verified_without_code_channel_is_signal_not_confirmed():
    # THE load-bearing case: verified, but guard_override None AND owner_view_corroborated not True.
    r = {"shape": "read_semantic", "ground_truth": "REAL", "final_verdict": "verified",
         "guard_override": None, "owner_view_corroborated": None,
         "ai_verdict_raw": "verified", "status": "completed", "degraded": False}
    assert _claim_tier(r) == "signal"
    assert case_outcome(r) == "signal"
    out = render_tree(r, color=False)
    assert "[SIGNAL" in out
    assert "[CONFIRMED]" not in out                     # NOT the alarming code-confirmed badge
    assert "not a zero-false-positive confirmation" in out.lower()   # the caveat is present


def test_real_target_code_confirmed_carries_honest_context_line():
    r = {"shape": "read_semantic", "ground_truth": None, "final_verdict": "verified",
         "guard_override": None, "owner_view_corroborated": True,
         "status": "completed", "degraded": False}
    out = render_tree(r, color=False)
    assert "[CONFIRMED]" in out
    # (the context sentence is line-wrapped; assert two contiguous fragments, not the whole span)
    assert "Real target: no ground truth" in out
    assert "NOT claimed on this target" in out


def test_lab_code_confirmed_has_no_real_target_context_line():
    r = {"shape": "delete", "ground_truth": "REAL", "final_verdict": "verified",
         "guard_override": DELETE_READBACK_EXEMPTION_REASON, "negative_assertion": "confirmed_physical",
         "status": "completed", "degraded": False}
    out = render_tree(r, color=False)
    assert "[CONFIRMED]" in out
    assert "NOT claimed on this target" not in out      # lab rows keep the [lab oracle] line only


# ==============================================================================
# DRIFT GUARDS - the renderer's code-channel set must never silently diverge from the engine's.
# ==============================================================================
def test_drift_guard_set_level_channels_match_deep_verifier_constants():
    # Set-level: the renderer's four channel strings ARE deep_verifier's four exemption reasons.
    assert _CODE_CONFIRMED_CHANNELS == set(_FOUR_CHANNELS)


def test_drift_guard_render_level_golden_channel_rows_always_confirmed():
    # Render-level positive anchor, INDEPENDENT of _claim_tier: over the committed golden corpus,
    # EVERY row whose guard_override equals one of deep_verifier's four constants must render
    # [CONFIRMED]. A self-consistent bug (a mistyped channel string reclassifying code-confirmed
    # rows as signal) would pass the tier-header test but fail HERE, because the expectation is
    # anchored to the engine's OWN constants, not the renderer's copy.
    four = set(_FOUR_CHANNELS)
    rows = [r for r in _golden_rows() if r.get("guard_override") in four]
    assert rows, "golden corpus should contain code-channel rows to anchor on"
    for r in rows:
        out = render_tree(r, color=False)
        assert "[CONFIRMED]" in out
        assert "[SIGNAL" not in out and "[REFUTED]" not in out


# ==============================================================================
# EXIT CODES per tier - a signal is a verified verdict, so it is NOT clean (still 1).
# ==============================================================================
def test_exit_code_tiers():
    cc = {"final_verdict": "verified", "guard_override": WRITE_RECORD_EXEMPTION_REASON,
          "shape": "x", "ground_truth": "REAL", "degraded": False}
    sg = {"final_verdict": "verified", "guard_override": None, "owner_view_corroborated": None,
          "shape": "x", "ground_truth": "REAL", "degraded": False}
    rf = {"final_verdict": "failed", "shape": "x", "ground_truth": "SECURE", "degraded": False}
    nd = {"final_verdict": None, "shape": "x", "ground_truth": "REAL",
          "degraded": True, "status": "degraded"}
    assert exit_code_for([cc]) == 1
    assert exit_code_for([sg]) == 1                     # a lone signal must NOT silently drop to 0
    assert exit_code_for([rf]) == 0
    assert exit_code_for([nd]) == 2
    assert exit_code_for([rf, sg]) == 1                 # any verified (signal) -> 1
    assert exit_code_for([rf, nd]) == 2                 # not-data with no verified -> 2


# ==============================================================================
# Broken-for-all conditional finding — renders [INCONCLUSIVE], NEVER [CONFIRMED].
# ==============================================================================
def _broken_for_all_record():
    # The shape the engine emits on the locked-inconclusive broken-for-all path.
    return {"shape": "read_semantic__orders", "ground_truth": None, "final_verdict": "inconclusive",
            "ai_verdict_raw": "verified", "guard_override": _BROKEN_FOR_ALL_REASON,
            "owner_view_corroborated": False, "broken_for_all_suspected": True,
            "status": "completed", "degraded": False, "method": "GET",
            "baseline_path": "/workshop/api/shop/orders/12", "attack_path": "/workshop/api/shop/orders/11"}


def test_broken_for_all_renders_inconclusive_never_confirmed():
    out = render_tree(_broken_for_all_record(), color=False)
    assert "[INCONCLUSIVE]" in out
    assert "[CONFIRMED]" not in out and "[SIGNAL" not in out
    # the two IF branches are BOTH present (equal prominence; neither is fine print)
    assert "IF that assertion holds" in out
    assert "EXPECTED, NOT A BUG" in out
    # the banned words never appear in this rendering
    low = out.lower()
    assert "confirmed" not in low and "verified" not in low
    # raw token kept (transparency), and the reason token surfaced
    assert _BROKEN_FOR_ALL_REASON in out
    assert "broken_for_all_suspected" in out


def test_broken_for_all_tier_is_outside_code_confirmed():
    rec = _broken_for_all_record()
    assert _claim_tier(rec) != "code_confirmed"          # never the zero-FP-claim tier
    assert case_outcome(rec) != "confirmed"
    # a lone conditional finding is not a confirmation -> does not raise the exit code to 1
    assert exit_code_for([rec]) == 0


def test_broken_for_all_windows_console_safe():
    out = render_tree(_broken_for_all_record(), color=False)
    assert "—" not in out                            # no em-dash
    assert _ESC not in out                                # no stray ANSI when color off


def test_drift_guard_broken_for_all_reason_matches_engine_and_is_not_a_code_channel():
    # The renderer's LOCAL reason string must match the engine's constant, and must NOT be one of
    # the four code-confirmed channels (so it can never render [CONFIRMED] / authorize a promotion).
    assert _BROKEN_FOR_ALL_REASON == BROKEN_FOR_ALL_ASSERTION_REASON
    assert _BROKEN_FOR_ALL_REASON not in _CODE_CONFIRMED_CHANNELS
    assert _BROKEN_FOR_ALL_REASON not in _FOUR_CHANNELS


# ==============================================================================
# Cut B, commit 2 — the renderer walks the PHYSICAL chain from the record's flattened, ALREADY-
# redacted bytes and emits a re-runnable evidence package (credentials as <REDACTED> placeholders,
# never a live token). Absent "evidence" -> renders EXACTLY as cut A (graceful degradation).
# ==============================================================================
_LIVE_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.SIGabc123"
_VICTIM_SSN = "999-11-2222"


def _enriched_record(**over):
    ev = {
        "baseline": {
            "request": {"method": "GET", "url": "http://t/api/records/1",
                        "headers": {"Authorization": "***REDACTED***"}, "body": None},
            "response": {"status_code": 200, "content_length": 24,
                         "body": '{"id":1,"owner":"alice"}', "url": "http://t/api/records/1"}},
        "attack": {
            "request": {"method": "GET", "url": "http://t/api/records/2",
                        "headers": {"Authorization": "***REDACTED***"}, "body": None},
            "response": {"status_code": 200, "content_length": 42,
                         "body": '{"id":2,"owner":"bob","ssn":"' + _VICTIM_SSN + '"}',
                         "url": "http://t/api/records/2"}},
        "owner_view": {"status": 200, "reason": "ok", "corroborated": True,
                       "body": '{"id":2,"owner":"bob","ssn":"' + _VICTIM_SSN + '"}'},
    }
    rec = {
        "shape": "read_semantic", "final_verdict": "verified", "owner_view_corroborated": True,
        "guard_override": None, "status": "completed", "ground_truth": None, "degraded": False,
        "method": "GET", "baseline_path": "/api/records/1", "attack_path": "/api/records/2", "body": None,
        "evidence": ev,
    }
    rec.update(over)
    return rec


def test_renderer_byte_chain_shows_victim_data_and_rerunnable_package():
    out = render_tree(_enriched_record(), color=False)
    # the ordered PHYSICAL chain with real bytes
    assert "physical bytes the engine actually exchanged" in out
    assert "Sent as the attacker" in out
    assert "Attack response received" in out
    assert "SAME object re-read AS THE VICTIM" in out            # step 3: the owner-view read-back
    assert _VICTIM_SSN in out                                    # the victim's data IS shown (the evidence)
    # the re-runnable evidence package with placeholders
    assert "Re-runnable evidence package" in out
    assert "curl -X GET 'http://t/api/records/2'" in out
    assert "<REDACTED>" in out                                   # credential placeholder, never a live token


def test_renderer_poc_never_contains_a_live_secret():
    # even if a live token slipped into the record's evidence (simulating a commit-1 miss), the
    # render-layer redactor MUST catch it — a test that FAILS if a live secret reaches the output.
    rec = _enriched_record()
    rec["evidence"]["attack"]["response"]["body"] = '{"token":"' + _LIVE_JWT + '","balance":4200}'
    out = render_tree(rec, color=False)
    assert _LIVE_JWT not in out                                  # live token never rendered
    assert "***REDACTED***" in out
    assert "4200" in out                                         # non-secret data still shown


def test_renderer_without_evidence_degrades_to_cut_a():
    rec = _enriched_record()
    rec.pop("evidence")                                          # a stale golden row: no bytes
    out = render_tree(rec, color=False)
    assert "physical bytes the engine actually exchanged" not in out   # NOT the byte chain
    assert "Evidence chain (the engine's own run)" in out       # the cut-A narrative chain
    assert "Reproduce:" in out                                   # the cut-A one-line reproduce
    assert "Re-runnable evidence package" not in out


def test_renderer_refuted_and_notdata_unaffected_by_evidence_key():
    # evidence is only walked in the confirming/signal chains; a refuted/not-data record is unchanged.
    refuted = _enriched_record(final_verdict="failed", owner_view_corroborated=False)
    out = render_tree(refuted, color=False)
    assert "[REFUTED]" in out
    notdata = _enriched_record(final_verdict=None, degraded=True, status="degraded")
    assert "[NOT DATA]" in render_tree(notdata, color=False)
