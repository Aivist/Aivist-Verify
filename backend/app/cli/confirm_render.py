# ==============================================================================
# Pure renderer for the CLI confirmer (Anti-Gravity's human-walkable front door).
#
# Takes a RESULT-RECORD - the flat dict shape of a `sweep_highN.jsonl` row, optionally
# enriched by the live `confirm` command with method/baseline_path/attack_path/body - and
# returns a human-readable evidence tree that explains, in plain language, WHAT THE ENGINE
# PHYSICALLY DID (wrote as the attacker, read back as another identity, refused to confirm
# when no cross-user effect occurred) instead of dumping internal field tokens.
#
# PURE + OFFLINE: no engine import, no network, no settings. That is deliberate - it makes
# the renderer testable against committed golden rows at zero API cost, and a future
# `--json` trivial (dump the record). The ONLY environment sensing is an OPTIONAL default
# TTY probe for color (sys.stdout.isatty / NO_COLOR / FORCE_COLOR); every caller can pin it
# explicitly with `color=`, and the offline tests always do, so rendering stays deterministic.
#
# INVARIANTS (structural):
#   * The verdict is READ from the record's engine fields ONLY (`final_verdict`, else
#     `ai_verdict`). This renderer CANNOT manufacture `verified` - it only renders what the
#     engine produced. The plain-language layer TRANSLATES field names; it never invents,
#     embellishes, or softens a verdict, and every sentence keeps its raw engine token
#     visible (dim, in parentheses) so a technical reader loses nothing.
#   * `ground_truth` is used ONLY for the separate, clearly-labeled "[lab oracle]" line
#     BELOW the tree - NEVER as an input to the verdict (that would be self-grading).
#   * ALL output passes through a credential redactor (belt-and-suspenders: records never
#     carry auth, but any bearer/token-looking substring is masked regardless).
# ==============================================================================
from __future__ import annotations

import json
import os
import re
import sys
import textwrap
from typing import Optional

_REDACT = "***REDACTED***"


# ------------------------------------------------------------------------------
# Color (ANSI). No third-party dependency: the renderer is pure stdlib on purpose,
# so a confirmed vuln looks alarming and a refuted candidate looks calm WITHOUT
# pulling `rich` into the offline test path. Auto-off when not a TTY (piping / CI /
# pytest capture stay clean), overridable with NO_COLOR / FORCE_COLOR, and every
# render_* function takes an explicit `color=` for deterministic tests.
# ------------------------------------------------------------------------------
_ANSI = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
    "red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m", "cyan": "\033[36m",
}


def _supports_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    try:
        return bool(sys.stdout.isatty())
    except Exception:
        return False


def _painter(color: Optional[bool]):
    """Return a paint(text, *styles) function. color=None => auto-detect once."""
    on = _supports_color() if color is None else bool(color)

    def paint(text: str, *styles: str) -> str:
        if not on or not styles:
            return text
        return "".join(_ANSI[s] for s in styles) + text + _ANSI["reset"]

    return paint


def _redact(text: str) -> str:
    """Mask anything that looks like a credential in rendered output (defense in depth)."""
    text = re.sub(r"(?i)\bbearer\s+\S+", "Bearer " + _REDACT, text)
    text = re.sub(
        r"(?i)\b(authorization|cookie|x-token|api[_-]?key|token|secret)(\s*[:=]\s*)\S+",
        lambda m: m.group(1) + m.group(2) + _REDACT, text,
    )
    return text


# ==============================================================================
# TRANSLATION LAYER - engine token -> ONE honest human sentence.
#
# Every string here is faithful to what the channel/anchor means IN CODE
# (deep_verifier.py). The raw token is always shown alongside (see `_tok`); this
# table only makes the token readable, it never replaces the evidence.
# ==============================================================================
_SHAPE_PLAIN = {
    "write_record": "cross-user write (BOLA)",
    "silent_write": "silent cross-user write (BOLA)",
    "read_semantic": "cross-user read (BOLA)",
    "delete": "cross-user delete (BOLA)",
    "mass_assignment": "mass-assignment / privilege escalation",
}

# guard_override -> short channel name shown on the verdict line.
_CHANNEL_NAME = {
    "write_record_readback_decisive": "write-record read-back",
    "state_readback_causally_decisive": "object-state read-back",
    "delete_readback_negative_assertion_decisive": "delete negative-assertion",
    "state_jump_causally_decisive": "mass-assignment state-jump",
}
_READ_SEMANTIC_CHANNEL_NAME = "read-semantic owner-view gate"

# guard_override -> the "what the engine proved" paragraph for a CONFIRMED verdict.
_CHANNEL_PROOF = {
    "write_record_readback_decisive": (
        "Wrote as the attacker, then read the object back through a different endpoint as "
        "another identity. A record carrying the victim's object id and the exact value this "
        "attack wrote was found on that read-back, so the unauthorized write provably persisted. "
        "That persisted read-back is the proof."
    ),
    "state_readback_causally_decisive": (
        "Wrote as the attacker, then re-read the victim's object's own state as another "
        "identity. It now carries the exact value this attack injected, so the cross-user "
        "write provably persisted."
    ),
    "delete_readback_negative_assertion_decisive": (
        "The victim's object existed and was active immediately before the attack, and was "
        "gone (or marked deleted) immediately after. An unauthorized delete that provably "
        "persisted."
    ),
    "state_jump_causally_decisive": (
        "Every field the attacker sent moved from the victim object's known prior value to "
        "the attacker's injected value. A mass-assignment write that provably persisted."
    ),
}
_READ_SEMANTIC_PROOF = (
    "Re-fetched the victim's object as the victim, and the attacker's response matched that "
    "authentic view. The attacker really did read the victim's data across the "
    "access-control boundary."
)
_SAME_RESOURCE_PROOF = (
    "The engine verified a cross-user effect on the same resource that was attacked "
    "(no cross-resource read-back was required)."
)

# The four deterministic exemption channels - the ONLY guard_override values that authorize a
# code-confirmed 'verified'. Derived from the _CHANNEL_PROOF keys so this cannot drift from the
# translation table; a test also pins it to deep_verifier's own *_EXEMPTION_REASON constants.
# This MIRRORS fuzzer._code_authorized_channel (those four channels OR owner_view_corroborated).
_CODE_CONFIRMED_CHANNELS = frozenset(_CHANNEL_PROOF)

# guard_override -> the "why it did not confirm" paragraph for a REFUTED verdict.
_REFUTE_CHANNEL = {
    "cross_resource_readback_not_decisive": (
        "The only confirming read-back landed on a DIFFERENT resource than the one attacked, "
        "so it cannot prove a cross-user effect. The verdict was downgraded to inconclusive."
    ),
    "owner_view_not_corroborated": (
        "Re-fetched the victim's object as the victim; the attacker's response did NOT return "
        "the victim's data, so no cross-user read actually occurred."
    ),
    "public_resource_read_not_cross_user": (
        "A third, unrelated identity could also read this resource, so it is public/shared - "
        "reading it across accounts is not an authorization violation. The verdict was "
        "suppressed to inconclusive (D30 public-resource discrimination)."
    ),
}
_READ_SEMANTIC_REFUTE = (
    "The owner-view check did not corroborate the attacker's response as the victim's data, "
    "so no cross-user read was confirmed."
)

# guard_override for the opt-in broken-for-all conditional finding. Defined LOCALLY (this module
# stays engine-import-free); a drift-guard test pins it to deep_verifier.BROKEN_FOR_ALL_ASSERTION_REASON.
# It is deliberately NOT in _CODE_CONFIRMED_CHANNELS, so it can never render [CONFIRMED].
_BROKEN_FOR_ALL_REASON = "broken_for_all_owner_assertion_human_review"

# Per-anchor value translations. Keys are the exact engine field values.
_CALLER_IDENTITY = {
    "confirmed": "the read-back object belongs to the victim, not the attacker (a genuine cross-user target)",
    "same_as_caller": "the write was attributed to the attacker's own identity",
    "owner_not_found": "no owner identity on the read-back (e.g. the object returned 404 / was gone)",
}
_PAYLOAD_CAUSALITY = {
    "confirmed_at_path": "this attack's unique value was present in the object's state read-back - the write landed",
    "confirmed_in_body": "this attack's unique value was present in the read-back body - the write landed",
    "absent": "this attack's unique value was NOT present in the read-back - the write did not land",
    "no_payload": "no injected value to trace for this shape",
}
_STATE_JUMP = {
    "confirmed_jump": "every field the attack sent moved from a known prior value to the attacker's value",
    "no_jump": "no field moved from a known prior state to the attacker's value",
    "preflight_unknown": "could not read the object's prior state, so a state-jump cannot be proven",
    "postread_unknown": "could not read the object's state after the attack, so a state-jump cannot be proven",
    "no_sent_fields": "the attack sent no fields to check for a state-jump",
    "indeterminate": "state-jump evidence inconclusive",
}
_NEGATIVE_ASSERTION = {
    "confirmed_physical": "present before the attack, gone (404/403/410) after - a persisted delete",
    "confirmed_logical": "present before the attack, marked deleted (a lifecycle field flipped) after - a persisted soft-delete",
    "still_present": "the object was still present after the attack - nothing was deleted",
    "no_preflight": "could not confirm the object existed before the attack, so a delete cannot be proven",
    "preflight_absent": "the object did not exist before the attack, so its later absence proves nothing",
    "preflight_already_deleted": "the object was already deleted before the attack",
    "indeterminate": "delete evidence inconclusive",
}
_ANCHORING = {
    "confirmed": "a code-side anchor in the response matched the victim (corroborating, observe-only)",
    "value_mismatch": "the code-side anchor did not match the victim (observe-only)",
    "no_path": "no evidence path to anchor on (observe-only)",
    "failed_path_not_found": "the anchoring read-back path was not found (observe-only)",
}


def _translate(table: dict, value) -> str:
    """Plain sentence for an engine value, or the raw value if we have no translation
    (degrade gracefully; never hide an unknown token)."""
    return table.get(value, str(value))


# ------------------------------------------------------------------------------
# Verdict plumbing (unchanged semantics; the verdict still comes ONLY from the engine).
# ------------------------------------------------------------------------------
def _verdict(record: dict):
    """The engine's verdict for this record. `final_verdict` (== res.ai_verdict) is
    authoritative; fall back to `ai_verdict` only when the key is absent."""
    if "final_verdict" in record:
        return record.get("final_verdict")
    return record.get("ai_verdict")


def _is_notdata(record: dict) -> bool:
    """A degraded / errored / verdict-less run is NOT DATA - excluded from any clean/confirm claim."""
    if record.get("degraded"):
        return True
    if record.get("status") in ("degraded", "error"):
        return True
    return _verdict(record) is None


def _claim_tier(record: dict) -> str:
    """The claim tier for a record, from ENGINE FIELDS ONLY (never `ground_truth`):
      "not_data"       - degraded / errored / no verdict;
      "refuted"        - a verdict that is not 'verified';
      "code_confirmed" - 'verified' AND a DETERMINISTIC code channel authorized it (one of the four
                         exemption channels, OR the D24 owner-view gate corroborated). This is the
                         zero-FP-claim domain;
      "signal"         - 'verified' but NO deterministic code channel authorized it (the model's
                         opinion / triage heuristics alone). An engineering lead, NOT a confirmation.
    Mirrors fuzzer._code_authorized_channel exactly; the renderer cannot manufacture `verified` or a
    higher tier - both are read from the record's own engine fields."""
    if _is_notdata(record):
        return "not_data"
    if _verdict(record) != "verified":
        return "refuted"
    if record.get("guard_override") in _CODE_CONFIRMED_CHANNELS:
        return "code_confirmed"
    if record.get("owner_view_corroborated") is True:
        return "code_confirmed"
    return "signal"


def case_outcome(record: dict) -> str:
    """'confirmed' (code-confirmed verified) | 'signal' (verified, not code-confirmed) |
    'refuted' (a verdict, not verified) | 'notdata' (degraded/error). Derived from `_claim_tier`."""
    tier = _claim_tier(record)
    if tier == "not_data":
        return "notdata"
    if tier == "code_confirmed":
        return "confirmed"
    if tier == "signal":
        return "signal"
    return "refuted"


def exit_code_for(records) -> int:
    """0 = nothing verified (clean); 1 = >=1 verified (code-confirmed OR signal); 2 = a NOT-DATA run.
    A 'signal' is still a 'verified' verdict, so it is NOT clean - it returns 1 alongside a
    code-confirmation (the tier distinction lives in the tree/tally, not the exit code). Precedence:
    any verified is the headline (1); else any NOT DATA blocks a clean 0 (2)."""
    outcomes = [case_outcome(r) for r in records]
    if "confirmed" in outcomes or "signal" in outcomes:
        return 1
    if "notdata" in outcomes:
        return 2
    return 0


# ------------------------------------------------------------------------------
# Tree sections - real engine fields only; translated; nothing invented; no
# competitor claims. Each detail bullet carries its raw token (dim) via `_tok`.
# ------------------------------------------------------------------------------
def _tok(paint, field: str, value) -> str:
    return paint(f"({field}={value})", "dim")


def _evidence_lines(record: dict, paint):
    """The CONFIRMED evidence chain: only anchors the engine actually produced."""
    out = []
    ci = record.get("caller_identity")
    if ci:
        out.append(_translate(_CALLER_IDENTITY, ci) + "  " + _tok(paint, "caller_identity", ci))
    pc = record.get("payload_causality")
    if pc and pc != "no_payload":
        out.append(_translate(_PAYLOAD_CAUSALITY, pc) + "  " + _tok(paint, "payload_causality", pc))
    sj = record.get("state_jump")
    if sj:
        out.append(_translate(_STATE_JUMP, sj) + "  " + _tok(paint, "state_jump", sj))
    na = record.get("negative_assertion")
    if na:
        out.append(_translate(_NEGATIVE_ASSERTION, na) + "  " + _tok(paint, "negative_assertion", na))
    pf = record.get("pre_flight_status")
    if pf is not None:
        out.append(f"pre-flight read HTTP {pf} - the object existed and was the victim's before the attack  "
                   + _tok(paint, "pre_flight_status", pf))
    sim = record.get("owner_view_similarity")
    if sim is not None:
        out.append(f"owner-view similarity {sim} vs the corroboration threshold  "
                   + _tok(paint, "owner_view_similarity", sim))
    if record.get("owner_view_corroborated") is True:
        out.append("re-fetched the victim's object as the victim; the attacker's response matched it  "
                   + _tok(paint, "owner_view_corroborated", True))
    ar = record.get("anchoring_result")
    if ar:
        out.append(_translate(_ANCHORING, ar) + "  " + _tok(paint, "anchoring_result", ar))
    return out


# ------------------------------------------------------------------------------
# Walkable evidence chain - the ordered, physical account (built ONLY from fields the
# record actually carries; any step whose field is absent is omitted, never fabricated).
# ------------------------------------------------------------------------------
def _attacker_step(record: dict) -> Optional[str]:
    """Step 1: what was sent as the attacker. None when the record lacks method/path (golden rows
    do; live `confirm` records carry them)."""
    method = record.get("method")
    path = record.get("attack_path") or record.get("baseline_path")
    if not method or not path:
        return None
    body = record.get("body")
    body_s = "" if body is None else f"  body={json.dumps(body, ensure_ascii=False)}"
    return f"{method} {path}{body_s}"


def _reread_step(record: dict, paint) -> Optional[str]:
    """Step 2: the independent re-read, as a DIFFERENT identity than the attack, named per channel.
    None when no code-gated re-read authorized the verdict (e.g. a model-opinion signal)."""
    ch = record.get("guard_override")
    _by_channel = {
        "write_record_readback_decisive":
            "read the object back through a record/log endpoint as another identity (write-record read-back)",
        "state_readback_causally_decisive":
            "re-read the attacked object's own state as another identity (object-state read-back)",
        "delete_readback_negative_assertion_decisive":
            "read the object's state before the attack and again after, as another identity (pre-flight then after read)",
        "state_jump_causally_decisive":
            "read the object's prior state and its state after the attack, as another identity (pre-flight then after read)",
    }
    if ch in _by_channel:
        return _by_channel[ch] + "  " + _tok(paint, "guard_override", ch)
    if record.get("owner_view_corroborated") is True:
        return ("re-fetched the victim's object AS THE VICTIM - a different identity than the attack "
                "(owner-view re-read)  " + _tok(paint, "owner_view_corroborated", True))
    return None


def _ruled_out_steps(record: dict, tier: str):
    """Step 4: what was NOT taken as proof - field-backed only. For a code-confirmed verdict, state
    explicitly that the model's raw opinion alone did not decide it (the code channel did)."""
    out = []
    if tier == "code_confirmed":
        raw = record.get("ai_verdict_raw")
        out.append(f"the model's raw opinion alone did NOT decide this - the deterministic code "
                   f"channel did  (ai_verdict_raw={raw})")
    return out


def _append_chain(lines, record: dict, paint, tier: str) -> None:
    """Emit the ordered, walkable evidence chain into `lines`. Steps with no backing field are
    omitted; the numbering counts only the steps actually shown."""
    lines.append(paint("  Evidence chain (the engine's own run):", "bold"))
    n = 0
    s1 = _attacker_step(record)
    if s1:
        n += 1
        lines.append(f"    {n}. Sent as the attacker:  " + s1)
    s2 = _reread_step(record, paint)
    if s2:
        n += 1
        lines.append(f"    {n}. Independent re-read (a different identity than the attack):  " + s2)
    comps = _evidence_lines(record, paint)
    if comps:
        n += 1
        lines.append(f"    {n}. What decided it:")
        for c in comps:
            lines.append("       - " + c)
    ruled = _ruled_out_steps(record, tier)
    if ruled:
        n += 1
        lines.append(f"    {n}. Not taken as proof:")
        for r in ruled:
            lines.append("       - " + r)
    if n == 0:
        lines.append("    (no per-step evidence fields were recorded on this row)")


def _why_not_lines(record: dict, paint):
    """The REFUTED reasoning: why no cross-user effect was confirmed."""
    out = []
    ch = record.get("guard_override")
    if record.get("shape") == "read_semantic":
        out.append(_READ_SEMANTIC_REFUTE
                   + ("  " + _tok(paint, "guard_override", ch) if ch else ""))
        sim = record.get("owner_view_similarity")
        if sim is not None:
            out.append(f"owner-view similarity {sim} (below the corroboration threshold)")
    else:
        if ch in _REFUTE_CHANNEL:
            out.append(_translate(_REFUTE_CHANNEL, ch) + "  " + _tok(paint, "guard_override", ch))
        # Supporting anchor detail (only what the engine actually recorded).
        pc = record.get("payload_causality")
        if pc == "absent":
            out.append(_translate(_PAYLOAD_CAUSALITY, pc) + "  " + _tok(paint, "payload_causality", pc))
        sj = record.get("state_jump")
        if sj in ("no_jump", "preflight_unknown", "postread_unknown"):
            out.append(_translate(_STATE_JUMP, sj) + "  " + _tok(paint, "state_jump", sj))
        na = record.get("negative_assertion")
        if na in ("still_present", "no_preflight", "preflight_absent", "preflight_already_deleted"):
            out.append(_translate(_NEGATIVE_ASSERTION, na) + "  " + _tok(paint, "negative_assertion", na))
        if not ch and not out:
            out.append("no deterministic exemption channel fired - the model's opinion alone does not confirm")
    if not out:
        out.append(f"engine verdict {_verdict(record)!r}: no deterministic channel confirmed a cross-user effect")
    return out


def _confirm_proof(record: dict):
    """(short channel name, proof paragraph) for a CONFIRMED verdict."""
    ch = record.get("guard_override")
    if ch in _CHANNEL_PROOF:
        return _CHANNEL_NAME.get(ch, ch), _CHANNEL_PROOF[ch]
    if record.get("shape") == "read_semantic":
        return _READ_SEMANTIC_CHANNEL_NAME, _READ_SEMANTIC_PROOF
    return "same-resource verdict", _SAME_RESOURCE_PROOF


def _reproduce_line(record: dict):
    method = record.get("method")
    path = record.get("attack_path") or record.get("baseline_path")
    if not method or not path:
        return None
    body = record.get("body")
    body_s = "" if body is None else f"  body={json.dumps(body, ensure_ascii=False)}"
    return f"{method} {path}{body_s}"


def _lab_oracle_line(record: dict, notdata: bool, verdict) -> str:
    gt = record.get("ground_truth")
    if gt is None:
        return "  [lab oracle] (no ground_truth on this record; nothing to compare)"
    if notdata:
        return f"  [lab oracle] lab label={gt}; engine produced NO verdict (NOT DATA - not comparable)."
    lab_expects_verified = (gt == "REAL")
    engine_verified = (verdict == "verified")
    agree = (lab_expects_verified == engine_verified)
    return (f"  [lab oracle] lab label={gt} (expects {'verified' if lab_expects_verified else 'not-verified'}); "
            f"engine said {verdict!r} - {'AGREES' if agree else 'DIVERGES'}. "
            f"(informational only; NEVER an input to the verdict)")


def render_tree(record: dict, *, color: Optional[bool] = None) -> str:
    """Render one result-record as a plain-language evidence tree. Verdict from engine
    fields only; the renderer structurally cannot manufacture `verified`.

    color: None => auto-detect (TTY / NO_COLOR / FORCE_COLOR); True/False to pin it.
    """
    paint = _painter(color)
    shape = record.get("shape", "?")
    shape_plain = _SHAPE_PLAIN.get(shape, shape)
    method = record.get("method") or "-"
    path = record.get("baseline_path") or "-"
    tier = _claim_tier(record)
    notdata = (tier == "not_data")
    verdict = _verdict(record)
    lines = []

    if notdata:
        lines.append(paint(f"[NOT DATA]  {shape_plain} - {method} {path}", "bold", "yellow"))
        reason = record.get("degraded_reason") or record.get("error") or "engine returned no usable verdict"
        lines.append(f"  Status: {record.get('status', 'degraded')} - {reason}")
        lines.append("  No verdict produced - excluded from any confirm/clean claim.")
    elif tier == "code_confirmed":
        channel_name, proof = _confirm_proof(record)
        ch_tok = record.get("guard_override")
        lines.append(paint(f"[CONFIRMED]  {shape_plain} - {method} {path}", "bold", "red"))
        lines.append("  Verdict: " + paint("verified", "bold", "red")
                     + f"  (confirming channel: {channel_name})  "
                     + _tok(paint, "guard_override", ch_tok if ch_tok else "read_semantic_owner_view_gate"))
        lines.append("  Basis: a deterministic code gate authorized this "
                     "(write-then-independent-read proof), not the model's opinion alone.")
        lines.append(paint("  What the engine proved:", "bold"))
        lines.append(textwrap.fill(proof, width=80, initial_indent="    ", subsequent_indent="    "))
        _append_chain(lines, record, paint, tier)
        if record.get("ground_truth") is None:
            lines.append(textwrap.fill(
                "Real target: no ground truth. The deterministic gate fired (on the two labs that "
                "meant zero false positives), but zero-FP is a lab-measured property and is NOT "
                "claimed on this target.", width=80, initial_indent="  ", subsequent_indent="  "))
        rep = _reproduce_line(record)
        if rep:
            lines.append(paint("  Reproduce:", "bold"))
            lines.append("    " + rep)
    elif tier == "signal":
        # Verified, but NO deterministic code channel authorized it - the model's opinion / triage
        # heuristics alone. A calmer marker (NOT bold red): this is a lead, not a zero-FP confirmation.
        lines.append(paint(f"[SIGNAL - model opinion, not code-confirmed]  {shape_plain} - {method} {path}", "cyan"))
        lines.append("  Verdict: " + paint("verified", "cyan")
                     + "  (no deterministic code channel authorized this)  "
                     + _tok(paint, "guard_override", record.get("guard_override")))
        lines.append(textwrap.fill(
            "No deterministic code gate authorized this. It rests on the model's judgment (and/or "
            "triage heuristics), not the write-then-independent-read proof. Engineering signal - "
            "NOT a zero-false-positive confirmation. Treat it as a lead to verify, not a confirmed "
            "finding.", width=80, initial_indent="  ", subsequent_indent="  "))
        _append_chain(lines, record, paint, tier)
        rep = _reproduce_line(record)
        if rep:
            lines.append(paint("  Reproduce:", "bold"))
            lines.append("    " + rep)
    elif record.get("guard_override") == _BROKEN_FOR_ALL_REASON:
        # A LOCKED-inconclusive conditional finding (opt-in `assert_owner_only`). NOT a confirmation:
        # by black-box design a broken-for-all gap and an all-authenticated-shared feature are
        # identical, so the tool refuses to decide from the operator's assertion alone. The two IF
        # branches carry EQUAL prominence (both bold); no confirming language appears anywhere here.
        lines.append(paint(f"[INCONCLUSIVE]  {shape_plain} - {method} {path}", "bold", "yellow"))
        lines.append("  Verdict: " + paint("inconclusive", "bold", "yellow")
                     + "  (locked - a conditional finding requiring human review)  "
                     + _tok(paint, "guard_override", record.get("guard_override")))
        s1 = _attacker_step(record)
        if s1:
            lines.append(paint("  Attempted:", "bold"))
            lines.append("    " + s1)
        lines.append(paint("  Mechanical evidence (what the engine physically observed):", "bold"))
        lines.append("    - Every AUTHENTICATED principal that tried could read this resource: the "
                     "attacker (cross-account) AND an unrelated third/bystander account both received "
                     "the owner's data.  "
                     + _tok(paint, "broken_for_all_suspected", record.get("broken_for_all_suspected")))
        lines.append("    - An ANONYMOUS request (auth token stripped) did NOT receive the owner's data.")
        lines.append(paint("  The operator asserted this resource should be owner-private.", "bold"))
        lines.append(paint(textwrap.fill(
            "IF that assertion holds: this is a serious BROKEN-FOR-ALL authorization gap - any "
            "authenticated user can read any owner's object.", width=78,
            initial_indent="  ", subsequent_indent="    "), "bold"))
        lines.append(paint(textwrap.fill(
            "IF this resource is shared-by-design (for example an internal directory readable by all "
            "staff): THIS IS EXPECTED, NOT A BUG.", width=78,
            initial_indent="  ", subsequent_indent="    "), "bold"))
        lines.append(textwrap.fill(
            "Why the verdict is locked to inconclusive: black-box, a broken-for-all gap and an "
            "all-authenticated-shared feature are identical from the outside. To hold Zero-FP the "
            "engine refuses to decide from a human assertion alone. Human review required.",
            width=80, initial_indent="  ", subsequent_indent="  "))
    else:  # refuted
        lines.append(paint(f"[REFUTED]  {shape_plain} - {method} {path}", "green"))
        lines.append("  Verdict: " + paint(str(verdict), "green") + "  (checked - no cross-user effect)")
        s1 = _attacker_step(record)
        if s1:
            lines.append(paint("  Attempted:", "bold"))
            lines.append("    " + s1)
        lines.append(paint("  Why it did not confirm:", "bold"))
        for ln in _why_not_lines(record, paint):
            lines.append("    - " + ln)
        lines.append(paint("  Conclusion: the code gate held the line - no cross-user effect confirmed.", "green"))

    lines.append(paint(_lab_oracle_line(record, notdata, verdict), "dim"))
    return _redact("\n".join(lines))


def render_tally(records, *, color: Optional[bool] = None) -> str:
    """One honest line for full-caseset mode. The ALARMING red count is CODE-CONFIRMED only
    (`verified` + a deterministic code channel); a `verified` that no channel authorized is broken
    out as an unconfirmed SIGNAL, not folded into the confirmed count. Counts strictly from the
    engine verdict via `case_outcome`; never `ground_truth`. No claims about other scanners."""
    paint = _painter(color)
    outcomes = [case_outcome(r) for r in records]
    total = len(outcomes)
    confirmed = outcomes.count("confirmed")
    signal = outcomes.count("signal")
    refuted = outcomes.count("refuted")
    notdata = outcomes.count("notdata")

    conf_seg = paint(f"{confirmed} confirmed (code-gated)", *(("bold", "red") if confirmed else ("dim",)))
    ref_seg = paint(f"{refuted} refuted", "green")
    parts = [f"{total} candidate(s) checked", conf_seg]
    if signal:
        parts.append(paint(f"{signal} unconfirmed signal(s)", "cyan"))
    parts.append(ref_seg)
    if notdata:
        parts.append(paint(f"{notdata} not-data", "yellow"))
    return _redact("  " + " | ".join(parts))
