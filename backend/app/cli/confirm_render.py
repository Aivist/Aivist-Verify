# ==============================================================================
# Pure renderer for the CLI confirmer (Anti-Gravity's human-walkable front door).
#
# Takes a RESULT-RECORD - the flat dict shape of a `sweep_highN.jsonl` row, optionally
# enriched by the live `confirm` command with method/baseline_path/attack_path/body - and
# returns a human-readable evidence tree.
#
# PURE + OFFLINE: no engine import, no network, no settings. That is deliberate - it makes
# the renderer testable against committed golden rows at zero API cost, and a future
# `--json` trivial (dump the record).
#
# INVARIANTS (structural):
#   * The verdict is READ from the record's engine fields ONLY (`final_verdict`, else
#     `ai_verdict`). This renderer CANNOT manufacture `verified` - it only renders what the
#     engine produced.
#   * `ground_truth` is used ONLY for the separate, clearly-labeled "[lab oracle]" line
#     BELOW the tree - NEVER as an input to the verdict (that would be self-grading).
#   * ALL output passes through a credential redactor (belt-and-suspenders: records never
#     carry auth, but any bearer/token-looking substring is masked regardless).
# ==============================================================================
from __future__ import annotations

import json
import re

_REDACT = "***REDACTED***"


def _redact(text: str) -> str:
    """Mask anything that looks like a credential in rendered output (defense in depth)."""
    text = re.sub(r"(?i)\bbearer\s+\S+", "Bearer " + _REDACT, text)
    text = re.sub(
        r"(?i)\b(authorization|cookie|x-token|api[_-]?key|token|secret)(\s*[:=]\s*)\S+",
        lambda m: m.group(1) + m.group(2) + _REDACT, text,
    )
    return text


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


def case_outcome(record: dict) -> str:
    """'confirmed' (verified) | 'refuted' (a verdict, not verified) | 'notdata' (degraded/error)."""
    if _is_notdata(record):
        return "notdata"
    return "confirmed" if _verdict(record) == "verified" else "refuted"


def exit_code_for(records) -> int:
    """0 = nothing confirmed (clean); 1 = >=1 confirmed; 2 = a NOT-DATA run (degraded/error).
    Precedence: a real confirmation is the headline (1); else any NOT DATA blocks a clean 0 (2)."""
    outcomes = [case_outcome(r) for r in records]
    if "confirmed" in outcomes:
        return 1
    if "notdata" in outcomes:
        return 2
    return 0


# ------------------------------------------------------------------------------
# Tree sections - real engine fields only; nothing invented; no competitor claims.
# ------------------------------------------------------------------------------
def _evidence_lines(record: dict):
    out = []
    if record.get("pre_flight_status") is not None:
        out.append(f"pre-flight read: HTTP {record['pre_flight_status']} "
                   f"(the object existed & was the victim's BEFORE the attack)")
    if record.get("caller_identity"):
        out.append(f"caller identity anchor: {record['caller_identity']}")
    if record.get("payload_causality"):
        out.append(f"payload causality anchor: {record['payload_causality']}")
    if record.get("state_jump"):
        out.append(f"state-jump anchor: {record['state_jump']}")
    if record.get("negative_assertion"):
        out.append(f"negative-assertion anchor: {record['negative_assertion']}")
    if record.get("anchoring_result"):
        out.append(f"evidence anchoring: {record['anchoring_result']}")
    if record.get("owner_view_corroborated") is not None:
        out.append(f"owner-view corroborated: {record['owner_view_corroborated']}")
    ch = record.get("guard_override")
    if ch:
        out.append(f"guard: cross-resource downgrade EXEMPTED via '{ch}'")
    elif record.get("owner_view_corroborated") is True:
        out.append("guard: read-semantic owner-view gate CORROBORATED (attack response is the victim's data)")
    return out


def _why_not_lines(record: dict):
    out = []
    if record.get("shape") == "read_semantic":
        ov = record.get("owner_view_corroborated")
        if ov is False:
            out.append("owner-view NOT corroborated: the attack response did not return the owner's data.")
        elif ov is None:
            out.append("owner-view gate did not corroborate the attack response as the owner's data.")
        sim = record.get("owner_view_similarity")
        if sim is not None:
            out.append(f"owner-view similarity: {sim} (below the corroboration threshold).")
    else:
        if record.get("payload_causality") == "absent":
            out.append("payload causality absent: this attack's injected value did not land in the read-back.")
        if record.get("state_jump") in ("no_jump", "preflight_unknown", "postread_unknown"):
            out.append(f"state jump: {record['state_jump']} (no proven move from a known pre-flight state).")
        if record.get("negative_assertion") in (
            "still_present", "no_preflight", "preflight_absent", "preflight_already_deleted"
        ):
            out.append(f"negative assertion: {record['negative_assertion']} (from-exists-to-absent not proven).")
        if not record.get("guard_override"):
            out.append("cross-resource guard: no deterministic exemption channel fired (verdict downgraded).")
    if not out:
        out.append(f"engine verdict '{_verdict(record)}': no deterministic channel confirmed a cross-user effect.")
    return out


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


def render_tree(record: dict) -> str:
    """Render one result-record as an evidence tree. Verdict from engine fields only."""
    shape = record.get("shape", "?")
    method = record.get("method") or "-"
    path = record.get("baseline_path") or "-"
    notdata = _is_notdata(record)
    verdict = _verdict(record)
    lines = []

    if notdata:
        lines.append(f"[NOT DATA] {shape} - {method} {path}")
        reason = record.get("degraded_reason") or record.get("error") or "engine returned no usable verdict"
        lines.append(f"  Status: {record.get('status', 'degraded')} - {reason}")
        lines.append("  No verdict produced (NOT DATA - excluded from any confirm/clean claim).")
    elif verdict == "verified":
        lines.append(f"[CONFIRMED] {shape} - {method} {path}")
        lines.append(f"  Verdict: verified (channel: {record.get('guard_override') or '(read-semantic owner-view gate)'})")
        lines.append("  Evidence chain (engine's own run):")
        for ln in _evidence_lines(record):
            lines.append("    - " + ln)
        rep = _reproduce_line(record)
        if rep:
            lines.append("  Reproduce: " + rep)
    else:
        lines.append(f"[REFUTED] {shape} - {method} {path}")
        lines.append(f"  Verdict: {verdict}")
        lines.append("  Why not confirmed:")
        for ln in _why_not_lines(record):
            lines.append("    - " + ln)
        lines.append("  no cross-user effect confirmed.")

    lines.append(_lab_oracle_line(record, notdata, verdict))
    return _redact("\n".join(lines))
