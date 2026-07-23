# ==============================================================================
# AI-in-the-loop Deep Verification  (Architecture Choice A — isolated component)
# ==============================================================================
#
# A NEW, isolated, *serial* deep-verification component. It is PURELY ADDITIVE:
# it does NOT modify or call the parallel engine's verdict path
# (execute_parallel_fuzzing / execute_differential_fuzzing / _differential_verdict).
# It reuses ONLY the stable, side-effect-free request primitives from fuzzer.py
# (mutate_request, _send_request, host helpers, ScopeViolationError) — so the
# existing 73 tests are unaffected.
#
# Purpose: resolve AMBIGUOUS access-control cases that a single-shot differential
# oracle cannot (e.g. a silent BOLA whose write endpoint always returns an opaque
# 200 {"status":"ok"}). It runs the two-turn AI-in-the-loop write-then-read we
# validated empirically:
#
#   Turn 1  : send a baseline (authorized/self) request and an attack
#             (cross-object) request; present BOTH real responses to the model;
#             the model may deliver a verdict now OR request exactly ONE follow-up
#             HTTP request.
#   Execute : if it asks for a follow-up, run it for real — SCOPE-LOCKED to the
#             approved host — and capture the raw response.
#   Turn 2  : feed the real follow-up response back IN THE SAME conversation and
#             obtain the final verdict.
#
# The returned result keeps the FULL evidence trail (baseline, attack, the exact
# follow-up requested, and its raw response) side-by-side with the AI verdict —
# the AI verdict is NEVER the sole field. On any Gemini timeout / error /
# invalid-JSON the function degrades gracefully (never crashes) and records why.
#
# Gated behind settings.AI_DEEP_VERIFY_ENABLED (default False): when disabled the
# function returns a clearly-marked "disabled" result and never touches the
# network. NOT wired into any API endpoint or existing flow — integration later.
# ==============================================================================

import re
import json
import asyncio
import logging
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

import httpx

from backend.app.core.config import settings
# Reuse ONLY stable request primitives from the existing engine (no verdict-path
# functions are imported, called, or modified).
from backend.app.services.fuzzer import (
    mutate_request,
    _send_request,
    _reconstruct_url,
    _host_of,
    _compute_similarity,
    ScopeViolationError,
)
# B-1: generic, target-agnostic catalog queries used to deterministically gather a
# write-record read-back (HALF 1) — no concrete target path/field/tag is referenced.
# M1.2(B) adds the parallel object-STATE resolver used when no RELEVANT write-record exists.
from backend.app.services.endpoint_catalog import (
    has_same_path_readback,
    select_write_record_endpoint,
    select_object_state_endpoint,
    _tokens as _catalog_tokens,
    _WRITE_RECORD_KEYWORDS,
)

_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _is_write_method(method: Optional[str]) -> bool:
    return str(method or "").upper() in _WRITE_METHODS


def _is_delete_method(method: Optional[str]) -> bool:
    """M1.3: the delete shape is special — its proof is a from-EXISTS-to-ABSENT jump, not a
    value appearing — so it takes the pre-flight + negative-assertion path, not payload-causality."""
    return str(method or "").upper() == "DELETE"


def _path_is_write_record(path: Optional[str]) -> bool:
    """Generic check that a CONCRETE follow-up path reads like a record/log/history
    endpoint (same vocabulary as the catalog classifier). Target-agnostic."""
    return bool(_catalog_tokens(path or "") & _WRITE_RECORD_KEYWORDS)

logger = logging.getLogger("app.services.deep_verifier")

# Max characters of a response body embedded in the prompt / evidence trail.
_EVIDENCE_BODY_MAX = 2000
# Transient-503 retry budget for the Gemini call (still degrades after this).
_GEMINI_503_RETRIES = 3


SYSTEM_PROMPT = (
    "You are an autonomous web application security verification agent. Your job "
    "is to judge whether a possible broken-access-control vulnerability is real, "
    "based on observed HTTP evidence. You are rigorous and avoid both false "
    "positives and false negatives. You may gather more evidence before concluding "
    "if the current evidence is ambiguous.\n\n"
    "Your verdict is one of: \"verified\", \"failed\", \"inconclusive\", or "
    "\"suspicious\". Apply this DECISIVE-EVIDENCE STANDARD to every verdict:\n"
    "1. An action endpoint's OWN response — above all an opaque success status such "
    "as 200 {\"status\":\"ok\"} — is NEVER, by itself, evidence that the targeted "
    "state did or did not change. An identical opaque success can be returned whether "
    "the write landed, was silently ignored, or was applied to a different object.\n"
    "2. Return \"verified\" or \"failed\" ONLY when a follow-up read-back demonstrably "
    "reflects the SAME state the attack tried to change: it returns the exact "
    "field/resource that was written (so you can compare it against the value the "
    "attack sent) or is an explicit record of that specific write. \"verified\" = that "
    "state was changed by the unauthorized actor; \"failed\" = that same state is "
    "provably unchanged (the server enforced authorization).\n"
    "3. If the evidence does NOT reflect the targeted state — a wrong or unrelated "
    "object, a read-back missing the written field, or no decisive observation of the "
    "exact thing the attack tried to change — you MUST answer \"inconclusive\". Do NOT "
    "fall back to \"failed\", and do NOT return \"verified\" on the action status alone.\n"
    "4. \"inconclusive\" means \"cannot confirm from the evidence gathered; a human must "
    "decide.\" It is the honest answer ONLY in a genuine evidence gap — when you DO hold "
    "decisive read-back evidence, commit to \"verified\" or \"failed\" rather than hedging.\n"
    "5. SAME-RESOURCE RULE (this is what makes a read-back decisive): a read-back reflects the "
    "targeted state ONLY in one of these cases — (a) it queries the SAME resource/path the "
    "attack targeted (any HTTP method on that same resource); (b) it is an explicit record of that "
    "specific write; (c) it is a read of the ATTACKED OBJECT'S OWN CURRENT STATE that THE SYSTEM "
    "ITSELF selected and executed and says so in the follow-up result — when the attacked resource "
    "has no same-path read-back, the system may fetch the attacked object's state by another path, "
    "and that response IS the state you attacked even though its path differs; or (d) for a DELETE "
    "attack, a PAIR of reads THE SYSTEM ITSELF took — a BEFORE read (taken before your attack) "
    "showing the attacked object existed and was active, and an AFTER read of that SAME object "
    "showing it is now gone (HTTP 404/403) OR its status/lifecycle field flipped to a "
    "deleted/archived value; or (e) for a MASS-ASSIGNMENT attack (you injected an extra field "
    "into a write), a PAIR of reads THE SYSTEM ITSELF took — a BEFORE read (taken before your "
    "attack) recording that field's ORIGINAL state, and an AFTER read of that SAME object showing "
    "the field now holds the value YOU injected, having MOVED from that original state. In case (c) commit "
    "only after checking BOTH that the object returned is the one the attack targeted AND what that "
    "state now holds for the field your attack wrote: if the value your attack sent is present, the "
    "unauthorized write landed (\"verified\"); if the state still holds a different/original value, "
    "it did not (\"failed\"). In case (d) commit only after checking BOTH that the BEFORE read "
    "proves the object existed and was the victim's AND that the AFTER read shows it gone or "
    "flipped to deleted/archived: a missing or deleted AFTER WITHOUT the system's BEFORE existence "
    "proof is NOT decisive (the object may never have existed, or was already deleted) -> answer "
    "\"inconclusive\"; if the AFTER read shows the object still present and unchanged, the delete "
    "did not land (\"failed\"). In case (e) the ORIGINAL state is what makes it decisive, because "
    "the injected value is LOW-ENTROPY: the field merely READING your value proves nothing (it may "
    "already have held it). Commit \"verified\" ONLY if the field MOVED — it was ABSENT from the "
    "system's BEFORE read (sensitive fields are often hidden from you, and absent->your value IS a "
    "real escalation), or it held a DIFFERENT value there. If the field still holds its BEFORE "
    "value, is still absent, or your injected value equals what the BEFORE read already showed, "
    "the escalation did NOT land -> \"failed\" or \"inconclusive\", NEVER \"verified\". Without "
    "the system's BEFORE read, answer \"inconclusive\". Cases (c), (d) and (e) NEVER apply to a read YOU chose: a DIFFERENT "
    "endpoint you picked yourself, or one that merely exposes a field with the SAME NAME as what "
    "you wrote, is NOT the same state — matching field names across different resources/paths do "
    "NOT make a read-back decisive, so you MUST answer \"inconclusive\" (not \"failed\", not "
    "\"verified\"). A read-back of the SAME resource/path you attacked remains FULLY decisive — "
    "use it to commit to \"verified\" or \"failed\"."
)

_OPTIONS_BLOCK = """\
## Your options THIS TURN
You may EITHER:
  (A) deliver a FINAL verdict now, OR
  (B) request exactly ONE additional HTTP request to gather more evidence before deciding.
The follow-up (if any) will be executed against the SAME target host and fed back
to you. You may request only ONE request, and only a relative path on this host.
Spend it well: choose the ONE follow-up that reads back the SAME resource/path you attacked
(any HTTP method on that same resource), or an explicit record of that specific write, so you
can compare it against the value the attack sent. A DIFFERENT endpoint that merely exposes a
field with the same NAME as what you wrote is NOT the same state and will NOT let you conclude
"verified" or "failed".

HOW TO CHOOSE when your attack was a WRITE (a state-changing request) and NO available endpoint
reads back the SAME path you attacked: do not settle for an endpoint on a different object just
because its response carries a field with the same name you wrote — a same-named field on a
different resource is NOT decisive and will only force an "inconclusive". Instead, scan the
available endpoints for one that is an explicit RECORD of write activity — a log, history,
journal, events feed, or audit-style record/trail that captures actions performed — and prefer
reading THAT. A record that lists the specific write you performed (the action on the exact
object you targeted) is decisive: its presence shows the unauthorized write landed, its absence
(when such writes would be recorded) shows it did not. Weigh the evidence by what it proves about
the state you attacked, not by which response happens to echo your field name. If neither a
same-path read-back nor such a record exists, gather what you can and answer "inconclusive".

## Required output
Respond with ONLY a JSON object of EXACTLY this shape (no markdown, no extra text):
{
  "decision": "verdict" | "request_more",
  "next_request": { "method": "...", "path": "/...", "body": {...} | null, "reason": "..." } | null,
  "verdict": "verified" | "suspicious" | "failed" | "inconclusive" | null,
  "confidence": 0.0-1.0,
  "evidence_path": "<a concrete JSON path INTO the observed response you cite as decisive — e.g. owner_id, data.owner_id, results[0].owner_id — or null if none>",
  "reasoning": "..."
}

Rules:
- If decision is "request_more", "next_request" MUST be populated and "verdict" MUST be null.
- If decision is "verdict", "verdict" MUST be populated and "next_request" MUST be null.
- "evidence_path": when you deliver a verdict, cite the single concrete JSON path in the
  observed response body that most decisively supports it (e.g. the field that identifies
  WHOSE object was returned, or the field that carries the written value). Use a dotted /
  bracket path from the root of that JSON body. null only when no field is decisive.
- An opaque action-response status (e.g. 200 {"status":"ok"}) is NEVER, by itself, proof
  that the targeted state did or did not change.
- "verified" = the attacked state was demonstrably changed — a read-back of the SAME resource/
  path you attacked, an explicit record of that write, or a read of the attacked object's own
  state THE SYSTEM ITSELF gathered, shows the value your attack sent.
- "failed" = the attacked state is demonstrably unchanged — one of those same three decisive
  read-backs shows the server enforced authorization (your value is absent; the original stands).
- "inconclusive" = the evidence does not reflect the attacked state — it came from a DIFFERENT
  resource/path that YOU chose (even if that endpoint exposes a same-named field), the written
  field is absent, or there was no decisive observation; you cannot confirm and a human must. Do
  NOT downgrade it to "failed" or inflate it to "verified" on the action status alone.
- "suspicious" = still ambiguous and you have not yet spent your one follow-up.
"""

_TURN2_TEMPLATE = """\
I have executed the ONE follow-up request you asked for, against the live target. Verbatim result:

## Follow-up request sent
{req_line}{body_line}

## Verbatim raw response received
{raw_response}

Now deliver your FINAL verdict. You may NOT request more information this turn.
Apply the decisive-evidence standard: return "verified" or "failed" ONLY if this read-back
(a) queries the SAME resource/path you attacked (any HTTP method on that same resource), (b) is
an explicit record of that specific write, (c) is a read of the ATTACKED OBJECT'S OWN CURRENT
STATE that the SYSTEM ITSELF selected and executed (a note above will say so explicitly) — in
case (c) it IS the state you attacked even though its path differs, so check that the object
returned is the one you targeted, compare the value your attack sent against what that state now
holds, and commit ("verified" if your value is present, "failed" if the original value stands) —
or (d) for a DELETE attack, the SYSTEM's BEFORE read (in the note above, showing the object
existed and was active) paired with this AFTER read: if the object is now gone (404/403) or its
status/lifecycle field flipped to a deleted/archived value, the unauthorized delete landed
("verified"); if it is still present and unchanged, it did not ("failed"). Without the system's
BEFORE existence proof, a missing/deleted AFTER is NOT decisive — answer "inconclusive".
Or (e) for a MASS-ASSIGNMENT attack, the SYSTEM's BEFORE read (in the note above, recording the
original state of the field you injected) paired with this AFTER read: commit "verified" ONLY if
that field now holds YOUR injected value AND it MOVED to get there — it was ABSENT in the BEFORE
read, or held a DIFFERENT value. The value merely matching proves nothing (it is low-entropy and
may already have been that). Unchanged, still absent, or injected == the BEFORE value -> the
escalation did not land ("failed"/"inconclusive"), NEVER "verified".
A DIFFERENT endpoint YOU chose that merely exposes a field with the same NAME as what you wrote
is NOT the same state — if that is all you have (or the written field is absent, or nothing
decisive was observed), you MUST answer "inconclusive"; do not fall back to "failed", and do not
return "verified" on the action status alone. A read-back of the SAME resource/path you attacked
IS decisive — use it to commit.
Respond with ONLY a JSON object of EXACTLY this shape (no markdown, no extra text):
{{
  "decision": "verdict",
  "next_request": null,
  "verdict": "verified" | "suspicious" | "failed" | "inconclusive",
  "confidence": 0.0-1.0,
  "evidence_path": "<a concrete JSON path into the observed response you cite as decisive, or null>",
  "reasoning": "..."
}}
"""


# ==============================================================================
# Structured, auditable result — AI verdict is NEVER the sole field.
# ==============================================================================
@dataclass
class DeepVerificationResult:
    status: str                              # "completed" | "degraded" | "disabled"
    ai_verdict: Optional[str]                # "verified" | "suspicious" | "failed" | None
    ai_confidence: Optional[float]
    ai_reasoning: str
    ai_requested_follow_up: bool
    follow_up_request: Optional[Dict[str, Any]]   # {method, path, body, reason}
    follow_up_response: Optional[Dict[str, Any]]  # {status_code, content_length, body, url}
    baseline: Dict[str, Any]                 # {request, response}
    attack: Dict[str, Any]                   # {request, response}
    model: str
    approved_host: str
    turns_raw: List[str] = field(default_factory=list)   # verbatim model JSON per turn
    degraded_reason: Optional[str] = None
    # B-2.2 transparency: the model's RAW (pre-guard) verdict + any structural override.
    ai_verdict_raw: Optional[str] = None
    guard_override: Optional[str] = None
    # M1.1 evidence anchoring (observe-only): the JSON path the model CITED as decisive,
    # and the CODE's structural verdict on whether that path resolves in the read-back and
    # points at the attacked victim's runtime id (OBJECT identity). anchoring_result is one of:
    # "confirmed" | "value_mismatch" | "failed_path_not_found" | "unparsable_read_back"
    # | "no_read_back" | "no_path". Never changes ai_verdict — it corroborates it.
    ai_evidence_path: Optional[str] = None
    anchoring_result: Optional[str] = None
    # M1.2 anchoring (observe-only, additive). Broken access control REQUIRES caller != owner
    # AND (for a silent write) that THIS attack's unique value caused the observed state:
    #   caller_identity_anchor  — "confirmed" | "same_as_caller" | "owner_not_found"
    #                             | "no_read_back" | "unparsable_read_back" | "no_ids"
    #   payload_causality_anchor — "confirmed_at_path" | "confirmed_in_body" | "absent"
    #                             | "no_payload" | "no_read_back" | "unparsable_read_back"
    # Both are logged and stored, NEVER used to change the verdict or gate anything.
    caller_identity_anchor: Optional[str] = None
    payload_causality_anchor: Optional[str] = None
    # M1.3 delete-shape (observe-first, gates ONLY the delete exemption):
    #   pre_flight_status         — HTTP status of the code's pre-attack existence read (or None)
    #   negative_assertion_anchor — "confirmed_physical" | "confirmed_logical" | "still_present"
    #                               | "no_preflight" | "preflight_absent"
    #                               | "preflight_already_deleted" | "indeterminate" | None
    #   preflight_caller_identity_anchor — the caller-identity anchor computed on the PRE-FLIGHT
    #     body, i.e. the one the delete gate ACTUALLY uses. Surfaced separately because
    #     `caller_identity_anchor` above is computed on the AFTER read, which for a physical
    #     delete is a 404 with no owner to anchor on (it reads "owner_not_found") — that would
    #     misrepresent the evidence chain in an audit transcript. Same values as
    #     caller_identity_anchor. OBSERVE-ONLY: reported, never used to change a verdict here.
    pre_flight_status: Optional[int] = None
    negative_assertion_anchor: Optional[str] = None
    preflight_caller_identity_anchor: Optional[str] = None
    # M1.4 mass-assignment (observe-first, gates ONLY the mass-assignment exemption):
    #   "confirmed_jump" | "no_jump" | "preflight_unknown" | "postread_unknown"
    #   | "no_sent_fields" | "indeterminate" | None
    state_jump_anchor: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ==============================================================================
# B-2.2 structural backstop (target-agnostic). A decisive verdict that rests on a
# follow-up read-back of a DIFFERENT concrete resource/path than the one attacked is
# NOT decisive. These helpers compare two path STRINGS only — they hold no knowledge
# of this (or any) target's endpoints, fields, or objects.
# ==============================================================================
CROSS_RESOURCE_OVERRIDE_REASON = "cross_resource_readback_not_decisive"
# B-1: a cross-path read-back is EXEMPTED from the cross-resource downgrade ONLY when the
# code has structurally verified it is an explicit record of THIS attack's write (same
# attacked object id + same written value, found together in a single record). The model's
# say-so is never sufficient — see _write_record_content_match.
WRITE_RECORD_EXEMPTION_REASON = "write_record_readback_decisive"
# M1.2(A): a SECOND, separate exemption channel. A cross-path STATE read-back (the attacked
# object's OWN state, NOT a write-record) is EXEMPTED from the downgrade ONLY when the code has
# structurally confirmed all three, AND-ed: the read object IS the attacked object (owner ==
# attacked), the actor differs from the owner (caller != owner), AND this attack's UNIQUE
# injected value appears in the read-back (payload causality). The causality check is the
# non-negotiable false-positive gate — (owner==attacked, caller!=owner) hold for BOTH a real
# leak and a securely-dropped write; only the unique value landing separates them. Computed by
# the caller from the M1.2 anchors and passed in as a boolean (see execute_deep_verification).
STATE_READBACK_EXEMPTION_REASON = "state_readback_causally_decisive"
# M1.3: a THIRD exemption channel, for the DELETE shape (negative assertion). A cross-path
# "verified" is exempted ONLY when code has structurally confirmed the from-EXISTS-to-ABSENT jump:
# a PRE-FLIGHT read (taken before the attack) proved the object EXISTED and was active AND was the
# victim's (owner==attacked, caller!=owner), AND the post-attack read-back shows it GONE (404/403)
# or soft-deleted (status flipped). The pre-flight existence proof is the coincidence gate — a
# missing/deleted read-back alone is never enough. Computed by the caller and passed as a boolean.
DELETE_READBACK_EXEMPTION_REASON = "delete_readback_negative_assertion_decisive"
# M1.4: a FOURTH exemption channel, for MASS-ASSIGNMENT. Its values are LOW-ENTROPY, so
# payload-causality (presence of a unique value) cannot prove causation. A cross-path "verified"
# is exempted ONLY when code confirms a STATE JUMP: every field the attack sent moved from a KNOWN
# pre-flight state (a present value, or proven-MISSING via a SUCCESSFUL pre-flight) to the value
# this attack injected. A failed/unparseable pre-flight or post read-back is UNKNOWN, never MISSING.
STATE_JUMP_EXEMPTION_REASON = "state_jump_causally_decisive"


def _normalize_path(path: Optional[str]) -> str:
    """Concrete-path comparison key: drop query + fragment, strip a trailing slash.

    Content-agnostic (string only); root "/" is preserved.
    """
    p = path or ""
    p = p.split("?", 1)[0].split("#", 1)[0]
    if len(p) > 1:
        p = p.rstrip("/")
    return p


def _apply_cross_resource_guard(
    verdict: Optional[str],
    attack_path: Optional[str],
    follow_up_path: Optional[str],
    follow_up_performed: bool,
    write_record_decisive: bool = False,
    state_readback_decisive: bool = False,
    delete_readback_decisive: bool = False,
    state_jump_decisive: bool = False,
):
    """Structural backstop. Returns (final_verdict, decision_reason).

    Downgrades a decisive verdict to "inconclusive" IFF it rests on a follow-up
    read-back of a DIFFERENT concrete resource/path than the one attacked:
        verdict in {"verified","failed"} AND a follow-up read-back was performed AND
        normalize(follow_up_path) != normalize(attack_path)
    Everything else is returned untouched (decision_reason None):
        - no follow-up performed (e.g. a read-type/GET BOLA confirmed by the attack
          response itself, with no follow-up) -> unchanged;
        - same-resource read-back (normalized paths equal) -> unchanged, decisive;
        - verdict "suspicious" / "inconclusive" / None -> unchanged.

    B-1 WRITE-RECORD EXEMPTION (the (b) standard): a cross-path "verified" is NOT
    downgraded when `write_record_decisive` is True — i.e. the caller has STRUCTURALLY
    verified (in code, against the attack's own runtime params) that the cross-path
    read-back is an explicit record containing the SAME attacked object id AND the SAME
    value this attack wrote. That presence is decisive proof the unauthorized write
    landed. The exemption applies ONLY to "verified" (a record's PRESENCE proves a write
    happened; it cannot prove the negative), and ONLY when the structural content match
    held — a write-record FLAG without the verified content match does NOT exempt (so a
    secure cross-path control with no matching record stays "inconclusive").

    M1.2(A) STATE-READBACK EXEMPTION (a SECOND, separate channel): a cross-path "verified"
    is ALSO kept decisive when `state_readback_decisive` is True — i.e. the caller has
    structurally confirmed (in code, from the read-back + the attack's OWN runtime params,
    never the model's say-so) that the cross-path read-back is the ATTACKED object's OWN
    STATE and it now carries THIS attack's unique injected value: owner==attacked AND
    caller!=owner AND payload-causality confirmed, all three AND-ed by the caller. Like the
    write-record channel it applies ONLY to "verified" and ONLY on a cross-path read-back.
    The two channels are DISJOINT (the caller never sets this for a write-record path), and
    the write-record exemption takes precedence when both are set — so B-1 is unaffected.

    M1.3 DELETE-READBACK EXEMPTION (a THIRD, separate channel): a cross-path "verified" is ALSO
    kept decisive when `delete_readback_decisive` is True — i.e. the caller has structurally
    confirmed the from-EXISTS-to-ABSENT jump for a DELETE attack: a pre-flight read proved the
    object existed, was active, and was the victim's, AND the post-attack read-back shows it gone
    (404/403) or soft-deleted. Like the others it applies ONLY to "verified" and ONLY on a
    cross-path read-back, and is DISJOINT (this shape has no written value, so the state-readback
    channel — which requires payload-causality — never fires for it, and vice versa).

    M1.4 MASS-ASSIGNMENT EXEMPTION (a FOURTH channel): a cross-path "verified" is ALSO kept
    decisive when `state_jump_decisive` is True — i.e. the caller has structurally confirmed a
    STATE JUMP: every field the attack sent moved from a KNOWN pre-flight state to the value this
    attack injected. Low-entropy values make mere presence meaningless, so only the jump counts.
    Disjoint from the M1.2 state channel: the caller routes a mass-assignment-typed attack here and
    suppresses the payload-causality channel for it (that channel would otherwise confirm on a
    SECURE allow-list target, where the legitimate field lands while the privileged one is stripped).

    Method-agnostic and target-agnostic: compares path strings; `write_record_decisive`,
    `state_readback_decisive`, `delete_readback_decisive` and `state_jump_decisive` are all
    computed by the caller as booleans.
    """
    if verdict not in ("verified", "failed"):
        return verdict, None
    if not follow_up_performed:
        return verdict, None
    if _normalize_path(follow_up_path) == _normalize_path(attack_path):
        return verdict, None
    # Cross-path read-back from here on.
    if verdict == "verified" and write_record_decisive:
        return verdict, WRITE_RECORD_EXEMPTION_REASON
    if verdict == "verified" and state_readback_decisive:
        return verdict, STATE_READBACK_EXEMPTION_REASON
    if verdict == "verified" and delete_readback_decisive:
        return verdict, DELETE_READBACK_EXEMPTION_REASON
    if verdict == "verified" and state_jump_decisive:
        return verdict, STATE_JUMP_EXEMPTION_REASON
    return "inconclusive", CROSS_RESOURCE_OVERRIDE_REASON


# ==============================================================================
# B-1 HALF 2 — structural content match (target-agnostic). Proves a cross-path
# read-back is an explicit record of THIS attack's write by checking, IN CODE and
# against the attack's OWN runtime parameters, that a SINGLE record object in the
# read-back contains BOTH the attacked object id AND a value this attack wrote.
# Equality on scalar values (NOT substring) — so a baseline self-write row, or a
# same-named field showing the OLD value, can never spuriously satisfy it.
# ==============================================================================
def _scalar_str(v: Any) -> str:
    return str(v).strip()


def _attacked_object_id(
    baseline_path: Optional[str], attack_path: Optional[str], payload: Optional[Dict[str, Any]]
) -> Optional[str]:
    """The object id the attack targeted, from the attack's own runtime params: the path
    segment that the mutation changed (baseline vs attack diff), else the BOLA
    payload_string. Target-agnostic (no field/path knowledge)."""
    b = (baseline_path or "").split("?", 1)[0].split("/")
    a = (attack_path or "").split("?", 1)[0].split("/")
    if len(a) == len(b):
        diffs = [a[i] for i in range(len(a)) if a[i] != b[i]]
        if len(diffs) == 1 and diffs[0]:
            return _scalar_str(diffs[0])
    ps = (payload or {}).get("payload_string")
    return _scalar_str(ps) if ps not in (None, "") else None


def _caller_object_id(
    baseline_path: Optional[str], attack_path: Optional[str], payload: Optional[Dict[str, Any]]
) -> Optional[str]:
    """The CALLER's own object id — the BASELINE's differing path segment (self). The
    baseline is the authorized/self request, so the segment the mutation changed carries the
    caller's own id (e.g. baseline '/api/x/1' vs attack '/api/x/2' -> caller '1'). Mirror of
    _attacked_object_id but returns the baseline value, else the payload's target_param.
    Target-agnostic (no field/path knowledge)."""
    b = (baseline_path or "").split("?", 1)[0].split("/")
    a = (attack_path or "").split("?", 1)[0].split("/")
    if len(a) == len(b):
        diffs = [b[i] for i in range(len(a)) if a[i] != b[i]]
        if len(diffs) == 1 and diffs[0]:
            return _scalar_str(diffs[0])
    tp = (payload or {}).get("target_param")
    return _scalar_str(tp) if tp not in (None, "") else None


def _written_values(attack_req: Dict[str, Any]) -> List[str]:
    """The scalar value(s) THIS attack wrote, taken from its OWN request body (runtime
    params). Target-agnostic: whatever the engine sent, not any known field name."""
    body = attack_req.get("body")
    out: List[str] = []
    parsed = body
    if isinstance(body, str) and body.strip():
        try:
            parsed = json.loads(body)
        except Exception:
            parsed = None
            out.append(body.strip())
    if isinstance(parsed, dict):
        for v in parsed.values():
            if isinstance(v, (str, int, float, bool)):
                out.append(_scalar_str(v))
    return [v for v in out if v != ""]


def _iter_records(obj: Any):
    """Yield every dict object found anywhere in a parsed JSON structure (recursively)."""
    if isinstance(obj, dict):
        yield obj
        for v in obj.values():
            yield from _iter_records(v)
    elif isinstance(obj, list):
        for item in obj:
            yield from _iter_records(item)


# ------------------------------------------------------------------------------
# D23 — the attacked-object-id check binds to an OWNER/SUBJECT-style key.
#
# A record's own primary key ("id", "pk", …) says NOTHING about WHOSE object the
# record is about. Matching the attacked id against *any* scalar therefore let a
# dirty/accumulated log false-match: a row whose own id coincidentally equals the
# attacked id (while belonging to a different user) would satisfy the gate and fire
# the exemption -> FALSE POSITIVE on a secure control (X-SAFE). The attacked id is
# now only compared against fields that NAME an owner/subject.
#
# Target-agnostic: this is a GENERIC vocabulary of universal API owner/subject
# concepts — the same sanctioned pattern as endpoint_catalog._WRITE_RECORD_KEYWORDS
# (audit/log/history/…). It is a CATEGORY, not this target's concrete field: the same
# words identify the subject key in any API, and a record naming its subject
# "ownerId"/"account_id"/"subjectId" works identically. Bare "id"/"pk" are
# deliberately ABSENT — excluding them IS the fix.
# ------------------------------------------------------------------------------
_OWNER_KEY_KEYWORDS = frozenset({
    "user", "users",
    "owner", "owners",
    "subject", "subjects",
    "account", "accounts",
    "actor", "actors",
    "member", "members",
    "customer", "customers",
    "principal", "principals",
    "holder", "holders",
    "author", "authors",
    "tenant", "tenants",
    "object", "objects",
    "resource", "resources",
    "entity", "entities",
    "target", "targets",
    "uid",
})

# Split camelCase boundaries so "userId"/"UserID" tokenize like "user_id".
_CAMEL_BOUNDARY_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_FIELD_SPLIT_RE = re.compile(r"[^a-z0-9]+")


def _field_tokens(name: Any) -> set:
    """Lower-cased whole tokens of a FIELD NAME, splitting camelCase and every
    non-alphanumeric boundary: 'user_id' / 'userId' / 'UserID' -> {'user','id'};
    'id' -> {'id'}. Target-agnostic."""
    spaced = _CAMEL_BOUNDARY_RE.sub(" ", str(name or ""))
    return {t for t in _FIELD_SPLIT_RE.split(spaced.lower()) if t}


def _is_owner_key(name: Any) -> bool:
    """True iff a field NAME reads like an owner/subject key by the generic vocabulary.
    A record's own primary key ('id', 'pk') is NOT an owner key — that is the D23 fix."""
    return bool(_field_tokens(name) & _OWNER_KEY_KEYWORDS)


def _record_owner_id_values(record: Dict[str, Any]) -> set:
    """The scalar values of this record's OWNER/SUBJECT-style fields ONLY — never the
    record's own primary key. Empty when the record names no subject (-> no match ->
    the caller stays inconclusive, the safe direction)."""
    return {
        _scalar_str(v) for k, v in record.items()
        if isinstance(v, (str, int, float, bool)) and _is_owner_key(k)
    }


# ------------------------------------------------------------------------------
# D23b — the VALUE check binds to non-primary-key CONTENT fields (mirror of D23).
#
# D23 stopped the attacked id matching a record's own primary key. The same hole
# existed on the value axis: scanning EVERY scalar meant an attack-written value that
# merely equalled a record's own `id` satisfied the value half via that id rather than
# via the content field the write actually landed in. A record's own primary key is
# never "content this attack wrote", so it is excluded from the value candidates.
#
# Target-agnostic and structural: a field is the record's own key only when its name is
# composed SOLELY of primary-key-ish tokens ("id", "pk", "uuid", "seq"…). A QUALIFIED
# name like "user_id" is NOT the record's own key (it names a subject) and therefore
# still counts as content — so this exclusion cannot swallow a real written value.
# ------------------------------------------------------------------------------
_PRIMARY_KEY_KEYWORDS = frozenset({
    "id", "pk", "uuid", "guid",
    "rowid", "row",
    "identifier",
    "seq", "sequence",
    "ordinal", "index",
})


def _is_primary_key_field(name: Any) -> bool:
    """True iff a field NAME is the record's OWN identity/ordinal key — i.e. its tokens
    are composed solely of primary-key-ish words ('id', 'pk', 'uuid', 'rowId', 'seq'…).
    A qualified name such as 'user_id' is NOT the record's own key (it names a subject),
    so it stays eligible as content. Target-agnostic."""
    tokens = _field_tokens(name)
    return bool(tokens) and tokens <= _PRIMARY_KEY_KEYWORDS


def _record_content_values(record: Dict[str, Any]) -> set:
    """The scalar values of this record's CONTENT fields — every scalar EXCEPT the
    record's own primary-key/ordinal field(s) (D23b). Strictly a subset of the record's
    scalars, so the value check can only get stricter."""
    return {
        _scalar_str(v) for k, v in record.items()
        if isinstance(v, (str, int, float, bool)) and not _is_primary_key_field(k)
    }


def _write_record_content_match(
    read_back_body: Optional[str], attacked_object_id: Optional[str], written_values: List[str]
) -> bool:
    """True iff some SINGLE record object in the (JSON) read-back binds the attacked
    object id to a value this attack wrote — equality on scalar values, not substring.
    Decisive proof the cross-user write LANDED on the attacked object.

    The attacked id must appear as the value of an OWNER/SUBJECT-style field of that
    record (D23) — matching it against the record's own primary key proves nothing about
    whose object the record is about. The written value must appear in one of the record's
    CONTENT fields (D23b) — the record's own primary key is never content this attack wrote.

    Safety: a baseline self-write row (different owner), a same-named field showing the
    OLD value, or a row whose own primary key merely collides with the attacked id (or with
    the written value) can never satisfy this — so a secure cross-path control yields False
    -> no exemption -> stays inconclusive. A record that names no subject at all also yields
    False (err toward inconclusive). Non-JSON / unparsable bodies -> False (conservative).
    """
    if not read_back_body or attacked_object_id is None or not written_values:
        return False
    aid = _scalar_str(attacked_object_id)
    wanted_values = {str(v).strip() for v in written_values if str(v).strip()}
    if not aid or not wanted_values:
        return False
    try:
        parsed = json.loads(read_back_body)
    except Exception:
        return False
    for record in _iter_records(parsed):
        # The attacked id must be this record's SUBJECT, not just any scalar it carries.
        if aid not in _record_owner_id_values(record):
            continue
        # The written value must be in the record's CONTENT, not its own primary key.
        if _record_content_values(record) & wanted_values:
            return True
    return False


def _record_is_relevant_to_write(
    record_body: Optional[str],
    caller_object_id: Optional[str],
    written_values: List[str],
) -> bool:
    """M1.2 OBJECT-SCOPE gate (target-agnostic). Is a candidate write-record endpoint plausibly
    ABOUT THE ATTACKED OBJECT's write-type — i.e. does it actually record writes like this one?

    Proven structurally WITHOUT any counterfactual or hardcoding: the BASELINE (authorized self)
    write DEFINITELY landed, so if this record endpoint tracks writes of this type it MUST already
    contain the CALLER's own write — the caller's id together with the value we wrote, in one
    record. Reuses the B-1 content-match (unchanged) with the CALLER's runtime id. Returns False
    when the record does NOT contain the caller's landed self-write (e.g. a global audit-log that
    does not record THIS resource) -> HALF-1 should step back and let the model choose its own
    follow-up (for a state-confirmable write, the object's own read-back)."""
    return _write_record_content_match(record_body, caller_object_id, written_values)


def _redact_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Mask auth secrets in the evidence trail / prompt (request still uses the real value)."""
    out = {}
    for k, v in (headers or {}).items():
        if k.lower() in ("authorization", "cookie", "x-token"):
            out[k] = "***REDACTED***"
        else:
            out[k] = v
    return out


def _summarize_response(result: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "status_code": result.get("status_code"),
        "content_length": result.get("content_length"),
        "body": (result.get("response_body") or "")[:_EVIDENCE_BODY_MAX],
        "url": result.get("url"),
    }


def _fmt_exchange(label: str, method: str, url: str, headers: dict, body: Any, result: Dict[str, Any]) -> str:
    lines = [f"{label}:", f"{method} {url}"]
    for k, v in _redact_headers(headers).items():
        lines.append(f"{k}: {v}")
    if body is not None:
        lines.append("Body: " + (json.dumps(body) if not isinstance(body, str) else body))
    lines.append(
        f"-> HTTP {result.get('status_code')} | Content-Length: {result.get('content_length')}"
    )
    lines.append((result.get("response_body") or "")[:_EVIDENCE_BODY_MAX])
    return "\n".join(lines)


def _build_turn1_prompt(context_note: str, evidence_block: str,
                        available_endpoints: Optional[List[str]]) -> str:
    parts = [
        "# Broken-access-control verification scenario\n",
        "You are verifying a POSSIBLE broken-access-control vulnerability on a target API.\n",
    ]
    if context_note:
        parts.append("## Context\n" + context_note.strip() + "\n")
    if available_endpoints:
        # The discoverable API surface a real integration would have (from the API
        # spec / HAR / proxy capture). Giving the model the catalog lets it request
        # the CORRECT read-back endpoint instead of guessing a path.
        cat = "\n".join(f"  - {e}" for e in available_endpoints)
        parts.append("## Available endpoints (you may request ONE of these as a follow-up)\n" + cat + "\n")
    parts.append("## Evidence collected so far (REAL responses just captured from the live target)\n")
    parts.append(evidence_block + "\n")
    parts.append(_OPTIONS_BLOCK)
    return "\n".join(parts)


# ==============================================================================
# Provider seam — ALL provider-specific generation config (incl. structured/JSON
# output mode) lives here, NOT in the business logic, so a different LLM provider is
# a swap of this one function. Gemini enforces strict JSON via
# response_mime_type="application/json"; another provider's adapter would set its own
# JSON-mode flag here. Enforcing JSON at the API layer (not by prompt alone) is what
# guarantees the {verdict, evidence_path, reasoning} contract parses.
# ==============================================================================
def _build_provider_config(types, system_instruction: str, temperature: float = 0.4):
    return types.GenerateContentConfig(
        system_instruction=system_instruction,
        response_mime_type="application/json",   # provider-specific JSON mode (swappable)
        temperature=temperature,
    )


async def _gemini_generate(client, types, model_name: str, contents, cfg):
    """One generate_content call with transient-503 retry; raises on final failure."""
    from google.genai import errors as genai_errors

    last_exc: Any = None
    for attempt in range(_GEMINI_503_RETRIES):
        try:
            return await asyncio.wait_for(
                client.aio.models.generate_content(
                    model=model_name, contents=contents, config=cfg
                ),
                timeout=settings.GEMINI_REQUEST_TIMEOUT_SECONDS,
            )
        except genai_errors.ServerError as e:
            last_exc = e
            if getattr(e, "status_code", None) == 503 or "503" in str(e):
                await asyncio.sleep(3 * (attempt + 1))
                continue
            raise
    raise last_exc


def _parse_model_json(text: str) -> Dict[str, Any]:
    """Parse the model's JSON; raise ValueError on anything unusable."""
    obj = json.loads(text)
    if not isinstance(obj, dict):
        raise ValueError("Model JSON was not an object")
    return obj


# ==============================================================================
# M1.1 evidence anchoring (observe-only). The AI makes the SEMANTIC call and CITES a
# JSON path; the CODE then structurally checks that the cited path resolves in the
# read-back and points at the attacked victim's runtime id. This NEVER changes the
# verdict — it corroborates (or contradicts) the AI's cited evidence, logged alongside.
# Target-agnostic: uses the model's path + the runtime attacked id; no target field names.
# ==============================================================================
_PATH_TOKEN_RE = re.compile(r"[^.\[\]]+|\[\d+\]")
_MISSING = object()


def _resolve_json_path(obj: Any, path: str) -> Any:
    """Resolve a dotted/bracket JSON path (e.g. 'owner_id', 'data.owner_id',
    'results[0].owner_id') against a parsed structure. A leading '$'/'root' and '.'
    are tolerated. Raises KeyError/IndexError/TypeError when a segment does not
    resolve — the caller catches those and records failed_path_not_found."""
    p = str(path or "").strip()
    if p[:1] == "$":
        p = p[1:]
    if p.lower().startswith("root."):
        p = p[len("root"):]
    cur = obj
    for m in _PATH_TOKEN_RE.finditer(p):
        tok = m.group(0)
        if tok.startswith("[") and tok.endswith("]"):
            cur = cur[int(tok[1:-1])]                 # list index
        elif isinstance(cur, list):
            cur = cur[int(tok)]                       # bare numeric key on a list
        else:
            cur = cur[tok]                            # dict key
    return cur


def _anchor_evidence(
    read_back_body: Optional[str], evidence_path: Optional[str], attacked_object_id: Optional[str]
) -> str:
    """Structurally check the model's cited evidence_path against the read-back. Returns:
      "confirmed"              — path resolves AND its scalar value == the attacked id;
      "value_mismatch"        — path resolves but its value != the attacked id;
      "failed_path_not_found" — path does not resolve (incl. AI-hallucinated paths);
      "unparsable_read_back"  — the read-back body is not JSON;
      "no_read_back"          — no read-back body available to anchor against;
      "no_path"               — the model cited no evidence_path.
    Type coercion is graceful: string "2" and int 2 compare equal. Never raises."""
    if not evidence_path:
        return "no_path"
    if not read_back_body:
        return "no_read_back"
    try:
        parsed = json.loads(read_back_body)
    except Exception:
        return "unparsable_read_back"
    try:
        value = _resolve_json_path(parsed, evidence_path)
    except (KeyError, IndexError, TypeError, ValueError):
        return "failed_path_not_found"
    if value is _MISSING or isinstance(value, (dict, list)) or value is None:
        # A container or null is not a scalar identity value to anchor on.
        return "failed_path_not_found"
    if attacked_object_id is None:
        return "value_mismatch"
    return "confirmed" if _scalar_str(value) == _scalar_str(attacked_object_id) else "value_mismatch"


# ==============================================================================
# M1.2 anchoring extensions (observe-only, additive). Broken access control REQUIRES
# caller != owner; and a silent WRITE confirmed by read-back is only PROVEN to be caused
# by this attack when THIS attack's UNIQUE injected value appears in the read-back (the
# expected value being present proves nothing if it was already there). Both are computed
# in code from the read-back + the attack's own runtime params — never the model's say-so —
# and are LOGGED/STORED only; they do NOT change the verdict or gate anything. Target-agnostic.
# ==============================================================================
def _read_back_owner_values(read_back_body: Optional[str]) -> set:
    """Union of OWNER/SUBJECT-style scalar values across every record in the (JSON) read-back,
    using the D23 owner-key vocabulary. Empty set on none/unparsable. Never raises."""
    if not read_back_body:
        return set()
    try:
        parsed = json.loads(read_back_body)
    except Exception:
        return set()
    out: set = set()
    for rec in _iter_records(parsed):
        out |= _record_owner_id_values(rec)
    return out


def _anchor_caller_identity(
    read_back_body: Optional[str],
    attacked_object_id: Optional[str],
    caller_object_id: Optional[str],
) -> str:
    """Corroborate that the read-back object belongs to the VICTIM (the attacked id), NOT to the
    caller (the baseline/self id) — the caller!=owner half BAC requires. Scans owner/subject-style
    fields (D23 vocabulary), type-coerced. Returns:
      "confirmed"       — attacked id is an owner value AND the caller id is not (victim's object);
      "same_as_caller"  — the caller id is an owner value (the read-back is the caller's OWN
                          object -> NOT a cross-user read; a would-be false positive);
      "owner_not_found" — no owner/subject value, or neither runtime id is among them;
      "no_read_back" / "unparsable_read_back" / "no_ids".
    Observe-only; never raises, never changes the verdict."""
    if not read_back_body:
        return "no_read_back"
    try:
        json.loads(read_back_body)
    except Exception:
        return "unparsable_read_back"
    if attacked_object_id is None and caller_object_id is None:
        return "no_ids"
    owners = _read_back_owner_values(read_back_body)   # already scalar-string values
    if not owners:
        return "owner_not_found"
    caller = _scalar_str(caller_object_id) if caller_object_id is not None else None
    attacked = _scalar_str(attacked_object_id) if attacked_object_id is not None else None
    if caller is not None and caller in owners:
        return "same_as_caller"
    if attacked is not None and attacked in owners:
        return "confirmed"
    return "owner_not_found"


def _anchor_payload_causality(
    read_back_body: Optional[str],
    evidence_path: Optional[str],
    written_values: List[str],
) -> str:
    """Corroborate that THIS attack's UNIQUE injected value actually appears in the read-back
    state — the causality proof that the write CAUSED the observed change (a read-back showing
    the 'expected' value proves nothing if it was already that value; only the unique fuzzer
    value does). Type-coerced; never raises. Returns:
      "confirmed_at_path" — a written value == the scalar at the model's cited evidence_path;
      "confirmed_in_body" — a written value appears among the read-back's CONTENT values (D23b:
                            excludes each record's own primary key), just not (only) at the path;
      "absent"            — no written value appears anywhere (the write did NOT land -> secure/
                            dropped case);
      "no_payload" / "no_read_back" / "unparsable_read_back".
    Observe-only; never changes the verdict."""
    wanted = {_scalar_str(v) for v in (written_values or []) if _scalar_str(v)}
    if not wanted:
        return "no_payload"
    if not read_back_body:
        return "no_read_back"
    try:
        parsed = json.loads(read_back_body)
    except Exception:
        return "unparsable_read_back"
    # Primary: the model's cited path (per the M1.2 spec "value appears at evidence_path").
    if evidence_path:
        try:
            v = _resolve_json_path(parsed, evidence_path)
            if not isinstance(v, (dict, list)) and v is not None and _scalar_str(v) in wanted:
                return "confirmed_at_path"
        except (KeyError, IndexError, TypeError, ValueError):
            pass
    # Fallback: the value landed somewhere in the read-back CONTENT (not a record's own id).
    for rec in _iter_records(parsed):
        if _record_content_values(rec) & wanted:
            return "confirmed_in_body"
    return "absent"


# ==============================================================================
# M1.3 — DELETE-shape negative-assertion anchor (target-agnostic, observe-first then gates the
# delete exemption). A delete's proof is a from-EXISTS-to-ABSENT jump, NOT a value appearing, so
# payload-causality does not apply. Two facts must both hold, structurally, in code:
#   * EXISTENCE (the coincidence gate): a PRE-FLIGHT read taken BEFORE the attack showed the
#     object existed and was active — otherwise "it's gone now" proves nothing (it may never
#     have existed, or was already deleted).
#   * ABSENCE (dual-track): the post-attack read-back is EITHER physically gone (404/403/410)
#     OR the SAME object with a status/lifecycle field flipped to a deleted/archived value
#     (soft delete). We must NOT hardcode 404 as the only proof of vanishing.
# The status-flip is detected by a GENERIC vocabulary (same sanctioned pattern as the D23
# owner-key vocabulary) — no target field name or value is hardcoded.
# ==============================================================================
_ABSENT_STATUS_CODES = frozenset({403, 404, 410})

# Field NAMES that carry an object's lifecycle/deletion state (generic, target-agnostic).
_STATUS_FIELD_KEYWORDS = frozenset({
    "status", "state", "lifecycle", "phase", "stage",
    "deleted", "archived", "removed", "active", "inactive",
    "enabled", "disabled", "visible", "trashed", "revoked", "voided",
})
# VALUES that mean "this object has been deleted / retired" (string status values).
_DELETED_VALUE_KEYWORDS = frozenset({
    "deleted", "archived", "removed", "inactive", "disabled", "trashed",
    "revoked", "gone", "expired", "void", "voided", "cancelled", "canceled",
    "closed", "terminated", "purged", "retired", "softdeleted", "tombstoned",
})
# VALUES that mean "this object is live / present".
_ACTIVE_VALUE_KEYWORDS = frozenset({
    "active", "enabled", "visible", "open", "live", "present", "ok", "valid",
    "available", "current", "published", "created",
})
# Field-name tokens whose BOOLEAN True means deleted, and whose True means active.
_BOOL_DELETE_TOKENS = frozenset({"deleted", "archived", "removed", "trashed", "revoked",
                                 "disabled", "inactive", "voided"})
_BOOL_ACTIVE_TOKENS = frozenset({"active", "enabled", "visible"})


def _deletion_signal(read_back_body: Optional[str]) -> str:
    """Classify an object's read-back as 'deleted' | 'active' | 'unknown' from its lifecycle
    field(s), GENERICALLY. Handles string status values, boolean flags (is_deleted / is_active),
    and timestamp markers (deleted_at non-null). 'unknown' when the object carries no lifecycle
    field at all (a hard-deletable object may simply have none — its existence is the 200 itself).
    Scans every record; returns 'deleted' as soon as any lifecycle field reads deleted. Never raises."""
    if not read_back_body:
        return "unknown"
    try:
        parsed = json.loads(read_back_body)
    except Exception:
        return "unknown"
    saw_active = False
    for rec in _iter_records(parsed):
        for k, v in rec.items():
            tokens = _field_tokens(k)
            if not (tokens & _STATUS_FIELD_KEYWORDS):
                continue
            # (a) boolean lifecycle flags: is_deleted=True -> deleted; is_active=False -> deleted.
            if isinstance(v, bool):
                if tokens & _BOOL_DELETE_TOKENS:
                    if v:
                        return "deleted"
                    saw_active = True
                elif tokens & _BOOL_ACTIVE_TOKENS:
                    if not v:
                        return "deleted"
                    saw_active = True
                continue
            # (b) timestamp / marker fields: deleted_at / archived_on non-null -> deleted.
            if (tokens & {"deleted", "archived", "removed", "trashed"}) and (
                tokens & {"at", "on", "date", "time", "ts", "timestamp"}
            ):
                if v not in (None, "", 0, False):
                    return "deleted"
                saw_active = True
                continue
            # (c) string status values.
            sval = _scalar_str(v).lower()
            if not sval:
                continue
            if sval in _DELETED_VALUE_KEYWORDS:
                return "deleted"
            if sval in _ACTIVE_VALUE_KEYWORDS:
                saw_active = True
    return "active" if saw_active else "unknown"


def _anchor_negative_assertion(
    pre_status: Optional[int], pre_body: Optional[str],
    post_status: Optional[int], post_body: Optional[str],
) -> str:
    """The delete-shape decisive-evidence anchor (replaces payload-causality for a DELETE).
    Confirms a from-exists-to-absent jump. Returns:
      "confirmed_physical"        — pre-flight EXISTED & active AND post is 404/403/410 (gone);
      "confirmed_logical"         — pre-flight EXISTED & active AND post is 200 with a lifecycle
                                    field flipped to a deleted/archived value (soft delete);
      "still_present"             — pre-flight existed & active AND post is still present & active
                                    (a securely-DROPPED delete — the SAFE case);
      "no_preflight"              — no pre-flight was taken / it did not return 200 (existence
                                    unproven -> the COINCIDENCE GATE forbids "verified");
      "preflight_absent"          — pre-flight showed the object did NOT exist (nothing to delete);
      "preflight_already_deleted" — pre-flight existed but was ALREADY deleted (can't attribute it);
      "indeterminate"             — post neither clearly gone nor clearly present.
    THE COINCIDENCE GATE: only the two 'confirmed_*' results are decisive; every other result
    means the delete cannot be attributed to this attack -> the caller must NOT exempt. Never raises."""
    # Existence anchor first — this is the coincidence gate.
    if pre_status is None:
        return "no_preflight"
    if pre_status in _ABSENT_STATUS_CODES:
        return "preflight_absent"
    if pre_status != 200:
        return "no_preflight"          # existence could not be established
    if _deletion_signal(pre_body) == "deleted":
        return "preflight_already_deleted"
    # The object provably EXISTED and was active before the attack. Now assert absence.
    if post_status in _ABSENT_STATUS_CODES:
        return "confirmed_physical"
    if post_status == 200:
        return "confirmed_logical" if _deletion_signal(post_body) == "deleted" else "still_present"
    return "indeterminate"


# ==============================================================================
# M1.4 — MASS-ASSIGNMENT: the STATE-JUMP causality anchor (target-agnostic).
#
# WHY a new anchor: mass-assignment writes LOW-ENTROPY values (a role, a tier, a boolean).
# M1.2's payload-causality assumes the injected value is effectively UNIQUE, so its mere
# PRESENCE in the read-back proves the write landed. That assumption BREAKS here: "the field
# reads admin" cannot distinguish "I set it" from "it was already admin". Decisive causality
# for this shape is therefore a STATE JUMP — the field moved FROM a KNOWN pre-flight state TO
# the value this attack injected.
#
# THE CRITICAL DISTINCTION (this is where a false positive hides):
#   * MISSING  — the field is ABSENT from a SUCCESSFUL (2xx, parseable) pre-flight read. This is
#                a VALID original state: sensitive fields are routinely hidden from non-privileged
#                callers, so MISSING -> injected is a REAL escalation and must be able to verify.
#   * UNKNOWN  — the pre-flight (or the post read-back) FAILED, was non-2xx, or was unparseable.
#                The original state is unknown, so NOTHING can be attributed to this attack.
# MISSING may verify; UNKNOWN may never.
#
# The gate requires EVERY field the attack sent to jump. That is deliberately stricter than
# checking one nominated field: on a secure allow-list target the legitimate field still lands
# while the privileged one is stripped, so an "any field jumped" rule would confirm a SECURE
# case. Requiring all of them means a stripped field alone defeats the exemption.
# ==============================================================================

# Generic vocabulary for an attack that DECLARES itself a mass-assignment / over-posting attempt.
# Read from the payload the attack itself carries (same runtime-param principle as target_param /
# payload_string) — no target path, field or tag is hardcoded.
_MASS_ASSIGNMENT_TYPE_TOKENS = frozenset({
    "massassignment", "overposting", "overpost", "overposted", "autobinding",
})


def _is_mass_assignment_payload(payload: Optional[Dict[str, Any]]) -> bool:
    """True iff the attack's own payload declares a mass-assignment/over-posting attempt
    (e.g. type "MASS_ASSIGNMENT", "mass-assignment", "MassAssignment", "overposting").
    Target-agnostic: it reads the attack's declared type, never a target's field or path."""
    tokens = _field_tokens((payload or {}).get("type"))
    # Joined forms ("overposting") and camelCase/underscore-split forms ("OverPost" -> over+post,
    # "MASS_ASSIGNMENT" -> mass+assignment) must both match.
    if {"mass", "assignment"} <= tokens:
        return True
    if "over" in tokens and tokens & {"post", "posting", "posted"}:
        return True
    return bool(tokens & _MASS_ASSIGNMENT_TYPE_TOKENS)


def _find_field_state(parsed: Any, field: Any):
    """(present, value) for `field` anywhere in a parsed JSON structure — the first record that
    carries the key wins. `present=False` means the field is ABSENT from this (successfully
    parsed) document, i.e. the MISSING state. Never raises."""
    try:
        for rec in _iter_records(parsed):
            if isinstance(rec, dict) and field in rec:
                return True, rec[field]
    except Exception:
        return False, None
    return False, None


def _anchor_state_jump(
    pre_status: Optional[int], pre_body: Optional[str],
    post_status: Optional[int], post_body: Optional[str],
    sent_fields: Optional[Dict[str, Any]],
) -> str:
    """The mass-assignment decisive-evidence anchor (replaces payload-causality for this shape).

    Confirms that EVERY field this attack sent jumped from its KNOWN pre-flight state to the
    value the attack injected. Returns:
      "confirmed_jump"    — every sent field: post == injected AND (pre was MISSING, or pre held a
                            DIFFERENT value). The only decisive result.
      "no_jump"           — some sent field did not move: post != injected, post still MISSING,
                            post still equals its pre-flight value, or injected == pre-flight value
                            (indistinguishable — the low-entropy trap).
      "preflight_unknown" — no pre-flight, non-2xx, or unparseable: ORIGINAL STATE UNKNOWN. Not the
                            same as MISSING; nothing may be attributed to this attack.
      "postread_unknown"  — the post-attack read-back failed / non-2xx / unparseable JSON.
      "no_sent_fields"    — the attack carried no body fields to reason about.
      "indeterminate"     — anything unexpected. NEVER raises; degrades to a non-decisive value.
    """
    try:
        if not sent_fields or not isinstance(sent_fields, dict):
            return "no_sent_fields"

        # --- the ORIGINAL state must be KNOWN (a successful, parseable pre-flight read) ---
        if pre_status is None or not (200 <= int(pre_status) < 300):
            return "preflight_unknown"
        try:
            pre_json = json.loads(pre_body) if pre_body else None
        except Exception:
            return "preflight_unknown"
        if pre_json is None:
            return "preflight_unknown"

        # --- the POST-attack state must also be KNOWN ---
        if post_status is None or not (200 <= int(post_status) < 300):
            return "postread_unknown"
        try:
            post_json = json.loads(post_body) if post_body else None
        except Exception:
            return "postread_unknown"
        if post_json is None:
            return "postread_unknown"

        for _field, _sent in sent_fields.items():
            _pre_present, _pre_val = _find_field_state(pre_json, _field)
            _post_present, _post_val = _find_field_state(post_json, _field)
            # The field must now HOLD the value this attack injected...
            if not _post_present:
                return "no_jump"                      # still missing -> nothing landed
            if _scalar_str(_post_val) != _scalar_str(_sent):
                return "no_jump"                      # holds something else -> not ours
            # ...and it must have MOVED to get there. pre MISSING -> a real jump; pre holding the
            # SAME value -> indistinguishable from "it was already that", so NOT decisive.
            if _pre_present and _scalar_str(_pre_val) == _scalar_str(_sent):
                return "no_jump"
        return "confirmed_jump"
    except Exception:
        return "indeterminate"


# ==============================================================================
# TWO-ACCOUNT OWNERSHIP BASELINE — the OWNER/VICTIM credential channel.
#
# Every request this engine sends today goes out as the ATTACKER. That is fine for the
# four working shapes, whose evidence is a STATE CHANGE observable from the attacker's own
# view. It is not enough for the read-semantic shape (D24), which is the only shape where
# code gathers no evidence at all: deciding whether the attacker actually received the
# VICTIM's data requires knowing what the victim's authentic view IS.
#
# This section adds ONLY the channel. Nothing here is consumed by any verdict path in this
# milestone — `execute_deep_verification` accepts the credential and never calls
# `fetch_owner_view`. The guard, the four exemption channels and every anchor are untouched.
#
# TWO STRUCTURAL PROPERTIES, deliberately not merely conventional. Do not relax them:
#   1. `OwnerCredential` is a frozen dataclass and NOT a Mapping, so it CANNOT be
#      `**`-splatted into the attack header merge — that raises TypeError. The two
#      identities cannot be conflated by accident.
#   2. `fetch_owner_view` takes NO method and NO body parameter (GET is hardcoded), so it
#      is structurally incapable of expressing an attack request.
#
# FAIL-SAFE DIRECTION IS BLOCK: `available` is True only on a clean 2xx. A missing
# credential, a non-2xx, a scope violation or any transport failure yields
# `available=False`. Any future consumer may treat ONLY `available=True` as permitting
# confidence; every other value must block. It may never increase confidence.
#
# KNOWN LIMITATION (documented, not a bug): the credential is configured per DEPLOYMENT
# (`settings.AI_DEEP_VERIFY_OWNER_AUTH`), not per finding. Sufficient for both local labs
# and for proving the D24 gate; a real target whose findings belong to DIFFERENT owners
# would need per-finding credentials, which DO NOT EXIST here. Do not imply otherwise.
# ==============================================================================

_HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9-]+$")


@dataclass(frozen=True)
class OwnerCredential:
    """The OWNER/VICTIM's credential. Deliberately NOT a Mapping (see property 1 above)."""

    header_name: str
    header_value: str

    def as_read_headers(self) -> Dict[str, str]:
        """The ONLY way to turn this into headers. Called solely by `fetch_owner_view`."""
        return {self.header_name: self.header_value}

    @staticmethod
    def from_config(raw: Optional[str]) -> Optional["OwnerCredential"]:
        """Parse `AI_DEEP_VERIFY_OWNER_AUTH`. Accepts "Header-Name: value", or a bare
        credential which is sent as "Authorization: Bearer <value>". Returns None for
        anything unusable — never raises, so a malformed setting degrades to "no second
        identity" (byte-identical behavior) rather than breaking a run."""
        if not raw or not str(raw).strip():
            return None
        text = str(raw).strip()
        name, sep, value = text.partition(":")
        if sep and _HEADER_NAME_RE.match(name.strip()) and value.strip():
            return OwnerCredential(header_name=name.strip(), header_value=value.strip())
        if text.lower().startswith("bearer "):
            return OwnerCredential(header_name="Authorization", header_value=text)
        return OwnerCredential(header_name="Authorization", header_value=f"Bearer {text}")


@dataclass(frozen=True)
class OwnerViewResult:
    """Outcome of an owner-scoped read. `available` is True ONLY on a clean 2xx."""

    available: bool
    status: Optional[int] = None
    body: Optional[str] = None
    reason: str = ""


async def fetch_owner_view(
    client: httpx.AsyncClient,
    path: str,
    base_url: str,
    owner: Optional[OwnerCredential],
    *,
    approved_host: Optional[str] = None,
) -> OwnerViewResult:
    """Read `path` AS THE OWNER, returning the object's authentic view.

    GET only, by construction — there is no method or body parameter, so this cannot be
    used to send an attack (structural property 2). Scope-locked with the same check the
    M1.3 pre-flight read uses.

    NOTE: `custody` is deliberately NOT passed to `_send_request`. Custody carries the
    ATTACKER's live session and would inline-inject it over these headers, silently
    conflating the two identities — the exact failure this channel exists to prevent.

    Never raises; every failure path returns `available=False` (fail-safe BLOCK).
    """
    if owner is None:
        return OwnerViewResult(available=False, reason="no_owner_credential")
    if not path or not path.startswith("/"):
        return OwnerViewResult(available=False, reason="invalid_path")
    req = {"method": "GET", "path": path, "query_params": {},
           "headers": owner.as_read_headers(), "body": None}
    try:
        approved = (approved_host or "").lower()
        if approved and _host_of(_reconstruct_url(req, base_url)) != approved:
            return OwnerViewResult(available=False, reason="outside_approved_scope")
        res = await _send_request(client, req, base_url)          # custody deliberately omitted
        status = res.get("status_code")
        if isinstance(status, int) and 200 <= status < 300:
            return OwnerViewResult(available=True, status=status,
                                   body=res.get("response_body"), reason="ok")
        return OwnerViewResult(available=False, status=status, reason=f"non_2xx:{status}")
    except ScopeViolationError:
        return OwnerViewResult(available=False, reason="scope_violation")
    except Exception as e:
        return OwnerViewResult(available=False, reason=f"transport_error:{type(e).__name__}")


# ==============================================================================
# D24 — the READ-SEMANTIC OWNER-VIEW DIFFERENTIAL gate.
#
# The read-semantic shape was the ONLY shape whose final verdict had no deterministic
# gate: when the model answers from the attack response alone it requests no follow-up, so
# the B-2.2 cross-resource guard is a structural no-op and all four exemption channels are
# unreachable. The verdict was simply the model's opinion (measured: a SECURE Depot
# endpoint reported `verified` 20/20).
#
# The fix is NOT to squeeze a discriminator out of the attack response — two attempts at
# that (provenance filtering on identity values) died offline, because on a
# SELF-REFERENTIAL object the victim-owned marker IS the attacked id. Instead this shape
# now gathers evidence like every other shape does: code issues an authenticated read of
# the SAME object AS THE OWNER, and a `verified` survives only if the attack response
# corroborates that authentic view — i.e. the attacker really did receive the victim's
# data. Masked stubs, sentinels, echoes and denials do not corroborate, no matter how the
# refusal happens to be encoded (denial keywords are deliberately NOT consulted; assuming
# a denial vocabulary is what produced this SEV-1 in the first place).
#
# CORROBORATION EXACTNESS reuses the fuzzer's EXISTING `_compute_similarity`
# (difflib.SequenceMatcher ratio, with the same _SEQUENCE_MATCHER_MAX_LEN CPU cap the rule
# oracle uses). No new comparison logic is invented. Byte-equality was rejected on purpose:
# two reads of a live object legitimately differ in timestamps / generated ids / tokens,
# and demanding equality would kill true positives — the exact failure direction that
# killed the previous two candidate gates.
#
# THRESHOLD CALIBRATION (measured offline on all five read-type cases, both targets):
#     DP-READ-VULN 1.0000 | X-EQUIV-VULN 1.0000        <- REAL   (must stay decisive)
#     DP-READ-SAFE 0.8857 | DP-READ-SAFE-ECHO 0.9203   <- SECURE (must be blocked)
#     X-EQUIV-SAFE 0.6697                              <- SECURE (must be blocked)
# The bands are separated by a 0.0797 gap; 0.95 sits mid-gap. The risk here is ASYMMETRIC:
# because this gate is downgrade-only it cannot manufacture a false positive — a case it
# fails to block is exactly as it is today — but a case it wrongly blocks kills a true
# positive. So the threshold is deliberately kept well BELOW the REAL band (0.05 of
# tolerance for volatile fields) rather than pushed up to maximise the margin above SECURE.
# This constant is validated per target; it is not a universal truth.
# ==============================================================================

_OWNER_VIEW_CORROBORATION_THRESHOLD = 0.95
OWNER_VIEW_NOT_CORROBORATED_REASON = "owner_view_not_corroborated"


def _owner_view_corroborates(attack_body: Optional[str], owner_body: Optional[str]) -> bool:
    """True iff the attack response plausibly IS the victim's data, judged with the rule
    oracle's own similarity helper. Missing either side is never corroboration."""
    if not attack_body or not owner_body:
        return False
    return _compute_similarity(attack_body, owner_body) >= _OWNER_VIEW_CORROBORATION_THRESHOLD


def _apply_owner_view_gate(current_verdict: Optional[str], corroborated: bool) -> Optional[str]:
    """DOWNGRADE-ONLY BY CONSTRUCTION.

    Every path either returns the verdict it was handed, unchanged, or the strictly weaker
    'inconclusive'. The string 'verified' is never assigned anywhere in this function, so
    it is structurally incapable of creating or upgrading to a `verified` verdict — it can
    only ever take one away.
    """
    if current_verdict != "verified":
        return current_verdict          # nothing but a 'verified' is ever gated
    if corroborated:
        return current_verdict          # unchanged
    return "inconclusive"               # the ONLY mutation this gate can make


async def execute_deep_verification(
    parsed_request: Dict[str, Any],
    payload: Optional[Dict[str, Any]],
    base_url: str,
    *,
    approved_host: Optional[str] = None,
    auth_context: Optional[Dict[str, str]] = None,
    context_note: str = "",
    available_endpoints: Optional[List[str]] = None,
    model_name: Optional[str] = None,
    owner_credential: Optional["OwnerCredential"] = None,
) -> DeepVerificationResult:
    """
    Run the isolated, serial AI-in-the-loop write-then-read deep verification.

    Args:
        parsed_request: the BASELINE (authorized/self) request dict
            {method, path, query_params, headers, body}.
        payload: a mutation instruction (same shape the fuzzer's mutate_request
            consumes, e.g. {"location":"path_segment","target_param":"1",
            "payload_string":"2","type":"BOLA"}) producing the ATTACK request.
            Pass None for read-only cases (no mutation; baseline == attack, e.g.
            a vertical-priv-esc GET).
        base_url: scheme://host[:port] anchor for all requests.
        approved_host: scope lock; defaults to the host of base_url. Any follow-up
            the model requests is REFUSED unless it resolves to this host.
        auth_context: extra headers (e.g. {"Authorization": "Bearer ..."}) merged
            into every request, including the model's follow-up.
        context_note: optional factual context (identity + intended authz policy)
            the model needs but cannot infer (e.g. "endpoint is admin-only").
        available_endpoints: optional discoverable API surface (e.g.
            ["GET /api/users/{id}/avatar", ...]) so the model can request the
            CORRECT read-back endpoint for its one follow-up instead of guessing.
        model_name: override the Gemini model; defaults to settings.GEMINI_PRO_MODEL.
        owner_credential: OPTIONAL owner/victim credential (two-account baseline).
            **RESERVED AND INTENTIONALLY INERT IN THIS MILESTONE.** It is accepted so the
            second identity genuinely reaches the real Phase-7 pipeline rather than only a
            harness, but NOTHING here consumes it: `fetch_owner_view` is never called from
            this function, no extra HTTP request is issued, and no verdict logic reads it.
            Whether it is set or None, this function's behavior — and every request it
            sends — is byte-identical. The consumer is the D24 read-semantic gate, which is
            a separate signed-off milestone. It is NEVER merged into any attack request:
            attacks always go out as the attacker (see the channel notes above).

    Returns:
        DeepVerificationResult — the AI verdict alongside the full evidence trail.
        Never raises for expected failure modes; degrades gracefully instead.
    """
    approved = (approved_host or _host_of(base_url) or "").lower()
    auth_context = auth_context or {}

    def _disabled_or_degraded(status: str, reason: str,
                              baseline=None, attack=None, turns=None) -> DeepVerificationResult:
        return DeepVerificationResult(
            status=status,
            ai_verdict=None,
            ai_confidence=None,
            ai_reasoning="",
            ai_requested_follow_up=False,
            follow_up_request=None,
            follow_up_response=None,
            baseline=baseline or {},
            attack=attack or {},
            model=model_name or settings.GEMINI_PRO_MODEL,
            approved_host=approved,
            turns_raw=turns or [],
            degraded_reason=reason,
        )

    # --- Feature gate: default behavior unchanged unless explicitly enabled ---
    if not settings.AI_DEEP_VERIFY_ENABLED:
        logger.info("[DEEP-VERIFY] Skipped: AI_DEEP_VERIFY_ENABLED is False.")
        return _disabled_or_degraded("disabled", "AI_DEEP_VERIFY_ENABLED is False")

    # Resolve / sanitize model name (mirror hunter.py)
    resolved_model = model_name or settings.GEMINI_PRO_MODEL
    if resolved_model.startswith("models/"):
        resolved_model = resolved_model[len("models/"):]

    # Merge auth context into the baseline request headers.
    baseline_req = dict(parsed_request)
    baseline_req["headers"] = {**(parsed_request.get("headers") or {}), **auth_context}

    timeout = httpx.Timeout(
        connect=settings.FUZZER_HTTP_TIMEOUT_CONNECT,
        read=settings.FUZZER_HTTP_TIMEOUT_READ,
        write=settings.FUZZER_HTTP_TIMEOUT_CONNECT,
        pool=settings.FUZZER_HTTP_TIMEOUT_CONNECT,
    )

    # M1.3: the DELETE shape needs the attacked object's state read BEFORE the attack (the
    # existence/coincidence anchor). These hold that pre-flight read across the flow.
    pre_flight_result: Optional[Dict[str, Any]] = None
    pre_flight_path: Optional[str] = None

    async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
        # ---------------- Step 1: real baseline (+ M1.3 pre-flight) + attack ----------------
        try:
            baseline_result = await _send_request(client, baseline_req, base_url)
            if payload:
                attack_req = await mutate_request(baseline_req, payload)
            else:
                attack_req = baseline_req  # read-only case: no mutation

            # --- M1.3 PRE-FLIGHT READ (delete shape only) -----------------------------------
            # A delete's proof is a from-EXISTS-to-ABSENT jump, so "it vanished" only proves a
            # delete if the object provably EXISTED and was active BEFORE the attack. For a DELETE
            # attack the CODE reads the victim object's OWN state first and caches it (the
            # existence/coincidence anchor). Target-agnostic: reuses the M1.2(B) object-state
            # resolver. Scope-locked like every code-issued request. A failure/absence here is NOT
            # fatal — it just means existence is unproven, so the negative assertion cannot confirm
            # and the verdict stays inconclusive (never a false "verified").
            # M1.4 reuses this same pre-flight to capture the ORIGINAL state of the fields the
            # attack injects (low-entropy values need a jump, not mere presence).
            # M1.4(fix): fire for ANY write. The stricter state-jump gate can only govern where a
            # pre-flight baseline exists, so the baseline must not depend on how the attack DECLARED
            # itself — a mass-assignment mistyped as plain BOLA would otherwise fall back to the
            # weaker payload-causality channel (the mixed-field false positive).
            if payload and _is_write_method(attack_req.get("method")):
                _pf_attacked_id = _attacked_object_id(
                    baseline_req.get("path"), attack_req.get("path"), payload
                )
                pre_flight_path = select_object_state_endpoint(
                    available_endpoints or [], attack_req.get("path", ""),
                    attacked_object_id=_pf_attacked_id,
                )
                if pre_flight_path and pre_flight_path.startswith("/"):
                    _pf_req = {"method": "GET", "path": pre_flight_path, "query_params": {},
                               "headers": dict(auth_context), "body": None}
                    if approved and _host_of(_reconstruct_url(_pf_req, base_url)) != approved:
                        logger.warning(
                            "[DEEP-VERIFY] M1.3 pre-flight %r is outside approved scope %r -> skipped "
                            "(existence unproven -> the delete cannot reach 'verified').",
                            pre_flight_path, approved,
                        )
                        pre_flight_path = None
                    else:
                        try:
                            pre_flight_result = await _send_request(client, _pf_req, base_url)
                            logger.info(
                                "[DEEP-VERIFY] M1.3 pre-flight: read victim object state %r BEFORE the "
                                "DELETE -> status=%s (existence anchor for the negative assertion).",
                                pre_flight_path, (pre_flight_result or {}).get("status_code"),
                            )
                        except Exception as e:
                            logger.warning(
                                "[DEEP-VERIFY] M1.3 pre-flight read of %r failed (%s); existence unproven "
                                "-> the delete cannot reach 'verified'.", pre_flight_path, e,
                            )
                            pre_flight_result = None

            attack_result = await _send_request(client, attack_req, base_url)
        except Exception as e:
            logger.warning(f"[DEEP-VERIFY] Baseline/attack send failed: {e}")
            return _disabled_or_degraded("degraded", f"baseline/attack request failed: {e}")

        baseline_url = _reconstruct_url(baseline_req, base_url)
        attack_url = _reconstruct_url(attack_req, base_url)
        baseline_trail = {
            "request": {"method": baseline_req.get("method", "GET"), "url": baseline_url,
                        "headers": _redact_headers(baseline_req.get("headers", {})),
                        "body": baseline_req.get("body")},
            "response": _summarize_response(baseline_result),
        }
        attack_trail = {
            "request": {"method": attack_req.get("method", "GET"), "url": attack_url,
                        "headers": _redact_headers(attack_req.get("headers", {})),
                        "body": attack_req.get("body")},
            "response": _summarize_response(attack_result),
        }

        # ---------------- B-1 HALF 1: deterministic write-record gathering ----------
        # When the attack was a state-changing WRITE and the attacked resource has NO
        # same-path read-back in the catalog, the CODE (not the model) will gather an
        # explicit record/log-style read-back. The write-record endpoint is identified
        # GENERICALLY from the catalog (record/log/history/events vocabulary) — never a
        # hardcoded path/field/tag. If none can be found generically, det_record_path is
        # None and we fall back to the model-driven follow-up (no fabrication).
        attacked_object_id = _attacked_object_id(
            baseline_req.get("path"), attack_req.get("path"), payload
        )
        caller_object_id = _caller_object_id(
            baseline_req.get("path"), attack_req.get("path"), payload
        )
        written_values = _written_values(attack_req)
        det_record_path: Optional[str] = None
        det_state_path: Optional[str] = None
        if (
            payload
            and _is_write_method(attack_req.get("method"))
            and not has_same_path_readback(available_endpoints or [], attack_req.get("path", ""))
        ):
            _candidate = select_write_record_endpoint(
                available_endpoints or [], attacked_object_id=attacked_object_id
            )
            # M1.3: HALF 1 is for VALUE-writes. A DELETE carries no written value, so B-1's
            # write-record exemption (`_write_record_content_match`, which REQUIRES written
            # values) can never fire for it — gathering a record would be useless AND would
            # preempt the object-state gather this shape actually needs. Skip it for deletes.
            # B-1's own cases are POST writes, so this cannot regress them.
            if _candidate and _is_delete_method(attack_req.get("method")):
                logger.info(
                    "[DEEP-VERIFY] M1.3: attack is a DELETE (no written value) -> skipping the "
                    "write-record gather (its exemption is unreachable without a written value); "
                    "the object-STATE negative assertion is this shape's evidence.",
                )
                _candidate = None
            if _candidate:
                # --- M1.2 OBJECT-SCOPE GATE ---------------------------------------------
                # Only HIJACK the follow-up with this record endpoint if it is plausibly ABOUT
                # THE ATTACKED OBJECT's write-type. We probe it ONCE and keep it only if it
                # already records the caller's OWN (baseline, definitely-landed) write. If it does
                # not — an unrelated global record (e.g. an audit-log that does not track THIS
                # resource) — we STEP BACK so the model can choose its own follow-up (for a
                # state-confirmable write, the object's own read-back). Default to the existing
                # gather behavior whenever we cannot POSITIVELY prove irrelevance (fetch error /
                # missing runtime ids) so B-1 never regresses. Target-agnostic; reuses the B-1
                # content-match; no path/field/tag hardcoded.
                _object_scoped = True
                if caller_object_id and written_values and _candidate.startswith("/"):
                    try:
                        _probe = {"method": "GET", "path": _candidate, "query_params": {},
                                  "headers": dict(auth_context), "body": None}
                        if approved and _host_of(_reconstruct_url(_probe, base_url)) != approved:
                            raise ScopeViolationError(
                                f"record probe host outside approved scope '{approved}'"
                            )
                        _probe_result = await _send_request(client, _probe, base_url)
                        _object_scoped = _record_is_relevant_to_write(
                            (_probe_result or {}).get("response_body"),
                            caller_object_id, written_values,
                        )
                    except Exception as e:
                        logger.warning(
                            "[DEEP-VERIFY] HALF 1 object-scope probe of %r failed (%s); defaulting "
                            "to the existing gather behavior (B-1 safe).", _candidate, e,
                        )
                        _object_scoped = True
                if _object_scoped:
                    det_record_path = _candidate
                    logger.info(
                        "[DEEP-VERIFY] HALF 1: write attack on %r has no same-path read-back; the "
                        "record endpoint %r IS about the attacked object (it records the caller's own "
                        "landed write) -> code will gather it (model choice not relied upon).",
                        attack_req.get("path"), det_record_path,
                    )
                else:
                    logger.info(
                        "[DEEP-VERIFY] HALF 1: candidate write-record %r is NOT about the attacked "
                        "object (it does not record the caller's own landed write) -> stepping back; "
                        "the code now resolves the object's OWN STATE read-back instead (M1.2(B)).",
                        _candidate,
                    )

            # --- M1.2(B) OBJECT-STATE GATHER (parallel to B-1's write-record gather) --------
            # No RELEVANT write-record exists (none in the catalog, or the object-scope gate
            # rejected the candidate). The only remaining confirmation for a silent write is the
            # ATTACKED OBJECT'S OWN STATE — which lives on a DIFFERENT path. Measurement showed
            # the model does not find that path on its own (0/5 at M1.2(A); B-1's wall was 0/20),
            # so the CODE resolves and gathers it GENERICALLY (resource-noun + object-scoping;
            # no target path/field/tag hardcoded). The model still does the irreplaceable part:
            # semantically reading the state we fetched. If no state endpoint can be resolved we
            # do NOT fabricate one -> the model chooses and the flow stays inconclusive.
            #
            # This only FEEDS the existing state-readback exemption; it changes no gate. The
            # exemption still independently requires owner==attacked AND caller!=owner AND
            # payload-causality, so a WRONG gather degrades to inconclusive, never to a verdict.
            if det_record_path is None:
                det_state_path = select_object_state_endpoint(
                    available_endpoints or [], attack_req.get("path", ""),
                    attacked_object_id=attacked_object_id,
                )
                if det_state_path:
                    logger.info(
                        "[DEEP-VERIFY] M1.2(B): write attack on %r has no same-path read-back and no "
                        "relevant write-record; resolved the attacked object's OWN state read-back %r "
                        "-> code will gather it (model choice not relied upon).",
                        attack_req.get("path"), det_state_path,
                    )
                else:
                    logger.info(
                        "[DEEP-VERIFY] M1.2(B): no object-state read-back could be resolved generically "
                        "for %r -> NOT fabricating one; the model chooses its own follow-up.",
                        attack_req.get("path"),
                    )

        # Build the evidence block (single exchange for read-only cases).
        if payload:
            evidence_block = (
                "1. BASELINE (authorized / self) request:\n"
                + _fmt_exchange("   request", baseline_req.get("method", "GET"), baseline_url,
                                baseline_req.get("headers", {}), baseline_req.get("body"), baseline_result)
                + "\n\n2. ATTACK (cross-object) request:\n"
                + _fmt_exchange("   request", attack_req.get("method", "GET"), attack_url,
                                attack_req.get("headers", {}), attack_req.get("body"), attack_result)
                + "\n"
            )
        else:
            evidence_block = (
                "1. Observed request (the suspected access-control attempt):\n"
                + _fmt_exchange("   request", attack_req.get("method", "GET"), attack_url,
                                attack_req.get("headers", {}), attack_req.get("body"), attack_result)
                + "\n"
            )

        # ---------------- Need an API key to run the AI step ----------------
        if not settings.GEMINI_API_KEY:
            return _disabled_or_degraded(
                "degraded", "GEMINI_API_KEY not configured", baseline_trail, attack_trail
            )

        # ---------------- AI turn 1 ----------------
        turns_raw: List[str] = []
        try:
            from google import genai
            from google.genai import types
        except ImportError:
            return _disabled_or_degraded(
                "degraded", "google-genai SDK not installed", baseline_trail, attack_trail
            )

        client_ai = genai.Client(api_key=settings.GEMINI_API_KEY)
        cfg = _build_provider_config(types, SYSTEM_PROMPT)

        turn1_prompt = _build_turn1_prompt(context_note, evidence_block, available_endpoints)
        contents = [types.Content(role="user", parts=[types.Part(text=turn1_prompt)])]

        try:
            resp1 = await _gemini_generate(client_ai, types, resolved_model, contents, cfg)
            turn1_text = resp1.text
            turns_raw.append(turn1_text)
            turn1_obj = _parse_model_json(turn1_text)
        except (asyncio.TimeoutError, ValueError, json.JSONDecodeError) as e:
            return _disabled_or_degraded(
                "degraded", f"Gemini turn-1 failed: {type(e).__name__}: {e}",
                baseline_trail, attack_trail, turns_raw,
            )
        except Exception as e:  # SDK ServerError, network, etc. — never crash
            return _disabled_or_degraded(
                "degraded", f"Gemini turn-1 error: {type(e).__name__}: {e}",
                baseline_trail, attack_trail, turns_raw,
            )

        # ---------------- B-1 HALF 1: override the follow-up deterministically ------
        # If the code identified a write-record read-back to gather, it takes over the
        # follow-up regardless of what the model asked (or whether it asked at all) — we
        # do NOT rely on the model to choose the right endpoint. The model's final verdict
        # is still produced in turn 2 from this evidence; the guard (HALF 2) adjudicates.
        decision = turn1_obj.get("decision")
        next_request = turn1_obj.get("next_request") or {}
        followup_is_code_gathered = False
        gathered_kind: Optional[str] = None
        if det_record_path:
            decision = "request_more"
            next_request = {
                "method": "GET",
                "path": det_record_path,
                "body": None,
                "reason": (
                    "code-gathered write-record read-back (deterministic; the attacked "
                    "resource has no same-path read-back, so the engine fetched an explicit "
                    "record of write activity rather than relying on the model's choice)"
                ),
            }
            followup_is_code_gathered = True
            gathered_kind = "record"
        elif det_state_path:
            # M1.2(B): no relevant write-record — gather the attacked object's OWN state.
            # M1.3: for a DELETE with a pre-flight, this same gather is the AFTER read of the
            # from-exists-to-absent pair (the BEFORE read was taken pre-attack).
            _is_delete_gather = _is_delete_method(attack_req.get("method")) and pre_flight_result is not None
            _is_mass_gather = (
                pre_flight_result is not None
                and isinstance(attack_req.get("body"), dict) and bool(attack_req.get("body"))
            )
            decision = "request_more"
            next_request = {
                "method": "GET",
                "path": det_state_path,
                "body": None,
                "reason": (
                    ("code-gathered object-state read-back AFTER a delete (deterministic; the "
                     "engine read the attacked object's own state before the delete and reads it "
                     "again here to confirm a present->absent transition)")
                    if _is_delete_gather else
                    ("code-gathered object-state read-back (deterministic; the attacked "
                     "resource has no same-path read-back and no relevant record of writes, so "
                     "the engine fetched the attacked object's own current state on its other "
                     "path rather than relying on the model's choice)")
                ),
            }
            followup_is_code_gathered = True
            gathered_kind = (
                "delete_state" if _is_delete_gather
                else "mass_state" if _is_mass_gather
                else "state"
            )

        # ---------------- If verdict now, we're done ----------------
        if decision != "request_more" or not next_request.get("path"):
            # No follow-up read-back was performed -> the structural guard never
            # triggers here (it must NOT break a read-type/GET BOLA confirmed by the
            # attack response itself). Recorded transparently anyway: raw == final.
            _raw_verdict = turn1_obj.get("verdict")
            _final_verdict, _override = _apply_cross_resource_guard(
                _raw_verdict, attack_req.get("path", ""),
                follow_up_path=None, follow_up_performed=False,
            )
            # M1.1/M1.2 anchoring (observe-only): no follow-up was performed, so the read-back
            # the model judged on is the ATTACK response itself (the read-type leak case).
            _evidence_path = turn1_obj.get("evidence_path")
            _anchor_body = attack_result.get("response_body")
            _anchor = _anchor_evidence(_anchor_body, _evidence_path, attacked_object_id)
            _caller_anchor = _anchor_caller_identity(_anchor_body, attacked_object_id, caller_object_id)
            _causality_anchor = _anchor_payload_causality(_anchor_body, _evidence_path, written_values)
            logger.info(
                "[DEEP-VERIFY] Evidence anchoring (turn-1 verdict): ai_verdict=%r evidence_path=%r "
                "attacked_id=%r caller_id=%r -> object=%r caller_identity=%r payload_causality=%r "
                "(observe-only).",
                _final_verdict, _evidence_path, attacked_object_id, caller_object_id,
                _anchor, _caller_anchor, _causality_anchor,
            )

            # ---------- D24: OWNER-VIEW DIFFERENTIAL gate (downgrade-only) ----------
            # Scoped to exactly this branch: the read-semantic path where NO follow-up was
            # performed and the four exemption channels are therefore unreachable. Nothing
            # below runs when a follow-up occurred.
            #
            # Not configured (owner_credential is None) -> the gate does not engage and
            # behavior is exactly as before. Configuring the credential is what OPTS IN;
            # once opted in, any failure to obtain the owner view BLOCKS (fail-safe), since
            # an unverifiable claim must never be the one that gets to stand.
            if owner_credential is not None and _final_verdict == "verified":
                _owner_view = await fetch_owner_view(
                    client, attack_req.get("path", ""), base_url, owner_credential,
                    approved_host=approved,
                )
                _corroborated = _owner_view.available and _owner_view_corroborates(
                    _anchor_body, _owner_view.body
                )
                _gated = _apply_owner_view_gate(_final_verdict, _corroborated)
                if _gated != _final_verdict:
                    logger.info(
                        "[DEEP-VERIFY] D24 owner-view differential: the attack response does "
                        "NOT corroborate the owner's authentic view (owner_view_available=%r "
                        "reason=%r) -> 'verified' DOWNGRADED to %r. The attacker did not "
                        "demonstrably receive the victim's data.",
                        _owner_view.available, _owner_view.reason, _gated,
                    )
                    _final_verdict = _gated
                    _override = OWNER_VIEW_NOT_CORROBORATED_REASON
                else:
                    logger.info(
                        "[DEEP-VERIFY] D24 owner-view differential: attack response "
                        "CORROBORATES the owner's authentic view -> 'verified' stands.",
                    )
            return DeepVerificationResult(
                status="completed",
                ai_verdict=_final_verdict,
                ai_confidence=turn1_obj.get("confidence"),
                ai_reasoning=turn1_obj.get("reasoning", ""),
                ai_requested_follow_up=False,
                follow_up_request=None,
                follow_up_response=None,
                baseline=baseline_trail,
                attack=attack_trail,
                model=resolved_model,
                approved_host=approved,
                turns_raw=turns_raw,
                ai_verdict_raw=_raw_verdict,
                guard_override=_override,
                ai_evidence_path=_evidence_path,
                anchoring_result=_anchor,
                caller_identity_anchor=_caller_anchor,
                payload_causality_anchor=_causality_anchor,
                pre_flight_status=(pre_flight_result or {}).get("status_code") if pre_flight_result else None,
                negative_assertion_anchor=None,   # no follow-up -> no from-exists-to-absent pair
                preflight_caller_identity_anchor=(
                    _anchor_caller_identity(
                        pre_flight_result.get("response_body"), attacked_object_id, caller_object_id
                    ) if pre_flight_result is not None else None
                ),
            )

        # ---------------- Execute the follow-up (scope-locked) ----------------
        fu_method = str(next_request.get("method", "GET")).upper()
        fu_path = str(next_request.get("path", ""))
        fu_body = next_request.get("body")
        fu_request_record = {
            "method": fu_method, "path": fu_path, "body": fu_body,
            "reason": next_request.get("reason", ""),
        }

        follow_up_response = None
        follow_up_feedback = None
        if not fu_path.startswith("/"):
            # Refuse absolute URLs / anything that could leave the host.
            follow_up_feedback = (
                f"REFUSED: follow-up path must be a relative path on the approved host "
                f"'{approved}'. Got: {fu_path!r}. No request was executed."
            )
        else:
            fu_parsed = {
                "method": fu_method, "path": fu_path, "query_params": {},
                "headers": dict(auth_context), "body": fu_body,
            }
            fu_url = _reconstruct_url(fu_parsed, base_url)
            if approved and _host_of(fu_url) != approved:
                follow_up_feedback = (
                    f"REFUSED (scope lock): follow-up host '{_host_of(fu_url)}' is outside the "
                    f"approved scope '{approved}'. No request was executed."
                )
            else:
                try:
                    fu_result = await _send_request(client, fu_parsed, base_url)
                    follow_up_response = _summarize_response(fu_result)
                    follow_up_feedback = (
                        f"HTTP {fu_result.get('status_code')} | "
                        f"Content-Length: {fu_result.get('content_length')}\n\n"
                        + (fu_result.get("response_body") or "")[:_EVIDENCE_BODY_MAX]
                    )
                except ScopeViolationError as sve:
                    follow_up_feedback = f"REFUSED (scope lock): {sve}. No request was executed."
                except Exception as e:
                    follow_up_feedback = f"ERROR executing follow-up: {type(e).__name__}: {e}"

        # ---------------- AI turn 2 (same conversation) ----------------
        body_line = f"\nBody: {json.dumps(fu_body)}" if fu_body is not None else ""
        turn2_msg = _TURN2_TEMPLATE.format(
            req_line=f"{fu_method} {base_url}{fu_path}",
            body_line=body_line,
            raw_response=follow_up_feedback or "(no response captured)",
        )
        if followup_is_code_gathered:
            # Be honest about WHAT the engine fetched and that it was not the model's choice.
            # The note states only what the response IS — it never suggests a verdict.
            if gathered_kind == "delete_state":
                _pf_status = (pre_flight_result or {}).get("status_code")
                _pf_body = (pre_flight_result or {}).get("response_body")
                turn2_msg = (
                    "NOTE: Your attack was a DELETE. BEFORE issuing it, the system read the "
                    "ATTACKED OBJECT'S OWN state and it EXISTED and was active:\n"
                    f"  BEFORE (system-taken): HTTP {_pf_status} | "
                    f"{(_pf_body or '')[:_EVIDENCE_BODY_MAX]}\n"
                    "AFTER your attack, the system read that SAME object's state again (verbatim "
                    "below, also NOT your choice). A transition from present/active (BEFORE) to "
                    "gone (404/403) — or to the same object with a status/lifecycle field flipped "
                    "to a deleted/archived value — is decisive proof the object was deleted by the "
                    "unauthorized actor. If the object is STILL present and unchanged, the delete "
                    "did not land. The BEFORE read is what makes a missing/deleted AFTER decisive: "
                    "the object provably existed first.\n\n"
                ) + turn2_msg
            elif gathered_kind == "mass_state":
                _pf_status = (pre_flight_result or {}).get("status_code")
                _pf_body = (pre_flight_result or {}).get("response_body")
                turn2_msg = (
                    "NOTE: Your attack injected extra field(s) into a write (mass assignment). "
                    "BEFORE issuing it, the system read the ATTACKED OBJECT'S OWN state, which "
                    "records the ORIGINAL state of those field(s):\n"
                    f"  BEFORE (system-taken): HTTP {_pf_status} | "
                    f"{(_pf_body or '')[:_EVIDENCE_BODY_MAX]}\n"
                    "AFTER your attack, the system read that SAME object again (verbatim below, "
                    "also NOT your choice). The injected values are LOW-ENTROPY, so the field merely "
                    "READING your value proves nothing — it may already have held it. It is decisive "
                    "ONLY if the field MOVED: absent in the BEFORE read (sensitive fields are often "
                    "hidden from you — absent->your value IS a real escalation), or holding a "
                    "DIFFERENT value there. If it is unchanged, still absent, or your value equals "
                    "what BEFORE already showed, the escalation did not land.\n\n"
                ) + turn2_msg
            elif gathered_kind == "state":
                turn2_msg = (
                    "NOTE: Because the resource you attacked has no same-path read-back and no "
                    "relevant record of write activity, the system itself selected and executed a "
                    "read of the ATTACKED OBJECT'S OWN CURRENT STATE on its other path (this was "
                    "NOT your choice). Treat the verbatim result below as the current state of the "
                    "object you attacked, and compare it against the value your attack sent.\n\n"
                ) + turn2_msg
            else:
                turn2_msg = (
                    "NOTE: Because the resource you attacked has no same-path read-back, the "
                    "system itself selected and executed an explicit record-of-writes endpoint "
                    "as the follow-up (this was NOT your choice). Treat the verbatim result "
                    "below as that record of write activity.\n\n"
                ) + turn2_msg
        contents.append(types.Content(role="model", parts=[types.Part(text=turn1_text)]))
        contents.append(types.Content(role="user", parts=[types.Part(text=turn2_msg)]))

        try:
            resp2 = await _gemini_generate(client_ai, types, resolved_model, contents, cfg)
            turn2_text = resp2.text
            turns_raw.append(turn2_text)
            turn2_obj = _parse_model_json(turn2_text)
        except (asyncio.TimeoutError, ValueError, json.JSONDecodeError) as e:
            return DeepVerificationResult(
                status="degraded",
                ai_verdict=None, ai_confidence=None,
                ai_reasoning="", ai_requested_follow_up=True,
                follow_up_request=fu_request_record,
                follow_up_response=follow_up_response,
                baseline=baseline_trail, attack=attack_trail,
                model=resolved_model, approved_host=approved,
                turns_raw=turns_raw,
                degraded_reason=f"Gemini turn-2 failed: {type(e).__name__}: {e}",
            )
        except Exception as e:
            return DeepVerificationResult(
                status="degraded",
                ai_verdict=None, ai_confidence=None,
                ai_reasoning="", ai_requested_follow_up=True,
                follow_up_request=fu_request_record,
                follow_up_response=follow_up_response,
                baseline=baseline_trail, attack=attack_trail,
                model=resolved_model, approved_host=approved,
                turns_raw=turns_raw,
                degraded_reason=f"Gemini turn-2 error: {type(e).__name__}: {e}",
            )

        # ---- B-2.2 structural guard + exemptions (B-1 write-record; M1.2(A) state read-back) ----
        # A follow-up read-back was performed iff we actually captured a response.
        _raw_verdict = turn2_obj.get("verdict")
        _follow_up_performed = follow_up_response is not None
        _fu_path = fu_request_record.get("path")
        _fu_is_write_record = _path_is_write_record(_fu_path)

        # B-1 HALF 2: structurally verify (in code, against the attack's own runtime params)
        # that the cross-path read-back is an explicit record of THIS write — same attacked
        # object id AND same written value, together in one record. The model's say-so is NOT
        # sufficient; only this content match exempts the downgrade. Write-record path ONLY.
        _content_match = False
        if _follow_up_performed and _fu_is_write_record:
            _content_match = _write_record_content_match(
                (follow_up_response or {}).get("body"),
                attacked_object_id,
                written_values,
            )

        # M1.1/M1.2 evidence anchoring. Computed HERE (before the guard) because the M1.2(A)
        # state-read exemption below is GATED on two of these anchors. The anchors are still
        # code-computed from the read-back + the attack's OWN runtime params — never the model's
        # say-so — and still never touch the RAW verdict. Read-back judged on: the follow-up
        # response when captured, else the attack response.
        _evidence_path = turn2_obj.get("evidence_path")
        _anchor_body = (
            (follow_up_response or {}).get("body")
            if _follow_up_performed
            else attack_result.get("response_body")
        )
        _anchor = _anchor_evidence(_anchor_body, _evidence_path, attacked_object_id)
        _caller_anchor = _anchor_caller_identity(_anchor_body, attacked_object_id, caller_object_id)
        _causality_anchor = _anchor_payload_causality(_anchor_body, _evidence_path, written_values)

        # M1.2(A) STATE-READBACK EXEMPTION — a SECOND, separate channel from B-1's write-record
        # exemption. A cross-path STATE read-back may stand as `verified` ONLY when code
        # structurally confirms ALL THREE, AND-ed:
        #   (1) the read object IS the ATTACKED object (owner id == attacked id), AND
        #   (2) the actor differs from the owner (caller id != owner id)
        #       -> (1)+(2) == the caller-identity anchor being "confirmed"; AND
        #   (3) PAYLOAD CAUSALITY: THIS attack's unique injected value appears in the read-back
        #       -> the payload-causality anchor being "confirmed_at_path"/"confirmed_in_body".
        # (3) is the NON-NEGOTIABLE false-positive gate: (1)+(2) hold for BOTH a real leak and a
        # securely-DROPPED write (a dropped write still leaves the object owned by the victim,
        # attacked by the caller) — only the unique-value-landed causality separates them. The
        # channel is DISJOINT from B-1: it never fires on a write-record path (those go through
        # the content-match exemption), so B-1 / D23 / D23b are untouched.
        # M1.4 DISJOINTNESS (a NARROWING, not a weakening): a mass-assignment attack is routed to
        # its own channel below and must NOT be exempted by payload-causality. Verified hazard: on a
        # SECURE allow-list target the LEGITIMATE field's unique value still lands, so
        # payload-causality confirms and this channel would exempt a SECURE case — a false positive.
        # The unique-value path is untouched for every other shape (see test_m14_mass_assignment.py).
        # M1.4(fix) ROUTING PRIORITY: the STATE-JUMP gate is strictly stricter than
        # payload-causality (it demands a proven move from a KNOWN pre-flight state, not the mere
        # presence of a written value). Whenever a pre-flight baseline exists for a body-write, the
        # state-jump gate GOVERNS and payload-causality is suppressed — regardless of how the attack
        # declared its type. This closes the mixed-field false positive: on a SECURELY-stripped case
        # a legitimate co-submitted field still satisfies payload-causality, so the weaker gate would
        # exempt a SECURE case. Routing only; no gate's own conditions are changed, and suppressing
        # the weaker channel can only REDUCE exemptions.
        _sent_fields = attack_req.get("body") if isinstance(attack_req.get("body"), dict) else None
        _state_jump: Optional[str] = None
        if pre_flight_result is not None and _sent_fields:
            _state_jump = _anchor_state_jump(
                pre_flight_result.get("status_code"), pre_flight_result.get("response_body"),
                (follow_up_response or {}).get("status_code"),
                (follow_up_response or {}).get("body"),
                _sent_fields,
            )
        # "no_sent_fields" means the jump could not be evaluated at all (e.g. a DELETE has no body),
        # so it must NOT suppress the other channels.
        _state_jump_governs = _state_jump not in (None, "no_sent_fields")

        _state_readback_decisive = (
            _follow_up_performed
            and not _fu_is_write_record
            and not _state_jump_governs
            and _caller_anchor == "confirmed"
            and _causality_anchor in ("confirmed_at_path", "confirmed_in_body")
        )

        # M1.3 DELETE-READBACK EXEMPTION — a THIRD, separate channel (negative assertion), for the
        # DELETE shape. Decisive ONLY when code confirms the from-EXISTS-to-ABSENT jump:
        #   * the PRE-FLIGHT read (taken before the attack) is the VICTIM's object — owner==attacked
        #     AND caller!=owner (`_anchor_caller_identity` on the PRE-FLIGHT body, since the AFTER
        #     read may be a 404 with no owner to anchor on); AND
        #   * the negative assertion is confirmed_physical (gone) or confirmed_logical (soft-deleted).
        # The pre-flight EXISTENCE proof is the coincidence gate baked into `_anchor_negative_assertion`
        # (no pre-flight existence -> no_preflight/preflight_absent -> not decisive). DISJOINT from the
        # other channels: a DELETE has no written value, so the state-readback (payload-causality) and
        # write-record channels never fire for it.
        _neg_assertion: Optional[str] = None
        _preflight_caller_anchor: Optional[str] = None
        _is_delete_attack = _is_delete_method(attack_req.get("method"))
        if _is_delete_attack and pre_flight_result is not None:
            _pf_body = pre_flight_result.get("response_body")
            _preflight_caller_anchor = _anchor_caller_identity(
                _pf_body, attacked_object_id, caller_object_id
            )
            _neg_assertion = _anchor_negative_assertion(
                pre_flight_result.get("status_code"), _pf_body,
                (follow_up_response or {}).get("status_code"),
                (follow_up_response or {}).get("body"),
            )
        _delete_readback_decisive = (
            _follow_up_performed
            and not _fu_is_write_record
            and _is_delete_attack
            and _preflight_caller_anchor == "confirmed"
            and _neg_assertion in ("confirmed_physical", "confirmed_logical")
        )

        # M1.4 MASS-ASSIGNMENT EXEMPTION — the FOURTH channel. Decisive ONLY when:
        #   * caller-identity confirms on the read-back (owner == attacked AND caller != owner), AND
        #   * the STATE JUMP confirms: EVERY field the attack sent moved from a KNOWN pre-flight
        #     state (a present value, or proven-MISSING via a SUCCESSFUL 2xx pre-flight) to the
        #     value this attack injected.
        # A failed/non-2xx/unparseable pre-flight or post read-back is UNKNOWN -> never decisive.
        # "post field == injected" ALONE is never enough: low-entropy values make presence
        # meaningless, which is exactly the false positive this gate exists to stop.
        _state_jump_decisive = (
            _follow_up_performed
            and not _fu_is_write_record
            and _state_jump_governs
            and _caller_anchor == "confirmed"
            and _state_jump == "confirmed_jump"
        )

        _final_verdict, _override = _apply_cross_resource_guard(
            _raw_verdict,
            attack_req.get("path", ""),
            _fu_path,
            follow_up_performed=_follow_up_performed,
            write_record_decisive=_content_match,
            state_readback_decisive=_state_readback_decisive,
            delete_readback_decisive=_delete_readback_decisive,
            state_jump_decisive=_state_jump_decisive,
        )
        if _override == WRITE_RECORD_EXEMPTION_REASON:
            logger.info(
                "[DEEP-VERIFY] Write-record exemption: cross-path read-back %r is a "
                "structurally-verified record of the attack (attacked_id=%r, written_value "
                "present) -> verdict %r kept decisive (NOT downgraded).",
                _normalize_path(_fu_path), attacked_object_id, _final_verdict,
            )
        elif _override == STATE_READBACK_EXEMPTION_REASON:
            logger.info(
                "[DEEP-VERIFY] State-readback exemption: cross-path read-back %r is the "
                "attacked object's OWN state (caller_identity=%r) and carries THIS attack's "
                "injected value (payload_causality=%r) -> verdict %r kept decisive (NOT "
                "downgraded). attacked_id=%r caller_id=%r.",
                _normalize_path(_fu_path), _caller_anchor, _causality_anchor,
                _final_verdict, attacked_object_id, caller_object_id,
            )
        elif _override == STATE_JUMP_EXEMPTION_REASON:
            logger.info(
                "[DEEP-VERIFY] Mass-assignment exemption: every field this attack sent JUMPED from "
                "its known pre-flight state to the injected value (state_jump=%r, caller_identity=%r) "
                "-> verdict %r kept decisive (NOT downgraded). attacked_id=%r caller_id=%r follow_up=%r.",
                _state_jump, _caller_anchor, _final_verdict,
                attacked_object_id, caller_object_id, _normalize_path(_fu_path),
            )
        elif _override == DELETE_READBACK_EXEMPTION_REASON:
            logger.info(
                "[DEEP-VERIFY] Delete-readback exemption: pre-flight proved the VICTIM's object "
                "existed (caller_identity=%r) and the post-attack read shows it GONE/deleted "
                "(negative_assertion=%r) -> verdict %r kept decisive (NOT downgraded). "
                "attacked_id=%r caller_id=%r follow_up=%r.",
                _preflight_caller_anchor, _neg_assertion, _final_verdict,
                attacked_object_id, caller_object_id, _normalize_path(_fu_path),
            )
        elif _override:
            logger.info(
                "[DEEP-VERIFY] Structural guard: model verdict=%r downgraded to %r "
                "(%s) — attack_path=%r follow_up_path=%r (different concrete resource; no "
                "verified write-record content match, no state-readback causality).",
                _raw_verdict, _final_verdict, _override,
                _normalize_path(attack_req.get("path", "")),
                _normalize_path(_fu_path),
            )

        logger.info(
            "[DEEP-VERIFY] Evidence anchoring (turn-2 verdict): ai_verdict=%r evidence_path=%r "
            "attacked_id=%r caller_id=%r -> object=%r caller_identity=%r payload_causality=%r "
            "negative_assertion=%r (state_readback_exempt=%r delete_readback_exempt=%r).",
            _final_verdict, _evidence_path, attacked_object_id, caller_object_id,
            _anchor, _caller_anchor, _causality_anchor, _neg_assertion,
            _override == STATE_READBACK_EXEMPTION_REASON,
            _override == DELETE_READBACK_EXEMPTION_REASON,
        )
        return DeepVerificationResult(
            status="completed",
            ai_verdict=_final_verdict,
            ai_confidence=turn2_obj.get("confidence"),
            ai_reasoning=turn2_obj.get("reasoning", ""),
            ai_requested_follow_up=True,
            follow_up_request=fu_request_record,
            follow_up_response=follow_up_response,
            baseline=baseline_trail,
            attack=attack_trail,
            model=resolved_model,
            approved_host=approved,
            turns_raw=turns_raw,
            ai_verdict_raw=_raw_verdict,
            guard_override=_override,
            ai_evidence_path=_evidence_path,
            caller_identity_anchor=_caller_anchor,
            payload_causality_anchor=_causality_anchor,
            anchoring_result=_anchor,
            pre_flight_status=(pre_flight_result or {}).get("status_code") if pre_flight_result else None,
            negative_assertion_anchor=_neg_assertion,
            preflight_caller_identity_anchor=_preflight_caller_anchor,
            state_jump_anchor=_state_jump,
        )
