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
    "targeted state ONLY in one of these three cases — (a) it queries the SAME resource/path the "
    "attack targeted (any HTTP method on that same resource); (b) it is an explicit record of that "
    "specific write; or (c) it is a read of the ATTACKED OBJECT'S OWN CURRENT STATE that THE SYSTEM "
    "ITSELF selected and executed and says so in the follow-up result — when the attacked resource "
    "has no same-path read-back, the system may fetch the attacked object's state by another path, "
    "and that response IS the state you attacked even though its path differs. In case (c) commit "
    "only after checking BOTH that the object returned is the one the attack targeted AND what that "
    "state now holds for the field your attack wrote: if the value your attack sent is present, the "
    "unauthorized write landed (\"verified\"); if the state still holds a different/original value, "
    "it did not (\"failed\"). Case (c) NEVER applies to a read YOU chose: a DIFFERENT endpoint you "
    "picked yourself, or one that merely exposes a field with the SAME NAME as what you wrote, is "
    "NOT the same state — matching field names across different resources/paths do NOT make a "
    "read-back decisive, so you MUST answer \"inconclusive\" (not \"failed\", not \"verified\"). "
    "A read-back of the SAME resource/path you attacked remains FULLY decisive — use it to "
    "commit to \"verified\" or \"failed\"."
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
an explicit record of that specific write, or (c) is a read of the ATTACKED OBJECT'S OWN CURRENT
STATE that the SYSTEM ITSELF selected and executed (a note above will say so explicitly) — in
case (c) it IS the state you attacked even though its path differs, so check that the object
returned is the one you targeted, compare the value your attack sent against what that state now
holds, and commit ("verified" if your value is present, "failed" if the original value stands).
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

    Method-agnostic and target-agnostic: compares path strings; both `write_record_decisive`
    and `state_readback_decisive` are computed by the caller and passed in as booleans.
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

    async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
        # ---------------- Step 1: real baseline + attack ----------------
        try:
            baseline_result = await _send_request(client, baseline_req, base_url)
            if payload:
                attack_req = await mutate_request(baseline_req, payload)
            else:
                attack_req = baseline_req  # read-only case: no mutation
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
            decision = "request_more"
            next_request = {
                "method": "GET",
                "path": det_state_path,
                "body": None,
                "reason": (
                    "code-gathered object-state read-back (deterministic; the attacked "
                    "resource has no same-path read-back and no relevant record of writes, so "
                    "the engine fetched the attacked object's own current state on its other "
                    "path rather than relying on the model's choice)"
                ),
            }
            followup_is_code_gathered = True
            gathered_kind = "state"

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
            if gathered_kind == "state":
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
        _state_readback_decisive = (
            _follow_up_performed
            and not _fu_is_write_record
            and _caller_anchor == "confirmed"
            and _causality_anchor in ("confirmed_at_path", "confirmed_in_body")
        )

        _final_verdict, _override = _apply_cross_resource_guard(
            _raw_verdict,
            attack_req.get("path", ""),
            _fu_path,
            follow_up_performed=_follow_up_performed,
            write_record_decisive=_content_match,
            state_readback_decisive=_state_readback_decisive,
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
            "(state_readback_exempt=%r).",
            _final_verdict, _evidence_path, attacked_object_id, caller_object_id,
            _anchor, _caller_anchor, _causality_anchor,
            _override == STATE_READBACK_EXEMPTION_REASON,
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
        )
