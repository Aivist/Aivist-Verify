# DEEP VERIFY — AI-in-the-loop Write-then-Read Verifier

> File: `backend/app/services/deep_verifier.py`. Manual script:
> `backend/scripts/deep_verify_live_check.py`.
>
> **Status:** present in tree; **not wired to any HTTP endpoint**. It IS now
> invoked, **read-only**, from the fuzzer as **shadow-mode Phase 7** (see
> [`VERIFY_ENGINE.md`](./VERIFY_ENGINE.md) §Phase 7). Two independent gates, both
> default `False`: `AI_DEEP_VERIFY_ENABLED` (the verifier itself runs / may call
> Gemini) and `AI_DEEP_VERIFY_SHADOW` (the fuzzer calls it after a batch). With the
> defaults, nothing here runs and behavior is byte-identical to before. The
> rule-based HTTP verify still uses `fuzzer.py`.
>
> **Confirms five vuln shapes, zero false positives** (each live-measured N=5, shadow):
> **M1.0/B-1** silent cross-path write via a code-gathered **write-record**; **M1.1** read-type
> **semantic equivalence**; **M1.2** silent cross-path write via a code-gathered **object-STATE**
> read-back; **M1.3** **delete**-type via a **NEGATIVE ASSERTION** (pre-flight existence + dual-track
> absence); **M1.4** **mass-assignment** via a **LOW-ENTROPY STATE JUMP** from a known pre-flight
> state. The verdict is still **observe-only** — promoting it to authoritative is **D19**.

---

## Purpose (from `deep_verifier.py` module header)

Resolve access-control cases that a single-shot differential oracle cannot
(e.g. silent BOLA with opaque `200 {"status":"ok"}` on write). Two-turn
AI-in-the-loop write-then-read. Does not call `execute_parallel_fuzzing` or
`_differential_verdict`.

---

## How it works

```
Turn 1   Send baseline (authorized/self) + attack (cross-object) requests.
         Present BOTH real HTTP responses to Gemini.
         Model returns either:
           (A) final verdict now, OR
           (B) exactly ONE follow-up HTTP request spec (relative path, same host).

Execute  If (B): run the follow-up for real (scope-locked to approved host).

Turn 2   Feed the follow-up's raw response back in the same conversation.
         Model delivers the final verdict.
```

The returned `DeepVerificationResult` keeps the **full evidence trail**
(baseline response, attack response, optional follow-up request/response) **beside**
the AI verdict — the verdict is never the sole field.

On Gemini timeout, 503, or invalid JSON the function **degrades gracefully**
(never raises through to callers) and records why in the result.

### Reused primitives (read-only from fuzzer)

Only stable, side-effect-free helpers are imported from `fuzzer.py`:

- `mutate_request`, `_send_request`, `_reconstruct_url`, `_host_of`
- `ScopeViolationError` for host lock enforcement

No changes to the fuzzer's verdict path; the rule-oracle tests stay green (backend
suite: **285 passed** — see [`STATUS.md`](./STATUS.md)).

---

## Verdict vocabulary & the decisive-evidence standard

Unlike the rule oracle (`fuzzer.py::_differential_verdict`, which emits **three**
values — `verified` / `suspicious` / `failed`), the AI verifier's verdict
vocabulary is **four** values; it adds `inconclusive`:

- `verified` — the attacked state was demonstrably changed by the unauthorized actor.
- `failed` — the attacked state is provably unchanged (the server enforced authorization).
- `inconclusive` — **NEW** (the rule oracle has no equivalent): cannot confirm from the
  evidence gathered; a human must decide.
- `suspicious` — still ambiguous and the model has not yet spent its one follow-up.

This vocabulary lives in `SYSTEM_PROMPT` (`deep_verifier.py` ~63-96) and is restated
in `_OPTIONS_BLOCK` (~116) and `_TURN2_TEMPLATE` (~159). `SYSTEM_PROMPT` carries a
five-point **DECISIVE-EVIDENCE STANDARD**:

1. An action endpoint's OWN response — above all an opaque success such as
   `200 {"status":"ok"}` — is **never, by itself** evidence that the targeted state
   did or did not change.
2. Return `verified` / `failed` **only** when a follow-up read-back reflects the
   **SAME** attacked state — it returns the exact field/resource that was written (so
   it can be compared against the value the attack sent) or is an explicit record of
   that specific write.
3. If the evidence does not reflect the targeted state (a wrong/unrelated object, a
   read-back missing the written field, or no decisive observation), the model **must**
   answer `inconclusive` — not fall back to `failed`, and not return `verified` on the
   action status alone.
4. `inconclusive` means "cannot confirm from the evidence gathered; a human must
   decide" — the honest answer **only** in a genuine evidence gap (when decisive
   read-back evidence does exist, commit to `verified` / `failed` rather than hedging).
5. **SAME-RESOURCE RULE** — a read-back is decisive in exactly **three** cases:
   **(a)** it queries the **same** resource/path the attack targeted (any HTTP method on
   that resource); **(b)** it is an explicit record of that write; or **(c)** *(M1.2(C))*
   it is a read of the **attacked object's own current state that the SYSTEM ITSELF
   gathered** and says so — when the attacked resource has no same-path read-back, the
   engine may fetch the object's state by another path, and that response *is* the attacked
   state. Case (c) requires checking that the object returned is the one attacked **and**
   comparing the value the attack wrote against what that state now holds. Case (c) **never**
   applies to a read the *model* chose: a **different** endpoint the model picked, or one that
   merely exposes a field with the *same name* as what was written, is **not** the same state
   and is **not** decisive → the model must answer `inconclusive`.

   > Rule 5 is restated in `_TURN2_TEMPLATE` and in the `_OPTIONS_BLOCK` verdict definitions —
   > **all three must agree.** M1.2(C) exists because they did not: code gathered a cross-path
   > object state and exempted it structurally while the prompt still forbade concluding from a
   > different path, so the model held decisive evidence and answered `inconclusive` 2/5.
   > Keeping prompt and code in agreement is now a standing discipline
   > ([`ROADMAP.md`](./ROADMAP.md) §6).

---

## Deterministic cross-resource guard (B-2.2)

The SAME-RESOURCE RULE is **also enforced deterministically in code**, not left to the
model alone. After the model returns, a target-agnostic structural backstop
(`_apply_cross_resource_guard`, `deep_verifier.py` ~213; path key via `_normalize_path`
~201) runs:

- It **downgrades** a `verified` / `failed` verdict to `inconclusive` — with override
  reason `CROSS_RESOURCE_OVERRIDE_REASON = "cross_resource_readback_not_decisive"` (~198)
  — **iff** a follow-up read-back was performed **and** its concrete path differs from
  the attack path (`normalize(follow_up_path) != normalize(attack_path)`).
- It is **method-agnostic** and compares two path strings only (drops query/fragment,
  strips a trailing slash); it holds no knowledge of any target's endpoints/fields.
- It does **nothing** when there was no follow-up (e.g. a read-type/GET BOLA confirmed
  by the attack response itself), when the paths match (a same-resource read-back stays
  fully decisive), or when the verdict is already `suspicious` / `inconclusive`.

It is applied at **both** return sites in `execute_deep_verification`. The result then
records the outcome transparently: `ai_verdict` is the **final** (post-guard) verdict,
`ai_verdict_raw` preserves the model's original pre-guard verdict, and `guard_override`
holds the override reason (or `None` when the guard did not fire).

### The exemption channels (all `verified`-only, cross-path-only, DISJOINT)

A cross-path `verified` is downgraded **unless** exactly one of these structural exemptions
fires. All are computed **in code** from the attack's own runtime params — the model's say-so is
never sufficient — and passed into the guard as booleans:

| Channel | Constant | Fires when | Applies to |
|---|---|---|---|
| **B-1 write-record** | `WRITE_RECORD_EXEMPTION_REASON` | `_write_record_content_match` finds the attacked object id **and** a value this attack wrote **in one record** (D23/D23b-hardened) | follow-up paths that ARE record/log-style |
| **M1.2(A) state read-back** | `STATE_READBACK_EXEMPTION_REASON` | all three anchors AND: owner==attacked ∧ caller!=owner (`caller_identity == "confirmed"`) **and** payload-causality confirmed | follow-up paths that are **not** record/log-style, **and only when no pre-flight baseline exists** (otherwise the state-jump channel governs — see below) |
| **M1.3 delete read-back** | `DELETE_READBACK_EXEMPTION_REASON` | caller-identity **on the PRE-FLIGHT body** is `confirmed` **and** the negative assertion is `confirmed_physical`/`confirmed_logical` | **DELETE** attacks only (no written value, so the value-based channels can never fire) |
| **M1.4 state jump** | `STATE_JUMP_EXEMPTION_REASON` | caller-identity is `confirmed` **and** `_anchor_state_jump` returns `confirmed_jump` — **every** field the attack sent moved from a **KNOWN pre-flight state** to the injected value | any write with a JSON body **and** a readable pre-flight baseline |

They are kept **disjoint** by `_path_is_write_record(follow_up_path)`, so D23/D23b remain the sole
authority on record paths. If several were somehow set, the write-record channel takes precedence,
so B-1's behaviour is unchanged.

**Payload-causality is the false-positive gate — but only for high-entropy values.** Owner-identity
and caller!=owner confirm for **both** a real leak and a securely-*dropped* write (a dropped
cross-user write still leaves the object owned by the victim and attacked by the caller) — only
"THIS attack's unique value is actually present" separates them. Measured: X-SILENT-VULN causality
`confirmed_at_path` 5/5 → `verified` 5/5; X-SILENT-SAFE causality `absent` 5/5 → no exemption →
`inconclusive` 5/5, **0 false positives**.

**M1.4 narrowed this (a real false positive, closed).** On a mass-assignment SAFE case — privileged
field stripped by an allow-list, legitimate co-submitted field lands — the anchors read
`caller_identity=confirmed` + `payload_causality=confirmed_in_body`, so the M1.2 channel **would
have exempted a secure endpoint**. Routing therefore keys on **evidence, not the declared attack
type**: whenever a readable pre-flight baseline exists, the **state-jump** gate governs and the
payload-causality channel yields. Strictly a narrowing — it can only ever produce *fewer*
exemptions; the other four shapes keep identical verdicts (three now exempt via the stricter
channel). Locked by `test_HAZARD_m12_causality_would_false_positive_on_mass_assignment_safe` and
`test_RESIDUAL_FIX_mass_assignment_mistyped_as_BOLA_safe_stays_inconclusive`.

> **Known boundary (now handled):** causality assumes the written value is high-entropy. On boolean /
> small-int / enum fields — or with concurrent runs writing the same value — it collides. That is
> exactly what M1.4's state-jump gate replaces it with; see the M1.4 section below and
> [`ROADMAP.md`](./ROADMAP.md) §7.

---

## M1.3 — the DELETE shape: pre-flight + negative assertion

A delete's proof is a **from-EXISTS-to-ABSENT jump**, not a value appearing, so payload-causality
does not apply. Two mechanisms, both target-agnostic:

**1. PRE-FLIGHT READ — the coincidence gate.** For a DELETE attack the code reads the victim
object's own state **before** issuing the delete (scope-locked, reusing
`select_object_state_endpoint`) and caches `{status, body}`. "It vanished" only proves a delete if
"it existed and was active just before" is anchored — otherwise the object may never have existed,
or was already deleted. **No pre-flight existence proof → never `verified`.** A pre-flight
failure/scope-refusal is *not* fatal: it simply leaves existence unproven, so the verdict stays
`inconclusive` (the safe direction).

**2. DUAL-TRACK ABSENCE** (`_anchor_negative_assertion`), returning one of
`confirmed_physical` | `confirmed_logical` | `still_present` | `no_preflight` | `preflight_absent`
| `preflight_already_deleted` | `indeterminate`:

- **Physical**: the post-attack read is `404/403/410`.
- **Logical (soft delete)**: the post-attack read is `200` but a lifecycle field flipped to a
  deleted value — detected generically by `_deletion_signal` (string statuses via
  `_DELETED_VALUE_KEYWORDS`/`_ACTIVE_VALUE_KEYWORDS`, boolean flags `is_deleted`/`is_active`, and
  timestamp markers like `deleted_at`). **404 is deliberately NOT hardcoded as the only proof of
  vanishing** — real APIs mostly soft-delete.

Only the two `confirmed_*` results are decisive; every other value means the delete cannot be
attributed to this attack, so the caller must not exempt.

> **A DELETE never takes B-1's write-record gather.** A delete carries no written value, so
> `_write_record_content_match` (which *requires* written values) is unreachable for it — gathering
> a record would be useless *and* would preempt the object-state gather this shape needs. HALF 1 is
> therefore skipped for `DELETE`. (This was a real bug: with no written values the M1.2 object-scope
> probe was skipped and `_object_scoped` defaulted to the B-1-safe `True`, so HALF 1 wrongly grabbed
> the audit-log.)

> **Auditability:** the result surfaces `pre_flight_status`, `negative_assertion_anchor`, and
> `preflight_caller_identity_anchor` — the last because the general-purpose `caller_identity_anchor`
> is computed on the AFTER read, which for a physical delete is a 404 with no owner to anchor on
> (it reads `owner_not_found`) and would misrepresent the evidence chain in a transcript.

**Measured** (N=5 each, gemini-2.5-pro, fresh-seeded per run): X-DELETE-VULN-HARD →`verified` 5/5
(`confirmed_physical`); X-DELETE-VULN-SOFT →`verified` 5/5 (`confirmed_logical`); X-DELETE-SAFE
→`verified` **0/5** (`still_present`); X-DELETE-CONTROL (object never existed) →`verified` **0/5**
(`preflight_absent` — the AFTER read was *also* 404, but nothing was proven to exist).

---

## M1.4 — the MASS-ASSIGNMENT shape: the low-entropy state jump

The attacker sneaks a privileged field (`role`, `is_admin`, `tier`) into a write on the **victim's**
object. The response is a byte-identical opaque `200 {"status":"ok"}`, and there is no same-path GET.

**Why the previous gate fails here.** Payload-causality asks "is THIS attack's value present in the
victim's object?" — sound only if the value is **unique**. Mass-assignment writes **low-entropy**
values, so `role == "admin"` in the AFTER read cannot distinguish *I set it* from *it was already
admin*. Presence is not causality once the value space is small.

**The replacement: prove MOVEMENT.** `_anchor_state_jump(pre_status, pre_body, post_status,
post_body, sent_fields)` returns `confirmed_jump` only when **every** field the attack sent moved
from a **KNOWN** pre-flight state to the injected value. Checking *all* sent fields is deliberately
stricter than checking one named field — and it is what makes the `path_segment` attack shape
workable (it keeps the object ids derivable, but never names the injected field).

| Pre-flight state | Meaning | Can it yield `confirmed_jump`? |
|---|---|---|
| 2xx, parseable, field present with a **different** value | KNOWN original | **Yes** — `old → injected` is a jump |
| 2xx, parseable, field **absent** | **MISSING** — a *legal* original state (privileged fields are commonly hidden) | **Yes** — `missing → injected` is hidden-field escalation |
| 2xx, parseable, field already **equals** the injected value | KNOWN, no movement | No → `no_jump` |
| non-2xx / unreachable / unparseable JSON | **UNKNOWN** — not the same as MISSING | **Never** → `preflight_unknown` |

The MISSING-vs-UNKNOWN split is safety-critical: collapsing them would turn every *unreadable*
object into a confirmed escalation. The post-read has the mirror rule (`postread_unknown`), and the
whole anchor is wrapped so a malformed body degrades to `inconclusive` rather than raising.

**Routing keys on evidence, not the declared attack type.** The pre-flight read fires for **all
write methods** (not just DELETE/mass-typed), and whenever that baseline exists the state-jump gate
**governs** — the payload-causality channel yields. This closes a residual hole where an attack
*mistyped* as plain BOLA, but carrying a low-entropy co-submitted field, would have fallen back to
the weaker gate. It is strictly a narrowing: fewer exemptions, never more.

**Measured** (N=5 each, gemini-2.5-pro, fresh-seeded per run): X-MASS-VULN present-value →`verified`
5/5 and MISSING→injected →`verified` 5/5 (`confirmed_jump`); X-MASS-SAFE present **and** missing
→`verified` **0/5** (the allow-list stripped `role`, so no full jump); CONTROL (injected == existing
value) →`verified` **0/5**. On the SAFE cases the model's **raw** verdict was `verified` and the gate
refused every time — the line is held by code, not model compliance.

---

## M1.2(B) — deterministic object-state gather

B-1's HALF 1 gathers a **write-record**. M1.2(B) adds the parallel gather for the case where **no
relevant write-record exists**: the code resolves and fetches the **attacked object's own state**,
which usually lives on a *different* path (write `POST /api/users/{id}/gizmo`, state
`GET /api/gizmos/{id}`).

- **Why:** measured, the model does **not** find that path on its own — `0/5` at M1.2(A) (it tried
  the same-path GET → 405, or an empty audit-log). That is B-1's wall (`0/20`) again.
- **Where:** `endpoint_catalog.select_object_state_endpoint(entries, attack_path, attacked_object_id)`,
  wired in `execute_deep_verification` as the fallback when `det_record_path is None`.
- **How (generic, no target path/field/tag hardcoded):** take the **resource noun** = the write
  path's last non-id segment (`attacked_resource_noun`, singular/plural-insensitive); keep GET
  endpoints that carry that noun as a whole segment **and** are object-scoped (have a `{template}`
  to bind to the attacked id — the same binding `select_write_record_endpoint` already uses);
  **exclude** record/log endpoints (B-1's channel); reject a candidate resolving to the attack's own
  path; prefer the canonical `<noun>/{id}` read. Returns `None` rather than fabricating.
- **Safety:** the resolver is only a **FETCHER** — the three-AND gate above remains the
  **VERIFIER**. A wrong gather fails the owner/causality anchors and degrades to `inconclusive`,
  never to a false positive.
- **Honesty:** when the engine (not the model) chose the follow-up, the turn-2 message carries an
  explicit NOTE saying so and describing *what* was fetched (state vs record). It never suggests a
  verdict.
- **Genericity proven** on a foreign spec sharing no vocabulary with this target
  (`/v2/widgets/{id}`, `/shop/policies/{id}`, `/erp/dispatch-boxes/{id}`) in
  `test_m12b_state_gather.py`.
- **Result:** gather `0/5 → 5/5`; with M1.2(C)'s prompt carve-out, X-SILENT-VULN `3/5 → 5/5`
  `verified`, X-SILENT-SAFE `verified` **0/5**.

---

## B-1 — confident cross-path verdict (✅ DONE, committed `37769b3`)

> ✅ **Status:** the machinery below is committed (`37769b3`), **live-measured** (shadow, N=5:
> X-CROSS→`verified` 5/5, X-SAFE→`inconclusive`/safe 5/5, reverse-guards intact —
> `scripts/audit/shadow_b1step3_code_gather_measure.out.txt`), and **locked by an automated
> regression test** — `test_d18_b1_shadow_integration.py` runs the real
> `execute_deep_verification` with a mocked Gemini and pins X-CROSS→`verified` /
> X-SAFE→never-`verified` (closes D22) — plus offline units (`test_d18_b1_write_record.py`).
> **Caveats:** proven on **one vuln shape only**; the final verdict still depends on the model
> reading the log correctly (a model-specific pillar — re-test on any model swap); and the
> content-match is hardened on both axes — the id check binds to an owner/subject key
> (**D23**) and the value check to non-primary-key content fields (**D23b**). See
> [`STATUS.md`](./STATUS.md)
> and [`TECH_DEBT.md`](./TECH_DEBT.md) B-1.

The integrity floor (B-2.2) refuses a false verdict on a cross-path write but stops
at `inconclusive` — it cannot yet *confirm*. B-1 aims to let the verifier confirm a
cross-path write whose only evidence is an explicit **write record** (audit log /
history / events feed), without weakening the floor. Three pieces, all
target-agnostic (no concrete path/field/tag is hardcoded):

1. **Catalog semantics** (`endpoint_catalog._format_entry`) — each entry now carries
   the operation's genuine `tags` + `operationId` (when the spec declares them), so a
   record-style endpoint is recognizable as such. Nothing is invented.
2. **Deterministic write-record gathering — HALF 1** (`deep_verifier`,
   `select_write_record_endpoint` / `has_same_path_readback`): when the attack is a
   write (`POST/PUT/PATCH/DELETE`) and the attacked resource has **no same-path
   read-back** in the catalog, the *code* — not the model — picks a record/log-style
   endpoint from the catalog (generic `_WRITE_RECORD_KEYWORDS` vocabulary) and forces
   it as the single follow-up. If none exists, it does **not** fabricate one → the
   flow stays `inconclusive`.
   - **Object-scope gate (M1.2, `_record_is_relevant_to_write`):** the force-gather is
     **conditional**. HALF 1 probes the candidate record once and hijacks the follow-up
     **only if that record already holds the caller's OWN (baseline, definitely-landed)
     write** — the caller's runtime id together with the value we wrote — proven by the
     same content-match with the *caller's* id (target-agnostic; no path/field/tag
     hardcoded). If the record does **not** record this write-type (e.g. a global
     audit-log unrelated to the attacked resource), HALF 1 **steps back** and lets the
     model choose its own follow-up (for a state-confirmable write, the object's own
     read-back). On a probe error / missing ids it defaults to the existing gather so B-1
     never regresses. This unblocks the M1.2 shape (silent write confirmed by the object's
     own state); the guard still downgrades that cross-path state read-back (no read-back-
     state exemption yet — see STATUS M1.2).
3. **Write-record exemption — HALF 2** (`_write_record_content_match` +
   `_apply_cross_resource_guard(..., write_record_decisive=True)`): a cross-path
   `verified` is normally downgraded by B-2.2. It is **exempted only when** the code
   structurally verifies — against the attack's own runtime params — that a **single
   record** in the read-back contains **both** the attacked object id **and** a value
   this attack wrote (scalar equality, not substring). That presence is decisive proof
   the unauthorized write landed. The exemption applies **only** to `verified` (a
   record's presence proves a write happened; its absence cannot prove the negative),
   so a secure cross-path control (X-SAFE, no matching record) still stays
   `inconclusive`. Override reason: `WRITE_RECORD_EXEMPTION_REASON =
   "write_record_readback_decisive"`.

The model's say-so is never sufficient for the exemption — only the in-code content
match is. This is what keeps the X-SAFE trap from re-opening the integrity hole.

---

## Configuration

| Setting | Default | Effect |
|---|---|---|
| `AI_DEEP_VERIFY_ENABLED` | `False` | When `False`, `execute_deep_verification` returns a clearly-marked `disabled` result and **never** touches the network. Gates the verifier itself. |
| `AI_DEEP_VERIFY_SHADOW` | `False` | When `False`, the fuzzer's Phase 7 shadow pass is an immediate no-op. When `True`, the fuzzer calls the verifier read-only after a batch. To get a live Gemini second opinion, **both** this and `AI_DEEP_VERIFY_ENABLED` must be `True`. |
| `GEMINI_API_KEY` | optional | If unset, AI steps return degraded output (see module). |
| `GEMINI_PRO_MODEL` | `gemini-2.5-flash` (code default; `.env` may override, e.g. `gemini-2.5-pro`) | Model used for both turns. |
| `GEMINI_REQUEST_TIMEOUT_SECONDS` | `60` | From `settings`; used by Gemini calls in this module. |

Set in `backend/.env` or override at runtime (as the live-check script does).

---

## `execute_deep_verification` parameters (seams)

```
execute_deep_verification(parsed_request, payload, base_url, *,
                          approved_host=None, auth_context=None,
                          context_note="", available_endpoints=None,
                          model_name=None) -> DeepVerificationResult
```

- `parsed_request` — the BASELINE (authorized/self) request; `payload` mutates it
  into the ATTACK request via the fuzzer's `mutate_request` (pass `payload=None`
  for read-only cases so baseline == attack).
- `auth_context` — headers merged into every request (incl. the follow-up); this
  is the **auth seam**.
- `available_endpoints` — the discoverable API surface handed to the model so it
  can request the correct read-back path for its one follow-up; this is the
  **endpoint-catalog seam**.
- `approved_host` — scope lock; a follow-up whose host ≠ this is refused.
- Returns a `DeepVerificationResult` with `status` (`completed`/`degraded`/`disabled`),
  `ai_verdict` (the **final**, post-guard verdict), `ai_verdict_raw` (the model's
  pre-guard verdict), `guard_override` (the structural-guard reason, or `None`),
  `ai_confidence`, `ai_reasoning`, `ai_requested_follow_up`,
  `follow_up_request`/`follow_up_response`, `baseline`, `attack`, `turns_raw`,
  and — new in M1.1 — `ai_evidence_path` + `anchoring_result` (see below).

---

## Structured evidence + code-anchoring (M1.1, observe-only)

The response contract carries **structured evidence**, not just a label: the model emits an
`evidence_path` (a concrete JSON path into the read-back it cites as decisive) alongside
`verdict` + `reasoning`. In CODE, `_anchor_evidence` resolves that path in the read-back
(`_resolve_json_path`, wrapped in try/except so a hallucinated path never crashes the engine)
and compares the value there — with type coercion (`"2"` == `2`) — against the attacked victim's
runtime id. The outcome is recorded as `anchoring_result`, one of: `confirmed` |
`value_mismatch` | `failed_path_not_found` | `unparsable_read_back` | `no_read_back` | `no_path`.

This is the project's principle in action — **the AI makes the semantic call; code anchors it
against ground truth** — but note the honest limits:

- **Corroboration, not proof.** For a read of object 2, `owner_id:2` in the response is
  *expected*; `confirmed` verifies the read-back exposes the attacked object's identity, it does
  **not** by itself prove the "caller is a different user" half. It is a cross-check on the
  model's cited evidence, not an independent oracle.
- **Observe-only.** `anchoring_result` is **logged, never used to change `ai_verdict`** in this
  task (no read-leak exemption was built). It corroborates; it does not gate.
- Measured on the read-type X-EQUIV pair (`vulnerable_target/benchmark/RESULTS.md`, M1.1):
  X-EQUIV-VULN → `verified` 5/5 with `evidence_path='owner_id'` / `anchoring_result='confirmed'`;
  X-EQUIV-SAFE → `failed` 5/5 (0 false positives) with `anchoring_result='value_mismatch'`.

**Provider seam (JSON mode):** strict JSON output is enforced at the **provider call site**, not
by prompt text alone — `_build_provider_config` centralizes the Gemini-specific
`response_mime_type="application/json"` so it stays swappable when other LLM providers are added
(business logic never hardcodes provider params).

---

## Shadow-mode Phase 7 (read-only integration)

`execute_parallel_fuzzing` appends an additive **Phase 7** after a batch fully
completes (`_run_shadow_deep_verification` in `fuzzer.py`). Gated by
`AI_DEEP_VERIFY_SHADOW` (default off → immediate no-op). When on, it:

1. queries back this run's `FuzzingRecord`s with `verification_status == "suspicious"`;
2. for each, re-runs `execute_deep_verification` against the same target; and
3. **logs** the AI verdict (`[FUZZER · SHADOW] … AI_shadow_verdict=… NOT applied
   (shadow, observe-only)`) **without** changing `verification_status` /
   `diff_details` or anything the user sees.

It never raises — any failure is logged and swallowed, so it cannot affect the
batch result. Phases 1–6, `_execute_single_fuzz`, and `_differential_verdict` are
unchanged. Two seams feed it, both currently minimal:

- **Auth seam** (`_shadow_auth_context`): prefer the live custody controller's
  active credential, else the auth header on the finding's `parsed_request`.
- **Endpoint-catalog seam** (`_shadow_endpoint_catalog`): real endpoint discovery
  now exists. `endpoint_catalog.py`'s `catalog_from_openapi` derives the surface from
  an OpenAPI/Swagger spec, and `_shadow_endpoint_catalog` **merges** it with the
  placeholder (the finding's own path + a same-resource GET read-back) when a spec
  source is provided — read from `settings.AI_DEEP_VERIFY_OPENAPI_SPEC` via `getattr`
  (a runtime-only seam, **not** a declared `config.py` field); with no source it falls
  back byte-identically to the placeholder. Each catalog entry **leads with
  `METHOD /path`** and, when the spec declares them, now **carries the operation's
  genuine `tags` and `operationId`** (nothing invented — see the B-1 section below),
  so the model can tell what an endpoint *is* (e.g. that an audit/log endpoint is a
  record of writes). See [`TECH_DEBT.md`](./TECH_DEBT.md) D18 / D21.

---

## Manual validation (not pytest)

The committed helper `backend/scripts/deep_verify_live_check.py`:

1. Requires the **vulnerable target** on `http://127.0.0.1:8001` (see
   [`../vulnerable_target/README.md`](../vulnerable_target/README.md)).
2. Requires **Gemini network access**.
3. Forces `settings.AI_DEEP_VERIFY_ENABLED = True` for the run only.
4. Exercises three cases (per `CASES` in the script) and prints verbatim model JSON
   + structured results:
   - **Vuln D** — `POST /api/users/{id}/settings` BOLA write (path `1`→`2`; expect `verified`),
   - **SAFE** — `POST /api/users/{id}/avatar` BOLA attempt (expect `failed` / not vulnerable), and
   - **Vuln C** — `GET /api/admin/users` admin-only access, read-only (`payload=None`; expect `verified`).

```powershell
# Terminal 1 — ground-truth target
python -m uvicorn vulnerable_target.main:app --port 8001

# Terminal 2 — from repo root, with GEMINI_API_KEY in backend/.env
python backend/scripts/deep_verify_live_check.py
```

Per `deep_verify_live_check.py` header: not under `backend/tests/` (it is not part
of the pytest count).

---

## Related repo paths

- [`../vulnerable_target/README.md`](../vulnerable_target/README.md)
- [`../vulnerable_target/benchmark/README.md`](../vulnerable_target/benchmark/README.md)
- [`../vulnerable_target/benchmark/RESULTS.md`](../vulnerable_target/benchmark/RESULTS.md)
