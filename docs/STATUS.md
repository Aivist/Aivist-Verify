# STATUS — where the project stands right now

> The single **current-state snapshot**: progress, what is proven, what is deferred.
> Grounded in the code and the test suite as of this writing — if a line here drifts
> from the source, the code wins, update this file. For *why / where it's going* read
> [`ROADMAP.md`](./ROADMAP.md); for *what exists + how to run it* read
> [`PROJECT_OVERVIEW.md`](./PROJECT_OVERVIEW.md); for the full gap register read
> [`TECH_DEBT.md`](./TECH_DEBT.md).

## One line

A single-tenant, locally-run access-control verification engine whose core is
**built, wired into the pipeline as a read-only shadow pass, and dormant by
default**. The integrity floor (never emit a false verdict) is proven. The engine now
confirms the hard case on **five distinct vuln shapes with zero false positives** —
**M1.0/B-1** (silent cross-path *write*, confirmed via a write-record), **M1.1**
(read-type *semantic-equivalence*, equal-length, confirmed by semantics + evidence
anchoring), **M1.2** (silent cross-path *write* confirmed via a code-gathered
object-**STATE** read-back), and **M1.3** (**delete**-type, confirmed by a **NEGATIVE
ASSERTION** — a code-anchored from-EXISTS-to-ABSENT jump), and **M1.4** (**mass-assignment**,
confirmed by a **LOW-ENTROPY STATE JUMP** from a known pre-flight state). **M1 — proving the
mechanism generalizes across shapes — is COMPLETE.** It is still shadow-only (not authoritative —
that's **D19**) and proven on five shapes / one target.

## Test suite

| Suite | Command (from repo root) | Result |
|---|---|---|
| Backend | `python -m pytest backend/tests -q` | **285 passed** |
| Ground-truth target | `python -m pytest vulnerable_target -q` | **31 passed** |

## The main line (three nodes)

The product's spine is three sequential nodes (see [`ROADMAP.md`](./ROADMAP.md) §4).
Node 1 ("judge correctly") is now organized as milestone **M1** — prove the verification
mechanism generalizes across vuln shapes with **zero false positives**. Where each stands:

| Node | Goal | State |
|---|---|---|
| **1. Judge correctly (= M1)** | Never a false verdict; confirm the hard case across *shapes* | **✅ COMPLETE — 5 shapes confirmed, 0 FP.** See the M1 breakdown below. |
| **2. Act** (`D19`) | Promote the AI verdict from observe-only/log to **authoritative** | **Not started.** The persisted verdict is still the rule oracle's; the AI verdict is shadow-only. Gated on M1 proving generalization. |
| **3. Be safe on real targets** | Consolidate scope-lock checks + adversarial tests before any non-localhost use | **Not started.** HARD prerequisite before any real / non-lab target. |

### M1 — Verifiable benchmark & reference engine (generalize across shapes, zero FP)

| Milestone | Shape / how confirmed | State |
|---|---|---|
| **M1.0 (B-1)** | silent cross-path **write**, confirmed via a **write-record** | **DONE, committed `37769b3`.** X-CROSS→`verified` 5/5, X-SAFE→safe 5/5; regression test locks it. |
| **M1.1** | read-type **semantic-equivalence**, equal-length, confirmed by **semantics + evidence anchoring** | **DONE, committed `002b33c`.** X-EQUIV-VULN→`verified` 5/5, X-EQUIV-SAFE→`failed` 5/5 — **0 FP**, N=5, one target. |
| **M1.2** | silent cross-path **write** confirmed via a code-gathered object-**STATE** read-back (not a write-record) | **DONE, committed `e4d5317`.** Three parts: **(A)** a SECOND guard exemption channel (`STATE_READBACK_EXEMPTION_REASON`, **disjoint from B-1**, `verified`-only) gated on three structural anchors AND-ed — owner==attacked ∧ caller!=owner (`caller_identity=confirmed`) **and payload-causality** (THIS attack's UNIQUE value present; causality is the false-positive gate). **(B)** a **deterministic object-state gather** (`select_object_state_endpoint`, target-agnostic resource-noun + object-scoping; mirrors B-1's HALF-1) — the model never found that path on its own (**0/5**), code now gathers it **5/5**. **(C)** a **prompt carve-out** (rule 5 / turn-2 / options-block) so a *system-gathered* read of the attacked object's own state counts as decisive — lifted VULN **3/5 → 5/5**. **Live-measured** (shadow, N=5, gemini-2.5-pro): X-SILENT-VULN→`verified` **5/5** (all 3 anchors confirmed, causality `confirmed_at_path` 5/5); **X-SILENT-SAFE→`verified` 0/5** (causality `absent` 5/5 → no exemption → `inconclusive`); B-1 X-CROSS still `verified` 5/5 — `scripts/audit/shadow_m12c_prompt_carveout_run.out.txt`. Offline both ways: `test_m12_state_readback_exemption.py`, `test_m12b_state_gather.py` (incl. a foreign-spec genericity proof). **⚠️ NARROWED by M1.4:** this channel yields whenever a pre-flight baseline exists (the state-jump gate governs), because payload-causality alone would have false-positived a securely-stripped mass-assignment case. Verdicts unchanged; strictly fewer exemptions. |
| **M1.3** | **delete-type**, confirmed by a **NEGATIVE ASSERTION** (from-EXISTS-to-ABSENT), dual-track physical *or* logical | **DONE (this commit).** Two new mechanisms: a **PRE-FLIGHT read** (code GETs the victim object, scope-locked, BEFORE the DELETE — the **coincidence gate**: "it vanished" only proves a delete if "it existed & was active just before" is anchored) and a **dual-track negative-assertion anchor** (`_anchor_negative_assertion`) accepting **physical** removal (404/403/410) **or** **logical/soft** deletion (200 with a lifecycle field flipped, by generic vocabulary — **404 is NOT hardcoded**). A **third, disjoint** exemption channel (`DELETE_READBACK_EXEMPTION_REASON`) gated on pre-flight caller-identity **AND** the negative assertion. **Live-measured** (N=5, gemini-2.5-pro, fresh-seeded per run): X-DELETE-VULN-HARD→`verified` **5/5** (`confirmed_physical`), X-DELETE-VULN-SOFT→`verified` **5/5** (`confirmed_logical`), **X-DELETE-SAFE→`verified` 0/5** (`still_present`), **X-DELETE-CONTROL (object never existed)→`verified` 0/5** (`preflight_absent` — the coincidence gate held even though the AFTER read was also 404) — `scripts/audit/shadow_m13_delete_run.out.txt`. Offline: `test_m13_delete.py` (incl. foreign-spec genericity). |
| **M1.4** | **mass-assignment** — the attacker sneaks a privileged field (role/flag) into a write on the VICTIM's object; confirmed by a **LOW-ENTROPY STATE JUMP** | **DONE (this commit).** Payload-causality breaks here: the injected value is low-entropy, so "the field reads admin" cannot tell "I set it" from "it was already admin". Causality is instead proven by a **STATE JUMP** — every field the attack sent moved from a **KNOWN pre-flight state** to the injected value. **MISSING** (absent from a SUCCESSFUL 2xx pre-flight — privileged fields are commonly hidden) is a VALID original state, so `missing→injected` verifies (hidden-field escalation); `missing→missing` does not. A **request failure / non-2xx / unparseable** read is **UNKNOWN**, never MISSING → never `verified`, never a crash. New disjoint channel `STATE_JUMP_EXEMPTION_REASON`, gated on caller-identity AND the jump. **Live (N=5):** X-MASS-VULN present-value→`verified` 5/5 and MISSING→injected→`verified` 5/5; **X-MASS-SAFE present + missing→`verified` 0/5**; control (injected==pre-flight)→0/5. On SAFE the model raw-said `verified` and the gate refused every time. |
| **M1.x (optional)** | further shapes (nested-object, multi-step) | Not started. M1's goal — *prove the mechanism generalizes* — is met at five shapes; more shapes are breadth, not a gate. |

> **M2 — Shared Domain Model (later, NOT started):** a resource/endpoint relationship graph —
> sink upstream observations (proxy/HAR/spec) into a shared layer every module can query, so the
> verifier isn't guessing which paths relate (precedent: RESTler-style request-dependency graph
> from OpenAPI). **Gated on** M1 proving generalization + an evidence-backed list of "what
> downstream actually needs from upstream." **Minimal slice already built (M1.2(B)):** "find the
> attacked object's own state endpoint" (`select_object_state_endpoint`) is the smallest slice of
> this graph and is DONE. The full dependency graph stays M2 — do NOT build it now.
>
> **Strategic radar (decide later, do NOT act now):** black-box (deployable, but a fundamental
> ceiling on truly-silent writes whose effect surfaces through *no* endpoint) vs. an optional
> gray-box mode (log/instrumentation ingestion, à la BACFuzz) for higher-assurance confirmation.

## What is proven (committed, in tests / measured)

- **Rule oracle** (`fuzzer._differential_verdict`, 3-value `verified`/`suspicious`/`failed`)
  — unchanged, offline-tested (`test_verdict_oracle.py`).
- **Deep verifier integrity floor** — the 4th verdict `inconclusive`, the prompt
  decisive-evidence / same-resource standard, and the deterministic
  `_apply_cross_resource_guard` (B-2.2). Offline-tested (`test_d18_b22_guard.py`).
- **B-1 — confident cross-path verdict** (`37769b3`): catalog semantics
  (`tags`/`operationId`) + deterministic code-side write-record gathering (HALF 1) +
  a structural content-match guard exemption (HALF 2). **Live-measured** (shadow, N=5,
  gemini-2.5-pro): X-CROSS→`verified` 5/5, X-SAFE→`inconclusive`/safe 5/5 (**no false
  positive**), reverse-guards intact (P0-PROFILE `verified`×5 / P0-AVATAR `failed`×5) —
  `scripts/audit/shadow_b1step3_code_gather_measure.out.txt`. **Locked by** an
  automated mock-Gemini regression test that runs the real `execute_deep_verification`
  end-to-end (`test_d18_b1_shadow_integration.py`, closes D22) plus offline unit tests
  (`test_d18_b1_write_record.py`).
- **M1.1 — read-type semantic-equivalence** (this commit): two read paths expose the SAME
  object; responses shaped **equal-length** so the rule oracle stalls at `suspicious` and the
  **AI must judge by semantic content, not size**. Adds structured evidence — the verdict
  carries `evidence_path` + a code-computed `anchoring_result` (AI makes the semantic call,
  code anchors it; **corroboration, observe-only, not an oracle**). **Live-measured** (shadow,
  N=5): X-EQUIV-VULN→`verified` 5/5 (`owner_id` anchoring `confirmed`), X-EQUIV-SAFE→`failed`
  5/5 (**0 false positives**) — `scripts/audit/shadow_m1_xequiv_run.out.txt`. Offline test:
  `test_m1_evidence_anchoring.py`.
- **M1.2 anchoring** (`2cac345`): evidence anchoring extended (observe-only) to bind
  **caller-identity** (`_anchor_caller_identity` — the read-back object is the victim's, not the
  caller's) and **payload-causality** (`_anchor_payload_causality` — THIS attack's unique value
  actually landed). Tests pin that caller-identity `confirms` for **both** a real leak and a
  securely-dropped write, so only **payload-causality** separates them (the D19 gating constraint).
- **M1.2 HALF-1 object-scope** (this commit): B-1's HALF-1 used to force-gather the single
  **global** write-record for ANY silent write, even one it doesn't record — hijacking the
  follow-up. HALF-1 now **probes the candidate once and gathers only if the record holds the
  caller's own (baseline, definitely-landed) write** (`_record_is_relevant_to_write`, reusing the
  B-1 content-match unchanged with the caller's id); otherwise it **steps back** and the model
  reads the object's own state. B-1 preserved (X-CROSS/X-SAFE audit carries the caller row);
  offline-tested both ways (`test_m12_object_scope.py`). No guard / content-match / verdict change.
- **M1.2 — silent write confirmed via a code-gathered object-STATE read-back** (`e4d5317`).
  Three parts, all target-agnostic:
  - **(A) state-readback exemption** (`STATE_READBACK_EXEMPTION_REASON`) — a SECOND guard-exemption
    channel, **DISJOINT** from B-1's write-record exemption (never fires on a write-record path),
    `verified`-only, cross-path-only. It exempts a cross-path STATE read-back from the B-2.2
    downgrade **only** when code AND-confirms all three anchors: **(1)** owner==attacked ∧
    **(2)** caller!=owner (`_anchor_caller_identity == "confirmed"`) **and (3)** payload-causality
    (`_anchor_payload_causality` confirmed — THIS attack's UNIQUE value present). **(3) is the
    non-negotiable false-positive gate:** (1)+(2) hold for BOTH a real leak and a securely-dropped
    write; only the unique value landing separates them.
  - **(B) deterministic object-state gather** (`endpoint_catalog.select_object_state_endpoint`) —
    resolves the attacked object's own state endpoint GENERICALLY (resource-noun + object-scoped
    `{template}` bound to the attacked id; record/log endpoints excluded so the two channels stay
    disjoint; returns `None` rather than fabricating). Mirrors B-1's HALF-1. **The resolver is only a
    FETCHER — the three-AND gate remains the VERIFIER**, so a wrong gather degrades to `inconclusive`,
    never to a false positive. Gather went **0/5 → 5/5**.
  - **(C) prompt carve-out** — `SYSTEM_PROMPT` rule 5 (plus `_TURN2_TEMPLATE` and the options-block
    verdict definitions) now names three decisive cases: same-path, an explicit write-record, **or a
    read of the attacked object's own state that the SYSTEM ITSELF gathered**. Restricted to
    system-gathered reads; a model-chosen different path is still non-decisive. This resolved a real
    prompt/code contradiction (the model was obeying rule 5 and answering `inconclusive` while holding
    decisive evidence) and lifted VULN **3/5 → 5/5**.
  - **Live-measured** (shadow, N=5, gemini-2.5-pro, `scripts/audit/shadow_m12c_prompt_carveout_run.out.txt`):
    X-SILENT-VULN→`verified` **5/5** (causality `confirmed_at_path` 5/5, exemption 5/5);
    **X-SILENT-SAFE→`verified` 0/5** (causality `absent` 5/5 → no exemption → `inconclusive`);
    B-1 X-CROSS→`verified` 5/5 and B-1 X-SAFE→0 `verified` (**not regressed**). Offline both ways:
    `test_m12_state_readback_exemption.py` + `test_m12b_state_gather.py` (foreign-spec genericity proof,
    B-1 precedence, no-fabrication, and a model-chosen cross-path read that stays `inconclusive`).
  - New target ground truth X-SILENT-VULN (`POST /api/users/{id}/gizmo`) / X-SILENT-SAFE (`.../sprocket`),
    byte-verified in `vulnerable_target/test_vulns.py`.
  - **Design principle (reinforced):** confirmation must NOT rely on the model *realizing* it should
    fetch other evidence — code deterministically gathers the evidence, the model only does the
    irreplaceable semantic read (prompt-nudging to self-discover was tried at B-1, 0/20 — not the path).
  - **OPTIONAL hardening (recorded, NOT done):** the prompt restricts case (c) by **provenance**
    (system-gathered) while the code gate keys on **evidence** (the three anchors, not provenance).
    Aligning them = adding `followup_is_code_gathered` to `_state_readback_decisive` — one line, and it
    could only ever make the gate **stricter**. Not required for correctness (a unique fuzzer value can
    only appear in the victim's object if this attack put it there, whoever chose the path).
- **M1.3 — delete-type confirmed by a NEGATIVE ASSERTION** (this commit). The proof is a
  from-EXISTS-to-ABSENT jump, not a value appearing, so payload-causality does not apply:
  - **PRE-FLIGHT read (the coincidence gate).** For a DELETE attack the CODE reads the victim
    object's own state BEFORE issuing the delete (scope-locked, reusing the M1.2(B) resolver) and
    caches it. "It vanished" only proves a delete if "it existed and was active just before" is
    anchored. **No pre-flight existence proof -> NEVER `verified`.** A pre-flight failure is not
    fatal: it just leaves existence unproven, so the verdict stays `inconclusive`.
  - **DUAL-TRACK negative assertion** (`_anchor_negative_assertion`): decisive on **physical**
    removal (404/403/410) **or** **logical/soft** deletion (200 with a lifecycle field flipped to a
    deleted value — detected by a generic vocabulary via `_deletion_signal`: string statuses,
    boolean flags `is_deleted`/`is_active`, timestamp markers `deleted_at`). **404 is deliberately
    NOT hardcoded as the only proof of vanishing** — real APIs mostly soft-delete.
  - **A THIRD, DISJOINT exemption channel** (`DELETE_READBACK_EXEMPTION_REASON`), `verified`-only,
    cross-path-only, gated on caller-identity computed on the **PRE-FLIGHT body** (the AFTER read of
    a physical delete is a 404 with no owner to anchor on) **AND** the negative assertion. Disjoint
    by construction: a DELETE carries no written value, so the M1.2 state channel (payload-causality)
    and B-1's write-record channel can never fire for it.
  - **Also fixed:** a DELETE no longer triggers B-1's write-record gather. With no written values the
    M1.2 object-scope probe was skipped and `_object_scoped` defaulted to the B-1-safe `True`, so
    HALF-1 wrongly grabbed the audit-log and preempted the object-state gather. Provably safe:
    B-1's exemption *requires* written values, so that channel was unreachable for a delete anyway.
  - **Live-measured** (N=5 each, gemini-2.5-pro, fresh-seeded per run,
    `scripts/audit/shadow_m13_delete_run.out.txt`): X-DELETE-VULN-HARD→`verified` **5/5**
    (`confirmed_physical`, pre-flight 200); X-DELETE-VULN-SOFT→`verified` **5/5**
    (`confirmed_logical`); **X-DELETE-SAFE→`verified` 0/5** (`still_present`);
    **X-DELETE-CONTROL→`verified` 0/5** (`preflight_absent`: the AFTER read was *also* 404, but
    nothing was proven to exist — the coincidence gate held). **No regression**: B-1 X-CROSS
    `verified` 5/5, X-SILENT-VULN `verified` 5/5, X-SILENT-SAFE 0 `verified`. All three exemption
    channels stayed disjoint (each case fired exactly its own).
  - **Auditability (observe-only):** the result also surfaces `preflight_caller_identity_anchor` —
    the caller-identity value the delete gate ACTUALLY used (pre-flight body), because the
    general-purpose `caller_identity_anchor` is computed on the AFTER read and reads
    `owner_not_found` on a 404, which would misrepresent the evidence chain in a transcript.
  - New target ground truth: X-DELETE-VULN-HARD (`DELETE /api/users/{id}/relic`),
    X-DELETE-VULN-SOFT (`.../badge`), X-DELETE-SAFE (`.../seal`), byte-verified in
    `vulnerable_target/test_vulns.py`. Offline: `test_m13_delete.py` (incl. foreign-spec genericity).
- **Same-path cases resolve correctly** — AI **8/8**, 0 false-pos / 0 false-neg. See
  `vulnerable_target/benchmark/RESULTS.md`.

## Honest limits (do not over-read the green)

- **Five vuln shapes, one target, N=5 each.** X-CROSS (write→write-record), X-EQUIV (read-type
  semantic equivalence), X-SILENT (write→object-state), X-DELETE (delete→negative assertion), X-MASS (mass-assignment→
  low-entropy state jump). nested-object, multi-step, and noisier real audit logs are untested.
  "Mechanism proven on these classes," not "verifier finished."
- **Post-fix live no-regression: CONFIRMED across all five shapes** (`scripts/audit/shadow_m14_regress_run.out.txt`,
  N=5 each, 30/30 runs clean, zero degraded). With the M1.4 routing fix in place: B-1 X-CROSS
  `verified` **5/5** (still `write_record_readback_decisive`), X-SILENT-VULN `verified` **5/5**,
  X-DELETE-VULN-HARD/SOFT `verified` **5/5** each (`confirmed_physical` / `confirmed_logical`), and
  **every SAFE case 0 `verified`** (X-SILENT-SAFE `no_jump`, X-DELETE-SAFE `still_present`).
  X-SILENT-VULN now exempts via `state_jump_causally_decisive` rather than
  `state_readback_causally_decisive` — **that is the routing fix working as designed** (a pre-flight
  baseline exists, so the stricter gate governs); the verdict is unchanged.
- **Black-box boundary (mapped, M1.2):** a silent write with **no same-path GET and no relevant
  write-record** is **NOT confirmable by the model's unaided follow-up** — the model does not, on its
  own, fetch a *different* resource path that exposes the attacked object's state (measured 0/5; it
  tried the same-path GET → 405, or an empty log). M1.2(B) closes this by having **code** steer it to
  the object's state path. What remains a fundamental black-box limit is a truly-silent write whose
  effect surfaces through *no* endpoint at all.
- **Payload-causality assumes a HIGH-ENTROPY written value.** The anti-false-positive gate works by
  finding THIS attack's unique injected value in the read-back. On **low-entropy** fields (booleans,
  small integers, enums) — or under concurrent runs writing the same value — the value can collide and
  the gate could confirm causality it did not cause. Real boundary; see ROADMAP "Future / deferred".
- **The final verdict still leans on the model reading the log.** Code *gathers* the
  evidence (deterministic); Gemini still *interprets* it (raw `verified` 5/5 here). A
  model-specific pillar — re-run the benchmark on any model swap.
- **Gate hardened (D23 + D23b ✅ both fixed):** `_write_record_content_match` used to match
  against *any* scalar of a record — including the record's own primary key — on **both** axes,
  so a dirty/accumulated log could false-match and fire the exemption on a SECURE control.
  Now: the **id** check binds to an **owner/subject-style key** (D23) and the **value** check
  binds to **non-primary-key content fields** (D23b) — both by generic, camelCase-aware
  vocabulary; bare `id`/`pk` excluded from both. Each is a strict subset of the old scalar set,
  so the gate only got **stricter**; both are proven by offline tests that fail against the
  pre-fix code. One narrow sibling accepted on purpose (see TECH_DEBT D23b).
- **Shadow-only.** Still observe-only, default-off; the persisted verdict is the rule
  oracle's. Making the AI verdict authoritative is D19 (not started).

## Uncommitted right now (working tree)

- **Proxy Radar tab (frontend)** — `preview_dashboard.html` gains the Step-9 proxy UI
  (start/stop, live SSE stream, flows list, "send to Hunter"). Backend `/proxy/*` routes
  already existed and are tested; this is the UI wiring. **Left uncommitted on purpose** —
  it belongs to the later frontend phase, not the verification milestones.
- `scripts/audit/` measurement drivers + `*.out.txt` transcripts — kept untracked
  (throwaway harnesses / evidence), not committed.

> Everything else (docs restructure, B-1/M1.0, D22, D23, D23b, M1.1, and M1.2 A/B/C) is committed.

## Runtime posture (defaults)

- **AI deep verifier is OFF by default.** Two gates, both default `False`:
  `AI_DEEP_VERIFY_ENABLED` and `AI_DEEP_VERIFY_SHADOW`. Both must be `True` for a live
  Gemini call. With defaults, Phase 7 is a no-op and the engine behaves as the committed
  rule-oracle path.
- **The real spec source is not auto-wired.** The shadow pass reads its OpenAPI spec from
  `settings.AI_DEEP_VERIFY_OPENAPI_SPEC`, which is **not a declared config field** (read
  via `getattr`; TECH_DEBT **D21**). With nothing set, the catalog stays the placeholder.
- **No authentication** on any API route (TECH_DEBT **D2**) — keep bound to localhost.

## Deferred on purpose (do not invest until the moat is broadened)

Authentication (D2), multi-tenancy, Alembic migrations (D1), Postgres, hosted
deployment, the nuclei keep-vs-cut decision — parked until a benchmark justifies them.

## Immediate next steps

> M1.2 and M1.3 are **done** (live-measured, 0 FP). The design principle they proved —
> **code deterministically gathers the evidence; the model only does the irreplaceable semantic
> read** — is a standing discipline in [`ROADMAP.md`](./ROADMAP.md) §6. The full deferred/rejected
> register lives in ROADMAP "Future / deferred" and "Considered and rejected".

1. **M1.4 — mass-assignment (the next shape).** ⚠️ **Known hazard, decide it up front:** this shape
   writes *existing, low-entropy* fields (an owner/role id, a boolean flag), which **breaks
   payload-causality's unique-value assumption** — the injected value can collide with a value that
   was already there, so "the value is present" would no longer prove *this* attack caused it. Like
   the delete shape, it likely needs its own decisive-evidence anchor (e.g. a pre-flight
   before/after diff of the specific field) rather than reusing causality as-is. See ROADMAP §7.
2. **D21** — promote the spec source to a declared config field (currently the `getattr`
   seam), so the real catalog can be wired for normal use, not just harnesses.
4. **D19** — only after generalization is proven: promote the AI verdict from observe-only to
   authoritative in the real flow, with a gating policy.
   - **Gating constraint (from M1.2 anchoring):** the authoritative gate must be
     **payload-causality**, not caller-identity — caller-identity `confirms` for BOTH VULN and
     SAFE (a dropped cross-user write still leaves the object owned by the victim), so only the
     unique-value-landed causality anchor separates a real leak from a securely-dropped write.
5. **Scope-lock hardening** (HARD prerequisite before any real / non-lab target);
   **benchmark vs agent-style PoC tools** on a public target; retire the legacy `frontend/` (D5).
