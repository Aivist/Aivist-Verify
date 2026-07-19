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
confirms the hard case on **two distinct vuln shapes with zero false positives** —
**M1.0/B-1** (silent cross-path *write*, confirmed via a write-record) and **M1.1**
(read-type *semantic-equivalence*, equal-length, confirmed by semantics + evidence
anchoring). It is still shadow-only (not authoritative — that's **D19**) and proven on
two shapes / one target.

## Test suite

| Suite | Command (from repo root) | Result |
|---|---|---|
| Backend | `python -m pytest backend/tests -q` | **208 passed** |
| Ground-truth target | `python -m pytest vulnerable_target -q` | **19 passed** |

## The main line (three nodes)

The product's spine is three sequential nodes (see [`ROADMAP.md`](./ROADMAP.md) §4).
Node 1 ("judge correctly") is now organized as milestone **M1** — prove the verification
mechanism generalizes across vuln shapes with **zero false positives**. Where each stands:

| Node | Goal | State |
|---|---|---|
| **1. Judge correctly (= M1)** | Never a false verdict; confirm the hard case across *shapes* | **In progress — 2 shapes done.** See the M1 breakdown below. |
| **2. Act** (`D19`) | Promote the AI verdict from observe-only/log to **authoritative** | **Not started.** The persisted verdict is still the rule oracle's; the AI verdict is shadow-only. Gated on M1 proving generalization. |
| **3. Be safe on real targets** | Consolidate scope-lock checks + adversarial tests before any non-localhost use | **Not started.** HARD prerequisite before any real / non-lab target. |

### M1 — Verifiable benchmark & reference engine (generalize across shapes, zero FP)

| Milestone | Shape / how confirmed | State |
|---|---|---|
| **M1.0 (B-1)** | silent cross-path **write**, confirmed via a **write-record** | **DONE, committed `37769b3`.** X-CROSS→`verified` 5/5, X-SAFE→safe 5/5; regression test locks it. |
| **M1.1** | read-type **semantic-equivalence**, equal-length, confirmed by **semantics + evidence anchoring** | **DONE, committed `002b33c`.** X-EQUIV-VULN→`verified` 5/5, X-EQUIV-SAFE→`failed` 5/5 — **0 FP**, N=5, one target. |
| **M1.2 — mechanism BUILT + proven SAFE offline, NOT yet confirmed live** | cross-path **silent write** confirmed via **read-back STATE** (not a write-record) | **Prerequisites DONE:** caller-identity + payload-causality anchoring (`2cac345`); object-scoped HALF-1 (`3e949cb`). **M1.2(A) — state-readback exemption BUILT (this commit):** a SECOND, separate guard channel (`STATE_READBACK_EXEMPTION_REASON`, **disjoint from B-1**, `verified`-only) that lets a correct cross-path STATE read stand as `verified` **iff** code AND-confirms all three anchors — owner==attacked ∧ caller!=owner (`caller_identity=confirmed`) **and** payload-causality (THIS attack's UNIQUE value present). **Proven SAFE offline both ways, 0 FP** (`test_m12_state_readback_exemption.py`): VULN-shape→exempt→`verified`; **SAFE-shape (payload absent)→NOT exempt→stays `inconclusive` even when the model raw-says `verified`.** **NOT exercised live:** gemini-2.5-pro never reaches the cross-path object-state read on its own — `GET /api/gizmos/2` chosen **0/5**; it tried the same-path GET (→405) or the empty audit-log (`shadow_m12a_state_readback_run.out.txt`). **Same wall as B-1** (model chose the decisive endpoint 0/20). Live: X-SILENT-VULN/SAFE both `inconclusive` 5/5 (**integrity floor held, 0 FP**). **So the exemption is safe & ready but currently has no inputs. Next = M1.2(B):** deterministically code-gather the object's own state read-back (target-agnostic, mirroring B-1's HALF-1) to feed it. |
| **M1.x (later)** | mass-assignment, delete-type, and further shapes | Not started — each is one more格 of generalization. |

> **M2 — Shared Domain Model (later, NOT started):** a resource/endpoint relationship graph —
> sink upstream observations (proxy/HAR/spec) into a shared layer every module can query, so the
> verifier isn't guessing which paths relate (precedent: RESTler-style request-dependency graph
> from OpenAPI). **Gated on** M1 proving generalization + an evidence-backed list of "what
> downstream actually needs from upstream." **Minimal slice pulled forward:** M1.2(B)'s "find the
> attacked object's own state endpoint" is exactly the smallest slice of this graph — build only
> that slice now; the full dependency graph stays M2.
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
- **M1.2(A) state-readback exemption — BUILT + proven SAFE offline, NOT exercised live** (this
  commit): a SECOND, separate guard-exemption channel (`STATE_READBACK_EXEMPTION_REASON`) —
  **DISJOINT** from B-1's write-record exemption (never fires on a write-record path), `verified`-only,
  cross-path-only. It exempts a cross-path STATE read-back from the B-2.2 downgrade **only** when code
  AND-confirms all three anchors: **(1)** owner==attacked ∧ **(2)** caller!=owner
  (`_anchor_caller_identity == "confirmed"`) **and (3)** payload-causality (`_anchor_payload_causality`
  confirmed — THIS attack's UNIQUE value present). **(3) is the non-negotiable false-positive gate:**
  (1)+(2) hold for BOTH a real leak and a securely-dropped write; only the unique value landing separates
  them. **Offline both ways, 0 FP** (`test_m12_state_readback_exemption.py`): VULN-shape→exempt→`verified`;
  SAFE-shape (payload absent)→NOT exempt→stays `inconclusive` even when the model raw-says `verified`.
  **Live (shadow, N=5, gemini-2.5-pro, `shadow_m12a_state_readback_run.out.txt`): the exemption fired 0/5 —
  the model never reached the cross-path object-state read** (`GET /api/gizmos/2` chosen 0/5; it tried the
  same-path GET → 405, or the empty audit-log). X-SILENT-VULN→`inconclusive` 5/5, X-SILENT-SAFE→`inconclusive`
  5/5 (**0 false positives** — integrity floor held). New target ground truth X-SILENT-VULN
  (`POST /api/users/{id}/gizmo`) / X-SILENT-SAFE (`.../sprocket`), byte-verified in
  `vulnerable_target/test_vulns.py`. **The mechanism is safe & ready but has no inputs until M1.2(B).**
  **Design principle (reinforced):** confirmation must NOT rely on the model *realizing* it should fetch
  other evidence — code deterministically gathers the evidence, the model only does the irreplaceable
  semantic read (prompt-nudging the model to self-discover was tried at B-1, 0/20 — not the path).
- **Same-path cases resolve correctly** — AI **8/8**, 0 false-pos / 0 false-neg. See
  `vulnerable_target/benchmark/RESULTS.md`.

## Honest limits (do not over-read the B-1 green)

- **One vuln shape, one target, N=5.** Only "cross-path write-then-read BOLA" (X-CROSS).
  nested-object, delete-type, multi-step, and noisier real audit logs are untested.
  "Mechanism proven on this class," not "verifier finished."
- **Black-box boundary (mapped, M1.2(A)):** a silent write with **no same-path GET and no relevant
  write-record** is **NOT confirmable by the model's unaided follow-up** — the model does not, on its
  own, fetch a *different* resource path that exposes the attacked object's state (it tries the
  same-path GET → 405, or an empty log). Confirmation of this shape requires **code** to steer it to
  the object's state path (M1.2(B)). This maps one edge of the black-box confirmation ceiling; a
  truly-silent write whose effect surfaces through *no* endpoint stays a fundamental black-box limit.
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

> Everything else (docs restructure, B-1/M1.0, D22, D23, D23b, and M1.1) is committed.

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

1. **M1.2(B) — code-gather the object's own state read-back (the next real step).** The
   state-readback exemption is built + proven safe offline (both ways, 0 FP) but **fired 0/5 live**
   because gemini-2.5-pro never reaches the cross-path object-state read on its own (same wall as
   B-1: the model chose the decisive endpoint 0/20). So **deterministically code-gather** the
   attacked object's own state read-back — target-agnostic, mirroring B-1's HALF-1 write-record
   gather — and feed it to the (already-proven) exemption; then re-measure live.
   - **Design principle (do NOT relitigate):** confirmation must NOT rely on the model *realizing*
     it should fetch other evidence — CODE deterministically gathers the evidence; the model only
     does the irreplaceable SEMANTIC read. Prompt-nudging the model to self-discover the read-back
     was tried at B-1 (0/20) and is not the path.
   - **M2 connection (do the minimal slice only):** M1.2(B)'s "find the object's own state endpoint"
     is the MINIMAL SLICE of the future API-dependency graph (M2 / RESTler-style). Build only that
     slice now; the full dependency graph stays **M2** (gated on M1 proving generalization).
2. **D21** — promote the spec source to a declared config field (currently the `getattr`
   seam), so the real catalog can be wired for normal use, not just harnesses.
3. **M1.x** — mass-assignment, delete-type, further shapes as generalization continues.
4. **D19** — only after generalization is proven: promote the AI verdict from observe-only to
   authoritative in the real flow, with a gating policy.
   - **Gating constraint (from M1.2 anchoring):** the authoritative gate must be
     **payload-causality**, not caller-identity — caller-identity `confirms` for BOTH VULN and
     SAFE (a dropped cross-user write still leaves the object owned by the victim), so only the
     unique-value-landed causality anchor separates a real leak from a securely-dropped write.
5. **Scope-lock hardening** (HARD prerequisite before any real / non-lab target);
   **benchmark vs agent-style PoC tools** on a public target; retire the legacy `frontend/` (D5).
