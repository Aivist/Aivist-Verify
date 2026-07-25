# D19 HANDOFF — promote the AI verdict from shadow to authoritative

> For the next agent. D19 is **planned and approved** (Option A below); it is **not yet
> implemented**. Implement from this approved plan, not from scratch. D19 is the
> highest-risk change on the roadmap — the first time the deep verifier can affect a
> user-visible verdict. Treat every red line here as hard, not guidance.
>
> **Golden rule of this project, measured not claimed:** *the line is held by code, not by
> model compliance.* D19 must preserve that as a structural property.

---

## 0. HEAD state (as of this handoff)

- **HEAD `4fcd629`**, branch `master`. Engine is **UNFROZEN for D19 only**, by director sign-off.
- Test suites green: **backend 325**, `vulnerable_target` **31**, `depot_target` **23**.
- **All five vuln shapes are code-gated on two structurally-different targets.** D24 (the
  read-semantic owner-view gate) is RESOLVED (`033fc9e`). The two-account ownership baseline
  credential channel exists (`5a33cb2`).
- **The GOLDEN record is the acceptance bar:** `scripts/measure/results/sweep_highN.jsonl` —
  five shapes × two targets × real gemini-2.5-pro, N=20 SAFE/control, N=10 VULN, **430/430
  usable, 0 degraded**: **300 SAFE/control → 0 `verified` (0 FP); 130 VULN → all `verified`**
  via their expected channel. Reproduce with `scripts/measure/verdict_measure.py`
  (see `scripts/measure/REPRODUCE.md`).
- The AI verdict is still **shadow-only**: Phase 7 observes and logs, never writes. D19 changes
  exactly that, conservatively.
- Relevant recent lineage: D21 `d3d6863` (declared spec field); D24 arc `f5beaee`→`52b5298`;
  measurement harness `aef68a0`→`4fcd629`.

---

## 1. THE GOVERNING INVARIANT — conservative-only, structural (hard red line)

The authoritative verdict may only become **more conservative or equal**, never more
aggressive, relative to today's rule-oracle verdict.

- A promoted `verified` may be produced **ONLY** when a **deterministic code channel** authorizes
  it: one of the four exemption channels firing decisively, **or** the D24 owner-view
  read-semantic gate corroborating. **The model's raw opinion ALONE may NEVER produce `verified`.**
  If no code channel authorizes, a model `verified` becomes `inconclusive` — exactly as shadow does today.
- D19 operates **ONLY on the rule oracle's `suspicious` band.** The rule oracle's own `verified`
  and `failed` are **not** overridden by the deep verifier.
- This must be a **structural impossibility**, asserted in code AND test: there is no code path
  that assigns a promoted `verified` without a non-None deterministic authorizer.
- **Default OFF.** D19 adds the *capability* to promote; it does not switch it on. Shadow remains
  the shipped default. The full evidence chain is logged whether promotion is on or off.
- **Fail-safe:** if the deep verifier errors, times out, or is disabled, the persisted verdict
  falls back to the rule oracle's, exactly as today. An AI-layer failure may never upgrade a
  verdict and may never crash the batch.

The four deterministic authorizers (each already sets `result.guard_override` positively on the
authorize path — `deep_verifier.py`):
`write_record_readback_decisive`, `state_readback_causally_decisive`,
`delete_readback_negative_assertion_decisive`, `state_jump_causally_decisive`.
Plus the D24 owner-view gate corroboration (see §3 for why it needs a new observability field).

---

## 2. APPROVED PLAN — Option A (implement this)

### 2.1 Where the verdict is set today
- Rule verdict computed by `_differential_verdict`, packaged as `item["verification_status"]`
  (`fuzzer.py` ~L1568), written by `_persist_record` (`fuzzer.py` ~L1681) via the single-writer
  `WriterService`.
- **Phase 7 runs AFTER the batch is fully persisted and the batch writer has drained**
  (`fuzzer.py` ~L1108–1124). `_run_shadow_deep_verification` (`fuzzer.py` ~L1272) then reads
  `suspicious` rows in a **read-only** session and only logs ("NOT applied").

### 2.2 The change (all additive; entirely in the consumer + config + tests)
1. **`backend/app/core/config.py`** — add `AI_DEEP_VERIFY_PROMOTE: bool = Field(default=False, …)`,
   same convention as the other `AI_DEEP_VERIFY_*` flags.
2. **`backend/app/services/deep_verifier.py`** — add ONE observability field to
   `DeepVerificationResult`: `owner_view_corroborated: Optional[bool] = None`, and set it at the
   **existing** D24 gate pass/block points only (`True` on corroborate, `False` on block, left
   `None` when the gate did not run). See §3 — this is **not** a red-line violation: it records the
   gate's already-made decision; it changes no verdict, no channel, no `guard_override`. Touch
   nothing else in the gate or any channel/anchor.
3. **`backend/app/services/fuzzer.py`** — in `_run_shadow_deep_verification`:
   - Add a pure module-level choke-point helper
     `_code_authorized_channel(result) -> Optional[str]` returning the authorizing channel iff
     `result.ai_verdict == "verified"` AND (`guard_override ∈ the four channel reasons` OR
     `result.owner_view_corroborated is True`); else `None`.
   - When `settings.AI_DEEP_VERIFY_PROMOTE` is True and the helper returns non-None, open a
     **write** session (sole writer — batch writer already drained) and update that record
     `suspicious → verified`, persisting the evidence chain into the existing `diff_details` JSON
     column (nullable, no schema change): authorizing channel, `ai_verdict_raw`, `guard_override`,
     the anchor results, and `owner_view_corroborated` where relevant. Preserve the rule-oracle
     diff already in `diff_details` (nest under a new key, e.g. `ai_promotion`).
   - When the helper returns `None`, do **not** write `verified`; the record keeps the rule
     verdict (`suspicious`) — i.e. promotion is downgrade-only. (Writing an explicit
     `inconclusive` is optional; the safe default is to leave the rule verdict untouched. Decide
     and state it, but never write `verified` without an authorizer.)
   - Wrap all promotion writes so any failure is swallowed and the rule verdict stands (existing
     Phase-7 pattern). Promotion must never crash the batch.
4. **`backend/tests/test_d19_promotion.py`** — new. See §5.

### 2.3 Flag composition
Promotion requires **all three**: `AI_DEEP_VERIFY_ENABLED` (verifier runs) ∧
`AI_DEEP_VERIFY_SHADOW` (fuzzer invokes Phase 7) ∧ `AI_DEEP_VERIFY_PROMOTE` (Phase 7 writes).
`PROMOTE` is a no-op unless `SHADOW` is on. **All three default False ⇒ behavior byte-identical to
today.** For read-semantic promotion, `AI_DEEP_VERIFY_OWNER_AUTH` must also be set (else the D24
gate cannot corroborate → read-semantic will not promote — conservative).

---

## 3. WHY Option A is NOT a red-line violation (director's ruling, recorded)

The forbidden action is **changing the D24 gate's verdict logic.** The D24 gate on its PASS path
today leaves `guard_override = None` and emits no positive marker (`deep_verifier.py` ~L1818),
so a read-semantic `verified` that D24 corroborated is indistinguishable, from result fields alone,
from a model-opinion `verified` (owner cred unset, or a same-path model-verified). Enforcing the
invariant structurally for the read shape therefore needs a positive corroboration signal.

**Ruling:** recording the gate's *already-made* pass/block decision into a pure observability field
(`owner_view_corroborated`) changes no verdict, no channel, no `guard_override` — it is **adding an
observation point, not altering logic.** That is Option A. **Option B (re-derive corroboration in
the promotion layer via a second `fetch_owner_view`) is REJECTED:** a safety-critical authorization
must have a **single source of truth**, never be re-derived in two places that can drift.

Do **not** set `guard_override` on the D24 pass path instead — that would change the golden record's
channel column for `X-EQUIV-VULN`/`DP-READ-VULN` (currently `None`) and break the case-for-case
acceptance. Use the separate `owner_view_corroborated` field; leave `guard_override` untouched.

**Accepted consequence (intended-conservative):** a **same-path model-verified** (guard_override
`None`, not read-semantic — e.g. classic profile-style same-path silent BOLA) is not among the
named authorizers, so promotion holds it to non-`verified`. Safe direction; there are **no same-path
cases in the golden record**, so acceptance is unaffected. Adding a same-path authorizer is **out of
scope** for D19 — do not.

---

## 4. RED LINES (why each exists)

- **Conservative-only, structural** (§1) — the whole point of D19; a model-created false positive
  is now user-visible. Express as structural impossibility + test, or stop and ask.
- **Engine frozen except the one `owner_view_corroborated` field.** The four channels, the
  cross-resource guard, every anchor, and the D24 gate **logic** are not modified. D19 changes what
  *consumes* their output.
- **The custody trap (most important safety catch — do not undo).** `fetch_owner_view` deliberately
  does **not** pass `custody` to `_send_request`. Custody inline-injects the **attacker's** live
  session over the supplied headers; routing the owner read through it would make owner-view ==
  attacker-view, corroboration would always succeed, and the gate would permit everything while
  appearing to work, **with tests green** — a silent-failure class no regression suite would catch.
  **Any refactor that routes owner reads through custody is a breaking change.** Keep the omission
  and its comment permanently.
- **Docs-update sequencing (hard red line — see §7).** Never claim authoritative promotion in docs
  before acceptance passes.
- **Never adjust to force a pass:** never edit the engine, the ground-truth labels, the D24
  threshold, or the golden record to make a run go green. A divergence is a finding.
- **Discipline:** one concern per commit; plan approved before code; **staged list shown before
  each commit**; exclude `preview_dashboard.html` and everything under `scripts/audit/*`
  (gitignored); **no AI co-author trailer**. A test may be repointed only when it asserted a
  scope-limited property (e.g. "nothing consumes X yet"); a test asserting a **safety** property is
  never adjusted to make code pass.

---

## 5. ACCEPTANCE BAR — offline first, then the golden record reproduced exactly

**5.1 Offline (no API) — prove the invariant, report the table before spending on the model:**
mocked-verdict unit tests covering
- model-says-`verified` + **no** channel → **`inconclusive`** (not promoted);
- model-says-`verified` + a channel → **`verified`**;
- read-semantic `owner_view_corroborated True` → **`verified`**; `False`/`None` → **not promoted**;
- rule-oracle `verified` / `failed` → **untouched** (D19 only touches `suspicious`);
- AI error / disabled → **rule-oracle fallback**, no crash;
- structural: the single choke point is the only assigner of a promoted `verified`.

**5.2 Real-model golden reproduction — with `PROMOTE` ON:**
re-run `scripts/measure/verdict_measure.py` (both casesets, `--n-safe 20 --n-vuln 10`) and prove the
FINAL verdicts are **identical, case-for-case**, to `sweep_highN.jsonl`:
- **300 SAFE/control → 0 `verified`.** Any single SAFE reaching `verified` with promotion on = **SEV-1**: stop, report, tune nothing.
- **130 VULN → all `verified`, each via the same channel** as the golden record.
- **The 79 SAFE runs where the model raw-said `verified` stay non-`verified`.** This is the
  load-bearing proof that promotion did not hand the model authority to create false positives.
- Full **backend + vulnerable_target (31) + depot (23)** green, plus the new D19 tests.
- Degraded/truncated runs are **NOT DATA** — report them, never quietly report a smaller N.

**STOP-and-report:** SAFE→`verified` = SEV-1; VULN losing its verdict = SEV-2; any non-read shape
changing channel = regression. In all cases stop and report; change nothing to force a pass.

---

## 6. DEAD ENDS — do NOT re-propose without new evidence

- **Gate A / Gate B (provenance filter on identity values) — DEAD.** For a self-referential object
  the victim-owned marker *is* the attacked id, so filtering attacker-supplied values deletes the
  proof of ownership; validated offline, killed a true positive. (TECH_DEBT D24 (d).)
- **Reusing `_sanitize_response_text` in the owner-view gate — REJECTED.** It scrubs the very
  fields that separate a denial stub from real data; measured to lift `X-EQUIV-SAFE` similarity
  0.6697 → 0.9744 (above the 0.95 threshold). Any scrubbing variant needs its own full 5-case
  validation first. (TECH_DEBT D24 (f).)
- **Driver-only owner credential — REJECTED.** Threading the second identity only through the
  measurement harness would make the gate work in tests and silently no-op in the real Phase-7
  pipeline — the exact harness-green/production-ungated gap D24 exists to close. The credential
  reaches Phase 7 via the real `AI_DEEP_VERIFY_OWNER_AUTH` config field.
- **ACT-CIA / any vector- or threshold-based verdict scheme — OUT OF SCOPE / rejected.** D19's
  verdict model is the existing 3/4-value oracle + deterministic channels, not a scored vector.
  Do not introduce one under D19.

---

## 7. DOCS-UPDATE SEQUENCING — HARD RED LINE

`STATUS.md`, `ROADMAP.md`, `TECH_DEBT.md` (and any other doc citing the **shadow-only** posture,
e.g. `DEEP_VERIFY.md`, `PROJECT_OVERVIEW.md`) are updated to reflect **authoritative promotion ONLY
as the final step**, in their **own separate docs-only commit**, **AFTER**:
1. the golden record is reproduced **case-for-case** with `PROMOTE` ON, and
2. all suites (backend + `vulnerable_target` 31 + `depot` 23 + new D19 tests) are green.

**Never before acceptance.** A docs claim that a later SEV-1 would force retracting is precisely the
failure to avoid. Until then every doc keeps saying the AI verdict is shadow-only / not
authoritative (which is true until the flag ships and acceptance passes).

---

## 8. KNOWN OPEN ITEMS (context, not D19 scope)

- **Model diversity** — everything is gemini-2.5-pro only.
- **Arbitrary real APIs** — the evidence is two self-built labs; not validated on real targets.
- **D24 threshold calibration** — `0.95` is calibrated on deterministic lab data comparing **raw**
  bodies; **unvalidated against real-target volatility** (timestamps/ETags). Real-target work is
  gated behind scope-lock hardening (pre-real-target register).
- **Public/shared resources** — a residual gap the downgrade-only owner-view gate does not address
  (a genuinely shared resource corroborates). Nothing upstream excludes public resources.
- **Owner credentials are per-deployment, not per-finding.** Sufficient for both labs and for D19;
  a real target with findings owned by different accounts would need per-finding credentials, which
  do not exist. No claim may imply they do.
- **Scope-lock hardening** — HARD prerequisite before any non-localhost target (relates to D2, no auth).
- **D5** — retire the legacy `frontend/`; `preview_dashboard.html` remains modified in the working
  tree (pre-existing, intentionally never staged).

---

## 9. WORKING DISCIPLINE (carry into D19)

- **Warm up before touching** any module — understand it and why it exists; verify against the code
  and the measurement transcripts, **not** the md docs (the docs have lagged the code before).
- **Offline-first:** prove the invariant with mocked verdicts before spending on the real model.
- **One concern per commit; staged list before each commit;** exclude `preview_dashboard.html` and
  `scripts/audit/*`; no AI co-author trailer.
- **Report conflicts/errors** rather than working around them silently; a surfaced divergence is the
  most valuable output.
- **RESULTS.md** (`vulnerable_target/benchmark/`) is the canonical measurement record; the GOLDEN
  section is authoritative, the 140/70 single-target run is superseded history.
