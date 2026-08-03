# AUDIT — full read-only findings register (pre-publication map)

> **Purpose.** A durable record of the full read-only audit of the verdict engine (11 areas),
> so the findings survive outside chat. **This is the authoritative "what's left before GitHub" map.**
> Every finding carries its evidence (`file:line`) and a **DIRECTION**:
> **DANGEROUS** = could cause a *false positive* (a SECURE/authorized resource reported `verified`) →
> gates the zero-FP claim; **SAFE** = could cause a *missed detection* (a real issue not confirmed) →
> affects coverage, not the claim.
>
> **Method.** Ground truth built from code (trusted over docs); full suite run. **Baseline at audit:
> backend `pytest` = 587 passed, 2 benign third-party warnings.** Re-verify before relying on any line
> number — code moves.
>
> **The claim being protected:** *zero false positives on private / authorization-gated resources,
> with a reproducible evidence chain.* The zero-FP property is a claim about the **deep-verifier final
> verdict / D19 promotion path**, not about the rule-oracle triage layer or the `verify --target`
> direct-render path (both noted below).

---

## Tier 1 — DANGEROUS-direction (could cause a FALSE POSITIVE → gates the zero-FP claim)

These are the pre-publication must-address items in the direction the whole discipline exists to prevent.

### ✅ RESOLVED — D30: public / shared resources confirmed as cross-user "leaks"
- **Was:** the D24 owner-view gate corroborated on a *public* resource because both identities
  legitimately receive the same bytes → real false positive (crAPI public community post → `verified`).
- **Fix (commit `ea65372`):** a downgrade-only public-resource probe — `fetch_control_view`
  ([deep_verifier.py:1301](../backend/app/services/deep_verifier.py:1301)) re-reads the resource as a
  third/bystander identity; `_resource_is_public`
  ([deep_verifier.py:1402](../backend/app/services/deep_verifier.py:1402)) suppresses confirmation only
  on affirmative certainty (2xx + corroborating body), fails safe to "private" on any ambiguity. Routed
  through the **unchanged** `_apply_owner_view_gate`
  ([deep_verifier.py:1425](../backend/app/services/deep_verifier.py:1425)); reason
  `PUBLIC_RESOURCE_NOT_BOLA_REASON` is not a D19 channel. Opt-in via `AI_DEEP_VERIFY_BYSTANDER_AUTH`
  ([config.py:238](../backend/app/core/config.py:238), default `None`). See [`TECH_DEBT.md` D30](./TECH_DEBT.md).
- **Residual (SAFE-direction, recorded):** a BOLA "broken for *every* authenticated user" is
  indistinguishable from a public resource → suppressed (missed detection). Deliberate trade; live crAPI
  order-endpoint check pending.

### 🔴 OPEN — Rule-oracle emits `verified` directly from coarse heuristics
- **Direction: DANGEROUS**, but **scoped to the rule-oracle triage layer — NOT the deep-verifier
  zero-FP claim.** The fast oracle `_differential_verdict` can output `verified` from:
  a 5xx status jump ([fuzzer.py:844](../backend/app/services/fuzzer.py:844)); a BOLA/IDOR length
  deviation ([fuzzer.py:851](../backend/app/services/fuzzer.py:851)); a mass-assignment length change
  ([fuzzer.py:869](../backend/app/services/fuzzer.py:869)); or a **substring** escalation on
  `_ESCALATION_KEYS` (incl. `"admin"`) present in the test body only
  ([fuzzer.py:87](../backend/app/services/fuzzer.py:87), [fuzzer.py:909](../backend/app/services/fuzzer.py:909)).
- **Why it stays open / why it's not the headline:** D19 promotion only ever touches the `suspicious`
  band and never revisits a rule-oracle `verified`
  ([fuzzer.py:1409](../backend/app/services/fuzzer.py:1409)). The deep verifier is the backstop for
  `suspicious`, not for a rule-oracle `verified`. **Risk:** a naive reader conflates "the tool is
  zero-FP" with "every verdict the tool prints is zero-FP." Pre-publication framing must scope the claim
  to the deep-verify path.

### 🔴 OPEN — Direct-render `verify --target` surfaces the raw model verdict
- **Direction: DANGEROUS (boundary).** `_record_from_result` renders `result.ai_verdict` directly
  ([external_verify.py:257](../backend/app/cli/external_verify.py:257)); on read-semantic / no-readback
  shapes the final verdict reduces to the model's opinion (downgrade-only guards + D24 + now the D30
  probe apply, but no positive code channel is required as on the promotion path).
- **Mitigations already in place:** the path is disclaimed in-tool as "an engineering signal, NOT a
  zero-FP claim" ([external_verify.py:449](../backend/app/cli/external_verify.py:449)); degradation is
  downgrade-only (challenge/timeout → NOT DATA). D30 closes the public-resource sub-case when a bystander
  credential is configured. **Remaining:** the direct path is not the promotion-gated path; keep the
  claim attached to D19 promotion on private resources.

---

## Tier 2 — Capability / coverage (SAFE-direction — affects which targets can be handled)

These do **not** threaten the zero-FP claim; they bound which real targets the tool can confirm on.

- **Full WAF / rate-limit handling.** Only single adaptive back-off on 429/503
  ([fuzzer.py:678](../backend/app/services/fuzzer.py:678)); no "a filter has started blocking → stop"
  circuit-breaker. `ROADMAP.md` §0 PLANNED #1. Direction: SAFE (a challenged response is NOT DATA).
- **Arbitrary real APIs / UUID wall.** Zero-FP is measured on **two self-built labs** (integer-id +
  UUID-id) + gemini-2.5-pro only; arbitrary real APIs and a second measured model are unproven.
  `ROADMAP.md` §0 PLANNED #3/#10. Direction: SAFE.
- **Per-deployment, not per-finding credentials.** Owner and now bystander creds are one-per-deployment
  ([config.py:218](../backend/app/core/config.py:218), [config.py:238](../backend/app/core/config.py:238));
  a target whose findings belong to different owners is unsupported (D24 boundary 2). Direction: SAFE.
- **D25 — DNS-rebinding TOCTOU.** `ScopePolicy.check` resolves + validates the IP
  ([scope.py:361](../backend/app/services/scope.py:361), [scope.py:420](../backend/app/services/scope.py:420)),
  but httpx re-resolves at connect time — a small time-of-check/time-of-use window; no IP pinning. See
  `TECH_DEBT.md` D25. Direction: SAFE (a containment residual, not a verdict FP).
- **Multi-step auth — deeper slices.** Login/relogin slice 1 is done (body/header/cookie token
  extraction, independent providers); OAuth-redirect / MFA / CSRF round-trips are out. Related: **D28** —
  a mid-run owner-view 401 is not refreshed ([external_verify.py:316](../backend/app/cli/external_verify.py:316));
  `fetch_owner_view` fails safe BLOCK, so the worst case is a missed confirmation. Direction: SAFE.

---

## Tier 3 — Documentation / boundary (write-a-sentence items)

- **0.95 owner-view threshold unvalidated on real-target volatility.**
  `_OWNER_VIEW_CORROBORATION_THRESHOLD = 0.95` ([deep_verifier.py:1385](../backend/app/services/deep_verifier.py:1385)),
  calibrated on byte-stable seeded lab data comparing raw bodies. Real volatility can push a true
  positive's similarity down (→ wrong block); the sanitizer remedy was measured and rejected because it
  pushes a SECURE case up. See `TECH_DEBT.md` D24(f). Direction: primarily SAFE; the dangerous side
  (a SECURE resource ≥ 0.95) is the D30-class case, now probed.
- **Rule-oracle heuristic thresholds are arbitrary.** Length-deviation cutoffs 0.05 / 0.1 / 0.15
  ([fuzzer.py:822](../backend/app/services/fuzzer.py:822) onward) are unvalidated magic numbers on the
  triage layer. Direction: DANGEROUS on the rule-oracle-only path (see Tier 1), boundary otherwise.
- **Doc drift (test counts).** Several docs stated stale backend counts (507 / 523; actual 587) and a
  stale lab count (14; actual 31). Corrected in a companion drift-alignment commit; historical deltas
  (e.g. "Suite 507→510") left verbatim.

---

## Pre-publication summary — DANGEROUS-direction items still OPEN after D30

1. **Rule-oracle direct `verified`** ([fuzzer.py:844](../backend/app/services/fuzzer.py:844),
   [fuzzer.py:909](../backend/app/services/fuzzer.py:909)) — scope the public claim to the deep-verify
   path; the rule oracle is noisy triage by design.
2. **Direct-render `verify --target`** ([external_verify.py:257](../backend/app/cli/external_verify.py:257))
   — model-opinion verdicts reach the user; keep the zero-FP claim attached to the D19 promotion path on
   private resources (disclaimed in-tool, D30 closes the public sub-case when configured).

Everything else that threatens the zero-FP claim (D30) is **resolved**; the remainder is SAFE-direction
coverage or write-a-sentence boundary work.
