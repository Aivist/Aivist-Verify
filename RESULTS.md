# Aivist Verify — Zero-False-Positive Benchmark

> **A controlled two-lab benchmark — not a tally of real-world kills.** These runs measure one
> thing: that the deterministic code gate is **not moved by the model**. Every number below is
> recomputed from the committed artifact
> [`scripts/measure/results/sweep_highN.jsonl`](scripts/measure/results/sweep_highN.jsonl); reproduce
> it yourself with [`REPRODUCE.md`](REPRODUCE.md).

## Setup

- **Five confirmation shapes** — cross-user write, silent write / object-state, read-type semantic
  equivalence, delete / negative-assertion, and mass-assignment / low-entropy state-jump.
- **Two structurally different, self-contained labs** — `vulnerable_target/` (integer ids) and
  `depot_target/` (UUID ids), each with its own **independent** ground-truth test suite (the engine is
  graded against them, never the reverse).
- **Real model:** `gemini-2.5-pro`, two-turn loop (the model may request ONE follow-up request,
  executed for real and fed back).
- **Sampling:** **N=20** per SAFE/control case, **N=10** per VULN case, the target **freshly seeded
  before every run**. 15 SAFE/control cases → 300 runs; 13 VULN cases → 130 runs; **430 total**
  (`vulnerable_target` 210 + `depot_target` 220).

## Headline

| Metric | Result |
|---|---|
| SAFE / control runs → final `verified` | **300 → 0** — zero false positives |
| VULN runs → final `verified` | **130 → 130** — every real vuln caught, via its expected channel |
| Usable runs | **430 / 430**, zero degraded |
| Model raw-said `verified` on a SAFE/control run, refused by the code gate | **79 / 79** |
| Per-row regression check vs. the caseset baseline | 430 / 430 OK |

The **79** is the point of the whole exercise: on secure controls the model's *raw* output asked for
`verified` 79 times, and the deterministic gate refused **every one** — 0 of the 300 SAFE/control runs
reached a final `verified`. The model proposes; code disposes, downgrade-only.

## Per-shape breakdown

Every "confirming channel" below is **computed in code** from the attack's own runtime bytes — never
taken from the model's opinion. (`verified` counts are *final*, post-gate.)

| Shape | SAFE/control runs → `verified` | VULN runs → `verified` | Confirming channel (code-computed) |
|---|---|---|---|
| Cross-user write | 40 → **0** | 20 → **20** | write-record read-back (`write_record_readback_decisive`) |
| Silent write / object-state | 40 → **0** | 20 → **20** | state-jump causality (`state_jump_causally_decisive`) |
| Read-type semantic equivalence | 60 → **0** | 20 → **20** | owner-view corroboration gate (D24; no cross-path exemption) |
| Delete / negative-assertion | 60 → **0** | 40 → **40** | delete negative-assertion (`delete_readback_negative_assertion_decisive`) |
| Mass-assignment / state-jump | 100 → **0** | 30 → **30** | state-jump causality (`state_jump_causally_decisive`) |
| **Total** | **300 → 0** | **130 → 130** | |

The cross-resource guard is **downgrade-only**: a decisive verdict that rests on a follow-up read-back
of a *different* concrete resource than the one attacked is downgraded to `inconclusive` unless one of
the four structural exemptions (write-record, state-readback, delete-readback, state-jump), each
AND-ed together in code, actually holds. The read-type shape is confirmed through a separate owner-view
corroboration gate rather than a cross-path exemption.

## What this is *not*, and the documented bounds

- **Controlled labs, freshly seeded — not real-world confirmations.** This benchmark proves the code
  gate holds the line against a real model; it is **not** a count of live findings. Real-world clean
  confirmations are genuinely rare. The honest headline is *discriminative power + a zero-false-positive
  discipline*, not a screen full of `CONFIRMED`.
- **Read-semantic / D24 gate bounds.** The owner-view corroboration threshold is calibrated on
  deterministic lab data; a **public/shared** resource that every authenticated user can read (but
  anonymous cannot) is a residual gap — surfaced, on opt-in (and only when a bystander token is also
  supplied), as an inconclusive **broken-for-all / human review** finding rather than confirmed. Two
  live instances of this miss are archived: VAmPI `/books` and crAPI `mechanic_report`.
- **Single measured model.** The zero-FP property is measured on `gemini-2.5-pro` only; it does not
  transfer to other providers.
- **No real-target zero-FP *claim*.** Against a real target there is no independent ground truth, so
  the **statistical** zero-FP record stays a lab result; a timeout / 401 / 403 / 429 is reported as
  `NOT DATA`, never a verdict. The engine *has* been run against two public third-party targets
  (crAPI + VAmPI) with ground truth established **by hand before each run** — 9 runs, zero false
  positives, every run archived verbatim in
  [`scripts/measure/real_targets/`](scripts/measure/real_targets/) and written up in
  [`REAL_TARGET_RESULTS.md`](scripts/measure/real_targets/REAL_TARGET_RESULTS.md). Read that as an
  engineering signal, not as an extension of the benchmark below.

## Reproduce it

Three independent layers (the labs' own ground truth with no API key; the committed structured
artifact; and regenerating the artifact from your own Gemini key) are documented in
[`REPRODUCE.md`](REPRODUCE.md).
