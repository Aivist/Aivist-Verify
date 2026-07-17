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
default**. The integrity floor (never emit a false verdict) is proven, and the
project's hardest milestone — a **confident cross-path verdict (B-1)** — is now
**done, committed (`37769b3`), live-measured, AND locked by an automated regression
test**. It is still shadow-only (not authoritative — that's D19) and proven on one
vuln shape.

## Test suite

| Suite | Command (from repo root) | Result |
|---|---|---|
| Backend | `python -m pytest backend/tests -q` | **145 passed** |
| Ground-truth target | `python -m pytest vulnerable_target -q` | **14 passed** |

## The main line (three nodes)

The product's spine is three sequential nodes (see [`ROADMAP.md`](./ROADMAP.md) §4).
Where each stands today:

| Node | Goal | State |
|---|---|---|
| **1. Judge correctly** | Never emit a false verdict; then *confirm* the hard cross-path bug | **DONE & committed.** Integrity floor + the confident cross-path verdict (**B-1**, `37769b3`): live-measured (X-CROSS→`verified` 5/5, X-SAFE→`inconclusive`/safe 5/5) and locked by a mock-Gemini regression test. |
| **2. Act** (`D19`) | Promote the AI verdict from observe-only/log to **authoritative** | **Not started.** The persisted verdict is still the rule oracle's; the AI verdict is shadow-only. |
| **3. Be safe on real targets** | Consolidate scope-lock checks + adversarial tests before any non-localhost use | **Not started.** Hard prerequisite for real targets. |

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
- **Same-path cases resolve correctly** — AI **8/8**, 0 false-pos / 0 false-neg. See
  `vulnerable_target/benchmark/RESULTS.md`.

## Honest limits (do not over-read the B-1 green)

- **One vuln shape, one target, N=5.** Only "cross-path write-then-read BOLA" (X-CROSS).
  nested-object, delete-type, multi-step, and noisier real audit logs are untested.
  "Mechanism proven on this class," not "verifier finished."
- **The final verdict still leans on the model reading the log.** Code *gathers* the
  evidence (deterministic); Gemini still *interprets* it (raw `verified` 5/5 here). A
  model-specific pillar — re-run the benchmark on any model swap.
- **Known sharp edge (tracked, TECH_DEBT D23):** `_write_record_content_match` treats a
  record's own primary-key `id` as a match candidate, so a *second* audit row whose
  event-`id` equals the attacked object id could spuriously match. It does **not** bite
  the real per-finding flow (X-SAFE has a single `id=1` row), but it should be tightened
  to a semantic owner/subject key. **Not** changed here (a safety-gate change is
  human-owned; see D23).
- **Shadow-only.** Still observe-only, default-off; the persisted verdict is the rule
  oracle's. Making the AI verdict authoritative is D19 (not started).

## Uncommitted right now (working tree)

- **Docs restructure** — this doc set, moved into `docs/` + a thin root README
  (about to be committed alongside this update).
- **Proxy Radar tab (frontend)** — `preview_dashboard.html` gains the Step-9 proxy UI
  (start/stop, live SSE stream, flows list, "send to Hunter"). Backend `/proxy/*` routes
  already existed and are tested; this is the UI wiring. **Left uncommitted on purpose** —
  it belongs to the later frontend phase, not the B-1 milestone.
- `scripts/audit/` measurement drivers + `*.out.txt` transcripts — kept untracked
  (throwaway harnesses / evidence), not committed.

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

1. **D21** — promote the spec source to a declared config field (currently the `getattr`
   seam), so B-1's real catalog can be wired for normal use, not just harnesses.
2. **Broaden the proof** — beyond the single X-CROSS shape: nested-object, delete-type,
   multi-step, noisier audit logs; and tighten the id match (D23) to a semantic
   owner/subject key so real logs can't spuriously match.
3. **D19** — only after the above: promote the AI verdict from observe-only to
   authoritative in the real flow, with a gating policy.
4. **Benchmark vs agent-style PoC tools** on a public target; **scope-lock hardening**
   before any non-localhost target; retire the legacy `frontend/` (D5).
