# Broken-Access-Control Verification Benchmark

A small, **ground-truth benchmark dataset** for *dynamic, black-box verification*
of broken-access-control (BAC) vulnerabilities — BOLA / object-level write,
vertical privilege escalation, and deliberately-secured "look-alike" controls.

## What this is

Every case in this dataset is a **planted, known-answer** endpoint on the
standalone target app in `vulnerable_target/` (localhost only, never deployed).
Because we control the planted truth, we can measure how well different verifiers
decide **"is this endpoint actually vulnerable?"** against an objective answer key.

The dataset currently spans **11 planted cases**: the five core BAC cases
(A, B, C, D, SAFE), the four Phase-1 additions (T-REAL, T-TRAP, T-WEAK,
T-SILENT2), and the two **Phase-2 cross-path** cases (X-CROSS, X-SAFE) whose
landed write is observable **only** on a *different* path (`GET /api/audit-log`),
never a same-path GET. See [`../README.md`](../README.md) for the full per-case
answer key.

We record, per case:

- the **ground truth** (REAL vulnerability vs. SECURE),
- what makes it hard to detect (the **evidence gap**),
- the **rule-based differential oracle** verdict (the existing `fuzzer.py`
  `_differential_verdict` path), where we have measured it, and
- the **AI-in-the-loop** verdict — a two-turn loop where the model may either
  decide immediately or request **one** follow-up HTTP request (e.g. a
  write-then-read read-back), which is then executed for real and fed back.

## What it measures

- **AI-in-the-loop verdict accuracy** against planted truth.
- **False-positive rate** — AI calls a SECURE endpoint vulnerable.
- **False-negative rate** — AI calls a REAL vulnerability secure/not-present.
- **Rule-based oracle accuracy** (where measured), as a baseline to compare the
  AI loop against — especially on "silent" cases where a single-shot diff oracle
  structurally cannot observe the side effect.

The headline question this dataset exists to answer: *does giving the verifier
the ability to gather one more piece of evidence (write-then-read) let it
correctly separate real silent BOLA from a secured endpoint that returns an
identical opaque `200 {"status":"ok"}`?*

## Integrity floor (`inconclusive`) and the B-2.2 guard

The Phase-2 cross-path cases (X-CROSS / X-SAFE) deliberately remove the same-path
GET, so a verifier that "confirms" a write by reading back a *different* concrete
resource is not actually proving the attacked object changed. To keep the
benchmark honest, the AI deep-verifier verdict vocabulary now includes
**`inconclusive`** (alongside `verified` / `suspicious` / `failed`). A
deterministic structural backstop — the **B-2.2 cross-resource guard** — downgrades
an otherwise-decisive `verified`/`failed` verdict to `inconclusive` whenever the
follow-up read-back path differs from the attacked path (concrete-path comparison;
target-agnostic).

Under this integrity fix, X-CROSS (REAL) and X-SAFE (SECURE) currently settle on a
stable `inconclusive` **integrity floor** — the verifier refuses to emit a false
confident verdict on a no-same-path-GET case — rather than a confident
`verified`/`failed`. That is a deliberate, honest outcome, not a measurement gap.

Two offline, network-free unit tests in `backend/tests/` encode these
expectations as human-owned ground truth:
- `test_verdict_oracle.py` (9 tests) — the rule oracle (`_differential_verdict`)
  verdicts for the single-shot cases.
- `test_d18_b22_guard.py` (18 tests) — the deterministic B-2.2 cross-resource guard
  and path normalization.

## Files

- [`RESULTS.md`](./RESULTS.md) — the append-only dataset: a summary table at the
  top plus one structured entry per case.

## How to extend (append-only)

This dataset is **append-only**: add new cases as new entries at the bottom of
`RESULTS.md` (keep IDs unique, reuse the entry template), then bump the counters
in the summary table at the top. Do not rewrite or delete past entries — a
benchmark is only meaningful if its history is stable. Verbatim experiment
output (requests, responses, model JSON) is the source of truth; paste it as-is.

## Scope / honesty

- This is **data and documentation**, not product code. Nothing here imports from
  or modifies `backend/`.
- "Not measured" means exactly that — we have not yet run that verifier on that
  case; it is **not** a synonym for pass/fail. Keep it honest.
- The target mutates state on write cases; re-seed (delete
  `vulnerable_target/vulnerable_target.db` and restart) before re-running so
  baselines stay reproducible.
