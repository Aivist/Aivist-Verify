# CLI Orientation — the confirmer front door (technical map)

A brief, code-anchored map for the next execution node. This is a technical map, not a
strategy doc.

## Where it lives
- **`run.py`** (repo root) — the `confirm` CLI entry: `python run.py confirm --caseset <path> [--case <id>]`.
- **`backend/app/cli/confirm_render.py`** — the **pure** renderer (`render_tree`, `case_outcome`,
  `exit_code_for`). No engine / network / settings import.
- **`backend/tests/test_confirm_render.py`** — offline renderer test, driven by the committed golden
  rows (`scripts/measure/results/sweep_highN.jsonl`), **zero API cost**.

## How it works (zero core edits)
- It **reuses** `scripts/measure/verdict_measure._run_one`, which already calls
  `execute_deep_verification` with the standard arguments and returns a **record == the sweep-row
  flat dict**. The CLI does not re-implement the engine call, and touches no core file
  (`deep_verifier` / `fuzzer` / `scope` / `config` and the channels / guard / D24 / D19 untouched).
- The live path **enriches** that record with case-derived fields the row lacks: `method`,
  `baseline_path`, `attack_path` (`_attack_path(case)`), and `body`.
- `render_tree(record)` renders from **engine fields only** — verdict is `final_verdict` (else
  `ai_verdict`); it structurally cannot manufacture `verified`. `ground_truth` feeds ONLY the
  separate `[lab oracle]` line, never the verdict.
- Runtime-only: the CLI sets `AI_DEEP_VERIFY_ENABLED = True` in-process (committed config defaults
  stay `False`) and fresh-seeds the target per case via the harness helpers
  (`_boot_target` / `_stop_target` / `_rm_db`).
- Commits: **`94d1fd5`** (spine), **`8727b12`** (offline test + full-caseset mode).

## Two open observations (pending director feedback — do not freeze the UX)
1. **ASCII dash** — the header uses `-`, not `—` (the Windows console mangles the em-dash).
   Already applied in `confirm_render.py`.
2. **The `Reproduce:` line renders the `$UNIQUE` template**, not a filled value — by design:
   `_run_one` generates a fresh high-entropy `unique` internally and the record does not carry the
   filled body. **Pending tweak:** relabel it explicitly as a reproduction *recipe* and append a
   redacted auth placeholder, e.g. `-H "Authorization: <attacker token>"`, so a reader sees where
   the credential goes — without any real token ever printed (extends the SecretStr redaction).

## Continuity
Strategy / roadmap continuity lives with the director and the strategic node.
**`STATUS.md` is the shared source of truth** for current state.
