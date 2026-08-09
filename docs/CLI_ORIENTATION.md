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

## Beyond the lab confirmer — the real-target front doors (`verify`, `scan`, `run`)

The map above is the **lab caseset** renderer. Over the same engine there are now **three** real-target
surfaces (verdict logic untouched — they only assemble the inputs and reuse `execute_deep_verification`).
Subcommands of `python run.py`: `verify · confirm · config · demo · target · scan · run`.

- **`verify` — one finding.** Subcommand `python run.py verify --target <url> --spec <openapi> --op <op.json>`
  (`+ --auth <login.json>` for auto re-login). Assembles one operation into the same engine call; the
  three red lines (scope fail-closed, attacker/owner identity isolation, `SecretStr` tokens) hold. Code in
  `backend/app/cli/external_verify.py`.
- **`scan` — auto-discover many (REPL command, no subcommand).** Launch the console (`python run.py` with
  no args) → `config` → `target` → `scan`. It builds a catalog from **one** of four sources — the target's
  spec, a `METHOD /path` endpoints list, a **captured-traffic file** (HAR/raw-HTTP), or a **LIVE `mitmdump`
  capture** — then has the model **propose** BOLA/IDOR candidates, **code-fences every op twice**, sources
  ids **per-account (never cross-account, never fabricated → SKIP)**, runs each through the existing confirm,
  and prints one tier-grouped report. Modules: `scan_run.py` (orchestration), `scan_discovery.py` (AI
  proposal + code fences), `scan_ids.py` (id sourcing tiers a/b/c), `scan_report.py` (tier-grouped render);
  REPL wiring in `console/controller.py:do_scan` + `console/intro.py`. Full behavior + red lines:
  [`STATUS.md`](./STATUS.md) "Auto-discovery `scan` onramp".
  - **Passive discovery (built).** LIGHT: `scan_traffic.py` templatizes a HAR/raw-HTTP capture (scope-locked
    to the target origin) into the endpoints list — non-interactive `run.py scan --traffic-file <cap>`, or the
    interactive `scan` prompt. HEAVY: `scan_capture.py` + `proxy/capture_addon.py` drive a synchronous
    `mitmdump` (clean process-tree teardown; no async ingest stack) writing scope-filtered flows to a temp
    file the LIGHT loader reads — `run.py scan --capture [--capture-port N] [--capture-duration S]`. See
    [`STATUS.md`](./STATUS.md) "Passive endpoint discovery — DONE".
  - **CLI experience fixes (director hands-on run).** Robust Windows ANSI/VT color detection (plain, no raw
    `\033[` leak, when unsupported); env-first owner+bystander tokens (masked, with a "from environment"
    message); required-choice framing when no spec; token re-entry from the scan review; and non-numeric
    `{templated}` id discovery (`{book_title}` etc.). Tests: `test_cli_regressions.py`. **Note:** a further
    round of interactive fixes (VT-enable hardening + strip-all-escapes; spec-less `verify` op-build) is
    **PARKED uncommitted** — the interactive console still has open issues. See [`STATUS.md`](./STATUS.md)
    "Uncommitted".
- **`run` — non-interactive, programmatic (CI / scripting).** Subcommand `python run.py run --config
  <file.json> [--pretty]`. Reads ALL config from a JSON file (`mode` = `verify` OR `scan`; `base_url`;
  endpoint + ids OR a scan catalog source) + tokens from **env only**, and emits **structured JSON** to
  stdout (`--pretty` summary → stderr). Zero interaction / color / getpass / prompts, so it sidesteps the
  interactive console's terminal pitfalls — the reliable path today. A thin input-adapter + output-serializer
  that reuses `_verify_external` (verify) and `run_scan` (scan) **unchanged**; tokens env-only + masked +
  never in the config file, collision guard fires, output redacted, NOT-DATA/error → non-zero exit. Code:
  `backend/app/cli/run_command.py`; tests `test_run_command.py`. Full behavior: [`STATUS.md`](./STATUS.md)
  "Non-interactive `run`".

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
