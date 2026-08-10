# Aivist Verify — Architecture

> Audience: a developer reading the code for the first time. This describes what the system
> **is** and how the pieces fit, grounded in the current source tree. It is a **local
> command-line tool** — a BOLA/IDOR access-control *confirmation* engine. There is **no server,
> HTTP API, or web UI**; `run.py` (the `aivist` command) is the only entry point.
>
> Companion docs: [`VERIFY_ENGINE.md`](./VERIFY_ENGINE.md) (the differential oracle),
> [`DEEP_VERIFY.md`](./DEEP_VERIFY.md) (the deep verifier + guard), [`PROJECT_OVERVIEW.md`](./PROJECT_OVERVIEW.md)
> (orientation), [`../RESULTS.md`](../RESULTS.md) / [`../REPRODUCE.md`](../REPRODUCE.md) (the evidence).

---

## 1. What it is

You give Aivist Verify a **candidate** — an endpoint plus two identities (an attacker and an
owner) — and it tells you, with a reproducible evidence chain, whether the attacker identity
actually crosses a user boundary into the owner's resource. It is a *confirmation* layer, not a
scanner and not a red-team tool, and it runs locally against targets you control.

The whole value is that **a model can never talk it into a false positive.** That property is
structural, and it lives in the two-layer verdict pipeline below.

## 2. The verdict pipeline — AI proposes, code disposes (downgrade-only)

```
 candidate (endpoint + attacker/owner identities)
        │
        ▼
 [ AI proposes ]   the model reads the real baseline/attack traffic and proposes a candidate
        │          verdict; it may request ONE extra evidence fetch, executed for real.
        ▼
 [ CODE disposes ] deterministic gates re-check the proposal against the attack's own runtime
        │          bytes. They can only DOWNGRADE. A `verified` survives only if a structural
        │          exemption, computed in code, actually holds.
        ▼
 verdict + evidence chain   (raw model verdict AND the gate's decision, recorded separately)
```

### Layer 1 — the differential oracle (`backend/app/services/fuzzer.py`)

`_differential_verdict(baseline, test_result, payload_instruction)` is deterministic. It sizes
the baseline vs. attack responses and applies Rules 1–5 (server-error; BOLA/IDOR status+length
divergence; mass-assignment; generic divergence; status change), then a **Veto** (a 200 OK whose
body carries an explicit denial string is forced back to `failed`) and an **Escalation** (a
`suspicious` row becomes `verified` only when sensitive keys appear in the attack response that
were absent from the baseline). No model output is an input to this function.

### Layer 2 — the cross-resource guard + four exemption channels (`backend/app/services/deep_verifier.py`)

`_apply_cross_resource_guard(...)` is the structural backstop. If a decisive verdict rests on a
follow-up read-back of a **different concrete resource** than the one attacked, it is downgraded
to `inconclusive`. The guard never upgrades. A cross-path `verified` is kept decisive **only**
when one of four exemptions — each computed in code from the attack's own runtime parameters and
the read-back bytes, never the model's say-so — holds:

| Channel (engine constant) | Shape it confirms |
|---|---|
| `write_record_readback_decisive` | cross-user write (a record carries the victim's id + this attack's written value) |
| `state_readback_causally_decisive` | silent write / object-state (attacked object's own state now carries the injected value) |
| `delete_readback_negative_assertion_decisive` | delete (pre-flight proved it existed; post-attack read shows it gone/soft-deleted) |
| `state_jump_causally_decisive` | mass-assignment (every sent field jumped from a known pre-flight state to the injected value) |

A fifth shape, **read-type semantic equivalence**, is confirmed by a separate owner-view
corroboration gate (D24): the attacker's response must match an independent re-fetch of the
victim's object *as the victim*. The result object records the model's **raw** verdict
(`ai_verdict_raw`) and the gate's decision (`guard_override`) as **separate fields**, so the
evidence chain literally reads "the model proposed X; code decided Y." Neither the engine nor the
CLI renderer (`backend/app/cli/confirm_render.py`, which reads the verdict from engine fields
only) can manufacture a `verified`.

## 3. The CLI surface (`run.py` → `backend/app/cli/`)

`run.py` at the repo root is the `aivist` command (registered via `pyproject.toml`
`[project.scripts]`). With no arguments it opens the interactive console; otherwise it dispatches
subcommands:

- **`verify`** — confirm one finding. *Lab mode* (`--caseset [--case]`) against a built-in
  ground-truth caseset; *external mode* (`--target --spec --op [--auth]`) against a locally-run
  real target. Code: `backend/app/cli/external_verify.py`.
- **`scan`** — non-interactive auto-discovery + confirm; the model proposes candidates, code vets
  each, and the same confirm runs on every one. Code: `backend/app/cli/scan_run.py`,
  `scan_discovery.py`, `scan_ids.py`, `scan_report.py`.
- **`run --config <json>`** — the fully non-interactive CI entry: JSON in, structured JSON to
  stdout, tokens from env only. Code: `backend/app/cli/run_command.py`.
- **`demo`** — zero-setup confirmation of a real cross-user write on the built-in lab.
- **`target` / `config`** — save a reusable target file; set the AI provider/key/model.

The interactive console is a presentation layer only (`backend/app/cli/console/`:
`controller.py` holds the logic with I/O injected; `text_view.py` / `tui_view.py` are the stdlib
and prompt_toolkit front-ends; `launcher.py` owns terminal-restore safety). It reuses the same
engine calls — it structurally cannot manufacture a verdict.

## 4. Supporting layers (inputs to the engine, not the verdict)

- **Endpoint discovery** (`services/endpoint_catalog.py`) — builds a catalog from an OpenAPI
  spec, a plain `METHOD /path` list, a captured-traffic file (`cli/scan_traffic.py`, HAR /
  raw-HTTP), or a live mitmproxy capture (`cli/scan_capture.py` + `proxy/capture_addon.py`, a
  standalone mitmdump addon with clean process-tree teardown).
- **Token sourcing** — the three roles come from `TARGET_ATTACKER_TOKEN` / `TARGET_OWNER_TOKEN` /
  `TARGET_BYSTANDER_TOKEN` (or a `--tokens-file` read at use-time, never persisted). Each becomes
  a `SecretStr`, routed per-account; an `attacker == owner` collision is refused fail-closed
  before the engine runs.
- **Scope lock** (`services/scope.py`, `scope_psl.py`) — one audited host-scope policy; every
  outbound request is scope-checked (fail-closed).
- **AI provider seam** (`services/llm/`) — a small `get_provider()` factory over Gemini
  (default), OpenAI-compatible, and Anthropic. Only the model *call* sits behind it; the verdict
  logic is untouched. See [`LLM_PROVIDERS.md`](./LLM_PROVIDERS.md).
- **DB/ORM as support, not verdict path** — `core/database.py` (SQLAlchemy async + aiosqlite) and
  `models/scan.py` (the ORM) are imported by the fuzzer at module load, but the `verify` /
  confirmation path does not depend on persisted state to reach a verdict; the DB is optional
  support, not part of the adjudication.

## 5. The two labs and their independent ground truth

The engine is graded against two structurally different, self-contained vulnerable labs, each
shipping its **own** ground-truth pytest suite (no API key required):

- `vulnerable_target/` (integer ids) + `vulnerable_target/test_vulns.py`
- `depot_target/` (UUID ids) + `depot_target/test_vulns.py`

These suites prove — against the live target's real bytes, with no involvement from the verifier —
that every case labelled REAL is genuinely exploitable cross-account and every case labelled
SECURE genuinely resists it. They are the oracle: the engine is measured against them, never the
reverse. The measurement harness (`scripts/measure/verdict_measure.py`) drives the real
`execute_deep_verification` across both labs and writes the committed evidence artifact
(`scripts/measure/results/sweep_highN.jsonl`). See [`../RESULTS.md`](../RESULTS.md).

## 6. End-to-end flow

```
candidate ──► assemble op (endpoint + ids + tokens)  [cli/external_verify or scan_run]
          ──► execute_deep_verification                [services/deep_verifier]
                 ├─ baseline + attack sent (scope-locked, SecretStr auth)  [services/fuzzer]
                 ├─ AI proposes a verdict (may request ONE follow-up)      [services/llm]
                 └─ code disposes: differential oracle + cross-resource guard + 4 channels
          ──► DeepVerificationResult (ai_verdict_raw, guard_override, anchors, evidence)
          ──► render evidence chain                    [cli/confirm_render]
```

It is a local CLI tool end to end: no listening socket, no authentication of its own, and it only
ever acts as the identities whose tokens you supply, against the single target you point it at.
