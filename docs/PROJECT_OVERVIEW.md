# Aivist Verify — Project Overview

> Audience: a technical reader who wants to know **what exists today**, how the pieces
> fit, and how far the evidence goes — without reading the whole source tree first.
> Principle: state the current reality plainly, neither overclaiming nor hiding limits.
> The code is the source of truth; where this document and the code disagree, the code
> wins and this document should be corrected.
>
> Companion docs: [`../README.md`](../README.md) (the front door / positioning),
> [`ARCHITECTURE.md`](./ARCHITECTURE.md) (how the engine is built),
> [`VERIFY_ENGINE.md`](./VERIFY_ENGINE.md) and [`DEEP_VERIFY.md`](./DEEP_VERIFY.md)
> (the oracle and the deep verifier in depth).

---

## 1. What this is

Aivist Verify is a **local, CLI-first confirmation engine** for Broken Object-Level
Authorization (BOLA / IDOR). You give it a candidate — an endpoint plus two identities
(an attacker and an owner) — and it tells you, **with a reproducible evidence chain**,
whether the attacker identity actually crosses a user boundary into the owner's resource.

It is a *confirmation* layer, not a scanner and not a red-team tool:

- **Not a scanner.** It does not crawl to surface *suspected* IDORs. It runs *after* that:
  feed it a candidate and it returns a confirmed verdict with proof, or an honest
  "not confirmed."
- **Not an exploitation tool.** It confirms reachability across a user boundary for
  blue-team verification; it is not built to weaponize or mass-exploit.
- **Local and single-tenant.** It runs from the command line, against locally-hosted
  targets you control, with credentials you supply. It has no authentication of its own
  and is not an internet-facing service.

The product is the confirmation engine and its command-line front door — a local CLI tool,
with no server, HTTP API, or web UI to run.

## 2. The moat — AI proposes, code disposes (downgrade-only)

The whole value of the tool is that a model can never talk it into a false positive.
Confirmation runs in two layers, and **both are adjudicated by code**:

```
 candidate (endpoint + attacker/owner identities)
        │
        ▼
 [ AI proposes ]   the model reads the real request/response traffic and proposes a
        │          candidate verdict. It may request ONE extra piece of evidence, which
        │          is executed for real and fed back. The model's opinion is an input to
        │          be checked — never the verdict.
        ▼
 [ CODE disposes ] a deterministic gate re-checks the proposal against the attack's own
        │          runtime bytes. It can ONLY DOWNGRADE. A `verified` survives only if a
        │          structural exemption, computed in code, actually holds.
        ▼
 verdict + evidence chain   (raw model verdict AND the code gate's decision, recorded
                             separately: "model said X, code decided Y")
```

### 2a. Layer one — the differential oracle

`backend/app/services/fuzzer.py :: _differential_verdict` is a deterministic oracle over
the baseline vs. attack responses. It applies Rules 1–5 (server-error, BOLA/IDOR
status+length divergence, mass-assignment, generic divergence, status-code change), then
a **Veto** rule (a 200 OK whose body carries explicit denial strings is forced back to
`failed`) and an **Escalation** rule (a `suspicious` row is promoted to `verified` only
when sensitive keys appear in the attack response that were absent from the baseline).
No model output is an input to this function.

### 2b. Layer two — the cross-resource guard and its four exemption channels

`backend/app/services/deep_verifier.py :: _apply_cross_resource_guard` is the structural
backstop. If a decisive verdict rests on a follow-up read-back of a **different concrete
resource** than the one attacked, it is downgraded to `inconclusive`. The guard never
upgrades a verdict.

A cross-path `verified` is kept decisive **only** when one of four structural exemptions,
each computed in code from the attack's own runtime parameters and the read-back bytes
(never from the model's say-so), actually holds:

| Channel (engine constant) | Confirmation shape | What code must prove |
|---|---|---|
| `write_record_readback_decisive` | cross-user write (BOLA) | a record on the read-back carries the victim's object id **and** the exact value this attack wrote |
| `state_readback_causally_decisive` | silent-write / object-state | the attacked object's own state now carries this attack's unique injected value (owner==attacked, caller!=owner, payload causality) |
| `delete_readback_negative_assertion_decisive` | delete / negative-assertion | a pre-flight read proved the victim's object existed and was active; the post-attack read shows it gone or soft-deleted |
| `state_jump_causally_decisive` | mass-assignment / low-entropy state-jump | every field the attack sent moved from a known pre-flight state to the injected value |

A fifth shape, **read-type semantic equivalence**, is confirmed through a separate
owner-view corroboration gate (the attacker's response must match an independent re-fetch
of the victim's object as the victim), not through a cross-path exemption.

Crucially, the result object records the model's **raw** verdict (`ai_verdict_raw`) and
the gate's decision (`guard_override`) as **separate fields**. The evidence chain a user
sees is therefore literally auditable as "the model proposed this; the code gate decided
that." Neither the engine nor the CLI renderer can manufacture a `verified` — the CLI
renderer (`backend/app/cli/confirm_render.py`) reads the verdict from engine fields only,
and a suite of drift-guard tests pins its channel set to the engine's own constants.

## 3. Entry points

The `aivist` command (repo-root `run.py`; installed via `pip install -e .`) is the front
door. With no arguments it opens an interactive console; otherwise it dispatches
subcommands:

- **`verify`** — confirm a single finding. *Lab mode* (`--caseset [--case]`) runs against
  a built-in ground-truth caseset; *external mode* (`--target --spec --op [--auth]`) runs
  against a locally-hosted real target described by an OpenAPI spec and one operation.
- **`scan`** — non-interactive auto-discovery + confirm from a saved target file. Works
  from an OpenAPI spec, or spec-less from an endpoints list, a captured-traffic file
  (HAR / raw-HTTP), or a live mitmproxy capture. An AI step proposes candidate endpoints,
  code vets each, and the same zero-false-positive confirm runs on every one.
- **`run --config <json>`** — the fully non-interactive, programmatic entry for CI /
  scripting: JSON config in, structured JSON to stdout. Tokens are read only from the
  environment, never from the config file.
- **`demo`** — a zero-setup confirmation of a real cross-user write on the built-in lab
  (no Docker, no external target, no tokens to supply). It needs only an API key.
- **`target`** / **`config`** — save a reusable target as one editable file; set the AI
  provider, key (entered masked), and model.

Tokens for the three roles are sourced **environment-first** —
`TARGET_ATTACKER_TOKEN` / `TARGET_OWNER_TOKEN` / `TARGET_BYSTANDER_TOKEN` — or, for
`scan`, an optional `--tokens-file` read at use-time and never persisted. A distinct
attacker and owner are required; an attacker==owner collision is refused fail-closed
before the engine ever runs, because a self-vs-self comparison could false-confirm.

## 4. The two labs and their independent ground truth

The engine is graded against two structurally different, self-contained vulnerable labs,
each shipping its **own** ground-truth pytest suite that proves — against the live
target's real bytes, with no involvement from the verifier — that every case labelled
REAL is genuinely exploitable cross-account and every case labelled SECURE genuinely
resists it:

- `vulnerable_target/` — a self-contained lab + `vulnerable_target/test_vulns.py`
- `depot_target/` — a second, structurally different lab + `depot_target/test_vulns.py`

These suites require no API key. They are the oracle: the engine is measured against them,
never the reverse, and a label is never edited to make the engine agree.

## 5. The zero-false-positive benchmark (controlled, not real-world)

The measurement harness (`scripts/measure/verdict_measure.py`) drives all five
confirmation shapes across both labs with a real `gemini-2.5-pro` loop, freshly seeded
every run, and writes one structured JSON row per run. From the committed artifact
`scripts/measure/results/sweep_highN.jsonl` (N=20 SAFE/control and N=10 VULN per case):

| | Result |
|---|---|
| SAFE / control runs → final `verified` | **300 → 0** (zero false positives) |
| VULN runs → final `verified` | **130 → 130** (every real vuln caught, via its expected channel) |
| Usable runs | **430 / 430**, zero degraded |
| Model raw-said `verified` on SAFE/control, refused by the code gate | **79 / 79** |

The 130 confirmed VULN runs break down by the channel that authorized them: write-record
20, mass-assignment state-jump 50, delete negative-assertion 40, and read-semantic 20
(confirmed via the owner-view gate, no cross-path exemption needed).

These are **controlled lab targets, freshly seeded** — the benchmark proves that *the code
gate is not moved by the model* (79 model-proposed `verified` verdicts on secure controls,
all refused). It is **not** a tally of real-world kills. The honest headline is
discriminative power plus a zero-false-positive discipline, not a screen full of
`CONFIRMED`.

The evidence is reproducible in three independent layers (no transcript to trust): the
labs' own ground-truth suites (Layer 1, no API key), the committed structured artifact
(Layer 2, no API key), and regenerating Layer 2 from Layer 1 with your own Gemini key
(Layer 3). See `REPRODUCE.md` and `RESULTS.md` for the full case-by-case matrix and each
channel's documented bounds.

## 6. Where the code lives

```
run.py                         # the `aivist` CLI front door (dispatch + orchestration)
backend/app/
├─ services/
│   ├─ fuzzer.py               # the differential oracle (_differential_verdict: Rules 1-5 + veto + escalation)
│   └─ deep_verifier.py        # the deep verifier: AI proposes, the cross-resource guard + four
│                              #   code-computed exemption channels dispose (downgrade-only)
└─ cli/
    ├─ external_verify.py      # external real-target verify (spec + op + tokens/relogin)
    ├─ scan_cli.py / scan_*    # non-interactive scan: discovery + per-candidate confirm
    ├─ confirm_render.py       # pure, offline evidence-chain renderer (cannot manufacture a verdict)
    ├─ console/                # the interactive console (controller + text/TUI views + launcher)
    └─ branding.py             # single-source brand constant (product/command names, config paths)
vulnerable_target/  depot_target/    # two labs, each with an independent ground-truth suite
scripts/measure/                     # the measurement harness + committed result artifacts (sweep_*.jsonl)
```

## 7. Honest limits

- **Measured on two controlled labs, not at scale in the wild.** "Supports X" means the
  capability exists and is audited in-repo — not that it has been battle-tested against
  diverse real-world targets.
- **Single AI provider.** The AI layer currently targets Gemini via the `google.genai`
  SDK; there is no provider-abstraction layer yet (the interactive `config` flow offers
  other providers, but the measured, load-bearing path is Gemini).
- **Read-semantic gate has documented bounds.** Its corroboration threshold is calibrated
  on deterministic lab data, and public/shared resources are a residual gap (see
  `RESULTS.md`). The `--assert-owner-only` option surfaces a "broken-for-all" resource as
  an explicitly conditional, human-review finding rather than confirming it.
- **No authentication of its own; localhost by design.** It only ever acts as the
  identities whose tokens you supply, against the single target you point it at.

## 8. Further reading

- [`../README.md`](../README.md) — the front door, positioning, and quickstart.
- `RESULTS.md` — the full zero-false-positive benchmark, case by case, with bounds.
- `REPRODUCE.md` — reproduce the evidence yourself, three independent layers.
- [`ARCHITECTURE.md`](./ARCHITECTURE.md) — how the engine is built.
- [`VERIFY_ENGINE.md`](./VERIFY_ENGINE.md) / [`DEEP_VERIFY.md`](./DEEP_VERIFY.md) — the
  differential oracle and the deep verifier in depth.
