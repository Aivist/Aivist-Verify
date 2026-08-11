<!-- Logo lives at docs/assets/logo.png -->
<p align="center">
  <img src="docs/assets/logo.png" alt="Aivist Verify" width="140"/>
</p>

<h1 align="center">Aivist Verify</h1>

<p align="center">
  <strong>A BOLA/IDOR access-control confirmation engine that a model cannot talk into a false positive.</strong>
</p>

<p align="center">
  The AI proposes. <strong>Code</strong> decides — and the code can only ever say <em>no</em>.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.11%2B-blue" alt="Python 3.11+"/>
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License: MIT"/>
  <img src="https://img.shields.io/badge/false%20positives-0%2F300-brightgreen" alt="0 false positives on the benchmark"/>
</p>

---

Most access-control tools hand you a pile of *maybe* — suspected IDORs you still have to verify by hand, at 2 a.m., one by one. **Aivist Verify hands you proof, or an honest "no."** You give it a candidate — one endpoint, two identities — and it tells you whether the attacker actually crosses a user boundary into the victim's resource, with a reproducible evidence chain attached.

The part that matters: **the verdict is decided by code, not the model.** The AI reads the traffic and *proposes*; a deterministic, downgrade-only gate *disposes*. On a 430-run benchmark, the model's raw output asked to mark a **secure** endpoint `verified` **79 times** — and the code gate refused **every single one of them**. Zero false positives. Not "fewer." Zero — by construction, on a benchmark you can re-run yourself in one command.

## Why this exists

Two kinds of tools already sit around this problem, and both leave the same gap:

- **Open-source scanners** are good at surfacing *maybe*. They flag suspected IDORs and — often in their own README — hand the actual confirmation back to you.
- **Closed SaaS validators** do run exploitability checks, but the logic is a black box, the finding is a report you can't independently reproduce, and "fewer false positives" is a statistical hope, not a structural guarantee.

Aivist Verify is the layer between them: **open-source, local, and structurally incapable of emitting a false `verified`** — with an evidence chain any reviewer can replay. It didn't start here. It started as a full AI penetration-testing *platform* — a server, an API, a dashboard. Somewhere in the build it became obvious that the world doesn't need another thing that surfaces *maybe*; it needs something that *confirms*. So the entire server layer got deleted, and everything collapsed onto the one part with real value: the confirmation engine. What's left is small on purpose.

## How it works — AI proposes, code disposes

```
 candidate (endpoint + attacker/owner identities)
        │
        ▼
 [ AI proposes ]   the model reads the real baseline/attack traffic and proposes a candidate
        │          verdict; it may request ONE extra evidence fetch, executed for real.
        ▼
 [ CODE disposes ] deterministic gates re-check the proposal against the attack's own runtime
        │          bytes. They can only DOWNGRADE. A `verified` survives only if a structural
        │          exemption, computed in code, actually holds. The model's opinion is not an input.
        ▼
 verdict + evidence chain   (the model's RAW verdict AND the gate's decision, recorded separately)
```

This is not "AI is useless, code does the real work." It's the opposite: **you need both, and most tools get the split wrong.** Only the model can read messy, business-specific traffic and pick out which of a thousand endpoints is *worth checking* — code can't guess that. And only code can then rule on whether the access *actually* crossed a user boundary — because a model, left to decide, will state a false positive with total confidence. The model is the prospector that smells where the gold might be; the code is the assay that never mistakes pyrite for gold. Aivist Verify puts each where it belongs: **the AI has range, the code has the final word, and the final word can only ever be to take a claim away** — never to invent one. That is why a model can't talk it into a false positive.

Every result records the model's **raw** verdict (`ai_verdict_raw`) *and* the gate's decision (`guard_override`) as **separate fields**, so the evidence chain literally reads "the model proposed X; code decided Y." Neither the engine nor the CLI can manufacture a `verified`.

## See it — a real confirmation, unedited

`aivist demo` boots a built-in vulnerable lab and confirms a real cross-user write end to end — no Docker, no target, no tokens. This is the actual, unmodified render:

```text
[CONFIRMED]  cross-user write (BOLA) - POST /api/users/1/display-name
  Verdict: verified  (confirming channel: write-record read-back)  (guard_override=write_record_readback_decisive)
  Basis: a deterministic code gate authorized this (write-then-independent-read proof), not the model's opinion alone.
  What the engine proved:
    Wrote as the attacker, then read the object back through a different
    endpoint as another identity. A record carrying the victim's object id and
    the exact value this attack wrote was found on that read-back, so the
    unauthorized write provably persisted. That persisted read-back is the
    proof.
  Here's what happened - the Evidence chain (physical bytes the engine actually exchanged):
    1. Sent as the attacker:
       POST http://127.0.0.1:8001/api/users/2/display-name
       Content-Type: application/json
       Authorization: ***REDACTED***
       Body: {"display_name": "vm-1-eae9d9d20e"}
    2. Attack response received:
       -> HTTP 200 | Content-Length: 15
       {"status":"ok"}
    3. What decided it (byte-level):
       - the write was attributed to the attacker's own identity  (caller_identity=same_as_caller)
       - this attack's unique value was present in the read-back body - the write landed  (payload_causality=confirmed_in_body)
       - the anchoring read-back path was not found (observe-only)  (anchoring_result=failed_path_not_found)
    4. Not taken as proof:
       - the model's raw opinion alone did NOT decide this - the deterministic code channel did  (ai_verdict_raw=verified)
  Re-runnable evidence package (fill <REDACTED> from YOUR config; never a live token):
    # 1) The attack request - reproduces the cross-user access AS THE ATTACKER:
    curl -X POST 'http://127.0.0.1:8001/api/users/2/display-name' \
    -H 'Content-Type: application/json' \
    -H 'Authorization: <REDACTED>' \
    --data '{"display_name": "vm-1-eae9d9d20e"}'
  So what / Next step:
    A real cross-user access bug: the attacker could write to the victim's
    object. It is reproducible (the request above).
    Next: report it, or fix by enforcing an ownership check on this endpoint.
  [lab oracle] lab label=REAL (expects verified); engine said 'verified' - AGREES. (informational only; NEVER an input to the verdict)
```

And when the attacker gains nothing, the tool says so: a run with no cross-user effect returns **`[REFUTED]`** ("the code gate held the line — no cross-user effect confirmed"); a run that gets rate-limited or hits an expired token returns **`[NOT DATA]`** and claims **no verdict at all** — neither safe nor vulnerable. It refuses to guess. That refusal is the whole point.

## The proof — 430 runs, zero false positives

Five confirmation shapes — cross-user write, read-type semantic equivalence, silent-write / object-state, delete / negative-assertion, and mass-assignment / low-entropy state-jump — run against **two structurally different, self-contained vulnerable labs** (integer ids and UUID ids), driven by a **real** `gemini-2.5-pro` loop, freshly seeded every run:

| | Result |
|---|---|
| SECURE / control runs → final `verified` | **300 → 0** — zero false positives |
| Real-vulnerability runs → final `verified` | **130 → 130** — every planted flaw caught, via its expected channel |
| Usable runs | **430 / 430**, zero degraded |
| Times the model's raw output asked to `verified` a SECURE endpoint — and the gate refused | **79 / 79** |

Read that last row again: on **79** separate runs the AI wanted to confirm a vulnerability that wasn't there, and the code gate stopped all 79 from ever reaching a `verified`. That is the moat, measured.

**This is a controlled benchmark on two labs — not a tally of real-world kills.** Clean real-world confirmations are genuinely rare, and this project's honest headline is *discriminative power plus a zero-false-positive discipline*, not a screen full of `CONFIRMED`. Every number above is recomputed from the committed artifact `scripts/measure/results/sweep_highN.jsonl` — see [`RESULTS.md`](./RESULTS.md).

## Quickstart

Python 3.11+ and a Gemini API key (`GEMINI_API_KEY`):

```bash
pip install -e .          # installs the `aivist` command
aivist config             # choose provider, paste your API key (hidden), pick a model
aivist demo               # confirm a real BOLA on the built-in lab — zero setup
```

Then point it at your **own** locally-running target — the shortest path is the interactive console:

```bash
aivist                    # opens the console: demo · config · target · verify · scan
```

…or drive it non-interactively (below).

## Installation & full usage

```bash
git clone git@github.com:Aivist/Aivist-Verify.git
cd Aivist-Verify
pip install -e .          # registers the `aivist` command; config lives under ~/.aivist/
```

**`aivist verify` — confirm one finding.**

```bash
# LAB mode: confirm against a built-in ground-truth caseset
aivist verify --caseset <caseset.json> [--case <id>]

# EXTERNAL mode: a locally-run real target = base URL + OpenAPI spec + one operation
aivist verify --target http://localhost:8888 --spec ./openapi.json --op ./operation.json
# optional: --auth ./login.json for automatic re-login instead of static tokens
```

**`aivist scan` — non-interactive auto-discovery + confirm.** From an OpenAPI spec *or* spec-less:

```bash
aivist scan --target-file ./mytarget.txt
aivist scan --target-file ./mytarget.txt --endpoints-file ./endpoints.txt   # plain METHOD /path list
aivist scan --target-file ./mytarget.txt --traffic-file   ./capture.har     # browser/Burp HAR or raw-HTTP
aivist scan --target-file ./mytarget.txt --capture                          # live mitmproxy capture
aivist scan --target-file ./mytarget.txt --assert-owner-only                # surface "broken for all" for review
```

**`aivist run --config <json>` — the fully non-interactive entry (CI / scripting).** JSON in, structured JSON to stdout, tokens from the environment only — no prompts. **This is the main path for automated use:**

```bash
aivist run --config ./config.json            # machine-readable JSON on stdout
aivist run --config ./config.json --pretty   # + a human summary on stderr (stdout stays pure JSON)
```

**`aivist target` / `aivist config`** — save a reusable target as one editable file (`--dump-template` / `--from-file`, all-errors-at-once validation); set the AI provider/key/model.

**Tokens** come from the environment (or, for `scan`, a `--tokens-file` read at use-time and never persisted):

```bash
export TARGET_ATTACKER_TOKEN=...    # the attacker (the attack is sent as this account)
export TARGET_OWNER_TOKEN=...       # the victim/owner (re-read only, as the owner)
export TARGET_BYSTANDER_TOKEN=...   # a third account that does NOT own the resource
```

An `attacker == owner` collision is refused fail-closed before the engine runs; tokens are never echoed or logged.

## Reproduce it yourself

You don't have to trust a transcript — the evidence is re-runnable in three independent layers:

```bash
# Layer 1 — the labs' own ground truth, NO API key. The engine is graded against these, never the reverse.
python -m pytest vulnerable_target/test_vulns.py -q      # 31 tests
python -m pytest depot_target/test_vulns.py -q           # 23 tests

# Layer 2 — the committed result artifact, NO API key: one JSON row per run, raw verdict -> final verdict,
# which exemption fired, every anchor, a per-row regression check. Small and diffable.
#   scripts/measure/results/sweep_highN.jsonl

# Layer 3 — regenerate Layer 2 from Layer 1 with YOUR OWN Gemini key (~430 calls).
python scripts/measure/verdict_measure.py \
  --caseset scripts/measure/casesets/vulnerable_target.json \
  --caseset scripts/measure/casesets/depot.json \
  --n-safe 20 --n-vuln 10 --out scripts/measure/results/sweep_highN.jsonl
```

Full method and the documented **bounds** of each channel: [`REPRODUCE.md`](./REPRODUCE.md) and [`RESULTS.md`](./RESULTS.md).

## ⚠️ Scope & safety

**Read this before pointing it at anything.**

- **Authorized targets only.** Confirming a BOLA/IDOR sends real cross-user requests with real credentials. Only run against systems you own or have **explicit written permission** to test. Unauthorized testing may be illegal.
- **Localhost / self-hosted targets.** Built and tested for locally-run targets you control. It is not a tool for scanning third-party or internet-facing systems, and it is not a mass-scanner.
- **No authentication of its own.** Aivist Verify has no access control around itself — run it locally, never expose it as a service.
- **You supply the credentials.** It only ever acts as the identities whose tokens you provide, against the single target you point it at.

A tool whose entire value is *honesty* has to be honest about its own boundaries. The narrower and clearer the scope, the more the zero-false-positive claim can be trusted.

## Capabilities & honest limits

**Supported (built and audited in-repo):** OpenAPI-spec and spec-less discovery (manual endpoint lists, HAR / raw-HTTP parsing, live mitmproxy capture); static-token *and* automatic re-login auth; a challenge/rate-limit circuit-breaker that aborts to `NOT DATA` rather than hammer a target; three model providers behind one seam (Gemini default, OpenAI-compatible, Anthropic); and the fully non-interactive `run --config` entry for CI.

**Limits, stated plainly:** the zero-false-positive record is measured on **two controlled labs**, not validated at scale across diverse real-world targets — "supported" means the capability exists and is audited, not that it's been battle-tested in the wild. The read-semantic confirmation gate has **documented bounds** (see `RESULTS.md`). The tool has **no authentication** and targets **localhost**.

## Repository layout

```
Aivist-Verify/
├─ run.py                    # CLI entry point (the `aivist` command)
├─ README.md · RESULTS.md · REPRODUCE.md · LICENSE
├─ backend/app/
│   ├─ services/             # the confirmation engine: differential oracle, deep verifier, exemption gates
│   └─ cli/                  # the command line and interactive console
├─ vulnerable_target/        # lab 1 (integer ids) + its independent ground-truth test suite
├─ depot_target/             # lab 2 (UUID ids) + ground-truth suite
├─ scripts/measure/          # the measurement harness + committed result artifacts (sweep_*.jsonl)
└─ docs/                     # architecture and engine documentation
```

## Documentation

- [`RESULTS.md`](./RESULTS.md) — the full zero-false-positive benchmark, case by case, with each channel's documented bounds.
- [`REPRODUCE.md`](./REPRODUCE.md) — reproduce the evidence yourself, three independent layers.
- [`docs/PROJECT_OVERVIEW.md`](./docs/PROJECT_OVERVIEW.md) — what exists today and how the pieces fit.
- [`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md) — the two-layer verdict pipeline in depth.
- [`docs/VERIFY_ENGINE.md`](./docs/VERIFY_ENGINE.md) / [`docs/DEEP_VERIFY.md`](./docs/DEEP_VERIFY.md) — the differential oracle and the deep verifier + the four exemption channels.

## License

MIT © 2026 Lang Li — see [`LICENSE`](./LICENSE).

---

<p align="center"><sub>Aivist Verify confirms; it does not merely flag. The AI proposes; code disposes; and code can only take a claim away, never invent one.</sub></p>
