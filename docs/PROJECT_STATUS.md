# Project Status & Direction

> A public snapshot of where Aivist Verify is and where it's headed, for anyone reading the repo.
> Capabilities and scope are stated honestly; for the mechanism see [`ARCHITECTURE.md`](./ARCHITECTURE.md),
> for the evidence see [`../RESULTS.md`](../RESULTS.md) and [`../REPRODUCE.md`](../REPRODUCE.md).

## What it is

Aivist Verify is a **local, CLI-first confirmation engine** for web/API vulnerabilities. You give it a
candidate; it treats the target as a **black box** and tells you — with a reproducible evidence chain —
whether the issue is real, or an honest "not confirmed." It is a *confirmation* layer, not a scanner and
not an exploitation tool, and it runs from the command line against targets you own or are authorized to
test. There is no server, HTTP API, or web UI.

The property that defines it: **a verdict is decided by code, not the model.** An AI (or a heuristic) may
*propose*; a deterministic, downgrade-only gate *disposes*. `CONFIRMED` is reserved, by construction, for a
finding backed by a **deterministic proof** — never a model's say-so.

## Direction — one discipline, many vuln types

The engine is built to cover **multiple web/API vulnerability types** behind a single verdict discipline,
expressed by the **tiered-verdict framework** ([`ARCHITECTURE.md`](./ARCHITECTURE.md) §8):

- **`CONFIRMED`** — reserved for a type whose finding is **deterministically provable** by code (e.g. a
  cross-user read the tool re-derives, or an out-of-band callback the target actually made).
- **`SIGNAL`** — a positive but **inference-only** lead for a future non-deterministic detector; it can
  never reach `CONFIRMED`.
- **`REFUTED`** / **`NOT DATA`** — checked with no effect, or not enough signal to judge (a rate-limit,
  an expired token, an unreachable dependency). The tool refuses to guess.

New vuln types plug in as **detectors** under this framework, so adding a type never dilutes the
zero-false-positive discipline of the ones already shipped.

## What has shipped

- **Access-control confirmation (BOLA / IDOR)** — the mature core. Five confirmation shapes
  (cross-user write, read-semantic, silent-write / object-state, delete, mass-assignment), each gated by a
  deterministic code channel. Object ids in the **path or the query string** are both supported.
- **Query-string / non-path IDOR** — an id carried in `?param=` is expressed, attacked, and
  owner-view-corroborated exactly like a path id.
- **Authorized-remote targets** — the confirmer runs against a local **or an authorized remote** host with
  the same verdict logic, hardened at the network layer (fail-closed scope lock; cloud-metadata /
  link-local / DNS-rebinding refusal; connection pinned to the scope-validated IP; per-hop redirect
  re-validation; a challenge / rate-limit circuit-breaker).
- **SSRF via out-of-band callback** — the **first non-access-control vuln type**. It is `CONFIRMED` only
  when the target's server makes a real callback to a unique probe domain (the interaction is the
  deterministic proof); otherwise `REFUTED` or `NOT DATA`. Reachable via `aivist ssrf`.
- **Bring-your-own model** — a provider seam (Gemini default; OpenAI-compatible including **DeepSeek**;
  Anthropic). Because verdicts are decided by the code gate reading HTTP evidence, the discipline does not
  depend on which model proposes.
- **CI-ready** — a fully non-interactive `run --config` entry and a packaged GitHub Action that turns
  access-control confirmation into a regression gate (confirm-only, fail-on-confirm).

## Scope, stated plainly

- The engine treats each target as a **black box** and only ever acts as the identities whose credentials
  you supply, against the single target you point it at. It has no authentication of its own — run it
  where only you can reach it.
- The controlled zero-false-positive benchmark is measured on two self-contained labs with a real model;
  it is a statement of **discriminative power plus a zero-FP discipline**, not a tally of real-world
  findings. Runs against public real targets are an engineering signal on hand-verified ground truth, not
  an extension of that statistical record.
- SSRF confirmation needs **outbound network and a reachable out-of-band (interactsh) server**; with none
  reachable it returns `NOT DATA`, never a guess.

## Where to read next

- [`PROJECT_OVERVIEW.md`](./PROJECT_OVERVIEW.md) — what exists today and how the pieces fit.
- [`ARCHITECTURE.md`](./ARCHITECTURE.md) — the verdict pipeline, the CLI surface, remote (§7), the tiered
  framework (§8), and SSRF (§9).
- [`SSRF.md`](./SSRF.md) / [`OOB.md`](./OOB.md) — the SSRF detector and the out-of-band client it uses.
- [`LLM_PROVIDERS.md`](./LLM_PROVIDERS.md) — model/provider options and the connectivity-not-correctness boundary.
