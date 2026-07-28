# Documentation Index

Developer/agent handoff docs for the Anti-Gravity AI Penetration Testing
Platform. **All project documentation lives here in `docs/`** (the repo root keeps
only a thin [`README.md`](../README.md) pointer).

**Reading order:** [`STATUS.md`](./STATUS.md) (where we are *now*) →
[`ROADMAP.md`](./ROADMAP.md) (strategy — why/where) →
[`PROJECT_OVERVIEW.md`](./PROJECT_OVERVIEW.md) (acceptance snapshot — what exists,
中文) → [`ARCHITECTURE.md`](./ARCHITECTURE.md) (engineering — how) → component docs
(VERIFY_ENGINE / DEEP_VERIFY / …) → [`TECH_DEBT.md`](./TECH_DEBT.md) (known gaps).

| Doc | Read it for |
|---|---|
| [`STATUS.md`](./STATUS.md) | **Current-state snapshot** — progress, what's proven, what's uncommitted/in flight, what's deferred. *Where the project stands right now.* **Read first.** |
| [`ROADMAP.md`](./ROADMAP.md) | **Strategy** (human-owned) — the thesis, explicit non-goals, main-line direction (B-1 / D19 / scope-lock), authorization reality. *Why / where.* |
| [`PROJECT_OVERVIEW.md`](./PROJECT_OVERVIEW.md) | **Acceptance snapshot (中文)** — product positioning, maturity, the end-to-end pipeline, API summary, run/verify checklist. Non-engineering entry point. |
| [`ARCHITECTURE.md`](./ARCHITECTURE.md) | System overview, components, runtime/concurrency model, security posture, directory map. Includes the **Step 9 proxy radar** and the **unified WriterService**. **Engineering entry point.** |
| [`DATA_MODEL.md`](./DATA_MODEL.md) | ORM tables, Step D columns, the **`captured_flows`** table (Step 9), the create_all migration gotcha. |
| [`HUNTER_PIPELINE.md`](./HUNTER_PIPELINE.md) | AI Logic Hunter: HAR ingest → prune → parse → Gemini analyze → persist (Step D). |
| [`VERIFY_ENGINE.md`](./VERIFY_ENGINE.md) | Differential fuzzing engine, oracle rules, auth-custody self-heal, parallel single-writer design (generalized to the app-wide WriterService in Step 9), and the read-only shadow **Phase 7**. **The core.** |
| [`DEEP_VERIFY.md`](./DEEP_VERIFY.md) | `deep_verifier.py` — AI write-then-read verifier (**4-value**: adds `inconclusive` + the B-2.2 cross-resource guard, vs the rule oracle's 3-value); not API-wired, invoked **read-only** by the fuzzer's shadow-mode **Phase 7**. Two gates, both default `False`. Endpoint surface seeded by `services/endpoint_catalog.py` (**D18**). Also documents the in-flight **B-1** write-record machinery. || [`../vulnerable_target/README.md`](../vulnerable_target/README.md) | Standalone ground-truth practice target (`:8001`) + planted-vuln answer key for benchmarks. |
| [`API_REFERENCE.md`](./API_REFERENCE.md) | Every HTTP endpoint, request/response shapes, status codes — including the **`/proxy/*` radar** routes (Step 9). |
| [`DEVELOPMENT.md`](./DEVELOPMENT.md) | Configure, run, test; Windows/PowerShell notes; DB reset recipe; manual E2E; **mitmproxy install + the two dependency pins** + proxy radar quickstart (Step 9). |
| [`TECH_DEBT.md`](./TECH_DEBT.md) | Known issues / risks / what's already resolved (incl. Step 9 R4, the §5 integrity fix R6), with a suggested priority order. |

> All docs are grounded in the source tree and include file references (e.g.
> `backend/app/services/fuzzer.py`). When code and docs disagree, the code wins —
> please update the docs.
>
> **Test counts:** `backend/tests` → **293** passed; `vulnerable_target` → **31**
> (separate suite). See [`STATUS.md`](./STATUS.md).
