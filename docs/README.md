# Documentation Index

Developer/agent handoff docs for the Anti-Gravity AI Penetration Testing
Platform. **Reading order:** [`../ROADMAP.md`](../ROADMAP.md) (strategy — why/where) →
[`../PROJECT_OVERVIEW.md`](../PROJECT_OVERVIEW.md) (acceptance snapshot — what exists now) →
[`ARCHITECTURE.md`](./ARCHITECTURE.md) (engineering — how) → component docs
(VERIFY_ENGINE / DEEP_VERIFY / …) → [`TECH_DEBT.md`](./TECH_DEBT.md) (known gaps).

| Doc | Read it for |
|---|---|
| [`../ROADMAP.md`](../ROADMAP.md) | **Strategy entry point** (human-owned) — the thesis, explicit non-goals, main-line direction (B-1 / D19 / scope-lock), and authorization reality. *Why / where* the project is going. **Read first.** |
| [`../PROJECT_OVERVIEW.md`](../PROJECT_OVERVIEW.md) | **Acceptance snapshot** — one-page product positioning, maturity, API summary, run/verify checklist. Non-engineering entry point. |
| [`ARCHITECTURE.md`](./ARCHITECTURE.md) | System overview, components, runtime/concurrency model, security posture, directory map. Includes the **Step 9 proxy radar** (ProxyManager / proxy_pipeline / SSE hub) and the **unified WriterService**. **Engineering entry point.** |
| [`DATA_MODEL.md`](./DATA_MODEL.md) | ORM tables, Step D columns, the **`captured_flows`** table (Step 9), the create_all migration gotcha. |
| [`HUNTER_PIPELINE.md`](./HUNTER_PIPELINE.md) | AI Logic Hunter: HAR ingest → prune → parse → Gemini analyze → persist (Step D). |
| [`VERIFY_ENGINE.md`](./VERIFY_ENGINE.md) | Differential fuzzing engine, oracle rules, auth-custody self-heal, parallel single-writer design (generalized to the app-wide WriterService in Step 9). **The core.** |
| [`DEEP_VERIFY.md`](./DEEP_VERIFY.md) | `deep_verifier.py` — AI write-then-read verifier (**4-value**: adds `inconclusive` + the B-2.2 cross-resource guard, vs the rule oracle's 3-value); not API-wired, but invoked **read-only** by the fuzzer's shadow-mode **Phase 7**. Two gates, both default `False`: `AI_DEEP_VERIFY_ENABLED` + `AI_DEEP_VERIFY_SHADOW`. Endpoint surface seeded by `services/endpoint_catalog.py` (**D18**; OpenAPI → bare `"METHOD /path"`), spec via `AI_DEEP_VERIFY_OPENAPI_SPEC`. |
| [`NUCLEI_SCAN_PIPELINE.md`](./NUCLEI_SCAN_PIPELINE.md) | Nuclei 3-phase scanner + adaptive profiler. |
| [`../vulnerable_target/README.md`](../vulnerable_target/README.md) | Standalone ground-truth practice target (`:8001`) + planted vuln answer key for benchmarks. |
| [`API_REFERENCE.md`](./API_REFERENCE.md) | Every HTTP endpoint, request/response shapes, status codes — including the **`/proxy/*` radar** routes (Step 9). |
| [`DEVELOPMENT.md`](./DEVELOPMENT.md) | Configure, run, test; Windows/PowerShell notes; DB reset recipe; manual E2E; **mitmproxy install + the two dependency pins** + proxy radar quickstart (Step 9). |
| [`TECH_DEBT.md`](./TECH_DEBT.md) | Known issues / risks / what's already resolved (incl. Step 9 R4), with a suggested priority order. |

> All docs are grounded in the source tree as of the current commit and include
> file references (e.g. `backend/app/services/fuzzer.py`). When code and docs
> disagree, the code wins — please update the docs.
>
> **Test counts:** `backend/tests` → **112** collected; `vulnerable_target/test_vulns.py` → **14** (separate suite).
