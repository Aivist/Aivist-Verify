# Documentation Index

Developer/agent handoff docs for the Anti-Gravity AI Penetration Testing
Platform. **Start with [`ARCHITECTURE.md`](./ARCHITECTURE.md).**

| Doc | Read it for |
|---|---|
| [`ARCHITECTURE.md`](./ARCHITECTURE.md) | System overview, components, runtime/concurrency model, security posture, directory map. **Entry point.** |
| [`DATA_MODEL.md`](./DATA_MODEL.md) | ORM tables, Step D columns, the create_all migration gotcha. |
| [`HUNTER_PIPELINE.md`](./HUNTER_PIPELINE.md) | AI Logic Hunter: HAR ingest → prune → parse → Gemini analyze → persist (Step D). |
| [`VERIFY_ENGINE.md`](./VERIFY_ENGINE.md) | Differential fuzzing engine, oracle rules, auth-custody self-heal, parallel single-writer design. **The core.** |
| [`NUCLEI_SCAN_PIPELINE.md`](./NUCLEI_SCAN_PIPELINE.md) | Nuclei 3-phase scanner + adaptive profiler. |
| [`API_REFERENCE.md`](./API_REFERENCE.md) | Every HTTP endpoint, request/response shapes, status codes. |
| [`DEVELOPMENT.md`](./DEVELOPMENT.md) | Configure, run, test; Windows/PowerShell notes; DB reset recipe; manual E2E. |
| [`TECH_DEBT.md`](./TECH_DEBT.md) | Known issues / risks / what's already resolved, with a suggested priority order. |

> All docs are grounded in the source tree as of the current commit and include
> file references (e.g. `backend/app/services/fuzzer.py`). When code and docs
> disagree, the code wins — please update the docs.
