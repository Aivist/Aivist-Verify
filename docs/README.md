# Documentation

Docs for **Aivist Verify** — the local, CLI-first BOLA/IDOR access-control confirmation engine.
Start at the root [`README.md`](../README.md); this folder holds the deeper references.

| Doc | Read it for |
|---|---|
| [`PROJECT_OVERVIEW.md`](./PROJECT_OVERVIEW.md) | What exists today and how the pieces fit — the orientation entry point. |
| [`ARCHITECTURE.md`](./ARCHITECTURE.md) | How the engine is built: the two-layer verdict pipeline, the CLI surface, supporting layers. |
| [`VERIFY_ENGINE.md`](./VERIFY_ENGINE.md) | The differential oracle (`fuzzer.py`) — rules, veto, escalation. |
| [`DEEP_VERIFY.md`](./DEEP_VERIFY.md) | The deep verifier (`deep_verifier.py`) — the cross-resource guard + the four code-computed exemption channels. |
| [`CLI_ORIENTATION.md`](./CLI_ORIENTATION.md) | A code-anchored map of the CLI front doors (`verify` / `scan` / `run` / `demo`). |
| [`QUICKSTART.md`](./QUICKSTART.md) | Run it now — the lab demo, a real-target `verify`, `scan`, and the non-interactive `run`. |
| [`DEVELOPMENT.md`](./DEVELOPMENT.md) | Contributor setup and how to run the test suites. |
| [`LLM_PROVIDERS.md`](./LLM_PROVIDERS.md) | Bring your own model / gateway (Gemini default · OpenAI-compatible · Anthropic) and the connectivity-not-zero-FP boundary. |

Evidence lives at the repo root: [`../RESULTS.md`](../RESULTS.md) (the zero-false-positive
benchmark, recomputed from the committed artifact) and [`../REPRODUCE.md`](../REPRODUCE.md)
(reproduce it yourself in three independent layers).

> All docs are grounded in the source tree and cite file references. When code and docs
> disagree, the code wins — please update the docs.
