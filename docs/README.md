# Documentation

Docs for **Aivist Verify** — a local, CLI-first web/API vulnerability **confirmation** engine.
Its mature core is BOLA/IDOR access control; it has begun covering other types (SSRF is the first
non-access-control type) via a tiered-verdict framework. See [`PROJECT_STATUS.md`](./PROJECT_STATUS.md)
for the current stage and direction. Start at the root [`README.md`](../README.md); this folder holds
the deeper references.

| Doc | Read it for |
|---|---|
| [`PROJECT_STATUS.md`](./PROJECT_STATUS.md) | Where the project is now and where it's headed — the public stage/direction snapshot. |
| [`PROJECT_OVERVIEW.md`](./PROJECT_OVERVIEW.md) | What exists today and how the pieces fit — the orientation entry point. |
| [`ARCHITECTURE.md`](./ARCHITECTURE.md) | How the engine is built: the two-layer verdict pipeline, the CLI surface, supporting layers, remote (§7), tiers (§8), SSRF (§9). |
| [`VERIFY_ENGINE.md`](./VERIFY_ENGINE.md) | The differential oracle (`fuzzer.py`) — rules, veto, escalation. |
| [`DEEP_VERIFY.md`](./DEEP_VERIFY.md) | The access-control deep verifier (`deep_verifier.py`) — the cross-resource guard + four exemption channels + the D24 owner-view gate. |
| [`SSRF.md`](./SSRF.md) | SSRF confirmation via out-of-band interactsh callback — the first non-access-control vuln type. |
| [`SQLI.md`](./SQLI.md) | Blind SQL injection confirmed via an injection-causal, token-matched out-of-band callback — the fourth vuln type. |
| [`OOB.md`](./OOB.md) | The out-of-band (interactsh) client the SSRF / SQLi detectors use. |
| [`CLI_ORIENTATION.md`](./CLI_ORIENTATION.md) | A code-anchored map of the CLI front doors (`verify` / `scan` / `run` / `ssrf` / `demo`). |
| [`QUICKSTART.md`](./QUICKSTART.md) | Run it now — the lab demo, a real-target `verify`, `scan`, `ssrf`, and the non-interactive `run`. |
| [`DEVELOPMENT.md`](./DEVELOPMENT.md) | Contributor setup and how to run the test suites. |
| [`LLM_PROVIDERS.md`](./LLM_PROVIDERS.md) | Bring your own model / gateway (Gemini default · OpenAI-compatible incl. DeepSeek · Anthropic) and the connectivity-not-zero-FP boundary. |

Evidence lives at the repo root: [`../RESULTS.md`](../RESULTS.md) (the zero-false-positive
benchmark, recomputed from the committed artifact) and [`../REPRODUCE.md`](../REPRODUCE.md)
(reproduce it yourself in three independent layers). For the **third-party** runs — the engine against
two public vulnerable targets it was not built for — see
[`../scripts/measure/real_targets/REAL_TARGET_RESULTS.md`](../scripts/measure/real_targets/REAL_TARGET_RESULTS.md)
(9 runs on crAPI + VAmPI, every capture archived verbatim; an engineering signal on hand-verified
ground truth, **not** an extension of the statistical benchmark). For the **authorized-remote path** —
the confirmer driven over a non-loopback network interface — see
[`../scripts/measure/real_targets/REMOTE_TARGET_RESULTS.md`](../scripts/measure/real_targets/REMOTE_TARGET_RESULTS.md)
(a controlled non-loopback target; likewise an engineering signal, not a benchmark entry). The rails that
make the remote path safe are locked by `backend/tests/test_remote_safety_lock.py` and
`backend/tests/test_remote_e2e_lock.py`.

> All docs are grounded in the source tree and cite file references. When code and docs
> disagree, the code wins — please update the docs.
