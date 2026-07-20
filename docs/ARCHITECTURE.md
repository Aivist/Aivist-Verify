# ARCHITECTURE — Anti-Gravity AI Penetration Testing Platform

> Audience: a developer/agent taking over this codebase. This document is the
> **engineering** entry point — it describes what the system is, how the pieces fit
> together, the runtime/concurrency model, and the security posture. For the
> **strategy/direction** entry point (thesis, non-goals, where it's going) start at
> [`ROADMAP.md`](./ROADMAP.md). Every claim here is grounded in the current source
> tree (see file references).
>
> Companion docs:
> - [`DATA_MODEL.md`](./DATA_MODEL.md) — database schema & ORM
> - [`HUNTER_PIPELINE.md`](./HUNTER_PIPELINE.md) — AI Logic Hunter (HAR → analyze → persist)
> - [`VERIFY_ENGINE.md`](./VERIFY_ENGINE.md) — differential fuzzing / verification engine
> - [`DEEP_VERIFY.md`](./DEEP_VERIFY.md) — `deep_verifier.py` (AI write-then-read; shadow-mode Phase 7, not API-wired)
> - [`NUCLEI_SCAN_PIPELINE.md`](./NUCLEI_SCAN_PIPELINE.md) — Nuclei 3-phase scanner
> - [`API_REFERENCE.md`](./API_REFERENCE.md) — every HTTP endpoint
> - [`DEVELOPMENT.md`](./DEVELOPMENT.md) — how to run & test
> - [`TECH_DEBT.md`](./TECH_DEBT.md) — known issues / risks / TODO

---

## 1. What this product is

A single-tenant, locally-run web application for **AI-assisted web application
penetration testing**. It has two largely independent analysis subsystems that
share one database and one frontend:

1. **Nuclei Scanner** — point it at a URL, it runs the external `nuclei` binary,
   ingests findings, and asks Gemini to write remediation patches.
2. **AI Logic Hunter** — paste a raw HTTP request (or import a HAR file), Gemini
   proposes business-logic exploit payloads (BOLA/IDOR, mass-assignment, etc.),
   and a built-in **differential fuzzing engine** actively *verifies* whether
   those payloads work against the live target.

The Hunter → Verify path is the more novel/valuable subsystem. The Nuclei path
is a more conventional scanner wrapper.

A third, **passive** front-end feeds the Hunter:

3. **Proxy Radar (Step 9)** — a supervised `mitmdump` subprocess acts as an
   HTTP/S intercepting proxy. The operator points a browser at it; in-scope
   dynamic flows are captured, scored, persisted to `captured_flows`, streamed
   live to the UI over SSE, and can be promoted into the Hunter → Verify pipeline
   with one click. It does not actively attack — it observes traffic the operator
   generates.

---

## 2. Tech stack

| Layer | Technology |
|---|---|
| Web framework | FastAPI (ASGI), served by uvicorn |
| Validation | Pydantic v2 + `pydantic-settings` |
| ORM | SQLAlchemy 2.0 **async** |
| Database | SQLite via `aiosqlite` (WAL mode) |
| HTTP client | `httpx.AsyncClient` (TLS verification disabled by design) |
| External scanner | Nuclei (subprocess) |
| Intercepting proxy | mitmproxy's `mitmdump` (subprocess, supervised by `ProxyManager`) |
| AI | Google Gemini via the official `google-genai` SDK |
| Frontend (canonical) | `preview_dashboard.html` — single-file React (CDN + Babel), Tailwind, light theme |
| Frontend (legacy) | `frontend/` Vite + TypeScript app — **dark theme, mock data, NOT the product baseline** |

> **Frontend note:** `preview_dashboard.html` at the repo root is the canonical,
> fully-wired UI. The `frontend/` Vite project is a historical/experimental
> branch running on mock data; do not treat it as the source of truth unless a
> migration is explicitly planned.

---

## 3. Directory map

```
anti gravity/
├─ preview_dashboard.html         # CANONICAL frontend (single file, talks to :8000)
├─ backend/
│  ├─ .env                        # config (NUCLEI_BINARY_PATH, GEMINI_API_KEY, ...)
│  ├─ run.py                      # uvicorn entrypoint (reload=True)
│  ├─ requirements.txt            # runtime deps
│  ├─ requirements-dev.txt        # pytest (dev-only)
│  ├─ app/
│  │  ├─ main.py                  # FastAPI app, lifespan create_all + schema check, CORS, routers
│  │  ├─ core/
│  │  │  ├─ config.py             # Pydantic Settings + validators (fail-fast)
│  │  │  └─ database.py           # async engine, session factory, get_db, SQLite pragmas
│  │  ├─ models/
│  │  │  └─ scan.py               # ScanTask, VulnerabilityFinding, FuzzingRecord, CapturedFlow
│  │  ├─ schemas/
│  │  │  ├─ scan.py               # Nuclei scan request/response schemas
│  │  │  ├─ hunter.py             # Hunter + verify + HAR + batch schemas
│  │  │  └─ proxy.py              # Step 9: ingest/projection/control/status contracts
│  │  ├─ api/v1/
│  │  │  ├─ scan.py               # /api/v1/scan/*  (Nuclei)
│  │  │  └─ hunter.py             # /api/v1/hunter/* (Hunter, verify, HAR, batch, auth, proxy)
│  │  ├─ proxy/
│  │  │  └─ radar_addon.py        # Step 9: mitmdump addon (separate interpreter), Tier-1 filter + loopback POST
│  │  └─ services/
│  │     ├─ nuclei.py             # 3-phase scan orchestrator + Gemini patch + profiler
│  │     ├─ traffic_parser.py     # raw HTTP text → structured dict
│  │     ├─ pruner.py             # heuristic exposure scoring / HAR noise filter (shared Tier-2 helpers)
│  │     ├─ fuzzer.py             # differential fuzzing engine + auth custody (the core)
│  │     ├─ proxy_pipeline.py     # Step 9: unified WriterService + SSEHub + ingest pipeline
│  │     ├─ proxy_manager.py      # Step 9: mitmdump process state machine + OS-agnostic tree kill
│  │     ├─ deep_verifier.py      # AI write-then-read verifier (shadow-mode Phase 7; not API-wired)
│  │     └─ endpoint_catalog.py   # D18: OpenAPI → "METHOD /path [tags/operationId]" catalog + write-record queries (B-1)
│  ├─ scripts/
│  │  └─ deep_verify_live_check.py  # Manual Gemini+target check (not pytest)
│  └─ tests/                      # pytest (227): pruner, step8_custody,
│                                 # step_d_hunter_link, api_endpoints, step9_proxy, verdict_oracle,
│                                 # endpoint_catalog, d18_phase2_crosspath, d18_b22_guard, d18_b1_write_record,
│                                 # d18_b1_shadow_integration, m1_evidence_anchoring, m12_object_scope,
│                                 # m12_state_readback_exemption (M1.2A), m12b_state_gather (M1.2B)
├─ vulnerable_target/            # Standalone ground-truth target (:8001), own DB, 14 pytest cases
│  ├─ main.py
│  ├─ test_vulns.py
│  └─ benchmark/                  # BAC verification benchmark docs + RESULTS
├─ scripts/audit/                # verdict-accuracy measurement harnesses/outputs (not product code)
├─ README.md                     # thin root pointer into docs/
└─ docs/                          # ALL project docs (ROADMAP, STATUS, PROJECT_OVERVIEW, this file, …)
```

---

## 4. Request → work flow (high level)

### 4a. Nuclei scan
```
POST /api/v1/scan/start
  → persist ScanTask(status="running")
  → BackgroundTasks: execute_nuclei_scan_async(...)
       Phase 0: fingerprint target → adaptive -tags
       Phase 1: subprocess.Popen(nuclei -jsonl) + reader thread → fast DB inserts (no AI)
       Phase 2: mark ScanTask completed/failed
       Phase 3: batch Gemini remediation patches for critical/high findings
GET /api/v1/scan/{id}            → poll status
GET /api/v1/scan/{id}/findings   → list findings (scan-scoped)
```

### 4b. Hunter → Verify (the key path)
```
(optional) POST /hunter/ingest-har[-file]  → prune HAR → high-value endpoints
POST /hunter/analyze            → parse raw HTTP + Gemini → report + automation_payloads
POST /hunter/findings           → persist analysis as VulnerabilityFinding(source="hunter")   [Step D bridge]
POST /hunter/verify/{id}        → BackgroundTasks: execute_differential_fuzzing(id)
GET  /hunter/verify/{id}/results→ poll FuzzingRecord rows (verdicts + diffs)
POST /hunter/verify/batch       → true-concurrent multi-endpoint fuzzing (shared auth custody)
POST /hunter/auth/dry-run       → test an Identity Provider Anchor (re-auth) before a batch
```

> **AI deep verifier (shadow mode).** The fuzzer additionally has an
> **AI-in-the-loop deep verifier** (`services/deep_verifier.py`) wired as an
> additive, read-only **Phase 7** of `execute_parallel_fuzzing`. Gated by
> `AI_DEEP_VERIFY_SHADOW` (default off; needs `AI_DEEP_VERIFY_ENABLED` too for a
> live Gemini call), it re-checks `suspicious` records with a two-turn
> write-then-read and **only logs** its verdict — it never changes the persisted
> verdict or what the user sees. Unlike the rule oracle (`_differential_verdict`,
> **3-value**: `verified`/`suspicious`/`failed`, unchanged), the AI verifier is
> **4-value**: it adds `inconclusive` for a genuine evidence gap. A deterministic
> structural **cross-resource guard** (B-2.2, `_apply_cross_resource_guard` /
> `CROSS_RESOURCE_OVERRIDE_REASON`) downgrades a `verified`/`failed` that rests on a
> follow-up read-back of a *different* path to `inconclusive`; the result preserves
> the model's raw verdict and any override (`ai_verdict_raw` + `guard_override`,
> with `ai_verdict` being the final post-guard value). Two **structural exemptions**
> (both `verified`-only, cross-path-only, and disjoint) can keep such a verdict decisive:
> **B-1's write-record** match (`WRITE_RECORD_EXEMPTION_REASON`) and **M1.2's object-state
> read-back** (`STATE_READBACK_EXEMPTION_REASON`, gated on owner-identity ∧ caller!=owner ∧
> **payload-causality** — the false-positive gate). The decisive read-back is **code-gathered**,
> not model-chosen (`select_write_record_endpoint` / `select_object_state_endpoint`). See
> [`VERIFY_ENGINE.md`](./VERIFY_ENGINE.md) §Phase 7 and
> [`DEEP_VERIFY.md`](./DEEP_VERIFY.md).

### 4c. Proxy Radar (Step 9 — passive capture)
```
POST /hunter/proxy/start  → ProxyManager spawns mitmdump with radar_addon.py
                            (env carries scope host, ingest URL, per-session token)
browser → mitmdump:
   Tier-1 (inline, <5ms): host-scope lock + static-asset veto (radar_addon.py)
   in-scope dynamic flow → fire-and-forget loopback HTTP POST
        → POST /hunter/proxy/internal-ingest  (loopback-only + token; include_in_schema=False)
             → ProxyIngestPipeline bounded asyncio.Queue
                  Tier-2 (async): calculate_exposure_score + detect_login_candidate
                  → WriterService (single serialized SQLite writer) → captured_flows
                  → SSEHub.publish(flow)
GET /hunter/proxy/stream  → SSE fan-out of captured flows to the UI
GET /hunter/proxy/flows   → recent captured flows (DB read projection)
GET /hunter/proxy/cert    → download the mitmproxy CA cert (for HTTPS interception)
POST /hunter/proxy/stop   → graceful stop + OS-agnostic process-tree kill
```

See [`HUNTER_PIPELINE.md`](./HUNTER_PIPELINE.md) and [`VERIFY_ENGINE.md`](./VERIFY_ENGINE.md) for the internals.

---

## 5. Runtime & concurrency model

- **One process, one event loop.** uvicorn runs the ASGI app. Long jobs are
  offloaded with FastAPI `BackgroundTasks` (in-process, same loop), *not* a
  separate queue/worker (no Celery/RQ/Redis).
- **Nuclei reader is threaded.** `nuclei.py` uses `subprocess.Popen` + a daemon
  `threading.Thread` to read stdout line-by-line, dispatching DB writes back to
  the event loop via `asyncio.run_coroutine_threadsafe`. This is for Windows
  compatibility and to avoid blocking the loop on process I/O.
- **Fuzzing is fully async.** `fuzzer.py` runs concurrent `httpx` requests under
  an `asyncio.Semaphore`, but **all database writes funnel through a single
  consumer coroutine** draining an `asyncio.Queue`. This is the central design
  rule: *parallelize the network, serialize the DB.*
  → See the `async-session-custody` skill and [`VERIFY_ENGINE.md`](./VERIFY_ENGINE.md).
- **Unified WriterService (Step 9).** The single-writer pattern was generalized
  out of the fuzzer into an **app-wide** `WriterService` (in
  `services/proxy_pipeline.py`): one long-lived consumer coroutine drains a queue
  of `WriteJob` callables and executes them sequentially against one
  `AsyncSession`. It is started in the lifespan and shared by **both** the proxy
  ingest pipeline and the fuzzer. When the service is running the fuzzer forwards
  its persistence jobs to it (so there is globally at most one SQLite writer);
  when it isn't (e.g. an isolated unit test), the fuzzer falls back to an
  ephemeral per-batch consumer. Net effect: *one writer for the whole process.*
- **Proxy IPC is out-of-process (Step 9).** `mitmdump` runs in a **separate
  Python interpreter**, so shared globals don't work. The `radar_addon.py` ships
  captured flows back to FastAPI via a low-latency loopback HTTP POST to
  `/hunter/proxy/internal-ingest`, which feeds an in-process `asyncio.Queue`.
  `ProxyManager` supervises the child: a small state machine, bounded restarts
  with backoff/circuit-breaker, and **OS-agnostic clean tree termination**
  (`taskkill /F /T` on Windows, process-group signals on Unix) wired into the
  lifespan so no orphan proxy survives a crash.
- **SSE is non-blocking with cleanup (Step 9).** `SSEHub` fans out flows to
  subscribers via **bounded per-client queues** (overflow drops oldest, never
  blocks ingest), enforces a max-subscriber cap, emits heartbeats, and on client
  disconnect catches `asyncio.CancelledError` to remove the queue — no memory
  leak.
- **SQLite tuning.** `database.py` sets `PRAGMA journal_mode=WAL`,
  `busy_timeout=5000`, and `synchronous=NORMAL` so reads proceed during writes and
  transient "database is locked" is waited out; writers wrap commits in a
  `commit_with_retry` helper with exponential backoff.

---

## 6. Configuration & startup

- `backend/app/core/config.py` loads `backend/.env` via `pydantic-settings`.
- **`NUCLEI_BINARY_PATH` is required and must be absolute** (validator rejects
  relative paths to prevent execution hijack). Its *existence* is only
  soft-checked, so the server boots even if the binary isn't installed (scans
  will then fail at runtime with a clear log).
- `GEMINI_API_KEY` is optional; when missing, all AI calls return a graceful
  Chinese "degraded" fallback string instead of crashing.
- **AI deep-verify flags** (both default `False`, so off by default):
  `AI_DEEP_VERIFY_ENABLED` (the `deep_verifier.py` component may run / call Gemini)
  and `AI_DEEP_VERIFY_SHADOW` (the fuzzer runs the read-only Phase 7 shadow pass).
  Both must be `True` for a live shadow second opinion. See
  [`DEEP_VERIFY.md`](./DEEP_VERIFY.md).
- On startup, `main.py`'s lifespan runs `Base.metadata.create_all`, then
  `_verify_schema_integrity` (D1) — `create_all` **creates missing tables but
  never alters existing ones**; the integrity check refuses to boot if an existing
  DB is missing ORM columns (see [`DATA_MODEL.md`](./DATA_MODEL.md) §Migrations).
- **Step 9 lifespan wiring:** the lifespan also **starts the `WriterService`**
  (and the `ProxyIngestPipeline`/`SSEHub`) on startup, and after `yield`
  **stops the proxy and drains/stops the writer** on shutdown, in that order, so
  the proxy subprocess and the writer coroutine are torn down cleanly.
- **Step 9 proxy config:** `config.py` adds `MITMDUMP_PATH` (validated; resolved
  from PATH if blank), `PROXY_LISTEN_PORT`, and bounds — `PROXY_INGEST_QUEUE_MAX`,
  `PROXY_SSE_MAX_CLIENTS`, `PROXY_SSE_CLIENT_QUEUE_MAX`, `PROXY_BODY_CAP`,
  `PROXY_INGEST_MAX_BYTES`.
- Health check: `GET /` returns status + the configured Nuclei path / DB URL / log level.

---

## 7. Security posture (read before deploying anywhere non-local)

This is a **local pentesting tool**, and its defaults reflect that. The next
agent must treat the following as deliberate-but-dangerous:

| Aspect | Current state | Implication |
|---|---|---|
| API auth | **None.** No auth on any endpoint. | Anyone who can reach `:8000` can launch scans/fuzzing. Keep it bound to localhost. |
| TLS verification | `verify=False` on every outbound `httpx` client. | Required for self-signed pentest targets; do not "fix" without understanding. |
| CORS | Allows configured origins **plus `'null'`** (so the `file://` HTML preview works). | `'null'` origin is broad; tighten for any hosted deployment. |
| Outbound scope | **Scope-lock** guards exist: the Nuclei profiler, the fuzzer's re-auth, and the proxy radar (Tier-1 host lock) refuse to touch hosts outside the approved target. | This is the main guardrail against hitting third-party hosts (Stripe/AWS/etc.). Preserve it. |
| Command injection | Nuclei is invoked with an argument list (no `shell=True`). | Safe; keep it that way. |
| Cookie header injection | `ScanRequest.cookie` validator rejects CRLF. | Minimal but present. |
| Proxy internal ingest | `/hunter/proxy/internal-ingest` is **excluded from OpenAPI** (`include_in_schema=False`), guarded by an **application-level loopback check** (request client must be `127.0.0.1`/`::1`) **plus a per-session shared token** generated on each proxy start. Any failure → **404** (not 401/403, to avoid confirming the route exists). | Shared-socket design (no second uvicorn) — see note below. Do **not** put the app behind a reverse proxy that rewrites client IP without re-adding an equivalent guard. |
| Proxy CA cert | `/hunter/proxy/cert` streams the generated mitmproxy CA so the operator can trust it for HTTPS interception. | The CA exists only after the proxy has run once; required for HTTPS capture. |

---

## 8. Mental model for the next agent

- The **fuzzer (`services/fuzzer.py`, ~1600 lines) is the heart** of the product
  and the hardest file. Budget time there. It is heavily structured into
  numbered "Sections 7.x / Step 8" matching the `async-session-custody` skill.
- The **proxy radar (Step 9)** spans four files: `services/proxy_manager.py`
  (process state machine + tree kill), `services/proxy_pipeline.py`
  (`WriterService` + `SSEHub` + ingest pipeline), `proxy/radar_addon.py` (the
  out-of-process mitmdump addon — Tier-1 filter), and the `/hunter/proxy/*`
  routes. The addon imports **shared helpers from `pruner.py`**
  (`is_static_path`, `host_in_scope`, `detect_login_candidate`) so Tier-1 and
  Tier-2 share one definition of "static" / "in scope" / "login candidate".
- The **two subsystems barely interact**: a Nuclei finding and a Hunter finding
  are both rows in `vulnerability_findings`, distinguished by the `source`
  column (single-table inheritance, but *without* SQLAlchemy polymorphic mapping
  — the discriminator is set manually).
- **"Step D"** is the recently-added bridge that lets a Hunter analysis become a
  fuzzable finding. Anything labelled Step D in code/comments is part of that
  Hunter→Verify link.
- **`deep_verifier.py`** is isolated from the fuzzer verdict path and has **no
  HTTP route**. It is, however, invoked **read-only** by the fuzzer's additive
  **shadow-mode Phase 7** (gated `AI_DEEP_VERIFY_SHADOW`, default off) — it logs an
  AI second opinion on `suspicious` records but never changes a persisted verdict.
  See [`DEEP_VERIFY.md`](./DEEP_VERIFY.md) and [`VERIFY_ENGINE.md`](./VERIFY_ENGINE.md)
  §Phase 7. Manual script: `backend/scripts/deep_verify_live_check.py`. **Endpoint
  discovery** is seeded by `services/endpoint_catalog.py` — `catalog_from_openapi`
  emits `"METHOD /path"` entries that now carry the operation's genuine
  `tags`/`operationId` when the spec declares them (enabling half of **B-1**);
  `catalog_from_har` is a stub. `endpoint_catalog.py` also holds the **structural catalog
  queries** the verifier uses to gather evidence deterministically instead of trusting the
  model to pick it: `has_same_path_readback`, `select_write_record_endpoint` (B-1) and
  `select_object_state_endpoint` (**M1.2(B)** — resolves the attacked object's own state
  endpoint by resource-noun + object-scoping; the minimal slice of the future M2 graph).
  The shadow pass reads its spec from
  `settings.AI_DEEP_VERIFY_OPENAPI_SPEC` (via `getattr` — *not* a declared config
  field, D21), else falls back to a same-resource placeholder. The benchmark attack
  surface is the 26-route `vulnerable_target/` app (`app.openapi()` lists 22 path
  templates; the +4 over the pre-M1.2 surface are the X-SILENT gizmo/sprocket routes). Two
  known seams (auth-context, endpoint catalog/spec wiring) are tracked in
  [`TECH_DEBT.md`](./TECH_DEBT.md) D18.
- When something "doesn't persist," suspect the **stale-SQLite-schema** trap
  documented in [`DATA_MODEL.md`](./DATA_MODEL.md) and [`DEVELOPMENT.md`](./DEVELOPMENT.md).
