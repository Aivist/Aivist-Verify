# ARCHITECTURE — Anti-Gravity AI Penetration Testing Platform

> Audience: a developer/agent taking over this codebase. This document is the
> entry point. It describes what the system is, how the pieces fit together, the
> runtime/concurrency model, and the security posture. Every claim here is
> grounded in the current source tree (see file references).
>
> Companion docs:
> - [`DATA_MODEL.md`](./DATA_MODEL.md) — database schema & ORM
> - [`HUNTER_PIPELINE.md`](./HUNTER_PIPELINE.md) — AI Logic Hunter (HAR → analyze → persist)
> - [`VERIFY_ENGINE.md`](./VERIFY_ENGINE.md) — differential fuzzing / verification engine
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
│  ├─ app/
│  │  ├─ main.py                  # FastAPI app, lifespan create_all, CORS, routers
│  │  ├─ core/
│  │  │  ├─ config.py             # Pydantic Settings + validators (fail-fast)
│  │  │  └─ database.py           # async engine, session factory, get_db, SQLite pragmas
│  │  ├─ models/
│  │  │  └─ scan.py               # ScanTask, VulnerabilityFinding, FuzzingRecord
│  │  ├─ schemas/
│  │  │  ├─ scan.py               # Nuclei scan request/response schemas
│  │  │  └─ hunter.py             # Hunter + verify + HAR + batch schemas
│  │  ├─ api/v1/
│  │  │  ├─ scan.py               # /api/v1/scan/*  (Nuclei)
│  │  │  └─ hunter.py             # /api/v1/hunter/* (Hunter, verify, HAR, batch, auth)
│  │  └─ services/
│  │     ├─ nuclei.py             # 3-phase scan orchestrator + Gemini patch + profiler
│  │     ├─ traffic_parser.py     # raw HTTP text → structured dict
│  │     ├─ pruner.py             # heuristic exposure scoring / HAR noise filter
│  │     └─ fuzzer.py             # differential fuzzing engine + auth custody (the core)
│  └─ tests/                      # pytest: test_pruner, test_step8_custody, test_step_d_hunter_link
└─ docs/                          # you are here
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
  consumer coroutine** (`_db_writer_consumer`) draining an `asyncio.Queue`. This
  is the central design rule: *parallelize the network, serialize the DB.*
  → See the `async-session-custody` skill and [`VERIFY_ENGINE.md`](./VERIFY_ENGINE.md).
- **SQLite tuning.** `database.py` sets `PRAGMA journal_mode=WAL` and a
  `busy_timeout` so transient "database is locked" is waited out; the fuzzer also
  wraps commits in `_commit_with_retry` with exponential backoff.

---

## 6. Configuration & startup

- `backend/app/core/config.py` loads `backend/.env` via `pydantic-settings`.
- **`NUCLEI_BINARY_PATH` is required and must be absolute** (validator rejects
  relative paths to prevent execution hijack). Its *existence* is only
  soft-checked, so the server boots even if the binary isn't installed (scans
  will then fail at runtime with a clear log).
- `GEMINI_API_KEY` is optional; when missing, all AI calls return a graceful
  Chinese "degraded" fallback string instead of crashing.
- On startup, `main.py`'s lifespan runs `Base.metadata.create_all` — this
  **creates missing tables but never alters existing ones** (see the migration
  warning in [`DATA_MODEL.md`](./DATA_MODEL.md) §Migrations).
- Health check: `GET /` returns status + the configured Nuclei path / DB URL.

---

## 7. Security posture (read before deploying anywhere non-local)

This is a **local pentesting tool**, and its defaults reflect that. The next
agent must treat the following as deliberate-but-dangerous:

| Aspect | Current state | Implication |
|---|---|---|
| API auth | **None.** No auth on any endpoint. | Anyone who can reach `:8000` can launch scans/fuzzing. Keep it bound to localhost. |
| TLS verification | `verify=False` on every outbound `httpx` client. | Required for self-signed pentest targets; do not "fix" without understanding. |
| CORS | Allows configured origins **plus `'null'`** (so the `file://` HTML preview works). | `'null'` origin is broad; tighten for any hosted deployment. |
| Outbound scope | **Scope-lock** guards exist: the Nuclei profiler and the fuzzer's re-auth refuse to probe hosts outside the approved target. | This is the main guardrail against hitting third-party hosts (Stripe/AWS/etc.). Preserve it. |
| Command injection | Nuclei is invoked with an argument list (no `shell=True`). | Safe; keep it that way. |
| Cookie header injection | `ScanRequest.cookie` validator rejects CRLF. | Minimal but present. |

---

## 8. Mental model for the next agent

- The **fuzzer (`services/fuzzer.py`, ~1400 lines) is the heart** of the product
  and the hardest file. Budget time there. It is heavily structured into
  numbered "Sections 7.x / Step 8" matching the `async-session-custody` skill.
- The **two subsystems barely interact**: a Nuclei finding and a Hunter finding
  are both rows in `vulnerability_findings`, distinguished by the `source`
  column (single-table inheritance, but *without* SQLAlchemy polymorphic mapping
  — the discriminator is set manually).
- **"Step D"** is the recently-added bridge that lets a Hunter analysis become a
  fuzzable finding. Anything labelled Step D in code/comments is part of that
  Hunter→Verify link.
- When something "doesn't persist," suspect the **stale-SQLite-schema** trap
  documented in [`DATA_MODEL.md`](./DATA_MODEL.md) and [`DEVELOPMENT.md`](./DEVELOPMENT.md).
