# DEVELOPMENT GUIDE

> How to configure, run, and test the platform. Environment observed: Windows +
> PowerShell + Python 3.11. Commands below use PowerShell syntax (`;` chains
> commands, not `&&`).

## 1. Prerequisites
- **Python 3.11** (the project is run on CPython 3.11).
- **Nuclei** binary (only needed to actually run scans; the server boots without
  it). Download from ProjectDiscovery.
- A **Gemini API key** (optional; without it, AI features degrade gracefully).
- **mitmproxy** (Step 9 proxy radar): pinned as `mitmproxy==11.0.2` in
  `requirements.txt`, so `pip install -r backend/requirements.txt` installs the
  `mitmdump` CLI. By default `ProxyManager` discovers it on PATH; set
  `MITMDUMP_PATH` (absolute) only if it isn't on PATH. HTTPS interception
  additionally requires the operator to trust the mitmproxy CA (download it from
  `GET /api/v1/hunter/proxy/cert` after the proxy has started once).
- Python deps are pinned in **`backend/requirements.txt`**:
  ```powershell
  pip install -r backend/requirements.txt
  ```
  Note: the manifest pins `python-jose` + `passlib[bcrypt]` (auth/crypto) which
  are **currently unused** (no auth is implemented), and it does **not** list
  `pytest` (install it separately to run the suite). See [`TECH_DEBT.md`](./TECH_DEBT.md).

### Two deliberate dependency pins (Step 9) — do not "upgrade" blindly
Installing mitmproxy forces two transitive constraints. Both are pinned on
purpose; bumping either re-introduces a crash:

| Pin | Why it exists |
|---|---|
| `httpcore==1.0.7` | `mitmproxy 11.0.2` requires `h11<0.15`, but newer `httpcore` (≥1.0.8/1.0.9, pulled in by `httpx`) requires `h11>=0.16`. `httpcore==1.0.7` is compatible with `h11 0.14` **and** `httpx 0.28.1`, resolving the conflict. |
| `bcrypt==4.0.1` | mitmproxy drags in `bcrypt>=4.1`, but the project's `passlib 1.7.4` runs a version probe at import with a >72-byte test password that crashes on bcrypt ≥4.1 (`ValueError: password cannot be longer than 72 bytes`) — which took down `mitmdump` at boot. `bcrypt==4.0.1` is compatible with `passlib 1.7.4`. |

> If you upgrade mitmproxy, httpx, or passlib, re-evaluate both pins together and
> re-run the full test suite before committing.

## 2. Configuration (`backend/.env`)
Loaded by `backend/app/core/config.py`. Required/important keys:

| Key | Required | Notes |
|---|---|---|
| `NUCLEI_BINARY_PATH` | **yes** | Must be an **absolute** path (validator rejects relative). Existence is **not** checked at startup (the validator only enforces an absolute path); a missing binary surfaces only at scan time as a Phase-1 `FileNotFoundError` → scan marked `failed`. The server still boots. |
| `NUCLEI_DEFAULT_SEVERITY` | no | default `critical,high`; passed to Nuclei `-severity`. |
| `GEMINI_API_KEY` | no | Without it, analyze/patch return degraded fallbacks. |
| `GEMINI_PRO_MODEL` | no | default `gemini-2.5-flash` in code; `.env` may set `gemini-2.5-pro`. |
| `GEMINI_BATCH_COOLDOWN_SECONDS` | no | default 3 |
| `GEMINI_REQUEST_TIMEOUT_SECONDS` | no | default 60; hard budget per Gemini call before a degraded fallback (D3). |
| `DATABASE_URL` | no | default `sqlite+aiosqlite:///./security_platform.db` (relative to CWD). |
| `API_HOST` | no | default `0.0.0.0` (binds ALL interfaces). Set `127.0.0.1` to restrict to localhost. **No auth yet (D2)** — see security note. |
| `API_PORT` | no | default 8000 |
| `LOG_LEVEL` | no | default `INFO`; exposed in `GET /` diagnostics. |
| `CORS_ALLOWED_ORIGINS` | no | comma list; `'null'` is auto-appended for `file://` previews |
| `FUZZER_HTTP_TIMEOUT_CONNECT` / `_READ` | no | 10s / 20s |
| `FUZZER_RESPONSE_BODY_MAX_LENGTH` | no | 5000 chars |
| `MITMDUMP_PATH` | no | **Step 9.** Absolute path to `mitmdump`; empty ⇒ PATH lookup (`shutil.which`). Validated absolute when set (rejects relative, like Nuclei). |
| `PROXY_LISTEN_PORT` | no | **Step 9.** Proxy listen port, default `8888`; must differ from `API_PORT`. |
| `PROXY_INGEST_QUEUE_MAX` | no | **Step 9.** Bounded ingest queue, default `1000`; over this the internal-ingest endpoint returns 503 (backpressure). |
| `PROXY_SSE_MAX_CLIENTS` | no | **Step 9.** Max concurrent SSE subscribers, default `32`. |
| `PROXY_SSE_CLIENT_QUEUE_MAX` | no | **Step 9.** Per-client SSE fan-out queue, default `500` (latest-wins on overflow). |
| `PROXY_BODY_CAP` | no | **Step 9.** Max chars retained per captured request/response body, default `65536`. |
| `PROXY_INGEST_MAX_BYTES` | no | **Step 9.** Max size of a single internal-ingest POST body, default `262144` (else 413). |
| `AI_DEEP_VERIFY_ENABLED` | no | default `False`. Gates the isolated `deep_verifier.py` verifier itself (it returns a `disabled` result and never calls the network when off). **No HTTP route uses it**; it is invoked read-only by the fuzzer's shadow-mode Phase 7. See [`DEEP_VERIFY.md`](./DEEP_VERIFY.md). |
| `AI_DEEP_VERIFY_SHADOW` | no | default `False`. When on, `execute_parallel_fuzzing` runs a read-only **Phase 7** after a batch: it re-checks `suspicious` records with the deep verifier and **only logs** the AI verdict (never changes the persisted verdict). For a live Gemini second opinion, **both** this and `AI_DEEP_VERIFY_ENABLED` must be `True`. See [`VERIFY_ENGINE.md`](./VERIFY_ENGINE.md) §Phase 7. |
| `AI_DEEP_VERIFY_OPENAPI_SPEC` | no | **Integration seam — NOT a declared Settings field.** Read via `getattr(settings, …)` in `fuzzer.py` (config uses `extra="ignore"`, so a plain `.env` value is *not* parsed into `Settings`). When present it optionally feeds the real OpenAPI endpoint catalog into the Phase-7 shadow pass; absent ⇒ a placeholder catalog (zero behavior change). See [`DEEP_VERIFY.md`](./DEEP_VERIFY.md). |

> Invalid config fails fast: `config.py` raises on import if a required/validated
> setting is wrong (e.g. relative `NUCLEI_BINARY_PATH` or `MITMDUMP_PATH`, or an
> out-of-range `API_PORT`/`PROXY_LISTEN_PORT`).

## 3. Running the backend
**Always run from the repository root** so the `backend.app...` package imports
resolve.

Standard (hot-reload, listens on all interfaces):
```powershell
python backend/run.py
```
`run.py` sets the Windows Proactor event-loop policy (needed for subprocess) and
runs uvicorn with `reload=True` on `0.0.0.0:API_PORT`.

Single process, no reload (recommended for debugging / scripted E2E — avoids the
reloader spawning a child process that holds the DB/port):
```powershell
python -c "import uvicorn; uvicorn.run('backend.app.main:app', host='127.0.0.1', port=8000, log_level='warning')"
```

Health check: open `http://127.0.0.1:8000/` or `GET /api/docs`.

On startup the lifespan handler runs `Base.metadata.create_all` then
`_verify_schema_integrity` — see the **migration gotcha** below.

## 4. Frontend
The canonical UI is the single file `preview_dashboard.html`. Just open it in a
browser (double-click → `file://`, which is why CORS allows the `'null'`
origin), or serve it statically. It calls the backend at `http://…:8000`. No
build step. (The `frontend/` Vite app is legacy/mock — ignore unless migrating.)

## 5. Tests
Tests live in `backend/tests/`. Run from the repo root (so `backend.app` is
importable):
```powershell
python -m pytest backend/tests -q
```
Current suite: **285 tests**. See [`STATUS.md`](./STATUS.md).
- `test_pruner.py` — exposure scoring + determinism regression tests
- `test_step8_custody.py` — auth custody / parallel engine
- `test_step_d_hunter_link.py` — Step D extraction (column-first + legacy fallback)
- `test_api_endpoints.py` — API-layer integration tests (FastAPI TestClient, isolated
  per-test SQLite, Gemini/nuclei/background-fuzzing mocked) — D7
- `test_step9_proxy.py` — proxy radar: WriterService serialization, SSEHub fan-out +
  overflow, ingest backpressure, Tier-2 enrichment, ProxyManager state machine + token,
  internal-ingest loopback/token/oversize guards
- `test_endpoint_catalog.py` — endpoint catalog surface + write-record queries (Phase-7 shadow input)
- `test_verdict_oracle.py` — rule-oracle verdict-correctness
- `test_d18_phase2_crosspath.py` — cross-path deep-verify (offline)
- `test_d18_b22_guard.py` — B-2.2 cross-resource guard
- `test_d18_b1_write_record.py` — B-1 write-record gathering + guard exemption (offline units)
- `test_d18_b1_shadow_integration.py` — B-1 shadow path: real `execute_deep_verification` end-to-end with mocked Gemini (D22)
- `test_m12_state_readback_exemption.py` — M1.2 object-STATE read-back exemption channel (both ways)
- `test_m12b_state_gather.py` — M1.2(B) deterministic object-state resolver (incl. foreign-spec genericity)
- `test_m13_delete.py` — M1.3 delete shape: negative assertion, pre-flight coincidence gate, channel
- `test_m14_mass_assignment.py` — M1.4 low-entropy state jump (MISSING vs UNKNOWN), the M1.2-narrowing hazard test, and the mistyped-BOLA routing regression

**Separate suite (ground-truth target, not counted in the backend total):**

```powershell
python -m pytest vulnerable_target/test_vulns.py -v
```

31 tests proving planted vulnerabilities on the standalone target app (port 8001).

`pytest` lives in `backend/requirements-dev.txt` (dev-only); install with
`pip install -r backend/requirements-dev.txt`.

> **`ModuleNotFoundError: backend.app`?** You're not running from the repo root,
> or pytest's rootdir/`sys.path` doesn't include it. Run `python -m pytest` from
> the project root. (See the `backend-testing` skill.)

### Determinism note (resolved)
`pruner.py` keyword scoring used to depend on `PYTHONHASHSEED` (frozenset
iteration order), causing an intermittently-failing pruner test. It's fixed
(counts all distinct keywords) and locked by regression tests. You should **no
longer need to pin `PYTHONHASHSEED`**; the suite passes under random seeds.

## 6. Database lifecycle & the migration gotcha
- The dev DB is `security_platform.db` in the process CWD (WAL mode → also
  `-wal` / `-shm` sidecar files).
- `create_all` **creates missing tables but never alters existing columns.** If
  you change `models/scan.py`, an existing DB will be missing the new columns.
  - **As of D1**, the lifespan now runs `_verify_schema_integrity` right after
    `create_all`: it diffs ORM columns vs `PRAGMA table_info` and **refuses to
    start** with a clear `RuntimeError` naming the missing columns — instead of
    the old deep `OperationalError` at insert time. Fix = recreate/migrate the DB.
- To reset in dev: stop the server, delete `security_platform.db*`, restart.
  - ⚠️ On Windows the file is frequently **locked** by a stray `uvicorn`/python
    process or the IDE's SQLite viewer. If deletion fails: confirm nothing holds
    port 8000 (`Get-NetTCPConnection -LocalPort 8000`), stop that PID, close any
    open DB viewer, then delete. Or sidestep entirely with a fresh
    `DATABASE_URL=sqlite+aiosqlite:///./fresh.db`.

## 7. Manual E2E (Hunter → Verify) recipe
Proven working. Pattern:
1. Start a **local target HTTP server** (so fuzzing hits something real & local).
2. Start the backend (no-reload form above), pointed at a fresh DB.
3. Drive the live API with `httpx`/curl:
   `POST /hunter/analyze` → `POST /hunter/findings` (get `finding_id`) →
   `POST /hunter/verify/{id}` → poll `GET /hunter/verify/{id}/results`.
4. Optionally inspect the SQLite file directly to confirm `source="hunter"`,
   the JSON columns, and `fuzzing_records` rows.

Tip: `/hunter/analyze` depends on the external Gemini API and can be slow/flaky
(503/timeout). For deterministic link testing, make the analyze step tolerant
(generous timeout + fallback to a locally-built `parsed_data`) — the Save→Verify
link is what matters and is independent of Gemini.

## 8. Common pitfalls
- PowerShell: chain with `;`, not `&&`.
- Don't run two servers at once — the second fails to bind 8000 (`Errno 10048`)
  while the first keeps serving (and may hold a stale-schema DB).
  - **Killing a stray server:** `Stop-Process` on the PowerShell wrapper does
    **not** kill the underlying python/uvicorn. Find the real PID with
    `Get-NetTCPConnection -LocalPort 8000` then `Stop-Process -Id <PID> -Force`.
- `python-multipart` must be installed for `/hunter/ingest-har-file`.
- `PROXY_LISTEN_PORT` (default 8888) **must differ from `API_PORT`** (default
  8000) — they are two separate listeners.
- `GET /hunter/proxy/cert` returns **404 until the proxy has started once** (the
  mitmproxy CA is generated on first run).

## 9. Proxy Radar (mitmdump) quickstart — Step 9
1. Start the backend (so the lifespan starts the `WriterService` + ingest pipeline).
2. `POST /api/v1/hunter/proxy/start` with the approved scope host (or use the
   **Proxy Radar** tab in `preview_dashboard.html`). `ProxyManager` spawns a
   supervised `mitmdump` running `proxy/radar_addon.py`.
3. Point a browser's HTTP/S proxy at `127.0.0.1:<PROXY_LISTEN_PORT>`.
4. For HTTPS, download the CA from `GET /api/v1/hunter/proxy/cert` and trust it.
5. Browse the in-scope target → captured flows appear live via
   `GET /api/v1/hunter/proxy/stream` (SSE) and are persisted to `captured_flows`.
6. `POST /api/v1/hunter/proxy/stop` cleanly tears down the proxy (OS-agnostic
   process-tree kill: `taskkill /F /T` on Windows, process-group signals on Unix).

> Integration testing pattern (Step 9, proven): drive a local proxied client
> through `mitmdump`, consume the SSE stream, then promote a captured flow into
> `analyze → findings → verify → results`. If the backend refuses to boot with a
> schema-drift `RuntimeError`, you're on a pre-Step-D DB — recreate it (see §6).

## 10. Ground-truth target (`vulnerable_target/`) — port 8001

A **standalone** deliberately-insecure FastAPI app for local benchmarking. It does
**not** import `backend.app` and uses its own SQLite file
(`vulnerable_target/vulnerable_target.db`).

```powershell
pip install -r vulnerable_target/requirements.txt
python -m uvicorn vulnerable_target.main:app --reload --port 8001
```

- Docs / answer key: [`../vulnerable_target/README.md`](../vulnerable_target/README.md)
- Benchmark dataset: [`../vulnerable_target/benchmark/README.md`](../vulnerable_target/benchmark/README.md)
- Automated proof: `python -m pytest vulnerable_target/test_vulns.py -v` (14 tests)

## 11. Deep verifier manual check (optional, needs Gemini)

Not part of the backend pytest suite. Requires target on `:8001` + `GEMINI_API_KEY`:

```powershell
python backend/scripts/deep_verify_live_check.py
```

See [`DEEP_VERIFY.md`](./DEEP_VERIFY.md). The script forces `AI_DEEP_VERIFY_ENABLED`
at runtime; production defaults keep it off.

> The verifier's verdict vocabulary now includes `inconclusive` (alongside
> `verified`/`failed`/`suspicious`), and a deterministic **B-2.2 cross-resource
> guard** downgrades a decisive verdict to `inconclusive` when it rests only on a
> different-resource read-back. Details in [`DEEP_VERIFY.md`](./DEEP_VERIFY.md).
