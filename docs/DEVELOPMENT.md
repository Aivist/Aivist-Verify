# DEVELOPMENT GUIDE

> How to configure, run, and test the platform. Environment observed: Windows +
> PowerShell + Python 3.11. Commands below use PowerShell syntax (`;` chains
> commands, not `&&`).

## 1. Prerequisites
- **Python 3.11** (the project is run on CPython 3.11).
- **Nuclei** binary (only needed to actually run scans; the server boots without
  it). Download from ProjectDiscovery.
- A **Gemini API key** (optional; without it, AI features degrade gracefully).
- Python deps are pinned in **`backend/requirements.txt`**:
  ```powershell
  pip install -r backend/requirements.txt
  ```
  Note: the manifest pins `python-jose` + `passlib[bcrypt]` (auth/crypto) which
  are **currently unused** (no auth is implemented), and it does **not** list
  `pytest` (install it separately to run the suite). See [`TECH_DEBT.md`](./TECH_DEBT.md).

## 2. Configuration (`backend/.env`)
Loaded by `backend/app/core/config.py`. Required/important keys:

| Key | Required | Notes |
|---|---|---|
| `NUCLEI_BINARY_PATH` | **yes** | Must be an **absolute** path (validator rejects relative). Existence is soft-checked; server still boots if missing. |
| `GEMINI_API_KEY` | no | Without it, analyze/patch return degraded fallbacks. |
| `GEMINI_PRO_MODEL` | no | default `gemini-2.5-flash` in code; `.env` may set `gemini-2.5-pro`. |
| `GEMINI_BATCH_COOLDOWN_SECONDS` | no | default 3 |
| `DATABASE_URL` | no | default `sqlite+aiosqlite:///./security_platform.db` (relative to CWD). |
| `API_PORT` | no | default 8000 |
| `CORS_ALLOWED_ORIGINS` | no | comma list; `'null'` is auto-appended for `file://` previews |
| `FUZZER_HTTP_TIMEOUT_CONNECT` / `_READ` | no | 10s / 20s |
| `FUZZER_RESPONSE_BODY_MAX_LENGTH` | no | 5000 chars |

> Invalid config fails fast: `config.py` raises on import if a required/validated
> setting is wrong (e.g. relative `NUCLEI_BINARY_PATH`).

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

On startup the lifespan handler runs `Base.metadata.create_all` — see the
**migration gotcha** below.

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
Current suite: **56 tests**
- `test_pruner.py` — exposure scoring + determinism regression tests
- `test_step8_custody.py` — auth custody / parallel engine
- `test_step_d_hunter_link.py` — Step D extraction (column-first + legacy fallback)

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
  you change `models/scan.py`, an existing DB will be missing the new columns and
  inserts will fail (`OperationalError: table … has no column named …`).
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
- `python-multipart` must be installed for `/hunter/ingest-har-file`.
