# TECH DEBT & KNOWN ISSUES

> A candid register for the next agent. Each item: **status**, severity, where it
> lives, and a suggested direction. "Resolved" items are recorded so you know
> what was already addressed and don't re-litigate it.
>
> Honesty note: this list reflects what is visible in the current source. It is
> not a guarantee that nothing else is wrong — areas with **no automated test
> coverage** (the API layer and the Nuclei pipeline) are the most likely place
> for undiscovered issues.

---

## ✅ Resolved (do not redo)

| # | Item | Where | Notes |
|---|---|---|---|
| R1 | **Hunter → Verify link was broken** | Step D: `models/scan.py`, `fuzzer.py`, `hunter.py`, `schemas/hunter.py` | `analyze` produced payloads that could never reach `verify`. Fixed by typed JSON columns + `POST /hunter/findings`. **Verified end-to-end** (real server + real local target + real DB): analyze → save → verify → 6 `FuzzingRecord`s with verdicts. |
| R2 | **`pruner` non-determinism (`PYTHONHASHSEED`)** | `services/pruner.py` | Keyword scoring depended on frozenset iteration order. Now counts all distinct keywords; locked by regression tests in `test_pruner.py`. Suite passes under random seeds. |
| R3 | **Tech-debt cleanup sweep (D1/D3/D4/D6/D7/D8/D9 + hardcoding N1–N7)** | see each item below | Done in two commits: **Stage A** (config/hardcoding/hygiene: D4, D8, N1–N7) and **Stage B** (D9, D3, D6, D1, D7). All 66 tests pass. Remaining open: **D2** (auth, intentionally deferred for local use) and **D5** (frontend consolidation, tracked as a separate task). |

---

## 🔴 High severity / fix before any real use

### D1 — No database migrations (schema drift trap)
- **✅ RESOLVED (Stage B):** added `_verify_schema_integrity` to the `main.py`
  lifespan. After `create_all`, it diffs each ORM table's expected columns
  against live `PRAGMA table_info` and raises a clear, actionable startup error
  (delete DB / migrate) instead of failing deep in an INSERT. Does NOT
  auto-migrate — Alembic is still the right long-term move if schemas churn.
- **Where:** `main.py` lifespan uses `Base.metadata.create_all` only; no Alembic.
- **Problem:** `create_all` never alters existing tables. Any model change leaves
  old DBs missing columns → runtime `OperationalError`. This already bit Step D
  ([`DATA_MODEL.md`](./DATA_MODEL.md) §Migrations).
- **Direction:** add Alembic, **or** at minimum a startup self-check that diffs
  `PRAGMA table_info` vs the ORM and emits a clear "recreate/migrate" error
  instead of failing deep in an insert.

### D2 — No authentication / authorization
- **Where:** every endpoint in `api/v1/*`.
- **Problem:** anyone who can reach the port can launch scans and active fuzzing
  against arbitrary targets. `requirements.txt` even ships `python-jose` +
  `passlib` (auth was clearly intended) but **nothing is wired**.
- **Direction:** keep bound to localhost for now; add at least an API key / local
  token before any shared or hosted deployment.

### D3 — `analyze` can hang on the external Gemini call
- **✅ RESOLVED (Stage B):** both Gemini call sites
  (`hunter._invoke_gemini_logic_hunt` + `nuclei.generate_gemini_remediation_patch`)
  are now wrapped in `asyncio.wait_for(..., timeout=settings.GEMINI_REQUEST_TIMEOUT_SECONDS)`
  (default 60s, configurable). On timeout each returns a fast degraded fallback
  instead of blocking the caller.
- **Where:** `hunter.py` `_invoke_gemini_logic_hunt` (and `nuclei.py` patch gen).
- **Problem:** the SDK call has no explicit timeout; observed real-world 503s and
  multi-second/timeout hangs. The endpoint catches errors but can still block the
  caller for a long time.
- **Direction:** wrap Gemini calls in `asyncio.wait_for` with a budget; surface a
  fast degraded response on timeout.

---

## 🟠 Medium severity

### D4 — `FindingDetails.scan_id` typed as non-optional `str`
- **✅ RESOLVED (Stage A):** `scan_id` is now `Optional[str] = None` and a
  `source: Optional[str]` field was added to `FindingDetails`; the scan endpoint
  populates it.
- **Where:** `schemas/scan.py` `FindingDetails.scan_id: str`.
- **Problem:** Hunter findings have `scan_id = NULL`. The scan-scoped endpoint
  filters by `scan_id` so it never serializes a Hunter row today, but **any
  future endpoint that returns a Hunter finding through `FindingDetails` will
  raise a validation error.** Latent landmine.
- **Direction:** make it `Optional[str]`, and add a `source` field to the schema.

### D5 — Two divergent frontends
- **Where:** `preview_dashboard.html` (canonical, light, wired) vs `frontend/`
  (Vite/TS, dark, mock data).
- **Problem:** confusion + maintenance drift; the Vite app is not the product.
- **Direction:** either delete/retire `frontend/`, or commit to migrating the
  canonical HTML into it with a real build. Don't leave both as "the frontend."

### D6 — `severity` column misused for Hunter findings
- **✅ RESOLVED (Stage B):** `persist_hunter_finding` now stores a real severity
  (`"INFO"`) and preserves the vulnerability *type* in `template_id`
  (e.g. `"logic-hunter:BOLA"`) and in the `automation_payloads` JSON. Severity
  filtering/sorting is no longer polluted by type strings.
- **Where:** `hunter.py` `persist_hunter_finding` sets `severity =
  payloads[0].type.upper()` (e.g. `"BOLA"`).
- **Problem:** `severity` semantically means CRITICAL/HIGH/… but for Hunter rows
  it holds a vulnerability *type*. Mixing semantics by `source` will confuse any
  severity-based filtering/sorting/UI.
- **Direction:** store a real severity (or `INFO`) and keep the type in the
  payload; or add a dedicated `vuln_type` column.

### D7 — No test coverage for the API layer or Nuclei pipeline
- **✅ RESOLVED (Stage B):** added `backend/tests/test_api_endpoints.py` — 10
  FastAPI `TestClient` tests over an isolated per-test SQLite DB with Gemini +
  nuclei + background fuzzing mocked. Covers analyze (success + 422), findings
  persist (201 + 422 paths), verify/batch 404s, and scan start/status (202 + 404).
- **Where:** `backend/tests/` covers pruner, custody, Step D extraction only.
- **Problem:** `api/v1/scan.py`, `api/v1/hunter.py`, and `services/nuclei.py`
  have **no automated tests**. Regressions there are invisible.
- **Direction:** add FastAPI `TestClient` tests (analyze/findings/verify/results,
  HAR ingest, batch validation 400/404) and a mocked-subprocess nuclei test.

### D8 — `requirements.txt` gaps
- **✅ RESOLVED (Stage A):** pinned `sqlalchemy`/`aiosqlite`/`google-genai`/
  `python-multipart` to tested versions, added `backend/requirements-dev.txt`
  (pytest), and annotated `python-jose`/`passlib` as reserved-for-D2 (still
  unused). Kept rather than removed so the future auth work has them ready.
- **Where:** `backend/requirements.txt`.
- **Problems:** ships unused `python-jose`/`passlib`; omits `pytest`
  (needed to run the suite); some pins are loose (`sqlalchemy>=2.0`, `aiosqlite`,
  `google-genai` unpinned).
- **Direction:** prune unused deps, add a dev-requirements (pytest), pin
  `aiosqlite`/`google-genai`/`sqlalchemy` to tested versions.

---

## 🟡 Low severity / hygiene

### D9 — `datetime.datetime.utcnow()` is deprecated
- **✅ RESOLVED (Stage B):** added a single `utcnow()` helper in `models/scan.py`
  and swept all call sites (`models/scan.py`, `fuzzer.py`, `nuclei.py`,
  `api/v1/scan.py`) to use it; removed now-unused `import datetime`s. Kept the
  values **naive UTC** on purpose (columns are not `timezone=True`) so stored
  timestamps and all existing comparisons remain byte-identical.
- **Where:** ~11 call sites across `models/scan.py`, `fuzzer.py`, `nuclei.py`,
  `api/v1/scan.py`.
- **Problem:** deprecated in Python 3.12+ (returns naive UTC). Works on 3.11.

### D10 — Single-table inheritance without polymorphic mapping
- **Where:** `vulnerability_findings.source` is set manually by each producer.
- **Problem:** no enforcement; a code path could forget to set `source` (defaults
  to `"nuclei"`) and silently misclassify a row.
- **Direction:** acceptable for v1; if it grows, consider SQLAlchemy polymorphic
  identity or a CHECK constraint.

### D11 — Single-host batch limit (v1)
- **Where:** `fuzzer.execute_parallel_fuzzing` + `/hunter/verify/batch`.
- **Status:** intended limitation, documented in [`VERIFY_ENGINE.md`](./VERIFY_ENGINE.md).
- **Direction:** a multi-host batch would need per-host custody controllers; only
  build if a real use case appears.

### D12 — Nuclei reader thread serializes DB writes with a 10s wait
- **Where:** `nuclei.py` `_nuclei_reader_thread` → `future.result(timeout=10)`
  per finding.
- **Problem:** very high finding rates could bottleneck on per-finding dispatch.
- **Direction:** batch findings before dispatch if it ever matters; low priority.

### D13 — `verify=False` (TLS) everywhere
- **Where:** all outbound `httpx` clients (fuzzer, profiler, nuclei patch path).
- **Status:** intentional for self-signed pentest targets. **Not a bug** — just
  be aware it disables cert validation globally for outbound calls.

---

## Suggested priority order for the next agent
> D1, D3, D4, D6, D7, D8, D9 are now **resolved** (see ✅ notes above). What's left:
1. **D5** (frontend consolidation) — pick one frontend; the canonical light
   `preview_dashboard.html` is the product, `frontend/` (Vite, dark, mock) is not.
   Tracked as a separate dedicated task (white/light "清新" theme).
2. **D2** (auth) — required before any non-localhost / shared exposure. The
   `API_HOST` knob + security notes are in place; `python-jose`/`passlib` are
   already vendored for this.
3. Everything else (D10–D13) is intentional/low-priority — see notes above.
