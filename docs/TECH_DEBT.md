# TECH DEBT & KNOWN ISSUES

> A candid register for the next agent. Each item: **status**, severity, where it
> lives, and a suggested direction. "Resolved" items are recorded so you know
> what was already addressed and don't re-litigate it.
>
> Honesty note: this list reflects what is visible in the current source. It is
> not a guarantee that nothing else is wrong — the **Nuclei subprocess pipeline**
> (real binary, JSONL reader thread, Phase 3 batch enrichment) still has **no
> dedicated automated tests**; API routes have partial mock-based coverage (D7).

---

## ✅ Resolved (do not redo)

| # | Item | Where | Notes |
|---|---|---|---|
| R1 | **Hunter → Verify link was broken** | Step D: `models/scan.py`, `fuzzer.py`, `hunter.py`, `schemas/hunter.py` | `analyze` produced payloads that could never reach `verify`. Fixed by typed JSON columns + `POST /hunter/findings`. **Verified end-to-end** (real server + real local target + real DB): analyze → save → verify → 6 `FuzzingRecord`s with verdicts. |
| R2 | **`pruner` non-determinism (`PYTHONHASHSEED`)** | `services/pruner.py` | Keyword scoring depended on frozenset iteration order. Now counts all distinct keywords; locked by regression tests in `test_pruner.py`. Suite passes under random seeds. |
| R3 | **Tech-debt cleanup sweep (D1/D3/D4/D6/D7/D8/D9 + hardcoding N1–N7)** | see each item below | Done in two commits: **Stage A** (config/hardcoding/hygiene: D4, D8, N1–N7) and **Stage B** (D9, D3, D6, D1, D7). All 66 tests pass. Remaining open: **D2** (auth, intentionally deferred for local use) and **D5** (frontend consolidation, tracked as a separate task). |
| R4 | **Step 9 — Passive Traffic Ingestion Proxy Radar + unified WriterService** | `models/scan.py` (`CapturedFlow`), `config.py`, `services/proxy_pipeline.py`, `services/proxy_manager.py`, `proxy/radar_addon.py`, `schemas/proxy.py`, `api/v1/hunter.py` (`/proxy/*`), `main.py`, `pruner.py` (shared helpers), `preview_dashboard.html` | The single-writer pattern was generalized out of the fuzzer into an **app-wide `WriterService`** (started in the lifespan); the fuzzer forwards to it when running and falls back to an ephemeral per-batch consumer otherwise — **globally ≤1 SQLite writer**. mitmdump runs out-of-process, ships in-scope flows via a loopback POST to a hidden internal-ingest endpoint, Tier-2 enriches + persists + SSE-streams. **All 66 prior tests still pass + 7 new (`test_step9_proxy.py`) = 73.** **Verified end-to-end** (real mitmdump + real DB): browser→proxy→ingest→queue→writer→`captured_flows`; ingest→SSE→client; captured flow→analyze→findings→verify→`FuzzingRecord`→results; plus clean process-tree kill on stop. |
| R5 | **Verdict-correctness measurement groundwork** | `docs/audit/verdict_coverage_audit.md`, `backend/tests/test_verdict_oracle.py`, `scripts/audit/capture_target_bytes*.py`, `backend/tests/test_endpoint_catalog.py` | Audit found **0 of 73** prior tests asserted the verdict oracle was correct. Added **9 human-owned verdict tests** (offline, pure-function; incl. a false-positive killer, a weak-signal guard, and a characterization test pinning that the rule oracle cannot separate a real silent BOLA from the SAFE look-alike). **Live-byte capture** confirmed the target's real bytes match the test inputs AND that `test_vulns.py` / `RESULTS.md` ground truth holds. Plus **6 catalog tests** (D18 Phase 1). Suite 73→88. Commits `292497e`, `6832922`, `2b3d4b9`. |

---

## 🔴 High severity / fix before any real use

### D1 — No database migrations (schema drift trap)
- **Status:** partially mitigated (Stage B); Alembic still open.
- **Where:** `main.py` lifespan — `create_all` + `_verify_schema_integrity`; no Alembic.
- **Was:** `create_all` never alters existing tables → old DBs missing new columns →
  deep `OperationalError` at INSERT (bit Step D; see [`DATA_MODEL.md`](./DATA_MODEL.md)).
- **Now:** startup self-check diffs ORM columns vs `PRAGMA table_info` and refuses
  to boot with a clear error naming missing columns.
- **Still open:** no automatic migration — dev must recreate the DB, point at a fresh
  file via `DATABASE_URL`, or hand-apply `ALTER TABLE`. Add Alembic if schemas churn.

### D2 — No authentication / authorization
- **Where:** every endpoint in `api/v1/*`.
- **Problem:** anyone who can reach the port can launch scans and active fuzzing
  against arbitrary targets. `requirements.txt` even ships `python-jose` +
  `passlib` (auth was clearly intended) but **nothing is wired**.
- **Direction:** keep bound to localhost for now; add at least an API key / local
  token before any shared or hosted deployment.

### D3 — `analyze` can hang on the external Gemini call
- **✅ RESOLVED (Stage B).**
- **Where:** `hunter.py` `_invoke_gemini_logic_hunt`, `nuclei.py`
  `generate_gemini_remediation_patch`.
- **Fix:** both wrapped in `asyncio.wait_for(...,
  timeout=settings.GEMINI_REQUEST_TIMEOUT_SECONDS)` (default 60s). Timeout → fast
  degraded fallback string; caller no longer blocks indefinitely.

---

## 🟠 Medium severity

### D4 — `FindingDetails.scan_id` typed as non-optional `str`
- **✅ RESOLVED (Stage A).**
- **Where:** `schemas/scan.py` `FindingDetails`.
- **Fix:** `scan_id: Optional[str] = None` and `source: Optional[str]` added; scan
  findings endpoint populates both.

### D5 — Two divergent frontends
- **Where:** `preview_dashboard.html` (canonical, light, wired) vs `frontend/`
  (Vite/TS, dark, mock data).
- **Problem:** confusion + maintenance drift; the Vite app is not the product.
- **Direction:** either delete/retire `frontend/`, or commit to migrating the
  canonical HTML into it with a real build. Don't leave both as "the frontend."

### D6 — `severity` column misused for Hunter findings
- **✅ RESOLVED (Stage B).**
- **Where:** `hunter.py` `persist_hunter_finding`.
- **Was:** Hunter rows stored vuln *type* in `severity` (e.g. `"BOLA"`), polluting
  severity-based filters.
- **Now:** `severity="INFO"`; type lives in `template_id` (e.g. `"logic-hunter:BOLA"`)
  and in `automation_payloads[].type`.

### D7 — No test coverage for the API layer or Nuclei pipeline
- **Status:** partially resolved (Stage B + Step 9) — API smoke tests + proxy
  radar tests added; Nuclei pipeline still bare.
- **Where:** `backend/tests/test_api_endpoints.py` (API smoke); `test_step9_proxy.py`
  (proxy radar, Step 9); plus pruner, custody, Step D extraction in other files.
  Total suite: **73 tests**.
- **Covered:** FastAPI `TestClient` over isolated per-test SQLite with Gemini,
  nuclei subprocess, and background fuzzing mocked — analyze (200 + 422), findings
  persist (201 + 422), verify/batch 404s, scan start/status (202 + 404), health check.
  **Step 9:** WriterService serialization, SSEHub fan-out + overflow, ingest
  backpressure, Tier-2 enrichment, ProxyManager state machine + token, internal-ingest
  loopback/token/oversize guards.
- **Still open:** HAR ingest, batch 400 mixed-host, verify results polling, real
  Nuclei subprocess / JSONL reader / Phase 3 enrichment loop — add mocked-subprocess
  nuclei tests when touching that code.

### D8 — `requirements.txt` gaps
- **✅ RESOLVED (Stage A).**
- **Where:** `backend/requirements.txt`, `backend/requirements-dev.txt`.
- **Fix:** pinned `sqlalchemy`/`aiosqlite`/`google-genai`/`python-multipart`;
  pytest moved to `requirements-dev.txt`; `python-jose`/`passlib` kept annotated
  as reserved-for-D2 (still unused).

---

## 🟡 Low severity / hygiene

### D9 — `datetime.datetime.utcnow()` is deprecated
- **✅ RESOLVED (Stage B).**
- **Where:** `utcnow()` helper in `models/scan.py`; call sites in `models/scan.py`,
  `fuzzer.py`, `nuclei.py`, `api/v1/scan.py`.
- **Fix:** replaced deprecated `datetime.utcnow()` while keeping **naive UTC**
  values (columns are not `timezone=True`).

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

### D14 — Proxy radar Tier-1 drops out-of-scope / static traffic (Step 9)
- **Where:** `proxy/radar_addon.py` (Tier-1 inline filter).
- **Status:** intentional. The radar only captures in-scope **dynamic** flows;
  static assets and out-of-scope hosts are vetoed in the mitmdump hook so the proxy
  adds no latency and never records third-party traffic. The `captured_flows.in_scope`
  flag exists for any future "capture-but-inert" mode.
- **Direction:** if you ever need full passive capture, relax the addon veto and
  rely on `in_scope`/`exposure_score` for filtering at read time.

### D15 — HTTPS interception requires trusting the mitmproxy CA (Step 9)
- **Where:** `proxy_manager.py` (CA discovery), `GET /hunter/proxy/cert`.
- **Status:** expected. The CA is generated **on first proxy start**, so `/proxy/cert`
  returns 404 until then, and the operator must import/trust it in the browser/OS to
  decrypt HTTPS. No bug; just an onboarding step.

### D16 — Dependency pins forced by mitmproxy (Step 9)
- **Where:** `backend/requirements.txt` — `httpcore==1.0.7`, `bcrypt==4.0.1`.
- **Status:** deliberate constraint coupling (see [`DEVELOPMENT.md`](./DEVELOPMENT.md) §1).
  `mitmproxy 11.0.2` needs `h11<0.15` (→ `httpcore==1.0.7`); `passlib 1.7.4`'s import
  probe crashes on `bcrypt>=4.1` (→ `bcrypt==4.0.1`).
- **Direction:** revisit both pins **together** whenever upgrading mitmproxy / httpx /
  passlib, and re-run the full suite. Note `passlib`/`python-jose` are still only
  vendored for the future D2 auth work.

### D17 — Internal-ingest guard assumes no trusted fronting proxy (Step 9)
- **Where:** `api/v1/hunter.py` `_client_is_loopback` + `/proxy/internal-ingest`.
- **Status:** the guard uses the **real TCP peer** and deliberately ignores
  `X-Forwarded-For` (attacker-controlled in local mode), plus a per-session token,
  failing closed as 404. Correct for the current localhost deployment.
- **Direction:** if the app is ever placed behind a real reverse proxy that rewrites
  the client IP, this loopback check must be re-derived from a trusted forwarded
  header — do **not** simply start honoring XFF.

### D18 — Endpoint / attack-surface discovery is not solved
- **Where:** the whole Hunter→Verify intake, and `fuzzer._shadow_endpoint_catalog`
  (the shadow verifier's endpoint list).
- **Status:** **Phase 1 done (commit `2b3d4b9`); discovery + cross-path value still
  open.** A real endpoint catalog now feeds the shadow verifier: `endpoint_catalog.py`
  (pure OpenAPI→`["METHOD /path"]` adapter + HAR stub + dispatch) is wired into
  `_shadow_endpoint_catalog` via an optional `catalog_source`. With **no source
  configured the output is byte-identical to the old placeholder (zero regression)**;
  the real 15-endpoint surface is used only when a spec source is explicitly provided.
  6 human-owned tests (`test_endpoint_catalog.py`) cover this; the B1/B2 pair is the
  allowed-to-fail proof (placeholder has 0 cross-resource endpoints; real catalog
  reaches them, incl. `GET /api/invoices/{invoice_id}`). Suite 82→88.
  - **Still open — automated attack-surface DISCOVERY:** the catalog is *fed* an
    OpenAPI/HAR source (operator-supplied). The system still does **not discover**
    endpoints on its own. This is the larger half of D18.
  - **Still open — cross-path value NOT yet proven:** on the current target every
    write-type finding's confirming read-back is the **same path** as the write, so
    the placeholder already sufficed (P0 proved this). The catalog's cross-resource
    reach is demonstrated **structurally** (test B2) but has **not** yet been shown to
    change a verdict in a real "write-at-A / confirm-at-B" case — because no such hole
    exists on this target. Proving it requires Phase 2 (below).
- **Direction:** feed a real API surface (OpenAPI/Swagger import, aggregated
  HAR/proxy-capture inventory, or crawl) into both the Hunter intake and the deep
  verifier's `available_endpoints`. Until then, document the catalog as a known seam.

### D19 — AI deep verifier is shadow-only, not authoritative
- **Where:** `services/deep_verifier.py` + `fuzzer._run_shadow_deep_verification`
  (Phase 7); flags `AI_DEEP_VERIFY_ENABLED` / `AI_DEEP_VERIFY_SHADOW` in `config.py`
  (both default `False`).
- **Status:** the AI-in-the-loop write-then-read verifier runs **read-only**. In
  shadow mode it re-checks `suspicious` records and **only logs** its verdict
  (`AI_shadow_verdict=… NOT applied (shadow, observe-only)`); it does **not**
  overwrite `verification_status`/`diff_details` or change what the user sees, and
  it never affects a batch (failures are swallowed). It is therefore **not yet
  authoritative** — the persisted verdict is still the rule oracle's, which stalls at
  `suspicious` on silent cases (opaque `200 {"status":"ok"}` writes). Accuracy so far
  is recorded in `vulnerable_target/benchmark/RESULTS.md` (n=9, 8/8 AI correct, 0
  FP/FN) but that is **measurement, not promotion**.
- **Update (commit `6832922`, P0):** the shadow verifier has now been run through the
  **real integrated pipeline** (`execute_parallel_fuzzing` → Phase 7), not just the
  isolated component. On two byte-identical `suspicious` cases — PROFILE (real silent
  BOLA) and AVATAR (secure look-alike) — the AI shadow verdict was `verified` and
  `failed` respectively, each on a real write-then-read read-back, **with no false
  positive and the persisted verdict unchanged**. This is the first real-pipeline
  evidence (the n=9 benchmark used isolated/manual drivers). It remains **measurement,
  not promotion**: still shadow-only, still not authoritative, still gated behind D18.
  The accuracy seen so far is **context-fed, on a simple target with easy same-path
  read-backs** — not a general accuracy claim.
- **Direction:** once shadow data is trusted at scale, decide a promotion policy
  (e.g. let the AI verdict resolve only the rule oracle's `suspicious` band, with the
  full evidence trail retained for audit). Do not promote before D18 is addressed —
  the verifier's reliability depends on being handed the right read-back endpoint.

### D20 — D18 cross-path value is unproven on the current target (Phase 2)
- **Where:** `vulnerable_target/` (needs a new hole) + the D18 catalog seam.
- **Status:** the current target has no "write at path A, confirm at path B" hole, so
  the catalog's real payoff (handing the verifier a read-back at a *different* path
  the placeholder could never synthesize) is untested. The observed 404-on-a-guessed
  path from an early run is not reproducible here for lack of such a case.
- **Direction:** add a maintainer-owned cross-path hole to the target, confirm its
  ground truth with **verbatim captured bytes** (independent of the engine), then
  re-run the shadow path to show the catalog hands the correct cross-path read-back
  and the verdict is right. **Ground truth is human-owned**: the agent may implement
  the target code to the maintainer's spec but must not design the hole or its
  expected behavior, and the behavior must be byte-verified before use as a test case.

---

## Suggested priority order for the next agent
> Current focus: sharpen the differentiator and PROVE it. All commercialization /
> scaling work is deferred until a benchmark justifies it. D1 (startup guard), D3,
> D4, D6, D8, D9 are done; Step 9 (R4) is done & E2E-verified; D7 is partial.

### Active line (work on these now)
1. **Differential verification engine** — deepen the oracle's precision and cover
   more broken-access-control classes. This is the core moat.
2. **Benchmark vs agent-style PoC validation** — on a public vulnerable target,
   quantify this engine's false-positive / reproducibility rate against
   agent-driven PoC tools. This is the only evidence for the "can it be sold" question.
3. **D5 (frontend consolidation)** — keep `preview_dashboard.html`, retire `frontend/`.

### Deferred — NOT in the active line (unlock condition: the benchmark above proves commercialization is worth it)
- **D2 (auth)**, multi-tenancy, **D1 (Alembic migrations)**, hosted/enterprise deployment.
  Product/scaling concerns, unrelated to the "portfolio piece + validation" goal.
  Do not spend effort here until the benchmark data justifies it.
- Everything else (D10–D17, incl. Step 9 items) is intentional/low-priority — see notes above.
