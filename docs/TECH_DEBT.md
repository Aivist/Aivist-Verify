# TECH DEBT & KNOWN ISSUES

> A candid register for the next agent. Each item: **status**, severity, where it
> lives, and a suggested direction. "Resolved" items are recorded so you know
> what was already addressed and don't re-litigate it.
>
> Honesty note: this list reflects what is visible in the current source. It is
> not a guarantee that nothing else is wrong; API routes have partial mock-based
> coverage (D7).

---

## ✅ Resolved (do not redo)

| # | Item | Where | Notes |
|---|---|---|---|
| R1 | **Hunter → Verify link was broken** | Step D: `models/scan.py`, `fuzzer.py`, `hunter.py`, `schemas/hunter.py` | `analyze` produced payloads that could never reach `verify`. Fixed by typed JSON columns + `POST /hunter/findings`. **Verified end-to-end** (real server + real local target + real DB): analyze → save → verify → 6 `FuzzingRecord`s with verdicts. |
| R2 | **`pruner` non-determinism (`PYTHONHASHSEED`)** | `services/pruner.py` | Keyword scoring depended on frozenset iteration order. Now counts all distinct keywords; locked by regression tests in `test_pruner.py`. Suite passes under random seeds. |
| R3 | **Tech-debt cleanup sweep (D1/D3/D4/D6/D7/D8/D9 + hardcoding N1–N7)** | see each item below | Done in two commits: **Stage A** (config/hardcoding/hygiene: D4, D8, N1–N7) and **Stage B** (D9, D3, D6, D1, D7). All 66 tests pass. Remaining open: **D2** (auth, intentionally deferred for local use) and **D5** (frontend consolidation, tracked as a separate task). |
| R4 | **Step 9 — Passive Traffic Ingestion Proxy Radar + unified WriterService** | `models/scan.py` (`CapturedFlow`), `config.py`, `services/proxy_pipeline.py`, `services/proxy_manager.py`, `proxy/radar_addon.py`, `schemas/proxy.py`, `api/v1/hunter.py` (`/proxy/*`), `main.py`, `pruner.py` (shared helpers), `preview_dashboard.html` | The single-writer pattern was generalized out of the fuzzer into an **app-wide `WriterService`** (started in the lifespan); the fuzzer forwards to it when running and falls back to an ephemeral per-batch consumer otherwise — **globally ≤1 SQLite writer**. mitmdump runs out-of-process, ships in-scope flows via a loopback POST to a hidden internal-ingest endpoint, Tier-2 enriches + persists + SSE-streams. **All 66 prior tests still pass + 7 new (`test_step9_proxy.py`) = 73.** **Verified end-to-end** (real mitmdump + real DB): browser→proxy→ingest→queue→writer→`captured_flows`; ingest→SSE→client; captured flow→analyze→findings→verify→`FuzzingRecord`→results; plus clean process-tree kill on stop. |
| R5 | **Verdict-correctness measurement groundwork** | `docs/audit/verdict_coverage_audit.md`, `backend/tests/test_verdict_oracle.py`, `scripts/audit/capture_target_bytes*.py`, `backend/tests/test_endpoint_catalog.py` | Audit found **0 of 73** prior tests asserted the verdict oracle was correct. Added **9 human-owned verdict tests** (offline, pure-function; incl. a false-positive killer, a weak-signal guard, and a characterization test pinning that the rule oracle cannot separate a real silent BOLA from the SAFE look-alike). **Live-byte capture** confirmed the target's real bytes match the test inputs AND that `test_vulns.py` / `RESULTS.md` ground truth holds. Plus **6 catalog tests** (D18 Phase 1). Suite 73→88. Commits `292497e`, `6832922`, `2b3d4b9`. *(Annotation 2026-06-09: extended since — the §5 verification-integrity fix + Phase-2 cross-path work later landed; suite now 112. See D18/D19/D20.)* |
| R6 | **D18 §5 — cross-path verification integrity fix + Phase-2 benchmark + doc truth-refresh** | `services/deep_verifier.py` (prompt standard + B-2.2 guard + `ai_verdict_raw`/`guard_override`), `backend/tests/test_d18_b22_guard.py` (18) + `test_d18_phase2_crosspath.py` (6), `vulnerable_target/` (X-CROSS/X-SAFE + `GET /api/audit-log`), `RESULTS.md`, all `docs/*` | The deep verifier gained an **`inconclusive`** verdict + a decisive-evidence / **SAME-RESOURCE** standard + a **deterministic cross-resource guard** (B-2 / B-2.1 / B-2.2; raw model verdict preserved as `ai_verdict_raw`/`guard_override`). Cross-path **X-CROSS** (REAL) / **X-SAFE** (SECURE) now exist on the target, are byte-verified, and were measured through the shadow path to a stable **integrity floor** (`inconclusive`, **0 false verdicts**; X-CROSS's raw `failed` 4/5 corrected by the guard). Same-path reverse-guards intact (P0 `verified`×5 / `failed`×5). Suite 88→**112**; all docs refreshed to match. Commits `20788e4`, `89aff11`, `b634c8d`, `80d42e7`. *(Still open as separate items: a **confident** cross-path verdict = **B-1**; promoting the AI verdict to authoritative = **D19**.)* |

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
  token before any shared or hosted deployment. **NOTE (scope-lock, D25):** the node-3
  scope-lock hardening adds a traffic-EGRESS guardrail (attack traffic is fail-closed to the
  declared scope) — it is **NOT** authentication and does **not** close D2; anyone who can reach
  the port can still drive the API. Keep bound to localhost.

### D3 — `analyze` can hang on the external Gemini call
- **✅ RESOLVED (Stage B).**
- **Where:** `hunter.py` `_invoke_gemini_logic_hunt` (the nuclei remediation call site
  was removed with the scan subsystem).
- **Fix:** the Gemini call is wrapped in `asyncio.wait_for(...,
  timeout=settings.GEMINI_REQUEST_TIMEOUT_SECONDS)` (default 60s). Timeout → fast
  degraded fallback string; caller no longer blocks indefinitely.

---

## 🟠 Medium severity

### D4 — `FindingDetails.scan_id` typed as non-optional `str`
- **✅ RESOLVED (Stage A); the schema itself was later removed with the nuclei scan subsystem.**
- **Where:** `schemas/scan.py` `FindingDetails` (file deleted).
- **Fix (historical):** `scan_id: Optional[str] = None` and `source: Optional[str]` were added.
  Moot now — the scan findings endpoint and its schema no longer exist.

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

### D7 — API-layer test coverage
- **Status:** partially resolved (Stage B + Step 9) — API smoke tests + proxy radar
  tests added. (The untested Nuclei subprocess pipeline this entry once flagged has
  been removed entirely.)
- **Where:** `backend/tests/test_api_endpoints.py` (API smoke); `test_step9_proxy.py`
  (proxy radar, Step 9); plus pruner, custody, Step D extraction in other files.
  Total backend suite: **587 tests**. See [`STATUS.md`](./STATUS.md).
- **Covered:** FastAPI `TestClient` over isolated per-test SQLite with Gemini and
  background fuzzing mocked — analyze (200 + 422), findings persist (201 + 422),
  verify/batch 404s, health check. **Step 9:** WriterService serialization, SSEHub
  fan-out + overflow, ingest backpressure, Tier-2 enrichment, ProxyManager state
  machine + token, internal-ingest loopback/token/oversize guards.
- **Still open:** HAR ingest, batch 400 mixed-host, verify results polling.

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
- **Where:** `utcnow()` helper in `models/scan.py`; call sites in `models/scan.py`
  and `fuzzer.py`.
- **Fix:** replaced deprecated `datetime.utcnow()` while keeping **naive UTC**
  values (columns are not `timezone=True`).

### D10 — Single-table inheritance without polymorphic mapping
- **Where:** `vulnerability_findings.source` is set manually by each producer.
- **Problem:** no enforcement; a code path could forget to set `source` (defaults
  to `"hunter"`) and silently misclassify a row. Lower risk now that Hunter is the
  sole producer (the nuclei producer was removed).
- **Direction:** acceptable for v1; if it grows, consider SQLAlchemy polymorphic
  identity or a CHECK constraint.

### D11 — Single-host batch limit (v1)
- **Where:** `fuzzer.execute_parallel_fuzzing` + `/hunter/verify/batch`.
- **Status:** intended limitation, documented in [`VERIFY_ENGINE.md`](./VERIFY_ENGINE.md).
- **Direction:** a multi-host batch would need per-host custody controllers; only
  build if a real use case appears.

### D12 — Nuclei reader thread serializes DB writes with a 10s wait — ✅ RESOLVED by removal
- **Where:** `nuclei.py` `_nuclei_reader_thread` (file deleted with the scan subsystem).
- **Resolution:** moot — the nuclei subprocess reader no longer exists.

### D13 — `verify=False` (TLS) everywhere
- **Where:** all outbound `httpx` clients (fuzzer, deep verifier, proxy radar).
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

### D18 — Endpoint catalog DONE; automated *discovery* still open
- **Where:** the whole Hunter→Verify intake, and `fuzzer._shadow_endpoint_catalog`
  (the shadow verifier's endpoint list).
- **Status:** the catalog + cross-path work is **DONE — see R6** (Phase 1 OpenAPI catalog
  adapter, `2b3d4b9`; Phase 2 cross-path hole + tests + shadow measurement). **Still open:**
  automated *discovery* — the system does **not find endpoints on its own**; it must be *fed*
  an OpenAPI/HAR spec (`catalog_from_har` is a `NotImplementedError` stub; the spec source is
  the *undeclared* `AI_DEEP_VERIFY_OPENAPI_SPEC` getattr seam — D21). A **confident** cross-path
  verdict (vs the HEAD integrity-floor `inconclusive`) is tracked as **B-1** (now done and
  live-measured and committed `37769b3` — see below). A real endpoint catalog now feeds
  the shadow verifier: `endpoint_catalog.py` (pure OpenAPI→catalog adapter — each entry
  leads with `METHOD /path` and now **carries the operation's genuine `tags`/`operationId`**
  when the spec declares them, `summary`/`description` deliberately not surfaced — + HAR
  stub raising `NotImplementedError` + dispatch) is wired into `_shadow_endpoint_catalog`
  via an optional `catalog_source`. With **no source configured the output is byte-identical
  to the old placeholder (zero regression)**; the real 36-route surface is used only when
  a spec source is explicitly provided. Human-owned tests (`test_endpoint_catalog.py`)
  cover this; the B1/B2 pair is the allowed-to-fail proof (placeholder has 0 cross-resource
  endpoints; real catalog reaches them, incl. `GET /api/invoices/{invoice_id}`).
  - **Phase 2 landed — cross-path holes proven + measured:** the target now carries a
    maintainer-owned cross-path pair — **X-CROSS** (REAL cross-path BOLA,
    `POST /api/users/{id}/display-name`) and **X-SAFE** (SECURE look-alike,
    `POST /api/users/{id}/nickname`) — whose only decisive confirmation is the cross-path
    write record `GET /api/audit-log` (there is **no** same-path GET). Structural tests pin
    this: `test_d18_phase2_crosspath.py` (6) asserts the placeholder catalog can **never**
    reach `GET /api/audit-log` while the real OpenAPI catalog (`build_catalog` over
    `app.openapi()`) does, and that the rule oracle stalls at `suspicious` on both;
    `test_d18_b22_guard.py` (18) asserts the B-2.2 structural guard. Both cases were
    **measured** through the shadow path (5 runs each, `RESULTS.md`) and resolve to an
    **integrity-floor `inconclusive`** — no false verdict either way (X-CROSS's raw model
    verdict was `failed` 4/5, downgraded by the guard; see D19). Suite at that commit: **112**.
  - **Still open — automated attack-surface DISCOVERY:** the catalog is *fed* an
    OpenAPI/HAR source (operator-supplied). The system still does **not discover**
    endpoints on its own. This is the larger half of D18.
  - **✅ DONE (committed `37769b3`) — a CONFIDENT cross-path verdict (B-1):** rather
    than wait for the model to *choose* the decisive `GET /api/audit-log` (it chose it 0/20
    unaided), the code gathers it deterministically and exempts the resulting `verified` from
    the B-2.2 downgrade only after a structural content match. **Live-measured: X-CROSS→
    `verified` 5/5, X-SAFE→`inconclusive` 5/5 (no false positive), reverse-guards intact**, and
    **locked by an automated regression test** (`test_d18_b1_shadow_integration.py`, D22). See
    the **B-1** entry under "Tracked next-line work" and [`STATUS.md`](./STATUS.md).
- **Direction:** feed a real API surface (OpenAPI/Swagger import, aggregated
  HAR/proxy-capture inventory, or crawl) into both the Hunter intake and the deep
  verifier's `available_endpoints`. Until then, document the catalog as a known seam.

### D19 — verdict promotion: IMPLEMENTED, default OFF, acceptance-passed
- **Where:** `services/deep_verifier.py` + `fuzzer._run_shadow_deep_verification`
  (Phase 7); flags `AI_DEEP_VERIFY_ENABLED` / `AI_DEEP_VERIFY_SHADOW` in `config.py`
  (both default `False`).
- **TL;DR:** ✅ the "judge correctly / integrity floor" half (§5) is **DONE — see R6**; ✅ the
  **core of D19 — promoting** the AI verdict to **authoritative** — is now **implemented and
  acceptance-passed, default OFF** (see the ✅ RESOLVED note below). Enabling it on real targets still
  waits on Node 3 (model/target diversity + scope-lock).
  > *The dated **Update (commit …)** bullets below narrate the journey — each accurate as of its
  > commit (when the verifier was still shadow-only); the current state is the **✅ RESOLVED** note at
  > the end of this entry.*
- **Status:** the AI-in-the-loop write-then-read verifier runs **read-only**. In
  shadow mode it re-checks `suspicious` records and **only logs** its verdict
  (`AI_shadow_verdict=… NOT applied (shadow, observe-only)`); it does **not**
  overwrite `verification_status`/`diff_details` or change what the user sees, and
  it never affects a batch (failures are swallowed). **In the default (shadow) posture the persisted
  verdict is still the rule oracle's**, which stalls at `suspicious` on silent cases (opaque
  `200 {"status":"ok"}` writes); D19 (below, default OFF) is what lets code promote that band when
  enabled. Accuracy so far
  is recorded in `vulnerable_target/benchmark/RESULTS.md` (n=9 at the time; 8/8 AI
  correct, 0 FP/FN) but that is **measurement, not promotion**.
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
- **Update (§5 verification-integrity fix landed; still shadow-only):** the deep verifier
  gained a 4th verdict **`inconclusive`** and a **5-point decisive-evidence / SAME-RESOURCE
  standard** in its `SYSTEM_PROMPT`, plus a **deterministic structural cross-resource guard**
  (`_apply_cross_resource_guard`) that downgrades a *cross-resource* `verified`/`failed`
  read-back to `inconclusive` (`guard_override = "cross_resource_readback_not_decisive"`),
  preserving the model's pre-guard verdict as `ai_verdict_raw`. Measured on the new
  X-CROSS/X-SAFE cross-path cases (both → integrity-floor `inconclusive`; X-CROSS's raw
  verdict was a `failed` false-negative 4/5, corrected by the guard — see `RESULTS.md` / D18).
  The rule oracle `_differential_verdict` is **unchanged (still 3-value)**. This is the
  "judge correctly / integrity floor" half of the work; it changes what gets **logged**, not
  what the user sees — still **shadow-only, observe-only, gated off by default**.
- **✅ RESOLVED — the core of D19 landed (default OFF).** The Phase-7 consumer can now PROMOTE a
  rule-oracle `suspicious` record to `verified`, but ONLY through the single choke point
  `_code_authorized_channel` (`fuzzer.py`): `ai_verdict=='verified'` AND (one of the four exemption
  channels fired OR the D24 gate's new `owner_view_corroborated` observability field is `True`). Model
  opinion alone never promotes. The single writer `_promote_record_verified` opens its own session
  (the batch writer has already drained), re-checks `suspicious` on the freshly-read row (so it can
  never override the oracle's own `verified`/`failed`), persists the full evidence chain under
  `diff_details['ai_promotion']`, and swallows any failure so the rule verdict stands. Flag
  `AI_DEEP_VERIFY_PROMOTE` defaults `False`; all three of ENABLED ∧ SHADOW ∧ PROMOTE must be on to
  write. **Acceptance:** offline invariant suite (`test_d19_promotion.py`, 26 mocked-verdict tests,
  zero API) + golden reproduction **clean 430/430** (`scripts/measure/results/sweep_highN_d19.jsonl`,
  harness golden-anchored): promotion reproduces the golden `verified` partition case-for-case, **0
  SAFE promoted, 0 golden-verified dropped, 0 degraded**. **Capability, not real-target readiness** —
  enabling it on real targets still waits on Node 3.
- **Direction (for ENABLING promotion — still default OFF):** the promotion *mechanism* is in place;
  turning it on in a real flow still depends on D18 (handing the verifier the right read-back endpoint)
  and on the Node-3 broadening (a second model, arbitrary real APIs, scope-lock). The full evidence
  trail is retained under `diff_details['ai_promotion']` for audit.

### D20 — D18 cross-path value on the current target (Phase 2) — ✅ RESOLVED (proof landed)
- **Status: ✅ RESOLVED — see R6.** The cross-path proof is done; only a **confident** verdict
  remains, tracked as **B-1** (below). The "write at path A, confirm at path B" hole now
  **exists** and is **measured**: **X-CROSS** (REAL, `POST /api/users/{id}/display-name`)
  + its **X-SAFE** secure look-alike (`POST /api/users/{id}/nickname`), each confirmable
  only via the cross-path write record `GET /api/audit-log` (no same-path GET). Ground
  truth was **byte-verified independent of the engine**
  (`scripts/audit/capture_phase2_crosspath.py`), it has **structural + catalog tests**
  (`test_d18_phase2_crosspath.py`, `test_d18_b22_guard.py`, `test_endpoint_catalog.py`),
  and the **shadow path was run** (`RESULTS.md`): the real catalog hands the verifier the
  cross-path read-back the placeholder never could.
- **Confident cross-path verdict — achieved and committed (B-1, `37769b3`):** previously the
  measured result was the **integrity floor** (`inconclusive` on both) because the model never
  chose the decisive `GET /api/audit-log` unaided (0/20). B-1 fixes this by having the **code**
  gather the read-back: live-measured **X-CROSS→`verified` 5/5, X-SAFE→`inconclusive`/safe 5/5**,
  now locked by a regression test. See the **B-1** entry and [`STATUS.md`](./STATUS.md).
- **Where:** `vulnerable_target/` (X-CROSS/X-SAFE) + the D18 catalog seam.
- **Direction:** the plan below is **done, and B-1 has now confirmed the cross-path case** — add a
  maintainer-owned cross-path hole to the target, confirm its ground truth with **verbatim
  captured bytes** (independent of the engine), then re-run the shadow path to show the
  catalog hands the correct cross-path read-back and the verdict is right. **Ground truth is
  human-owned**: the agent may implement the target code to the maintainer's spec but must
  not design the hole or its expected behavior, and the behavior must be byte-verified
  before use as a test case.

### D21 — Catalog spec source read from an *undeclared* setting — ✅ RESOLVED
- **Where:** `config.py` now declares `AI_DEEP_VERIFY_OPENAPI_SPEC: Optional[str] = None`
  (co-located with `AI_DEEP_VERIFY_ENABLED`/`AI_DEEP_VERIFY_SHADOW`, same convention); the
  consumer is `fuzzer._resolve_openapi_catalog_source` + `_run_shadow_deep_verification`.
- **Was:** the field was **not declared** in `config.py` and read defensively via
  `getattr(settings, "AI_DEEP_VERIFY_OPENAPI_SPEC", None)`, so the real endpoint catalog was
  reachable only by patching settings in-process (tests/drivers), never from normal `.env`/env.
- **Now:** a first-class **`Optional[str]` path** to an OpenAPI/Swagger **JSON** file, loadable
  from `.env`/env like the other `AI_DEEP_VERIFY_*` flags (`AI_DEEP_VERIFY_OPENAPI_SPEC=/path/to/openapi.json`).
  The consumer resolves the path → parsed spec dict and **FAILS SAFE** to the byte-identical
  placeholder on any missing-file / parse / wrong-type error (mirrors the existing
  `_shadow_endpoint_catalog` fail-safe). **Back-compat:** an already-parsed spec **dict** injected
  in-process is still accepted verbatim, so the measurement drivers under `scripts/audit/` keep
  working unchanged. **Default `None` ⇒ zero regression** (unset → byte-identical placeholder).
  JSON only (the repo declares no YAML dependency). Observe-only — it widens only the model's
  `available_endpoints`, never a verdict or the verdict gate.
- **Proof:** `backend/tests/test_d21_spec_config.py` (8) — zero-regression (the allowed-to-fail
  safety anchor), positive file→discovered-surface-merged, fail-safe on missing/malformed/non-object/
  wrong-type, and the dict back-compat path.
- **Not done here (deliberate):** no startup validator that *raises* on a bad path (would crash the
  app on a misconfig and violate the shadow-pass "never break" rule); resolution stays fail-safe.
  YAML support waits on a declared YAML dependency. Live spec fetch is still not performed.

### D22 — Phase-7 shadow path had no automated test — ✅ RESOLVED (`37769b3`)
- **Where:** `deep_verifier.execute_deep_verification`.
- **Was:** the suite never exercised the shadow **integration** end-to-end; the code path that
  invokes the AI verifier was proven only by throwaway harnesses under `scripts/audit/`.
- **Now:** `backend/tests/test_d18_b1_shadow_integration.py` runs the **real**
  `execute_deep_verification` end-to-end with a **mocked Gemini** (no live API, no token cost),
  asserting the B-1 outcomes as a CI asset: X-CROSS→`verified`, X-SAFE→`inconclusive` even when
  the model wrongly says `verified` (the safety line), HALF 2 never fabricates `verified`, and
  same-path cases untouched. Suite 140→**145** green.
- **Still bare:** the `_run_shadow_deep_verification` Phase-7 *wrapper* itself (the integration test
  drives `execute_deep_verification` directly, not via `execute_parallel_fuzzing`) — add if that
  wrapper changes.

### D23 — Content match matched the attacked id against a record's own `id` — ✅ RESOLVED
- **Where:** `deep_verifier._write_record_content_match` (the B-1 HALF-2 safety gate).
- **Was:** the match scanned **all** scalar values of a record, including the record's own
  primary-key `id`. A *second* audit row whose `id` numerically equalled the attacked object id
  — while carrying a value this attack wrote — spuriously satisfied the match, firing the
  exemption on a SECURE control (**X-SAFE false positive**). Confirmed empirically: on a 2-row
  X-SAFE body (2nd row `id==2`, `user_id==1`) the old predicate returned **True**.
- **Now:** the attacked-id check binds to an **owner/subject-style key** —
  `_OWNER_KEY_KEYWORDS` (generic vocabulary: user/owner/subject/account/actor/tenant/…, the
  same sanctioned pattern as `_WRITE_RECORD_KEYWORDS`) + `_field_tokens` (camelCase-aware, so
  `user_id`/`userId`/`UserID` all tokenize alike) + `_record_owner_id_values`. Bare `id`/`pk`
  are deliberately **absent** from the vocabulary — that exclusion *is* the fix. The owner-value
  set is a strict subset of the old scalar set, so the gate can only get **stricter**.
- **Proof:** the collision case returns `True` on the old code and `False` now
  (`test_D23_record_own_id_colliding_with_attacked_id_does_not_match` + 8 more), genericity
  proven on foreign logs naming their subject `ownerId`/`account_id`/`subjectId`/`actor`.
- **Known trade-off:** a record naming its subject outside the vocabulary yields no owner value
  → no match → `inconclusive` (a false negative, but the **safe** direction). Extend the
  vocabulary as real log samples appear.

### D23b — Value match scanned a record's own `id` (mirror of D23) — ✅ RESOLVED
- **Where:** `deep_verifier._write_record_content_match` — the *value* half of the same gate.
- **Was:** D23 tightened the **id** check, but the **value** check still scanned **all** scalars,
  including the record's own primary key. An attack-written value that happened to equal a
  record's `id` satisfied the value half via the id rather than via the content field. Verified:
  `{"id":1,"event":"rename","user_id":2,"new_value":"something_else"}` with attacked id `2` and
  written value `"1"` matched — although `new_value` is **not** what the attack wrote.
- **Now:** the value check binds to **content fields** — `_record_content_values` excludes fields
  whose name is composed **solely** of primary-key/ordinal tokens (`_PRIMARY_KEY_KEYWORDS`:
  id/pk/uuid/guid/rowid/identifier/seq/sequence/ordinal/index, via `_is_primary_key_field`).
  A **qualified** name like `user_id` is *not* the record's own key and stays eligible as content,
  so the exclusion cannot swallow a real written value. Content-value set ⊂ the old scalar set →
  strictly **stricter**.
- **Proof:** the mirror case returns `True` pre-D23b and `False` now
  (`test_D23b_written_value_equal_to_records_own_id_does_not_match` + 4 more); the legitimate
  cases stay green, including a written value that genuinely equals the attacked id when it
  really landed in a content field.
- **Remaining sibling (accepted, not fixed):** value candidates still include the *owner* field's
  value, so if the attack's written value happens to equal the **attacked id itself**, the value
  half can match via `user_id` rather than the content field. Narrow (requires written value ==
  attacked id, and the subject is already the attacked object, so a write to it did occur).
  Closing it would mean excluding owner fields from value candidates too — which would cause
  **false negatives on mass-assignment writes** (where the attack legitimately writes an owner
  field). Judged not worth that trade; revisit if real logs show it. Human-owned.

### D24 — READ-SEMANTIC verdicts had NO deterministic gate (SEV-1) — ✅ RESOLVED
- **Status: RESOLVED** by the **owner-view differential gate** (commit `033fc9e`), on top of the
  two-account ownership baseline (`5a33cb2`). Found by the second target (`depot_target/`) v1 pilot
  and confirmed deterministic at N=20. The history below is kept verbatim: it records the dead ends,
  the adversarial anchor and the boundaries, so none of it is re-litigated.
- **What closed it.** Read-semantic was the only shape where **code gathered no evidence at all**;
  the other four each issue a code-gathered second request, which is exactly why they had real
  gates. It now gathers evidence the same way: code issues an authenticated read of the SAME object
  **as the owner** (via the second identity), and a `verified` survives only if the attack response
  **corroborates that authentic view** — i.e. the attacker demonstrably received the victim's data.
  Masked stubs, sentinels, echoes and denials do not corroborate **regardless of how the refusal is
  encoded** (denial keywords are deliberately never consulted — assuming a denial vocabulary is what
  produced this SEV-1). Downgrade-only by construction: `_apply_owner_view_gate` never assigns the
  literal `verified` (asserted on the AST), so it can only ever take a `verified` away, never create
  one. Scoped to the **no-follow-up branch** — keyed on the structural condition, not on HTTP method,
  because "no follow-up ⇒ no channel reachable" *is* the root cause.
  Measured outcome — three read-type SECURE cases blocked, two read-type REAL cases still `verified`,
  the other four shapes untouched (the diff removes zero lines and contains no guard/channel/anchor
  line). Behavioural proof: same case, same pinned model verdict, pre-gate `FINAL='verified'` vs
  post-gate `FINAL='inconclusive'`.
- **Real-model confirmation (the loop is closed).** The SEV-1 was discovered with the real model, so
  the fix was re-measured the same way — 5 read-type cases, N=1, real Gemini, owner credential
  supplied through the real `AI_DEEP_VERIFY_OWNER_AUTH` field
  (`scripts/audit/shadow_d24_realmodel_run.out.txt`):

  | case | truth | RAW | FINAL | similarity | gate reason |
  |---|---|---|---|---|---|
  | **DP-READ-SAFE** | SECURE | `verified` | **`inconclusive`** | 0.8857 | `owner_view_not_corroborated` |
  | **DP-READ-SAFE-ECHO** | SECURE | `verified` | **`inconclusive`** | 0.9203 | `owner_view_not_corroborated` |
  | X-EQUIV-SAFE | SECURE | `failed` | `failed` | 0.6697 | — (model self-corrected; gate not load-bearing) |
  | DP-READ-VULN | REAL | `verified` | `verified` | 1.0000 | — (corroborated) |
  | X-EQUIV-VULN | REAL | `verified` | `verified` | 1.0000 | — (corroborated) |

  `DP-READ-SAFE` — the original SEV-1, previously `verified` 20/20 deterministically — now lands
  `inconclusive` **while the model still raw-says `verified`**. The model's failure mode is
  unchanged; code holds the line. Note honestly that on `X-EQUIV-SAFE` the model answered `failed`
  on its own, so the gate never engaged there — that row is **not** evidence of the gate working.
- **✅ Confirmed at scale (GOLDEN two-target run).** The initial confirmation was N=1; the gate is now
  exercised in the authoritative GOLDEN run (`scripts/measure/results/sweep_highN.jsonl`, real
  gemini-2.5-pro, N=20 SAFE / N=10 VULN, both targets). Read-semantic results at full N:
  `DP-READ-SAFE` and `DP-READ-SAFE-ECHO` held to `inconclusive` **20/20 each** while the model raw-said
  `verified`; both read VULN `verified` 10/10; and on `X-EQUIV-SAFE` the model flipped to `verified`
  **1/20** and the gate caught it (**without D24 that run is a false positive** — first live evidence
  the read gate is load-bearing on target #1, not only Depot).
- **⚠️ STILL OPEN — boundaries this fix does NOT close. No claim may imply otherwise:**
  1. **Public / shared resources (residual gap).** A genuinely public or shared resource legitimately
     returns the same content to both identities, so it corroborates and the gate permits. Nothing
     upstream excludes public resources — verified by code reading; the only near-hit
     (`"unauthenticated"`, `fuzzer.py:109`) is a soft-logout signature for auth self-heal, unrelated.
     Because the gate is downgrade-only this is **status quo, not a regression**, and the gate was
     deliberately NOT contorted to handle it. **(Update — now addressed by the D30 public-resource
     probe: an opt-in, downgrade-only bystander re-read that suppresses confirmation only when
     affirmatively certain a resource is public. See the **D30 — ✅ RESOLVED** entry below. One
     residual remains: a resource "broken for every authenticated user" is indistinguishable from a
     public one and is suppressed — a safe-direction miss.)**
  2. **Owner credential is per-DEPLOYMENT, not per-finding** (`AI_DEEP_VERIFY_OWNER_AUTH`). Sufficient
     for both labs and for proving this gate; a real target whose findings belong to different owners
     would need per-finding credentials, which **do not exist**.
  3. **Threshold calibration boundary (see D24 (f)).** `0.95` is calibrated on **deterministic,
     seeded lab data** across two targets, comparing **raw** bodies. Robustness against high-entropy
     real-target responses is **unvalidated**.

#### D24 (f) — calibration boundary and the sanitizer dead end
- **The threshold rests on lab determinism.** Both REAL cases scored exactly `1.0000` only because
  seeded lab objects are byte-stable between two reads. Real objects differ (timestamps, generated
  ids, ETags), which would push a true positive's similarity **down** — toward a wrong block, the
  same direction the earlier candidate gates died in.
- **The obvious remedy was measured and REJECTED.** The gate calls `_compute_similarity`
  ([`fuzzer.py:681`](../backend/app/services/fuzzer.py)) on **raw** bodies; that helper does no
  scrubbing. The rule oracle instead sanitizes first via `_sanitize_response_text`
  ([`fuzzer.py:648`](../backend/app/services/fuzzer.py) — JSON noise-key blanking plus regexes for
  timestamps, **UUIDs** and hex tokens) and only then compares. Reusing that in the gate path looks
  like a free win. It is not — measured on all five cases:

  | case | truth | RAW sim | SANITIZED sim |
  |---|---|---|---|
  | DP-READ-VULN / X-EQUIV-VULN | REAL | 1.0000 | 1.0000 |
  | DP-READ-SAFE | SECURE | 0.8857 | 0.8991 |
  | DP-READ-SAFE-ECHO | SECURE | 0.9203 | 0.8972 |
  | **X-EQUIV-SAFE** | **SECURE** | 0.6697 | **0.9744 → would PASS the gate** |

  The band gap collapses **0.0797 → 0.0256** and `max(SECURE)` rises **above** the threshold. Cause:
  the sanitizer scrubs precisely the evidence that separates a denial stub from real data — for
  X-EQUIV-SAFE the `id` key is a `_DYNAMIC_JSON_KEYS` member and `account_ref` is caught by the UUID
  regex, so both sides blank to `{{DYNAMIC_NOISE}}` and only a trivial delta survives. **Do not adopt
  the sanitizer wholesale in the gate path.**
- **Net:** volatile real-target fields push REAL *down*; scrubbing pushes SECURE *up*. Neither
  direction is validated, and **this cannot be settled by more lab tuning — it needs real-target
  data.** A "scrub volatile-but-not-identity fields" variant might thread the needle, but that is new
  logic and would require its own 5-case validation before it is believed.
- **Where:** `deep_verifier.execute_deep_verification` + `_apply_cross_resource_guard`, on the
  **read-semantic** shape (M1.1) — i.e. any case where the model answers from the attack response
  alone and requests **no follow-up**.
- **The gap.** All four exemption channels (`write_record`, `state_readback`, `delete_readback`,
  `state_jump`) exist to *exempt a cross-path verdict from a downgrade*, and the B-2.2 guard only
  *downgrades a cross-resource read-back*. When there is **no follow-up**, there is no read-back to
  judge: the guard is structurally a **no-op** and every channel is **unreachable**. The FINAL
  verdict is therefore **exactly the model's raw opinion, with no code between it and the user**.
  The anchors still compute (`caller_identity`, `anchoring_result`) but on this shape they are
  **observe-only and gate nothing**.
- **Measured (N=20 each, gemini-2.5-pro, both driven direct in ONE session for comparability —
  `scripts/audit/shadow_readtype_severity_run.out.txt`):**

  | Case | ground truth | raw dist | FINAL dist | guard_override | follow-up | FINAL==RAW |
  |---|---|---|---|---|---|---|
  | **DP-READ-SAFE** (Depot) | SECURE | `verified` 20/20 | **`verified` 20/20** | `None` 20/20 | none 20/20 | 20/20 |
  | X-EQUIV-SAFE (target #1) | SECURE | `failed` 20/20 | `failed` 20/20 | `None` 20/20 | none 20/20 | 20/20 |

  - The Depot false positive is **DETERMINISTIC (20/20), not intermittent** — a securely-refused
    cross-account read is reported as a confirmed BOLA on every single run.
  - **Target #1's clean read-type record is MODEL COMPLIANCE, not a code-held line.** Its
    `guard_override` is `None` on all 20 runs and FINAL rides RAW on all 20 — identical engine-side
    posture to the failing case. The engine did not "catch" anything on X-EQUIV-SAFE; the model
    simply happened to answer `failed`.
  - Engine-side posture is **identical** across both (`caller_identity='owner_not_found'` 20/20, no
    follow-up 20/20). The ONLY difference is what the model decided. Depot's differently-encoded
    denial (S5: `status:"SEALED"` + zeroed owner, vs target #1's `"DENY"`) is enough to flip it.
  - Incidental: Depot's `anchoring_result` was `confirmed` in 7/20 runs (the denial echoes the
    requested `docket_id`, which matches the attacked id), i.e. the observe-only anchor would have
    *corroborated* the wrong answer. It gates nothing, so it changed no verdict — but it is not a
    safety net either.
- **Ground truth is not in doubt.** Depot's denial discloses **no** victim data (`account_id` zeroed,
  `route` masked, `status` a constant refusal token) and is proven secure independently by
  `depot_target/test_vulns.py::test_DP_READ_SAFE_alice_cannot_read_bobs_docket`. It is the same
  soft-200-denial convention as target #1's T-TRAP, which is likewise labelled SECURE. The label was
  **not** adjusted to make the engine agree.
- **Scope — do NOT over-read this into the other shapes.** The other four shapes are genuinely
  code-gated and that result stands, including on Depot: in the v1 pilot every core VULN verified
  through its own channel (`write_record` / `state_jump` / `delete_readback` ×2) and every
  non-read SAFE/control was held at `inconclusive` by a real gate
  (`cross_resource_readback_not_decisive`, `no_jump`, `preflight_absent`). Their zero-FP property is
  held by code. **Only the read-semantic shape is ungated.**
- **Consequence for the record (now closed):** the earlier single-target headline "140 SAFE runs → 0
  false positives" was true as measured, but 20 of those 140 (the X-EQUIV-SAFE runs) were **not
  code-gated** — correct only because the model was. With D24 landed and the GOLDEN two-target run
  (300 SAFE/control → 0 FP), the read shape is now code-gated and X-EQUIV-SAFE at N=20 caught the
  model's one `verified` flip. The 140/70 record is superseded by the GOLDEN record; both are stated
  in `RESULTS.md`.
- **Direction — ✅ DELIVERED as specified.** The requirement was: a deterministic gate so a
  `verified` resting on the attack response alone must be corroborated by code rather than asserted
  by the model; provably **stricter** (only ever weakening a `verified`); no regression to the four
  existing channels; proven on **both** targets before being believed. All four held — see "What
  closed it" above. **D19 is no longer blocked by D24 on the read-semantic shape**, subject to the
  three boundaries listed above, which remain open and must not be glossed.

#### D24 (a) — the PROVENANCE principle
- **Statement:** evidence must never be credited from a value the **ATTACKER supplied** — the
  attacked object id, or any value already present in the attack request's path / query / body.
  Only **genuinely victim-owned** data may corroborate a leak. A verifier that credits an echo of
  its own input is not measuring the server; it is measuring itself.
- **This is the same class of error as the historical B-1 / D23 resource-identity conflation.** D23
  fixed one instance of it (an attacked id matching a record's *own* primary key) by binding the
  match to an owner/subject-**named** key. The read-semantic path reproduces the same mistake in a
  different place, which is why it deserves a named principle rather than another point fix.
- **A field-NAME filter is necessary but NOT sufficient.** Naming tells you a field is *supposed* to
  carry an owner identity; it says nothing about **where the value came from**. See (b).

#### D24 (b) — `DP-READ-SAFE-ECHO`: the adversarial anchor (committed `6773bd5`)
- `GET /depot/bonds/{bond_id}` is a **genuinely SECURE** read whose cross-account denial **echoes the
  attacker-supplied id back into the owner-named field** instead of zeroing it. It forms a controlled
  pair with `DP-READ-SAFE`, differing in exactly one field:

  | SECURE case | owner-named field | `_anchor_caller_identity` |
  |---|---|---|
  | `DP-READ-SAFE` (docket) | `account_id`: zero-uuid | `owner_not_found` |
  | `DP-READ-SAFE-ECHO` (bond) | `account_id`: **the requested id** | **`confirmed`** |

- **What it defeats, by construction:** the obvious candidate gate — *"`caller_identity ==
  owner_not_found` cannot be decisive"* — discriminates 4/4 on the cases known before it existed, and
  this case passes straight through it while leaking nothing. Verified offline on the real anchor
  (pure function, no API calls). It is an **allowed-to-fail safety anchor**: it must never be
  weakened or relabelled to make a gate pass. Ground truth SECURE, proven independently by
  `depot_target/test_vulns.py` (no engine imports).

#### D24 (d) — dead ends already ruled out (do NOT re-propose without new evidence)
- **Gate A / Gate B (provenance filter on identity values) — DEAD.** Validated offline on all
  five read-type cases before any engine edit; both readings failed acceptance.
  Root cause: for a **self-referential object** — where the object's identity IS the owner's
  identity (`GET /users/2` → `{"user_id": 2}`, `GET /depot/waybills/{BOB}` → `{"account_id": BOB}`,
  the most common read-BOLA shape) — the victim-owned marker **necessarily equals** the attacked id,
  so filtering out attacker-supplied values deletes the only proof of ownership. `X-EQUIV-VULN`
  survived only because target #1 happens to carry a second owner-named field (`account_ref`); a gate
  whose verdict depends on how many owner-named fields a response happens to contain is not a gate.
  Gate A additionally let two SAFE cases through, because **"not attacker-supplied" ≠ "victim-owned"**:
  there are three categories — attacker echo, sentinel/placeholder, genuinely victim-owned — and the
  first and third are **value-identical** on self-referential objects.
- **The reframe that followed:** read-semantic is the ONLY shape where **code gathers no evidence at
  all**. The other four each have a code-issued second request (write-record read-back, object-state
  read-back, negative assertion, state-jump pre-flight), which is precisely why they have real gates.
  Squeezing a discriminator out of the attack response alone is the wrong move.
- **Current direction — OWNER-VIEW DIFFERENTIAL:** code issues an authenticated read of the same
  object **as the owner**, and a read-semantic verdict may be decisive only if the attack response
  corroborates that authentic view. Independent of denial encoding, owner-field count and schema luck.
  **Precondition was missing and is now built:** the engine held exactly one identity; the
  two-account ownership baseline (`AI_DEEP_VERIFY_OWNER_AUTH`, commit `5a33cb2`) supplies the second.
  **Known boundary:** that credential is **one per DEPLOYMENT, not per finding** — sufficient for both
  labs and for proving the gate, but a real target whose findings belong to different owners would
  need per-finding credentials, which **do not exist**. No claim may imply they do.

#### D24 (e) — BLIND SPOTS to validate when the gate is actually built
> Carried forward deliberately: the adversarial review of the owner-view principle was never reached,
> because the precondition check (Step 1) failed first. These are **recorded, not designed** — each
> must be settled before the gate ships, and the 5-case offline table must be re-run.
- **(1) Public / shared resources.** A genuinely PUBLIC or shared resource legitimately returns the
  same content to both identities, so owner-view corroboration would "confirm" on an endpoint with no
  access-control flaw at all — a **false positive**. Must be checked explicitly, and it must first be
  established whether anything **upstream already excludes** public resources (the rule oracle, the
  Hunter intake, or the catalog) or whether nothing does. Do not assume it is handled.
- **(2) Corroboration exactness vs high-entropy fields.** Two reads of the same object will differ in
  timestamps, generated ids, tokens and other volatile fields, so "the attack response matches the
  owner view" cannot mean byte-equality. How exact the match must be needs settling — and it should
  **reuse existing normalization** (the fuzzer already computes similarity/length-deviation for the
  rule oracle) rather than inventing new comparison logic.
- **(3) Fail-safe remains BLOCK.** A failed, timed-out, out-of-scope or non-2xx owner view must make
  the verdict *less* confident, never more. `OwnerViewResult.available` is True only on a clean 2xx;
  every other value must block. Already expressible — do not weaken it for convenience.

#### D24 (c) — `_anchor_evidence` never received the D23 hardening
- [`deep_verifier.py:843`](../backend/app/services/deep_verifier.py) —
  `return "confirmed" if _scalar_str(value) == _scalar_str(attacked_object_id) else "value_mismatch"`.
  It compares the value at **any** model-cited `evidence_path` against the attacked object id, with
  **no field-name filter and no provenance notion whatsoever**. Any endpoint that echoes the
  requested id back satisfies it.
- Measured consequence: on `DP-READ-SAFE` the model cited `docket_id`, the denial echoed it, and
  `anchoring_result` read **`confirmed` in 7/20 runs on a SECURE endpoint** — the observe-only anchor
  would have *corroborated the wrong answer*. It gates nothing today, so it changed no verdict, but
  it is not a latent safety net either, and it must not be used as one.
- By contrast `_anchor_caller_identity` ([`deep_verifier.py:891-899`](../backend/app/services/deep_verifier.py))
  does carry the D23 lesson — it only considers values in `_OWNER_KEY_KEYWORDS`-named fields — which
  is why it is the stronger of the two. It is still **not** provenance-aware, which is exactly what
  `DP-READ-SAFE-ECHO` exploits.

---

## Tracked next-line work (OPEN — see [`ROADMAP.md`](./ROADMAP.md) §4)

> Not severity items — the roadmap's main-line nodes, recorded here because ROADMAP.md
> says to track them in this file. Concise on purpose; ROADMAP.md is the source of truth.

### B-1 (✅ DONE — committed `37769b3`) — confident cross-path verdict
- **What:** make the verifier actually *confirm* cross-path bugs (promote X-CROSS from
  `inconclusive` → `verified`) **without regressing the §5 integrity floor**. Achieved.
- **Landed & committed (`37769b3`):**
  1. **Catalog semantics** — `endpoint_catalog._format_entry` carries the operation's genuine
     `tags`/`operationId` (was: bare `METHOD /path`).
  2. **Deterministic write-record gathering (HALF 1)** — when the attack is a write with no
     same-path read-back, the *code* (not the model) selects a record/log endpoint from the
     catalog and forces it as the follow-up (`select_write_record_endpoint` /
     `has_same_path_readback`), sidestepping the model never choosing it unaided (0/20).
     *(M1.2 update: HALF 1 is now **object-scoped** — `_record_is_relevant_to_write` probes the
     candidate and force-gathers only if the record holds the caller's own landed write, else
     steps back so the model reads the object's own state. B-1 preserved; see STATUS M1.2 /
     `test_m12_object_scope.py`.)*
  3. **Write-record exemption (HALF 2)** — `_write_record_content_match` +
     `_apply_cross_resource_guard(write_record_decisive=…)`: a cross-path `verified` is
     exempted from the B-2.2 downgrade **only** when a single record structurally contains
     the attacked object id **and** a value this attack wrote (scalar equality). `verified`
     only; a secure control (X-SAFE) with no matching record stays `inconclusive`.
  - **Live-measured** (shadow, N=5, gemini-2.5-pro): X-CROSS→`verified` 5/5,
    X-SAFE→`inconclusive` 5/5 (no false positive), reverse-guards intact (transcript
    `scripts/audit/shadow_b1step3_code_gather_measure.out.txt`), and **locked by an automated
    regression test** (`test_d18_b1_shadow_integration.py`, D22) + offline units
    (`test_d18_b1_write_record.py`).
- **Follow-ups (separate items, not B-1 blockers):** D21 (declare the spec field), D23/D23b (tighten
  the id match), broaden beyond the single X-CROSS shape, update `RESULTS.md` with the B-1 result,
  then D19 (make the verdict authoritative — ✅ since landed, default OFF; see the D19 entry). See
  [`STATUS.md`](./STATUS.md).

### M1.2 (✅ DONE) — silent write confirmed via a code-gathered object-STATE read-back
- **What:** the third confirmed vuln shape. A silent cross-path write with **no same-path GET and
  no relevant write-record** — the only decisive evidence is the attacked object's **own state on a
  different path**. Achieved without weakening the integrity floor; **0 false positives**.
- **Landed (three parts):**
  1. **(A) State-readback exemption** — `STATE_READBACK_EXEMPTION_REASON`, a SECOND guard channel
     **disjoint** from B-1's write-record exemption (kept apart by `_path_is_write_record`), `verified`-only,
     cross-path-only. Fires **only** when code AND-confirms three anchors: owner==attacked ∧
     caller!=owner (`_anchor_caller_identity == "confirmed"`) **and payload-causality**
     (`_anchor_payload_causality` — THIS attack's unique value present). Causality is the
     **false-positive gate**: the other two confirm for a securely-dropped write too.
  2. **(B) Deterministic object-state gather** — `endpoint_catalog.select_object_state_endpoint`
     (+ `attacked_resource_noun`), the target-agnostic mirror of B-1's HALF 1: resource-noun match +
     object-scoped `{template}` bound to the attacked id, record/log endpoints excluded, the attack's
     own path rejected, `None` rather than fabrication. The model found that path **0/5** unaided;
     code now gathers it **5/5**. Genericity proven on a foreign spec (`test_m12b_state_gather.py`).
  3. **(C) Prompt carve-out** — `SYSTEM_PROMPT` rule 5 (+ `_TURN2_TEMPLATE` + the options-block verdict
     definitions) now names a **system-gathered** read of the attacked object's own state as decisive
     alongside same-path and write-record. This closed a real **prompt/code contradiction**: the code
     gathered and exempted a cross-path state read while the prompt still forbade concluding from a
     different path, so the model held decisive evidence and answered `inconclusive` 2/5. VULN **3/5 → 5/5**.
- **Live-measured** (shadow, N=5, gemini-2.5-pro, fresh-seeded per run; transcript
  `scripts/audit/shadow_m12c_prompt_carveout_run.out.txt`): X-SILENT-VULN→`verified` **5/5**;
  **X-SILENT-SAFE→`verified` 0/5** (causality `absent` 5/5 → no exemption → `inconclusive`);
  **B-1 not regressed** (X-CROSS `verified` 5/5, X-SAFE 0 `verified`).
- **Offline:** `test_m12_state_readback_exemption.py` (exemption both ways) + `test_m12b_state_gather.py`
  (resolver, foreign-spec genericity, B-1 precedence, no-fabrication, and a model-chosen cross-path read
  that stays `inconclusive`). New byte-verified target ground truth X-SILENT-VULN/SAFE in `test_vulns.py`.
- **Known boundary (recorded, not fixed):** payload-causality assumes a **high-entropy** written value;
  on boolean / small-int / enum fields, or under concurrent runs, it can collide. See ROADMAP §7.
- **Optional hardening (recorded, NOT done):** the prompt restricts case (c) by *provenance*
  (system-gathered) while the code gate keys on *evidence* (the three anchors). Aligning them = adding
  `followup_is_code_gathered` to `_state_readback_decisive` — one line, only ever stricter.
- **Still open (unchanged by M1.2):** D19 (verdict authority) and D21 (declared spec field).

### M1.3 (✅ DONE) — delete-type confirmed by a NEGATIVE ASSERTION
- **What:** the FOURTH confirmed vuln shape, and the first whose proof is an **absence** rather
  than a presence. A cross-user DELETE returns an opaque 200; the only decisive evidence is that
  the victim's object went from EXISTING to GONE. Achieved with **0 false positives**.
- **Landed:**
  1. **PRE-FLIGHT READ (the coincidence gate)** — for a DELETE attack the code GETs the victim
     object's own state (scope-locked, reusing `select_object_state_endpoint`) **before** issuing
     the delete, and caches it. "It vanished" only proves a delete if "it existed and was active
     just before" is anchored; otherwise the object may never have existed or was already deleted.
     **No pre-flight existence proof → NEVER `verified`.** A pre-flight failure is non-fatal: it
     leaves existence unproven, so the verdict stays `inconclusive`.
  2. **DUAL-TRACK negative assertion** (`_anchor_negative_assertion` + `_deletion_signal`) —
     decisive on **physical** removal (404/403/410) **or** **logical/soft** deletion (200 with a
     lifecycle field flipped, detected by generic vocabulary: string statuses, boolean
     `is_deleted`/`is_active`, timestamp `deleted_at`). **404 is deliberately NOT hardcoded** as
     the only proof of vanishing — real APIs mostly soft-delete.
  3. **A THIRD, DISJOINT exemption channel** (`DELETE_READBACK_EXEMPTION_REASON`), `verified`-only,
     cross-path-only, gated on caller-identity computed on the **PRE-FLIGHT body** (the AFTER read
     of a physical delete is a 404 with no owner) **AND** the negative assertion. Disjoint by
     construction: a DELETE has no written value, so the M1.2 state channel (payload-causality) and
     B-1's write-record channel can never fire for it.
- **Bug fixed in passing:** a DELETE no longer triggers B-1's HALF-1 write-record gather. With no
  written values the M1.2 object-scope probe was skipped and `_object_scoped` defaulted to the
  B-1-safe `True`, so HALF 1 wrongly grabbed the audit-log and preempted the object-state gather.
  Provably safe: `_write_record_content_match` *requires* written values, so B-1's exemption was
  unreachable for a delete anyway; B-1's own cases are POST writes.
- **Live-measured** (N=5 each, gemini-2.5-pro, fresh-seeded per run; transcript
  `scripts/audit/shadow_m13_delete_run.out.txt`): X-DELETE-VULN-HARD→`verified` **5/5**
  (`confirmed_physical`); X-DELETE-VULN-SOFT→`verified` **5/5** (`confirmed_logical`);
  **X-DELETE-SAFE→`verified` 0/5** (`still_present`); **X-DELETE-CONTROL→`verified` 0/5**
  (`preflight_absent`). **No regression:** B-1 X-CROSS `verified` 5/5, X-SILENT-VULN `verified` 5/5,
  X-SILENT-SAFE 0 `verified`.
- **Offline:** `test_m13_delete.py` (negative-assertion truth table, `_deletion_signal` variants,
  guard channel, **foreign-spec genericity**, integrated both-ways + the coincidence gate). New
  byte-verified target ground truth X-DELETE-VULN-HARD/SOFT + X-DELETE-SAFE in `test_vulns.py`.
- **Auditability (additive, observe-only):** the result surfaces `preflight_caller_identity_anchor`
  so the transcript shows the anchor the gate ACTUALLY used, not the AFTER-read one.
### M1.4 (✅ DONE) — mass-assignment confirmed by a LOW-ENTROPY STATE JUMP
- **What:** the FIFTH and final M1 shape — the attacker sneaks a privileged field (`role`,
  `is_admin`, `tier`) into a write on the VICTIM's object. The response is a byte-identical
  `{"status":"ok"}` whether the field was bound or stripped. Achieved with **0 false positives**;
  **M1 is complete.**
- **The problem it exposed:** payload-causality (M1.2's false-positive gate) assumes the written
  value is **UNIQUE** — "my value is in the object, so I wrote it". Mass-assignment writes
  **LOW-ENTROPY** values (`"admin"`, `true`), where presence proves nothing: it cannot tell
  "I set it" from "it was already that". The hazard was flagged in ROADMAP §7 *before* building,
  then demonstrated empirically.
- **Landed:**
  1. **STATE-JUMP anchor** (`_anchor_state_jump`) — causality proven by **movement**, not presence:
     **every** field the attack sent must have moved from a **KNOWN pre-flight state** to the
     injected value. Checking all sent fields is strictly stronger than checking one named field
     (and survives the `path_segment` attack shape, which keeps ids derivable but does not name
     the injected field).
  2. **MISSING is a valid original state, UNKNOWN is not.** A field absent from a **SUCCESSFUL
     2xx, parseable** pre-flight read is genuinely MISSING — privileged fields are commonly hidden
     — so `missing→injected` verifies (hidden-field escalation). A request failure, a non-2xx, or
     unparseable JSON is **UNKNOWN**: it can never yield `confirmed_jump`, so it can never
     `verify`. The anchor is wrapped so it never raises; a malformed post-read degrades to
     `inconclusive`, never a crash.
  3. **A FOURTH, DISJOINT exemption channel** (`STATE_JUMP_EXEMPTION_REASON`), `verified`-only,
     cross-path-only, gated on caller-identity **AND** `confirmed_jump`.
- **A REAL false positive found and fixed (the narrowing).** On a mass-assignment **SAFE** case
  (privileged field stripped by an allow-list, legitimate co-submitted field lands) the observed
  anchors were `caller_identity=confirmed` + `payload_causality=confirmed_in_body` — meaning
  **M1.2's channel would have exempted a SECURE case**. The fix narrows M1.2: whenever a pre-flight
  baseline exists, the state-jump gate **governs** and the payload-causality channel yields. This
  is a narrowing, not a weakening — it can only ever produce **fewer** exemptions. Locked by
  `test_HAZARD_m12_causality_would_false_positive_on_mass_assignment_safe`.
- **Residual fix (routing priority).** Routing originally chose the state-jump gate by the
  *declared attack type*, so an attack **mistyped** as plain BOLA (but carrying a body that
  co-submits a low-entropy field) would still have fallen back to payload-causality. Routing now
  keys on **evidence, not declaration**: a pre-flight state exists → state-jump governs, whatever
  the attack was called. The pre-flight read was widened from delete-or-mass to **all write
  methods** to make that baseline available. Locked by
  `test_RESIDUAL_FIX_mass_assignment_mistyped_as_BOLA_safe_stays_inconclusive`; the other four
  shapes are unchanged in verdict (three of them now exempt via the state-jump channel instead —
  same `verified`, stricter reason).
- **Live-measured** (N=5 each, gemini-2.5-pro, fresh-seeded per run; transcript
  `scripts/audit/shadow_m14_mass_assignment_run.out.txt`. These cases were later **re-measured at
  higher N** — `scripts/audit/shadow_highN_zerofp_run.out.txt` (SAFE/control N=20, VULN N=10) plus
  `shadow_highN_xequiv_run.out.txt` (the M1.1 read shape, same N) — which is now **the authoritative
  record for the whole M1 suite**, superseding every per-shape N=5 figure across these docs. A second
  N=5 transcript, `…_postfix_run.out.txt`, was **accidentally overwritten** by a regression driver
  copied from it that kept its hardcoded output path; the figures below were recorded before that and
  are unaffected, and the high-N re-run supersedes them):
  X-MASS-VULN present-value→`verified` **5/5** (high-N **10/10**); X-MASS-VULN MISSING→injected→`verified`
  **5/5** (high-N **10/10**); **X-MASS-SAFE present→`verified` 0/5** and **missing→`verified` 0/5**
  (high-N **0/20** each); **CONTROL (injected == pre-flight value, no jump)→`verified` 0/5** (high-N
  **0/20**). On the SAFE cases the model raw-said `verified` (high-N: **40/40** across the two X-MASS-SAFE
  cases) and **the gate refused every time** — the line is held by code, not by model compliance.
  **High-N aggregate (single-target, SUPERSEDED): 140 SAFE/control runs → 0 false positives; 70 VULN → all `verified`.**
  The **authoritative** record is now the GOLDEN two-target run — **300 SAFE/control → 0 FP; 130 VULN → all
  `verified`; 430/430 usable** (`scripts/measure/results/sweep_highN.jsonl`); see `RESULTS.md`.
  ⚠️ **Qualified by D24:** 20 of those 140 SAFE runs (X-EQUIV-SAFE, the read-semantic shape) were
  **not code-gated** — `guard_override=None` 20/20, FINAL rode RAW 20/20. The mass-assignment result
  described here IS code-gated and stands; the read-type one rests on model compliance. See D24.
- **Post-fix live NO-REGRESSION: CONFIRMED, all prior shapes.** Authoritative record = the high-N
  re-measure above (`shadow_highN_zerofp_run.out.txt` + `…_highN_xequiv_run.out.txt`), which supersedes
  the earlier N=5 regression run (`shadow_m14_regress_run.out.txt`, 30/30 clean; itself a re-run after
  an attempt truncated by the Gemini project's monthly spending cap — 27/55 runs `429 RESOURCE_EXHAUSTED`
  → `status=degraded`, graceful but not data). With the routing fix in place, at high N: B-1 X-CROSS
  `verified` **10/10** (`write_record_readback_decisive`, pre-flight `None` — a record path resolves no
  object state, exactly as designed); X-SILENT-VULN `verified` **10/10**; X-EQUIV-VULN `verified`
  **10/10**; X-DELETE-VULN-HARD `verified` **10/10** (`confirmed_physical`); X-DELETE-VULN-SOFT
  `verified` **10/10** (`confirmed_logical`); X-MASS-VULN present + missing `verified` **10/10** each;
  **every SAFE/control case `verified` 0/20** (X-SILENT-SAFE `no_jump`, X-DELETE-SAFE `still_present`,
  X-EQUIV-SAFE `value_mismatch`, both X-MASS-SAFE, the no-jump CONTROL, B-1 X-SAFE).
- **Expected channel shift, not a regression:** X-SILENT-VULN now exempts via
  `state_jump_causally_decisive` instead of `state_readback_causally_decisive`. It is a POST with a
  JSON body whose object-state endpoint resolves, so a pre-flight baseline exists and the **stricter**
  gate governs by construction. Verdict unchanged (`verified` 10/10), `confirmed_jump` 10/10. The DELETE
  cases keep their own channel (no body → `no_sent_fields` → the jump cannot govern), so the four
  channels remain disjoint under the new routing.
- **Offline:** `test_m14_mass_assignment.py` (state-jump truth table incl. MISSING vs UNKNOWN,
  the guard channel, the hazard test, the residual-fix test, integrated both-ways). New
  byte-verified target ground truth X-MASS-VULN / X-MASS-SAFE in `test_vulns.py`.
- **Still open (unchanged by M1.4):** D19 (verdict authority) and D21 (declared spec field) —
  these are now the next line, since the M1 gate on D19 is met.

### Scope-lock hardening (OPEN) — prerequisite for real targets
- **What:** consolidate the duplicated host-scope checks — the fuzzer's `_send_request` /
  `ScopeViolationError` enforcement and the deep verifier's own follow-up pre-check, plus the
  proxy's separate capture-side `in_scope` — into one audited implementation; add an
  adversarial test suite (substring / protocol-relative / userinfo tricks); and add runtime
  out-of-scope probes (don't trust config alone).
- **Why open:** hard prerequisite before pointing at anything beyond localhost / self-built
  labs (relates to D2 — no auth).

### D25 — Scope-lock hardening — ✅ RESOLVED (IP-pinning follow-up open)
- **Status: ✅ RESOLVED.** Node-3 scope-lock hardening landed as six commits
  (`2b6e457` → `633c015`). ALL host-scope decisions now go through ONE audited `ScopePolicy`
  (`backend/app/services/scope.py`), replacing the former duplicated `_host_of` checks.
- **Active enforcement** is converged at the `_send_request` chokepoint: fail-closed
  (unconditional — no longer only when a custody controller is present), per-hop redirect
  validation (httpx auto-follow disabled under a locked scope; the FIRST out-of-scope hop is
  refused), and a resolved-IP DNS-rebinding / SSRF guard (a PUBLIC registrable name resolving to
  loopback/private/reserved is refused; cloud-metadata + link-local are always refused; an
  explicitly-declared private/intranet target is honored). The deep verifier's four inline checks,
  the custody re-auth probe, `dry_run_auth_refresh`, and the batch route all consult the same policy.
- **Passive capture** (`pruner.host_in_scope` / `radar_addon`) shares the SAME matcher — passive and
  active return the IDENTICAL host decision (proven by test). Passive is host/port/wildcard only: the
  resolved-IP guard is an active-connection concern (the browser, not the proxy, opens those sockets).
- **Also delivered:** a unified run-time `scope`+`model` declaration (`approved_host` a legacy
  alias); over-broad-wildcard rejection via a vendored Public Suffix List snapshot; port rules (no
  port ⇒ any; explicit ⇒ strict host+port); adversarial normalization tests (substring / endswith /
  protocol-relative / userinfo / trailing-dot / IDN / decimal+hex IP encodings); and SecretStr
  wrapping of the API key + owner-auth + ingest token (no repr/log/serialization leak; verifiable
  no-leak test).
- **OPEN FOLLOW-UP — IP-pinning (the DNS TOCTOU window).** The resolved-IP guard currently does
  *resolve+validate*: it resolves the declared name and validates the IP class BEFORE the request,
  but httpx re-resolves at connect time, leaving a small time-of-check-to-time-of-use window a fast
  DNS-rebinding attacker could exploit. Recorded httpx judgment: clean IP-pinning has no public
  resolver hook and forcing it breaks TLS SNI / cert validation, so fragile pinning was deliberately
  kept OUT of the core network path for v1. **Follow-up:** pin the validated IP for the connection
  (a custom transport/resolver) to close the window. Not yet built. The verdict core is untouched by
  any of the scope-lock work.

### D26 — API_HOST default bound to ALL interfaces (N5) — ✅ RESOLVED (hardened to loopback)
- **Status: ✅ RESOLVED.** `API_HOST` now defaults to **`127.0.0.1`** (loopback) in
  `backend/app/core/config.py`; it was `"0.0.0.0"`. The server binds to THIS machine only unless the
  operator explicitly opts into exposure with `API_HOST=0.0.0.0` (env / `.env` still override — that
  ability is unchanged). This was the pre-release "API_HOST → 127.0.0.1" register item (ROADMAP §7).
- **Why:** with no authentication (D2), a `0.0.0.0` default exposed the API to anyone on the LAN/Wi-Fi
  who could reach the port. The loopback default is the safe posture. It does **not** close D2 (still
  no auth) — it removes the accidental-exposure footgun and makes "keep bound to localhost" the default.
- **Blast radius:** default-only; the engine, scope enforcement, verdict logic, and every other
  default/flag are untouched. Full backend suite green (**507**); no test depended on `0.0.0.0`.

### D27 — `run.py` (repo root) and `backend/run.py` share the top-level module name `run` — OPEN
- **Status: OPEN (must-fix before formal packaging).** Two files are importable as the top-level module
  `run`: the **CLI entry** `run.py` at the repo root (the `lanivist` console script points at `run:main`
  via `pyproject.toml`) and the **uvicorn server launcher** `backend/run.py`. Whichever directory sits
  earlier on `sys.path` wins the bare `import run`.
- **Current impact: contained, not breaking.** The installed console script resolves to the **repo-root**
  `run.py` (verified from a non-repo cwd: `import run` → the repo-root file; `lanivist --help` shows the
  CLI, not the server launcher), because `backend/` is not on the top-level path in normal use. The
  collision only bites under **pytest**, which puts `backend/` on `sys.path`; the CLI-parser test loads
  the repo-root `run.py` by explicit file path to sidestep it
  (`backend/tests/test_cli_branding_and_config.py`).
- **Direction:** before formal packaging, disambiguate — e.g. rename the server launcher
  `backend/run.py` → `backend/server.py` (updating its references), or move the CLI entry out of a bare
  `run` module. A rename is the low-risk fix but is a code change out of scope for docs-alignment work,
  and must not be done casually — cross-check every reference to `backend/run.py` first. Cross-linked
  from [`ROADMAP.md`](./ROADMAP.md) §0 DEFERRED.

### D28 — `--auth` relogin does not refresh a mid-run owner-view 401 — LOW (safe-direction, non-blocking)
- **Status: OPEN (safe-direction).** The `--auth` auto-relogin (multi-step auth slice 1, commit
  `675835ff`) refreshes tokens PROACTIVELY (a fresh login per run, near-expiry aware in
  `relogin.TokenProvider.token()`) and REACTIVELY retries the engine ONCE when the **baseline or attack**
  request returns 401 (`external_verify._auth_degraded` — attacker-token expiry). It does NOT cover the
  **D24 owner-view read-back** 401ing mid-engine: if the owner token expires AFTER baseline/attack
  succeeded (200) but BEFORE the owner-view read late in the run, that read fails and is not retried.
- **Why this is SAFE (never a false verdict).** `fetch_owner_view` is fail-safe BLOCK — a non-2xx owner
  view yields `available=False`, so the D24 gate cannot corroborate and a `verified` is downgraded. The
  worst case is a **missed confirmation / NOT DATA**, NEVER a false positive. The proactive
  fresh-login-per-run keeps the window small (a read-semantic run is well under a 60s TTL), so this rarely
  fires — the live VAmPI-at-60s run confirmed without hitting it.
- **Proper fix (deferred to a later multi-step-auth slice).** Per-request token refresh inside the engine
  needs an **engine-level token hook** (a callable the engine consults before each request) — a core
  change out of slice 1's scope, deliberately not built. Until then the safe-direction behavior above
  stands. Cross-linked from [`ROADMAP.md`](./ROADMAP.md) §0 NEXT.

### D29 — query-string / non-path IDOR is not expressible or confirmable — MEDIUM (capability, SAFE-direction)
- **Where:** the external assembly layer — `external_verify._build_parsed_request` +
  `fuzzer._reconstruct_url` + the owner-view read call in `deep_verifier.execute_deep_verification`.
- **Observed on a REAL target (crAPI acceptance run-through).** `GET /workshop/api/mechanic/mechanic_report?report_id=`
  is a **hand-verified REAL IDOR** (attacker account read the owner's report by changing `report_id` in the
  query string — HTTP 200 returning the owner's `problem_details`). The tool returned **REFUTED
  (`inconclusive`, exit 0) — a FALSE NEGATIVE.** There is **no ground-truth label** on a real target; the
  verdict was judged against hand-verification done first.
- **Root cause — the query id is dropped at TWO sites (the attack side works; baseline + owner-view do not):**
  1. **Baseline can't carry a query id.** `_build_parsed_request` hardcodes `"query_params": {}` and the
     external `op.json` has no field for a baseline query parameter, so the baseline (attacker reading their
     OWN resource) is sent with **no `report_id`**. Observed: baseline request
     `GET .../mechanic_report` → **HTTP 500**. (The attack side is fine: `payload.location="query_param"`
     correctly injected `?report_id=6`, attack → HTTP 200.)
  2. **Owner-view read is path-only.** The D24 gate calls
     `fetch_owner_view(client, attack_req.get("path", ""), …)` (`deep_verifier.py` ~line 1792), passing the
     **path only** — `attack_req["query_params"]` (the `report_id`) is not included, so the owner re-read
     also hits `.../mechanic_report` with no id → `available=False` → `owner_view_corroborated=False` →
     downgrade. Observed: `guard_override=owner_view_not_corroborated`, `ai_verdict_raw=verified` →
     `final=inconclusive`.
- **No workaround in the current op format.** Embedding the id in `baseline_path`
  (`/…/mechanic_report?report_id=7`) makes the *attack* URL malformed —
  `.../mechanic_report?report_id=7?report_id=6` (**double `?`**) → **HTTP 400** — because
  `_reconstruct_url` appends `?<query>` even when the path already contains a `?`. Observed as a second run.
- **Direction: SAFE.** Because the gate is downgrade-only, the consequence is a **MISSED detection (false
  negative), never a false positive.** The id-shaped anchors were observe-only (`caller_identity=owner_not_found`,
  `anchoring_result=confirmed` but not load-bearing); the **owner-view gate carried the (downgrade) judgment**
  — consistent with the VAmPI portable-moat finding.
- **Severity:** capability gap, safe-direction. **Next-slice input** (assembly/input layer: add a baseline
  query-param field + carry `query_params` through URL reconstruction). ⚠️ **Engine-adjacent:** site (2), the
  owner-view path-only read, is inside `deep_verifier` — the one spot the fix must touch the core, so it needs
  care (minimal blast radius, full regression), not a casual assembly-layer edit.

### D30 — public / shared resources produced a FALSE POSITIVE — ✅ RESOLVED (public-resource probe; default OFF)
- **Status: ✅ RESOLVED (commit `ea65372`).** The D24 read-semantic owner-view gate now runs a
  PUBLIC-RESOURCE PROBE before it may confirm. `fetch_control_view` (`deep_verifier.py` — a
  custody-free, GET-only, scope-locked sibling of `fetch_owner_view`) re-reads the SAME resource as a
  THIRD / bystander identity that has no ownership of the object, and the pure predicate
  `_resource_is_public` (`deep_verifier.py`) suppresses the confirmation ONLY when affirmatively
  certain the resource is public — a clean 2xx AND a body that corroborates the owner's authentic
  view (reusing the existing `_owner_view_corroborates` / 0.95 discipline). On ANY ambiguity (probe
  missing / non-2xx / errored / timed-out / out-of-scope / empty / decoy / non-matching body) it fails
  safe to "private" and the confirmation proceeds.
- **Downgrade-only, by construction.** The probe's ONLY possible mutation is turning a would-be
  `verified` into `inconclusive`, routed through the UNCHANGED `_apply_owner_view_gate`; no new path
  assigns `verified`. The suppression reason `PUBLIC_RESOURCE_NOT_BOLA_REASON` is deliberately NOT one
  of the four D19 promotion channels, and suppression sets `owner_view_corroborated=False`, so a
  suppressed record can never promote. Opt-in via `AI_DEEP_VERIFY_BYSTANDER_AUTH` (default `None` → no
  probe → byte-identical), mirroring the owner-auth opt-in; the four exemption channels, the
  cross-resource guard, D24's helpers, and D19 are untouched.
- **Validation.** 24 offline tests with independent ground truth
  (`backend/tests/test_d30_public_resource.py`): known-public → suppressed; known-private BOLA → still
  confirmed; ambiguous / soft-deny → fails safe to private (still confirmed); the probe is proven
  custody-free, GET-only, and scope-locked. Backend suite **587 passed**. The two crAPI acceptance
  assertions were reproduced against **FAITHFUL crAPI-shaped responses driving the real engine**
  (crAPI itself was NOT booted here): the public community post flips **CONFIRMED → not-confirmed**,
  and the private order BOLA **STILL CONFIRMS when a third account is denied / differs**. **Live crAPI
  confirmation is pending the director's machine.**
- **RESIDUAL (weigh before enabling on a real target).** The probe cannot distinguish "public by
  design" from "broken for EVERY authenticated user": if a private object is readable by an unrelated
  third account (a BOLA with no ownership check *anywhere*), the probe reads it too and the real BOLA
  is SUPPRESSED — a SAFE-direction **missed detection**. This is the deliberate trade — eliminate the
  dangerous-direction FP, accept a narrow safe-direction miss — and it is exactly what the live crAPI
  order-endpoint check must settle (whether that endpoint denies an unrelated third account).
- **Historical context — the finding as first recorded (kept verbatim below):**
- **This is the more serious of the two crAPI findings, and the one that matters most.** It is the
  first **empirical, real-target** trigger of **D24 residual gap #1 (public / shared resources)** —
  see [D24 "STILL OPEN — boundaries" #1](#d24--read-semantic-verdicts-had-no-deterministic-gate-sev-1--resolved)
  and D24 (e) blind spot (1). That gap was recorded as a known limitation; crAPI now demonstrates it in the wild.
- **Where:** the D24 read-semantic owner-view gate (`_apply_owner_view_gate` / `fetch_owner_view` /
  `_owner_view_corroborates` in `deep_verifier.py`).
- **Observed on a REAL target (crAPI acceptance run-through).** `GET /community/api/v2/community/posts/{postId}`
  is a **hand-verified TRUE-NEGATIVE**: the community feed is public by design — `GET /community/api/v2/community/posts/recent`
  returns the same post to any authenticated user, so reading another user's post by id is **intended**, not a
  BOLA. The tool returned **CONFIRMED (`verified`, exit 1) — a real FALSE POSITIVE.** Evidence:
  `owner_view_corroborated=True`, `ai_verdict=verified`, no follow-up (read-semantic shape).
- **Cause.** The owner-view gate re-fetches the resource **as the owner**, the attacker's response **matches**
  it — *because the resource is public, both identities legitimately receive the same bytes* — so the gate
  corroborates. The gate **cannot distinguish "leaked private data" from "intentionally public data"**
  (denial vocabulary is deliberately never consulted; matching content is the only signal, and here it matches
  for a benign reason). The id-shaped anchors were observe-only; the **owner-view gate carried the
  confirmation** — same portable-moat pattern as VAmPI, but here that portability *confirms a non-vulnerability*.
- **Direction: DANGEROUS.** This is a **false positive** — the exact failure mode the project's entire zero-FP
  discipline exists to prevent. On the same crAPI run the gate was *correct* on a private resource
  (`GET /workshop/api/shop/orders/{order_id}`, a hand-verified REAL BOLA → correctly `verified`), so the
  distinction is precisely public-vs-private, not the mechanism.
- **This defines the real boundary of the zero-FP guarantee (record explicitly):** the zero-FP property holds
  for **private / authorization-gated resources**, and does **NOT** currently hold when the target contains
  **public / shared resources** — the owner-view gate will confirm them as cross-user "leaks." The two labs
  and VAmPI happened to contain no public-read endpoint of this shape, so this surfaced only against a complex
  real target.
- **No fix proposed here — deliberately.** Whether to *fix* (e.g. detect public reachability without the
  victim credential) or to *document the boundary and scope real-target use to private resources* is a
  **sequencing / positioning call for the director**, not decided in this register.
- **Severity:** HIGH, dangerous-direction. **Gates real-target readiness** — it must be weighed before any
  zero-FP claim is made against a target that includes public/shared resources.

---

## Suggested priority order for the next agent
> Current focus: sharpen the differentiator and PROVE it. All commercialization /
> scaling work is deferred until a benchmark justifies it. **Done:** D1 (startup guard),
> D3, D4, D6, D8, D9; Step 9 (R4, E2E-verified); the §5 integrity fix + D18 Phase-2 (R6);
> **B-1 (`37769b3`)** and its **D22** regression test. **Partial:** D7. The next-line nodes
> are the source of truth in [`ROADMAP.md`](./ROADMAP.md) §4 — mirrored below.

### Active line (work on these now)
1. **D21 ✅ DONE** — the spec source (`AI_DEEP_VERIFY_OPENAPI_SPEC`) is now a declared `Optional[str]`
   config field, wired for normal `.env`/env use with a fail-safe to the placeholder (see the D21
   entry above). Next up is broadening the proof, then D19.
2. **Broaden the proof — ✅ SECOND TARGET DONE.** Five shapes are now proven on **two structurally-
   different targets**: the GOLDEN record is **300 SAFE/control + 130 VULN runs, 0 FP** across
   `vulnerable_target` (integer-id) and `depot_target` (UUID-id) — `scripts/measure/results/sweep_highN.jsonl`,
   reproducible via `scripts/measure/`. Building the second lab also surfaced and closed a SEV-1
   (D24). **Still open on this axis:** a **second model** (only gemini-2.5-pro) and **arbitrary real
   APIs** (these are two self-built labs). Optional shape breadth (nested-object, multi-step) is extra.
   > **Provider abstraction — ✅ IMPLEMENTED (`services/llm/`), decoupled from zero-FP re-validation.**
   > The engine now talks to Gemini / OpenAI-compatible / Anthropic behind one interface (see
   > [`LLM_PROVIDERS.md`](./LLM_PROVIDERS.md)); the Gemini path is byte-identical (proven by
   > `test_llm_provider.py`'s request-capture anchor). As designed, it gives **provider freedom, not a
   > zero-FP guarantee**: the zero-FP evidence stays **measured on gemini-2.5-pro only** and was NOT
   > re-validated on any other model (connectivity, not correctness). A **second *measured* model**
   > remains the open model-diversity item — separate work from the (now-done) abstraction.
3. **D24 ✅ RESOLVED** — the read-semantic shape now has a deterministic gate (owner-view
   differential, `033fc9e`), built on the two-account ownership baseline (`5a33cb2`). All five shapes
   are code-gated. **Three boundaries remain open** (public/shared resources, per-deployment rather
   than per-finding owner credentials, and the threshold's lab-only calibration) — see D24.
4. **D19 — ✅ DONE (default OFF).** The AI verdict can now be promoted to authoritative for the rule
   oracle's `suspicious` band under a deterministic authorizer; acceptance-passed clean 430/430. The
   three D24 boundaries are **recorded, not assumed closed** — they must be weighed before promotion is
   *enabled* on a real target (Node 3), which is why the capability ships default OFF.
5. **Benchmark vs agent-style PoC validation** — on a public vulnerable target, quantify
   this engine's false-positive / reproducibility rate. The "can it be sold" evidence.
6. **Scope-lock hardening — ✅ DONE (see D25).** One audited `ScopePolicy` governs active +
   passive host decisions (fail-closed + per-hop redirect + resolved-IP guard; the proxy shares the
   matcher); unified `scope`+`model` declaration; SecretStr key privacy. Residual: IP-pinning
   follow-up (small DNS TOCTOU window). **D5** — keep `preview_dashboard.html`, retire `frontend/`.

### Deferred — NOT in the active line (unlock condition: the benchmark above proves commercialization is worth it)
- **D2 (auth)**, multi-tenancy, **D1 (Alembic migrations)**, hosted/enterprise deployment.
  Product/scaling concerns, unrelated to the "portfolio piece + validation" goal.
  Do not spend effort here until the benchmark data justifies it.
- Everything else (D10–D17, incl. Step 9 items) is intentional/low-priority — see notes above.
