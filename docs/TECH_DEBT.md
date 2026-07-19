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
  Total backend suite: **145 tests** (grew from an old 73 via the verdict-oracle, B-2.2
  guard, cross-path, catalog, and B-1 write-record + shadow-integration tests). See
  [`STATUS.md`](./STATUS.md).
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
  to the old placeholder (zero regression)**; the real 22-route surface is used only when
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

### D19 — AI deep verifier is shadow-only, not authoritative
- **Where:** `services/deep_verifier.py` + `fuzzer._run_shadow_deep_verification`
  (Phase 7); flags `AI_DEEP_VERIFY_ENABLED` / `AI_DEEP_VERIFY_SHADOW` in `config.py`
  (both default `False`).
- **TL;DR:** ✅ the "judge correctly / integrity floor" half (§5) is **DONE — see R6**;
  ⏳ the **core of D19 — promoting** the AI verdict from observe-only/log to **authoritative**
  — is still open (gated behind D18/B-1).
- **Status:** the AI-in-the-loop write-then-read verifier runs **read-only**. In
  shadow mode it re-checks `suspicious` records and **only logs** its verdict
  (`AI_shadow_verdict=… NOT applied (shadow, observe-only)`); it does **not**
  overwrite `verification_status`/`diff_details` or change what the user sees, and
  it never affects a batch (failures are swallowed). It is therefore **not yet
  authoritative** — the persisted verdict is still the rule oracle's, which stalls at
  `suspicious` on silent cases (opaque `200 {"status":"ok"}` writes). Accuracy so far
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
- **Still pending (the core of D19):** promote the AI verdict from observe-only/log to
  **authoritative** — let it take over the rule oracle's `suspicious` band in the real flow
  and decide the gating defaults. Not yet done; gated behind D18/B-1.
- **Direction:** once shadow data is trusted at scale, decide a promotion policy
  (e.g. let the AI verdict resolve only the rule oracle's `suspicious` band, with the
  full evidence trail retained for audit). Do not promote before D18 is addressed —
  the verifier's reliability depends on being handed the right read-back endpoint.

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

### D21 — Catalog spec source is read from an *undeclared* setting (getattr seam)
- **Where:** `fuzzer.py` (~L1267) `getattr(settings, "AI_DEEP_VERIFY_OPENAPI_SPEC", None)`;
  `config.py` declares only `AI_DEEP_VERIFY_ENABLED` (L78) and `AI_DEEP_VERIFY_SHADOW`
  (L90), both default `False`.
- **Status:** intentional Step-1 seam, but worth knowing. The shadow verifier's real
  endpoint catalog is fed from `settings.AI_DEEP_VERIFY_OPENAPI_SPEC`, yet that field is
  **not declared** in `config.py` — it is read defensively via `getattr(..., None)`, so with
  nothing set the catalog stays the byte-identical placeholder (zero regression).
  Practically, the spec source is reachable only by patching settings (tests/drivers), not
  via normal config.
- **Direction:** when wiring a real spec for production use (B-1), promote it to a declared
  `config.py` field (a path or inline spec) so it is discoverable and validated like the rest.

### D22 — Phase-7 shadow path had no automated test — ✅ RESOLVED (`37769b3`)
- **Where:** `deep_verifier.execute_deep_verification`.
- **Was:** the suite never exercised the shadow **integration** end-to-end; the code path that
  invokes the AI verifier was proven only by throwaway harnesses under `scripts/audit/`.
- **Now:** `backend/tests/test_d18_b1_shadow_integration.py` runs the **real**
  `execute_deep_verification` end-to-end with a **mocked Gemini** (no live API, no token cost),
  asserting the B-1 outcomes as a CI asset: X-CROSS→`verified`, X-SAFE→`inconclusive` even when
  the model wrongly says `verified` (the safety line), HALF 2 never fabricates `verified`, and
  same-path cases untouched. Suite 140→**145** green.
- **Still bare:** the real Nuclei subprocess pipeline (D7) and the `_run_shadow_deep_verification`
  Phase-7 *wrapper* itself (the integration test drives `execute_deep_verification` directly, not
  via `execute_parallel_fuzzing`) — add if that wrapper changes.

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
  then D19 (make the verdict authoritative). See [`STATUS.md`](./STATUS.md).

### Scope-lock hardening (OPEN) — prerequisite for real targets
- **What:** consolidate the duplicated host-scope checks — the fuzzer's `_send_request` /
  `ScopeViolationError` enforcement and the deep verifier's own follow-up pre-check, plus the
  proxy's separate capture-side `in_scope` — into one audited implementation; add an
  adversarial test suite (substring / protocol-relative / userinfo tricks); and add runtime
  out-of-scope probes (don't trust config alone).
- **Why open:** hard prerequisite before pointing at anything beyond localhost / self-built
  labs (relates to D2 — no auth).

---

## Suggested priority order for the next agent
> Current focus: sharpen the differentiator and PROVE it. All commercialization /
> scaling work is deferred until a benchmark justifies it. **Done:** D1 (startup guard),
> D3, D4, D6, D8, D9; Step 9 (R4, E2E-verified); the §5 integrity fix + D18 Phase-2 (R6);
> **B-1 (`37769b3`)** and its **D22** regression test. **Partial:** D7. The next-line nodes
> are the source of truth in [`ROADMAP.md`](./ROADMAP.md) §4 — mirrored below.

### Active line (work on these now)
1. **D21** — declare the spec source (`AI_DEEP_VERIFY_OPENAPI_SPEC`) as a real config field so
   B-1's catalog can be wired for normal use, not just harnesses.
2. **Broaden the proof** — beyond the single X-CROSS shape (nested-object, delete-type,
   multi-step, noisier audit logs). Gate hardening (D23 + D23b) is **done**; extend the
   owner/subject vocabulary as real log samples appear. Update `RESULTS.md` with the B-1 result.
3. **D19** — only then: promote the AI verdict from observe-only to authoritative.
4. **Benchmark vs agent-style PoC validation** — on a public vulnerable target, quantify
   this engine's false-positive / reproducibility rate. The "can it be sold" evidence.
5. **Scope-lock hardening** before any non-localhost target; **D5** — keep
   `preview_dashboard.html`, retire `frontend/`.

### Deferred — NOT in the active line (unlock condition: the benchmark above proves commercialization is worth it)
- **D2 (auth)**, multi-tenancy, **D1 (Alembic migrations)**, hosted/enterprise deployment.
  Product/scaling concerns, unrelated to the "portfolio piece + validation" goal.
  Do not spend effort here until the benchmark data justifies it.
- Everything else (D10–D17, incl. Step 9 items) is intentional/low-priority — see notes above.
