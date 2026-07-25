> **SUPERSEDED: D19 landed and passed acceptance — see [`../TECH_DEBT.md`](../TECH_DEBT.md) D19 (RESOLVED) and [`../STATUS.md`](../STATUS.md).** Point-in-time audit snapshot, kept unedited as history.

# Verdict-Coverage Audit (read-only)

## UPDATE 2026-06-09 — superseded in part

> **This is a dated 2026-06-06 snapshot whose headline conclusions no longer hold at HEAD.**
> The central gaps it measured have since been (partly) closed. The original analysis is
> preserved **verbatim** below as the historical record; this banner reconciles it with the
> current code.
>
> **What changed since this audit:**
> - **Suite size:** the backend suite grew from ~73 (here) to **145** at that time (**285** as of M1.4,
>   with M1 complete). Files that landed
>   since this audit: `test_verdict_oracle.py` (9), `test_d18_b22_guard.py` (18),
>   `test_d18_phase2_crosspath.py`, `test_endpoint_catalog.py`, `test_d18_b1_write_record.py`,
>   `test_d18_b1_shadow_integration.py` (the B-1 shadow-path regression test, D22),
>   `test_m12_state_readback_exemption.py`, `test_m12b_state_gather.py`, `test_m13_delete.py`,
>   and `test_m14_mass_assignment.py` (the M1.2/M1.3/M1.4 shapes). See
>   [`../STATUS.md`](../STATUS.md).
> - **Bucket-(A) verdict-correctness coverage NOW EXISTS** — this audit's central finding is
>   **superseded**:
>   - `test_verdict_oracle.py` (9) **imports and asserts** `fuzzer.py::_differential_verdict`:
>     it feeds realistic baseline/test pairs and asserts the verdict — incl. a `verified`
>     (Rule 2 BOLA/IDOR), the `suspicious` single-shot ceiling, and a `failed` produced by the
>     **Veto** post-rule on a soft-200 denial (`{"error":"forbidden"}`).
>   - `test_d18_b22_guard.py` (18) is the first bucket-(A) AI-verdict-**path** coverage: it
>     asserts `deep_verifier._apply_cross_resource_guard` directly.
>   - Therefore the body's headlines **"(A) VERDICT-CORRECTNESS | 0"**, **"ZERO bucket-(A)
>     tests"**, and **"no test imports `_differential_verdict`"** are **SUPERSEDED**.
> - **AI deep verifier vocabulary expanded:** the verifier now has a 4th verdict
>   **`inconclusive`** plus a 5-point decisive-evidence / SAME-RESOURCE standard and a
>   deterministic **B-2.2 structural cross-resource guard** (`_apply_cross_resource_guard`,
>   override `cross_resource_readback_not_decisive`, with the raw model verdict preserved as
>   `ai_verdict_raw`/`guard_override`). The rule oracle `_differential_verdict` itself is
>   **unchanged (still 3-value: `verified`/`suspicious`/`failed`)**.
>
> **What is STILL uncovered (confirmed by grep at HEAD — these parts of the audit still hold):**
> - The **Escalation** post-rule (sensitive-key leak promotes `suspicious`→`verified`) — no
>   asserting test.
> - **Rule 1** (server-error escalation) and **Rules 3/4/5** (mass-assignment, generic
>   divergence, status-change) — no asserting test (the new oracle tests exercise **Rule 2 +
>   the Veto post-rule** only).
> - The **deep verifier integration** — now has an automated test (**D22 closed**,
>   `test_d18_b1_shadow_integration.py`): it runs the real `execute_deep_verification` end-to-end
>   with a mocked Gemini and pins X-CROSS→`verified` / X-SAFE→never-`verified`. Still untested:
>   the `_run_shadow_deep_verification` **wrapper** and `execute_parallel_fuzzing` Phase-7 entry
>   (the test drives `execute_deep_verification` directly).
>
> _(Historical 2026-06-06 snapshot below — preserved unchanged.)_

> **Purpose:** measure whether `backend/tests/` actually *proves* the differential
> verdict engine (`backend/app/services/fuzzer.py :: _differential_verdict`) is
> correct. This is measurement, not repair. No code or tests were modified.
>
> **Date:** 2026-06-06
> **Scope read as ground truth (from disk):**
> - `backend/app/services/fuzzer.py` :: `_differential_verdict` (L697-825),
>   `_execute_single_fuzz` (L1301-1444), `_run_shadow_deep_verification` (L1195-1268)
> - every file under `backend/tests/` (`test_pruner.py`, `test_step8_custody.py`,
>   `test_step_d_hunter_link.py`, `test_step9_proxy.py`, `test_api_endpoints.py`)
> - `vulnerable_target/main.py`, `vulnerable_target/test_vulns.py`
> - `vulnerable_target/benchmark/RESULTS.md`

---

## Bucket definitions

| Bucket | Meaning |
|---|---|
| **(A) VERDICT-CORRECTNESS** | Feeds the oracle a realistic baseline+test response pair and asserts the resulting verdict (`verified`/`suspicious`/`failed`) is the CORRECT one. **Only these tests, if they fail, mean the product's judgement is wrong.** |
| **(B) PLUMBING** | Asserts concurrency / custody / writer / scope / auth-refresh / extractor mechanics — not verdict correctness. |
| **(C) API-SHAPE** | Asserts HTTP status / schema / route wiring. |
| **(D) OTHER / unclear** | Anything else (here: the heuristic traffic-*pruner* scorer — a different engine from the verdict oracle). |

---

## STEP 2 — Full classification (every test in `backend/tests/`)

### `test_api_endpoints.py` (10 tests)

| file::test_name | bucket | one-line reason |
|---|---|---|
| `test_api_endpoints.py::test_root_health_check` | C | asserts `GET /` returns 200 + `status/version` schema. |
| `test_api_endpoints.py::test_analyze_success_with_mocked_gemini` | C | asserts `/hunter/analyze` 200 + payload schema; Gemini mocked, no verdict. |
| `test_api_endpoints.py::test_analyze_rejects_too_short_traffic` | C | asserts Pydantic 422 on short input. |
| `test_api_endpoints.py::test_persist_finding_then_verifiable` | C | asserts 201 persist + 202 verify wiring; fuzzing is monkeypatched to a no-op. |
| `test_api_endpoints.py::test_persist_finding_requires_payloads` | C | asserts 422 when `automation_payloads` empty. |
| `test_api_endpoints.py::test_persist_finding_unresolvable_host_returns_422` | C | asserts 422 when no base URL derivable. |
| `test_api_endpoints.py::test_verify_unknown_finding_returns_404` | C | asserts 404 for unknown finding id. |
| `test_api_endpoints.py::test_batch_verify_unknown_finding_returns_404` | C | asserts 404 for unknown batch id. |
| `test_api_endpoints.py::test_scan_start_then_status` | C | asserts 202 start + 200 status wiring; Nuclei mocked. |
| `test_api_endpoints.py::test_scan_status_unknown_returns_404` | C | asserts 404 for unknown scan id. |

### `test_step8_custody.py` (5 tests)

| file::test_name | bucket | one-line reason |
|---|---|---|
| `test_step8_custody.py::test_single_flight_one_reauth` | B | asserts 12 concurrent triggers fire exactly ONE re-auth (single-flight). |
| `test_step8_custody.py::test_scope_lock_blocks_thirdparty_reauth` | B | asserts re-auth refuses an out-of-scope host (domain scope lock). |
| `test_step8_custody.py::test_reauth_cap_dissolves_barrier` | B | asserts re-auth cap / circuit breaker dissolves the barrier (no hang). |
| `test_step8_custody.py::test_single_writer_drains_concurrent_producers` | B | asserts the single-writer consumer persists all 30 queued records. |
| `test_step8_custody.py::test_worker_detects_death_then_resumes` | B | runs `_execute_single_fuzz` end-to-end but asserts re-auth fired + a queue item exists + `error != reauth_failed` — **NOT the verdict value**. |

### `test_step_d_hunter_link.py` (7 tests)

| file::test_name | bucket | one-line reason |
|---|---|---|
| `test_step_d_hunter_link.py::test_payloads_read_from_explicit_column` | B | asserts `_extract_payloads` reads the typed column. |
| `test_step_d_hunter_link.py::test_parsed_request_read_from_explicit_column` | B | asserts `_extract_parsed_request` reads the typed column. |
| `test_step_d_hunter_link.py::test_auth_refresh_read_from_explicit_column` | B | asserts `_extract_auth_refresh_request` reads the typed column. |
| `test_step_d_hunter_link.py::test_legacy_json_in_text_still_extracts_payloads` | B | asserts legacy JSON-in-text payload fallback. |
| `test_step_d_hunter_link.py::test_legacy_json_in_text_still_extracts_parsed_request` | B | asserts legacy JSON-in-text parsed-request fallback. |
| `test_step_d_hunter_link.py::test_nuclei_finding_yields_no_payloads` | B | asserts markdown/raw Nuclei finding yields no payloads. |
| `test_step_d_hunter_link.py::test_explicit_column_takes_precedence_over_legacy` | B | asserts typed column wins over legacy embedded JSON. |

### `test_step9_proxy.py` (7 tests)

| file::test_name | bucket | one-line reason |
|---|---|---|
| `test_step9_proxy.py::test_writer_service_serializes_jobs` | B | asserts the unified `WriterService` runs jobs in submission order. |
| `test_step9_proxy.py::test_sse_hub_fanout_and_overflow` | B | asserts SSE register/publish + drop-oldest overflow. |
| `test_step9_proxy.py::test_ingest_pipeline_backpressure` | B | asserts a full bounded queue returns False / drops. |
| `test_step9_proxy.py::test_ingest_pipeline_handle_enriches_and_publishes` | B | asserts ingest enriches (pruner score), persists via writer, publishes. |
| `test_step9_proxy.py::test_proxy_manager_failed_without_mitmdump` | B | asserts FAILED state when binary missing + token/cert guards. |
| `test_step9_proxy.py::test_internal_ingest_guards` | C | asserts internal-ingest HTTP guards (404/202/503/413). |
| `test_step9_proxy.py::test_proxy_cert_404_when_absent` | C | asserts `/proxy/cert` 404 when CA absent. |

### `test_pruner.py` (33 tests) — all **(D)**: exercise the heuristic *pruner* scorer (`calculate_exposure_score` / `filter_high_value_traffic`), **not** the verdict oracle

> **Important disambiguation:** the pruner's "veto" (static asset → `0.0`) is a
> *different* mechanism from the oracle's **Veto rule** (denial strings in a 200 OK).
> None of these tests touch `_differential_verdict`.

| file::test_name | bucket | one-line reason |
|---|---|---|
| `test_pruner.py::TestStaticAssetVeto::test_static_file_extensions_vetoed` | D | parametrized (12 cases): static extensions score `0.0` in the pruner. |
| `test_pruner.py::TestStaticAssetVeto::test_javascript_bundle_vetoed` | D | JS bundle pruner-vetoed to `0.0`. |
| `test_pruner.py::TestStaticAssetVeto::test_html_page_vetoed` | D | HTML page pruner-vetoed to `0.0`. |
| `test_pruner.py::TestTelemetryVeto::test_analytics_route_vetoed` | D | analytics route pruner-vetoed. |
| `test_pruner.py::TestTelemetryVeto::test_metrics_route_vetoed` | D | metrics route pruner-vetoed. |
| `test_pruner.py::TestTelemetryVeto::test_google_analytics_vetoed` | D | GA collect route pruner-vetoed. |
| `test_pruner.py::TestTelemetryVeto::test_doubleclick_vetoed` | D | doubleclick route pruner-vetoed. |
| `test_pruner.py::TestMethodScoring::test_post_base_score` | D | POST base exposure score. |
| `test_pruner.py::TestMethodScoring::test_put_base_score` | D | PUT base exposure score. |
| `test_pruner.py::TestMethodScoring::test_patch_base_score` | D | PATCH base exposure score. |
| `test_pruner.py::TestMethodScoring::test_delete_base_score` | D | DELETE base exposure score. |
| `test_pruner.py::TestMethodScoring::test_get_with_params_score` | D | GET-with-params exposure score. |
| `test_pruner.py::TestMethodScoring::test_static_get_score` | D | plain GET exposure score. |
| `test_pruner.py::TestPathSegmentScanning::test_admin_reset_path_surfaces` | D | admin/reset path segments raise the pruner score. |
| `test_pruner.py::TestPathSegmentScanning::test_user_delete_path_surfaces` | D | user/delete path segments raise the pruner score. |
| `test_pruner.py::TestPathSegmentScanning::test_checkout_transfer_path` | D | checkout/transfer scores high in the pruner. |
| `test_pruner.py::TestPathSegmentScanning::test_admin_update_path` | D | admin/update scores high in the pruner. |
| `test_pruner.py::TestContextualSignals::test_json_content_type_bonus` | D | JSON content-type adds a pruner bonus. |
| `test_pruner.py::TestContextualSignals::test_graphql_content_type_bonus` | D | GraphQL content-type adds a pruner bonus. |
| `test_pruner.py::TestContextualSignals::test_api_path_marker_bonus` | D | `/api` marker adds a pruner bonus. |
| `test_pruner.py::TestParameterSensitivity::test_sensitive_query_params` | D | sensitive query params raise the pruner score. |
| `test_pruner.py::TestParameterSensitivity::test_sensitive_body_keys` | D | sensitive body keys raise the pruner score. |
| `test_pruner.py::TestParameterSensitivity::test_multi_keyword_key_counts_all_keywords` | D | determinism: a multi-keyword key counts both keywords. |
| `test_pruner.py::TestParameterSensitivity::test_sensitive_query_params_score_is_exact` | D | determinism: locks an exact pruner score. |
| `test_pruner.py::TestParameterSensitivity::test_score_is_stable_across_repeated_calls` | D | pruner score stable across 50 calls. |
| `test_pruner.py::TestParameterSensitivity::test_param_bonus_capped_at_04` | D | pruner param bonus capped at 0.4. |
| `test_pruner.py::TestScoreNormalization::test_score_never_exceeds_1` | D | pruner score clamps ≤ 1.0. |
| `test_pruner.py::TestScoreNormalization::test_score_never_below_0` | D | pruner score clamps ≥ 0.0. |
| `test_pruner.py::TestBatchFilter::test_filters_below_threshold` | D | batch filter keeps high-value, drops static. |
| `test_pruner.py::TestBatchFilter::test_empty_input_returns_empty` | D | batch filter on empty input. |
| `test_pruner.py::TestBatchFilter::test_all_below_threshold` | D | batch filter returns empty when all below threshold. |
| `test_pruner.py::TestBatchFilter::test_results_sorted_descending` | D | batch filter sorts by score descending. |
| `test_pruner.py::TestBatchFilter::test_exposure_score_annotated` | D | batch filter annotates `_exposure_score`. |

### Bucket totals

| Bucket | Count (test functions) |
|---|---|
| (A) VERDICT-CORRECTNESS | **0** |
| (B) PLUMBING | 17 |
| (C) API-SHAPE | 12 |
| (D) OTHER (pruner scorer) | 33 |
| **Total** | **62 functions** (→ 73 collected cases after the ×12 parametrize in `test_static_file_extensions_vetoed`) |

---

## STEP 3 — Explicit answers

### 1. How many bucket-(A) tests exist? List them.

**ZERO.** There are **no** bucket-(A) tests.

- No test imports or calls `_differential_verdict` (confirmed: the only occurrence of
  any oracle entrypoint name in `backend/tests/` is `execute_differential_fuzzing` in
  `test_api_endpoints.py`, where it is **monkeypatched to a no-op** so the route never
  runs the engine).
- Exactly one test reaches the oracle *indirectly*:
  `test_step8_custody.py::test_worker_detects_death_then_resumes` calls
  `_execute_single_fuzz`, which internally calls `_differential_verdict`. But its
  assertions are `refresh_calls == 1`, the queue item's `finding_id/payload_index`, and
  `diff_details.get("error") != "reauth_failed"`. **It never asserts the verdict value**
  (`verified`/`suspicious`/`failed`), so it does not validate oracle correctness.

### 2. Coverage matrix — is there ≥1 (A) test exercising each outcome / post-rule?

| Verdict outcome / post-rule | Covered by an (A) test? |
|---|---|
| `verified` | **NO** |
| `suspicious` | **NO** |
| `failed` | **NO** |
| **Veto rule** (denial string in 200 OK demotes to `failed`) | **NO** |
| **Escalation rule** (sensitive-key leak promotes `suspicious`→`verified`) | **NO** |

Every cell is **NO**. None of the five `_differential_verdict` rule families (Rule 1
server-error, Rule 2 BOLA/IDOR, Rule 3 mass-assignment, Rule 4 generic divergence,
Rule 5 status-change) nor the two post-rules (Veto, Escalation) has any asserting test.

### 3. THE KEY QUESTION — false-positive / false-negative tests

- **False-positive test** (oracle says `verified`/`suspicious` on a SECURE case):
  **NONE** in `backend/tests/`.
- **False-negative test** (oracle says `failed` on a REAL vuln): **NONE** in
  `backend/tests/`.

The only FP/FN-style traps that exist anywhere (the `SAFE` avatar control and the
`T-TRAP` soft-200 denial) live in `vulnerable_target/` + `RESULTS.md` and are driven by
*manual* scripts, **never** by an automated test in `backend/tests/`.
`vulnerable_target/test_vulns.py` asserts the target's planted ground truth (that the
vulns/controls behave as designed) but **does not run the verdict oracle at all**, so it
is not an FP/FN test of the oracle.

### 4. Does the n=9 benchmark run through the integrated Phase 7 path?

**No.** The n=9 benchmark (`A, B, C, D, SAFE, T-REAL, T-TRAP, T-WEAK, T-SILENT2`) was
produced entirely by **manual** drivers, per `RESULTS.md` §Provenance:

- Rule-based oracle (A, B only): temporary standalone scripts importing the real fuzzer
  functions against the live target.
- AI-in-the-loop (B, C, D, SAFE): a temporary two-turn script.
- AI-in-the-loop (T-REAL/TRAP/WEAK/SILENT2): the **isolated**
  `execute_deep_verification` component invoked directly (i.e. the same path
  `scripts/deep_verify_live_check.py` uses), gated by `AI_DEEP_VERIFY_ENABLED`.

The **integrated Phase 7** (`_run_shadow_deep_verification`, L1195-1268) is **shadow-only
and gated behind `AI_DEEP_VERIFY_SHADOW` (default `False`)**. It is **not invoked by any
automated test** — no test sets that flag, and no test runs `execute_parallel_fuzzing`
to completion. So Phase 7 itself is also untested.

**Which of the 9 are exercised by an automated test in `backend/tests/`?**
**None of the 9.** All nine benchmark cases are outside the automated suite. (For
completeness: 5 of the underlying target endpoints — A, B, C, D, SAFE — *are* exercised
by `vulnerable_target/test_vulns.py`, but that suite (a) is not under `backend/tests/`
and (b) tests the target's ground truth, not the verdict oracle. The 4 `T-*` cases have
no automated test at all.)

---

## GAPS

Everything below has **no test** in `backend/tests/`:

**Verdict outcomes (0/3 covered):**
- `verified` — no (A) test asserts the oracle returns `verified` on a real positive.
- `suspicious` — no (A) test asserts `suspicious` on an ambiguous case.
- `failed` — no (A) test asserts `failed` on a benign/denied case.

**Per-rule (0/5 + 0/2 covered):**
- Rule 1 — server-error escalation (`<500 → ≥500` ⇒ `verified`): untested.
- Rule 2 — BOLA/IDOR 200-OK length-deviation split (`verified` vs `suspicious`): untested.
- Rule 3 — mass-assignment / parameter-pollution: untested.
- Rule 4 — generic significant divergence (`>0.15`): untested.
- Rule 5 — non-error status-code change: untested.
- **Veto** post-rule (denial keywords in a 200 OK demote to `failed`): untested.
- **Escalation** post-rule (sensitive keys present only in the test body promote
  `suspicious`→`verified`): untested.

**False-positive cases (0 covered):**
- SECURE look-alike with opaque `200 {"status":"ok"}` (the `SAFE` family) — no test that
  the oracle does **not** over-call it. (Note: the rule oracle alone caps at `suspicious`
  here and cannot exonerate — but there is no test asserting even that bound.)
- Soft-200 denial body (`200` + `{"error":"forbidden"}`, the `T-TRAP` family) — no test
  that the Veto rule demotes it to `failed`.

**False-negative cases (0 covered):**
- Real silent-BOLA writes whose POST response is byte-identical (`B`/`D`/`T-SILENT2`
  family) — no test characterizing the oracle's single-shot ceiling (`suspicious`,
  cannot reach `verified` without write-then-read).
- Weak-signal IDOR where length deviation ≈ 0 but a cross-user object is leaked
  (`T-WEAK` family) — no test that a faint-but-real positive is not dropped to `failed`.

**Integration path:**
- `_run_shadow_deep_verification` (Phase 7) — no automated test exercises shadow mode
  (the `AI_DEEP_VERIFY_SHADOW` branch) at all.
- `execute_parallel_fuzzing` / `execute_differential_fuzzing` — never run end-to-end by a
  test (always monkeypatched to a no-op); only the per-worker `_execute_single_fuzz` is
  invoked, and only for plumbing assertions.

**Bottom line:** the 73 green tests thoroughly cover *plumbing* (concurrency, custody,
writer, extractors, proxy), *HTTP shape*, and the *pruner* scorer — but **0 of them
assert that the verdict oracle returns the correct verdict for any input.** The core
correctness claim of the product is currently unverified by the automated suite.

---

## Appendix — "is this already written down somewhere?"

There is **no** pre-existing file that classifies the tests by verdict coverage; this
audit is the first. The closest related material (for reference only):

- `docs/VERIFY_ENGINE.md` — documents the oracle's rules/pipeline (the *spec*), not test coverage.
- `vulnerable_target/benchmark/RESULTS.md` — the n=9 ground-truth benchmark + provenance (manual runs, not `backend/tests/`).
- `docs/TECH_DEBT.md` — registers known gaps (incl. D19: AI deep verifier is shadow-only).
- `backend/tests/test_step8_custody.py` header — describes the plumbing it covers.
