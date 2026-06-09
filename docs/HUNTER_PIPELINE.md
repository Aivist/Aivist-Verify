# HUNTER PIPELINE — AI Logic Hunter

> The Hunter turns raw HTTP traffic into AI-proposed business-logic exploit
> payloads, and (via Step D) persists them as a fuzzable finding so the
> [Verify engine](./VERIFY_ENGINE.md) can actively confirm them.
>
> Files: `api/v1/hunter.py`, `services/traffic_parser.py`, `services/pruner.py`,
> schemas in `schemas/hunter.py`.

## End-to-end flow

```
        ┌─────────────────────── optional bulk intake ───────────────────────┐
        │  HAR file ──► /hunter/ingest-har[-file] ──► pruner ──► ranked list   │
        └─────────────────────────────────────────────────────────────────────┘
                                     │ (operator picks an endpoint → raw HTTP string)
                                     ▼
 raw HTTP text ──► /hunter/analyze ──► traffic_parser ──► Gemini ──► report_markdown
                                                                  └► automation_payloads[]
                                     │
                                     ▼
            /hunter/findings (Step D) ──► VulnerabilityFinding(source="hunter")
                                     │  returns finding_id
                                     ▼
                  /hunter/verify/{finding_id}  →  see VERIFY_ENGINE.md
```

---

## Stage 1 — HAR ingestion & pruning (optional)

Two endpoints, same pipeline:
- `POST /hunter/ingest-har` — HAR JSON in the request body.
- `POST /hunter/ingest-har-file` — multipart file upload (uses FastAPI
  `UploadFile`/`SpooledTemporaryFile`, so big HAR files spool to disk instead of
  OOM-ing).

Pipeline (`ingest_har_traffic` / `ingest_har_file_upload` in `hunter.py`):
1. Extract `log.entries[]` from the HAR.
2. `_har_entry_to_parsed_request(entry)` → internal parsed-request dict
   (`method, path, query_params, headers, body, response_headers, response_body,
   _source_url, _is_login_candidate`).
3. `filter_high_value_traffic(parsed, threshold)` (the pruner) → drops noise,
   scores the rest, returns only entries `>= threshold`, sorted descending.
4. Each surviving entry is returned with `raw_http_string` (reconstructed via
   `_reconstruct_raw_http`) so the frontend can drop it straight into the analyze
   textarea, plus `is_login_candidate` to pre-fill the Identity Anchor.

### The pruner (`services/pruner.py`)
`calculate_exposure_score(parsed_request) -> float` in `[0.0, 1.0]`:

- **Hard veto → 0.0** for static-asset extensions (`.css`, `.js`, `.png`, `.jpg`,
  `.jpeg`, `.gif`, `.ico`, `.woff`, `.woff2`, `.svg`, `.map`, `.html`, `.ttf`,
  `.eot`, `.mp4`, `.webm`, `.mp3`, `.pdf`, …) and telemetry routes (the complete
  `_TELEMETRY_ROUTES` set: `/analytics/`, `/metrics/`, `/telemetry/`, `/beacon/`,
  `/_track/`, `google-analytics`, `doubleclick`).
- **Method weight:** POST/PUT/PATCH = 0.4, DELETE = 0.3, GET+params = 0.2,
  bare GET = 0.1.
- **Sensitive-keyword bonus:** +0.1 for each *distinct* keyword from
  `_SENSITIVE_KEYWORDS` (`id, uuid, role, user, amount, price, pay, admin,
  privilege, status, token, auth, checkout, invoice, delete, reset, update,
  transfer`) found across query keys + body keys (recursive) + path segments,
  capped at `_MAX_PARAM_BONUS = 0.4`.
- **Context bonus:** API content-type (`application/json`, `application/graphql`)
  and API path markers (`/api/`, `/v1/`, `/v2/`, `/v3/`, `/graphql`, …) add small amounts.
- Final score clamped to `[0, 1]`.

> **Determinism (regression-fixed):** keyword counting collects *all* distinct
> keywords present (not "first match per key"). The previous "break on first
> match" logic depended on `frozenset` iteration order and produced
> `PYTHONHASHSEED`-dependent scores. Locked by regression tests in
> `backend/tests/test_pruner.py`. **Do not reintroduce per-key short-circuiting.**

Default HAR threshold is `0.65`.

---

## Stage 2 — Analyze (`POST /hunter/analyze`)

Handler: `analyze_http_traffic`. Never returns 500 (all failures are caught and
returned as a structured response).

1. **Parse** `request.raw_traffic` with `parse_raw_http_request`
   (`traffic_parser.py`):
   - Normalises line endings, splits head/body on the first blank line.
   - Parses the request line → `method`, `path`, `query_params` (single-value
     lists flattened).
   - Parses headers but **keeps only security-relevant ones**
     (`cookie, authorization, content-type, referer, origin, x-forwarded-for,
     x-real-ip, x-csrf-token, x-xsrf-token, x-requested-with, x-api-key,
     x-auth-token, host, content-length`) to save LLM tokens.
   - Parses the body as JSON when `Content-Type: application/json`, else raw text.
   - Returns a best-effort dict with an `errors[]` list; never raises.
2. **Gemini call** `_invoke_gemini_logic_hunt(parsed_data, auth_context_b)`:
   - System prompt = red-team OWASP API-security expert (in `hunter.py`,
     `_SYSTEM_PROMPT`). It instructs Gemini to look for BOLA/IDOR, vertical
     privilege escalation, parameter pollution / mass assignment, and race
     conditions.
   - Uses `response_mime_type="application/json"`, `temperature=0.4`, model =
     `settings.GEMINI_PRO_MODEL`.
   - Expects JSON `{ "report_markdown": str, "automation_payloads": [...] }`.
   - **Timeout budget:** the call is wrapped in
     `asyncio.wait_for(..., timeout=settings.GEMINI_REQUEST_TIMEOUT_SECONDS)`, so a
     slow/hung upstream can't block `analyze` indefinitely (D3).
   - **Graceful degradation:** no API key, SDK missing, **request timeout**, bad
     JSON, or any API error all return a Chinese "degraded" `report_markdown` with
     `automation_payloads: []` (status still `success`). The endpoint stays 200.
3. **Validate payloads:** each raw payload is coerced into `AutomationPayload`;
   malformed ones are skipped with a warning.

`auth_context_b` is an optional "comparison session" credential the operator can
provide to help Gemini reason about cross-user (horizontal) access.

### `AutomationPayload` shape (`schemas/hunter.py`)
| field | meaning |
|---|---|
| `phase` (int) | 1 = basic probe, 2 = bypass/exploit |
| `type` (str) | `BOLA`, `IDOR`, `Parameter_Pollution`, `Mass_Assignment`, `Race_Condition`, … |
| `location` (str) | where to mutate: `json_key`, `query_param`, `header`, `path_segment`, `cookie` |
| `target_param` (str) | the parameter name to mutate |
| `payload_string` (str) | the value to inject |
| `expected_match` (str) | the success signal Gemini expects |

---

## Stage 3 — Persist as a fuzzable finding (`POST /hunter/findings`) — Step D

Handler: `persist_hunter_finding`. **This is the bridge that closed the
Hunter→Verify gap.**

1. Resolve the fuzz base URL via `_derive_base_url(parsed_data, target_url)`:
   priority is explicit `target_url`, else the `Host` header inside
   `parsed_data` (assumed `https://`). If neither yields a host → **422**.
2. Build a `VulnerabilityFinding` with:
   - `source="hunter"`, `scan_id=None`, `template_id=f"logic-hunter:{type}"`
     (e.g. `logic-hunter:BOLA`; the first payload's `type`)
   - `severity="INFO"` (a real severity level; the vuln *type* is preserved in
     `template_id` + the payload JSON, not in `severity` — D6)
   - `matched_at = base_url`
   - `ai_patch = report_markdown`
   - `parsed_request`, `automation_payloads`, `auth_refresh_request` → the new
     JSON columns
3. Commit and return `finding_id`.

Request/response: `HunterPersistRequest` / `HunterPersistResponse` in
`schemas/hunter.py`. The frontend (`preview_dashboard.html`,
`handleSaveHunterFinding`) calls this after an analyze, then adds a
`HUNTER-<finding_id>` entry to the verifiable-findings list.

> Because Hunter findings have `scan_id=NULL`, they are naturally excluded from
> the scan-scoped `GET /scan/{id}/findings` query — they only surface through the
> verify endpoints. (See the `FindingDetails.scan_id` typing caveat in
> [`TECH_DEBT.md`](./TECH_DEBT.md).)

---

## Identity Provider Anchor (re-auth) — supporting feature

- A login/identity endpoint is heuristically flagged by `_detect_login_candidate`
  (POST/PUT + a login/auth/token/session/password marker in path or body).
- The operator can supply an **`auth_refresh_request`** (method/url/headers/body)
  describing how to re-login. It is stored on the Hunter finding (Step D column)
  and/or passed transiently to a batch run.
- `POST /hunter/auth/dry-run` executes that re-auth request **once**
  (scope-locked) and reports whether a fresh cookie/token could be extracted —
  letting the operator validate it before a long fuzzing run. Nothing is
  persisted. Implemented by `dry_run_auth_refresh` in `fuzzer.py`.

How the credential is consumed during fuzzing is described in
[`VERIFY_ENGINE.md`](./VERIFY_ENGINE.md) (Auth Custody).

[`DEEP_VERIFY.md`](./DEEP_VERIFY.md) documents `deep_verifier.py` (no HTTP route in this pipeline).
