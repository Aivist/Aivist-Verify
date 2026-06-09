# API REFERENCE

> Base URL: `http://127.0.0.1:8000`. All routes are mounted under `/api/v1`.
> Interactive docs: `GET /api/docs` (Swagger) and `GET /api/redoc`.
> Schemas: `backend/app/schemas/scan.py` and `backend/app/schemas/hunter.py`.
>
> ⚠️ **No authentication on any endpoint.** Keep the server bound to localhost.
>
> **Note:** `services/deep_verifier.py` is not exposed over HTTP. Its AI verdict
> vocabulary now includes `inconclusive` (alongside `verified`/`failed`/`suspicious`),
> and results carry `ai_verdict_raw` + `guard_override`; the optional
> `AI_DEEP_VERIFY_OPENAPI_SPEC` seam is read via `getattr` (not a declared Settings
> field). See [`DEEP_VERIFY.md`](./DEEP_VERIFY.md).

## Diagnostics

### `GET /`
Health check. Returns `{ status, service, version, diagnostics: {
nuclei_configured_path, database_url_configured, logging_level } }`.

---

## Nuclei Scanner — `/api/v1/scan` (router in `api/v1/scan.py`)

### `POST /scan/start` → 202 / 422 / 500
Start an async Nuclei scan.
```json
// request (ScanRequest)
{ "target_url": "https://example.com", "cookie": "PHPSESSID=...; security=low" }
// response (ScanResponse)
{ "scan_id": "uuid", "status": "started", "message": "..." }
```
- `target_url` must be a valid HTTP/HTTPS URL (Pydantic `HttpUrl`).
- `cookie` optional; rejects CRLF (header-injection guard).
- Side effect: persists `ScanTask(status="running")`, enqueues
  `execute_nuclei_scan_async` on BackgroundTasks.
- **422** if `target_url` or `cookie` fails Pydantic validation.
- **500** if DB persist or task enqueue fails (rare; surfaces as HTTP error detail).

### `GET /scan/{scan_id}` → 200 / 404 / 500
Poll status. Returns `ScanTaskState { scan_id, target_url, status, updated_at }`.
`status` ∈ `pending|running|completed|failed`.
- **500** on an unexpected DB error (`"Database inquiry failed"`).

### `GET /scan/{scan_id}/findings` → 200 / 404 / 500
List findings for a scan (`List[FindingDetails]`), ordered by id. 404 if the
scan id doesn't exist.
- **500** on an unexpected DB error (`"Database inquiry failed"`).
> Only returns rows whose `scan_id` matches — i.e. **Nuclei findings only**.
> Hunter findings (`scan_id=NULL`) never appear here.

---

## AI Logic Hunter — `/api/v1/hunter` (router in `api/v1/hunter.py`)

### `POST /hunter/analyze` → 200 / 422 (handler never 500)
Parse raw HTTP + Gemini logic analysis.
```json
// request (HunterAnalyzeRequest)
{ "raw_traffic": "POST /api/... HTTP/1.1\nHost: ...\n\n{...}", "auth_context_b": "session=..." }
// response (HunterAnalyzeResponse)
{ "status": "success",
  "parsed_data": { "method","path","query_params","headers","body","errors" },
  "report_markdown": "…",
  "automation_payloads": [ { "phase","type","location","target_param","payload_string","expected_match" } ],
  "error_message": null }
```
- `raw_traffic` min length 10, must be non-whitespace → **422** if too short/blank
  (Pydantic, before handler runs).
- Handler never returns **500**; parse failures return `status:"error"` in the body.
- If Gemini is unavailable, `status` stays `success`, `report_markdown` carries a
  degraded notice, `automation_payloads` is `[]`.

### `POST /hunter/findings` → 201 / 422  (Step D bridge)
Persist an analysis as a fuzzable finding.
```json
// request (HunterPersistRequest)
{ "parsed_data": { ... },                 // required; stored in parsed_request column
  "automation_payloads": [ ... ],         // required, min 1
  "target_url": "https://host",           // optional; else derived from Host header
  "auth_refresh_request": { "method","url","headers","body" }, // optional
  "report_markdown": "…" }                // optional; stored in ai_patch
// response (HunterPersistResponse)
{ "status": "success", "finding_id": 1, "message": "… Trigger via POST /verify/1." }
```
- **422** if no host can be derived (no `target_url` and no `Host` header), or if
  `automation_payloads` is empty (`min_length=1`).
- Creates `VulnerabilityFinding(source="hunter", scan_id=NULL,
  template_id="logic-hunter:<type>"` (e.g. `logic-hunter:BOLA`)`, severity="INFO")`
  — the vuln type is kept in `template_id` + the payload JSON, not in `severity` (D6).

### `POST /hunter/verify/{finding_id}` → 202 / 404
Trigger single-target differential fuzzing.
```json
// response (VerifyTriggerResponse)
{ "status": "accepted", "finding_id": 1, "message": "… Poll GET /verify/1/results …" }
```
- Enqueues `execute_differential_fuzzing(finding_id)` on BackgroundTasks.

### `GET /hunter/verify/{finding_id}/results` → 200 / 404
List `FuzzingRecord` rows for a finding (`List[FuzzingRecordSchema]`), ordered by
`payload_index`.
```json
{ "id": "uuid", "finding_id": 1, "payload_index": 0,
  "sent_request": "...", "received_response": "...",
  "verification_status": "untested|verified|suspicious|failed|running",  // default "untested"
  "diff_details": { "length_deviation_ratio","status_code_baseline","status_code_test","similarity_ratio","analysis_notes", ... },
  "created_at": "iso8601" }
```
- While a session re-auth is in flight, a **transient** diagnostic record is
  prepended: `id="__custody_diagnostic__"`, `payload_index=-1`,
  `verification_status="running"`. Filter by `payload_index >= 0` for real rows.

### `POST /hunter/verify/batch` → 202 / 400 / 404  (Step 8)
True-concurrent multi-endpoint fuzzing under one shared auth custody.
```json
// request (BatchVerifyRequest)
{ "finding_ids": [1,2,3],                 // required, min 1
  "approved_host": "host:port",           // optional; derived if all share one host
  "auth_refresh_request": { ... },        // optional transient re-auth (not persisted)
  "max_concurrency": 5 }                  // 1..20, default 5
// response (BatchVerifyResponse)
{ "status": "accepted", "finding_ids": [1,2,3], "approved_host": "host", "message": "…" }
```
- **404** if any finding id is missing.
- **400** for a mixed-host batch (no single `approved_host`) or any selection
  outside the approved host (refuses third-party probing — Constraint 2).

### `POST /hunter/auth/dry-run` → 200
Test an Identity Provider Anchor once (scope-locked); nothing is persisted.
```json
// request (AuthDryRunRequest)
{ "auth_refresh_request": { "method","url","headers","body" }, "approved_host": "host?" }
// response (AuthDryRunResponse)
{ "success": true, "status_code": 200, "extracted_kind": "cookie|token", "extracted_preview": "…", "message": "…" }
```

### `POST /hunter/ingest-har` → 200 (never 500)
Prune a HAR JSON body to high-value endpoints.
```json
// request (HarIngestRequest)
{ "log": { "entries": [ ... ] }, "threshold": 0.65 }
// response (HarIngestResponse)
{ "status":"success", "total_entries":N, "filtered_count":M, "threshold_used":0.65,
  "high_value_entries": [ { "method","path","query_params","headers","body",
                            "exposure_score","raw_http_string","source_url","is_login_candidate" } ] }
```

### `POST /hunter/ingest-har-file` → 200 (never 500)
Same as above but via multipart upload (OOM-safe streaming).
- Form fields: `file` (the `.har` file), `threshold` (float 0..1, default 0.65).
- Accepts both `{ "log": {...} }` and a flat `{ "entries": [...] }` root.

---

## Proxy Radar — `/api/v1/hunter/proxy` (Step 9; router in `api/v1/hunter.py`)

Passive traffic capture via a supervised `mitmdump` subprocess. Schemas in
`backend/app/schemas/proxy.py`.

### `POST /hunter/proxy/start` → 200
Spawn + supervise the interception proxy under an operator-supplied scope.
```json
// request (ProxyStartRequest)
{ "scope": ["app.example.com"],   // approved host allow-list (Tier-1); [] = no host filter
  "listen_port": 8888 }           // optional; overrides PROXY_LISTEN_PORT for this run
// response (ProxyControlResponse)
{ "state": "RUNNING|FAILED|...", "listen_port": 8888, "pid": 12345,
  "scope": ["app.example.com"], "message": "Radar started. Point your browser proxy at 127.0.0.1 …" }
```
- Idempotent-ish: returns the current `state`. Point the browser proxy at
  `127.0.0.1:<listen_port>`; for HTTPS, trust the CA from `/proxy/cert`.

### `POST /hunter/proxy/stop` → 200
Graceful stop + **OS-agnostic process-tree kill** (`taskkill /F /T` on Windows,
process-group signals on Unix). Returns `ProxyControlResponse` with the resulting
`state` (e.g. `STOPPED`).

### `GET /hunter/proxy/status` → 200
Process state + ingest/stream telemetry.
```json
// response (ProxyStatusResponse)
{ "state": "RUNNING", "pid": 12345, "listen_port": 8888, "uptime_seconds": 42.0,
  "dropped_flows": 0, "sse_clients": 1, "queue_depth": 0,
  "scope": ["app.example.com"], "ca_cert_available": true, "message": null }
```

### `GET /hunter/proxy/stream` → 200 (SSE) / 503
`text/event-stream` live fan-out of captured flows. Each client gets a bounded
queue; on disconnect the generator's `finally` deregisters it
(`CancelledError`-safe — no leak). Emits `: heartbeat` comments on idle.
- **503** if `PROXY_SSE_MAX_CLIENTS` is already reached.
- Event frames: `event: flow\ndata: {…ProxyFlowProjection-ish…}\n\n`.

### `GET /hunter/proxy/flows` → 200
List recently captured flows, most recent first.
```json
// query: ?limit=100   (clamped to 1..500)
// response: List[ProxyFlowProjection]
[ { "id":"uuid","flow_id":"…","captured_at":"iso8601","method":"GET",
    "host":"app.example.com","path":"/api/orders","url":"https://…/api/orders",
    "response_status":200,"exposure_score":0.82,"is_login_candidate":false,
    "in_scope":true,"promoted_finding_id":null } ]
```

### `GET /hunter/proxy/cert` → 200 / 404
Stream the locally-generated mitmproxy CA cert
(`application/x-x509-ca-cert`) for HTTPS interception.
- **404** until the radar has started once (the CA is generated on first run).

### `POST /hunter/proxy/internal-ingest` → 202 / 404 / 413 / 422 / 503  (INTERNAL)
> **Not in OpenAPI** (`include_in_schema=False`). Receives captured flows from the
> mitmdump addon only. Documented here for completeness — **never call it
> directly**.
- **404** (fail-closed, doesn't confirm the route) unless **both**: the real TCP
  peer is loopback (`127.0.0.1`/`::1`; `X-Forwarded-For` is deliberately ignored)
  **and** `X-Ingest-Token` constant-time-matches the per-session token minted at
  `/proxy/start`.
- **413** if the body exceeds `PROXY_INGEST_MAX_BYTES`.
- **422** on a malformed `ProxyIngestFlow`.
- **503** when the ingest queue is saturated (`PROXY_INGEST_QUEUE_MAX`) — signals
  the addon to apply backpressure.

---

## Status-code conventions
- `202 Accepted` — long job queued (scan start, verify, batch) or flow accepted
  into the proxy ingest queue.
- `200 OK` — analyze/HAR/dry-run/results + all `/proxy/*` control & read endpoints
  (analyze & HAR handlers never 500; logical failures come back as `status:"error"`).
- `404` — unknown scan/finding id; CA not yet generated (`/proxy/cert`); or a
  fail-closed reject on the internal-ingest guard (loopback/token).
- `413` — oversize internal-ingest body (`PROXY_INGEST_MAX_BYTES`).
- `422` — Pydantic validation (e.g. short `raw_traffic`, empty `automation_payloads`,
  invalid scan request, malformed proxy flow) or no derivable host on `/hunter/findings`.
- `400` — mixed-host / out-of-scope batch.
- `503` — proxy SSE client cap reached (`/proxy/stream`) or ingest queue saturated
  (`/proxy/internal-ingest` backpressure).
- `500` — unhandled failure on `/scan/start` (DB or dispatcher error), or an
  unexpected DB error on `GET /scan/{scan_id}` and `GET /scan/{scan_id}/findings`
  (`"Database inquiry failed"`).
