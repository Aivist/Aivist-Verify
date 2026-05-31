# API REFERENCE

> Base URL: `http://127.0.0.1:8000`. All routes are mounted under `/api/v1`.
> Interactive docs: `GET /api/docs` (Swagger) and `GET /api/redoc`.
> Schemas: `backend/app/schemas/scan.py` and `backend/app/schemas/hunter.py`.
>
> ⚠️ **No authentication on any endpoint.** Keep the server bound to localhost.

## Diagnostics

### `GET /`
Health check. Returns `{ status, service, version, diagnostics: {
nuclei_configured_path, database_url_configured, logging_level } }`.

---

## Nuclei Scanner — `/api/v1/scan` (router in `api/v1/scan.py`)

### `POST /scan/start` → 202
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

### `GET /scan/{scan_id}` → 200 / 404
Poll status. Returns `ScanTaskState { scan_id, target_url, status, updated_at }`.
`status` ∈ `pending|running|completed|failed`.

### `GET /scan/{scan_id}/findings` → 200 / 404
List findings for a scan (`List[FindingDetails]`), ordered by id. 404 if the
scan id doesn't exist.
> Only returns rows whose `scan_id` matches — i.e. **Nuclei findings only**.
> Hunter findings (`scan_id=NULL`) never appear here.

---

## AI Logic Hunter — `/api/v1/hunter` (router in `api/v1/hunter.py`)

### `POST /hunter/analyze` → 200 (never 500)
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
- `raw_traffic` min length 10, must be non-whitespace.
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
- **422** if no host can be derived (no `target_url` and no `Host` header).
- Creates `VulnerabilityFinding(source="hunter", scan_id=NULL,
  template_id="logic-hunter")`.

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
  "verification_status": "verified|suspicious|failed|running",
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

## Status-code conventions
- `202 Accepted` — long job queued (scan start, verify, batch).
- `200 OK` — analyze/HAR/dry-run/results (analyze & HAR never 500; failures come
  back as `status:"error"` in the body).
- `404` — unknown scan/finding id.
- `422` — validation (Pydantic) or no derivable host on `/hunter/findings`.
- `400` — mixed-host / out-of-scope batch.
