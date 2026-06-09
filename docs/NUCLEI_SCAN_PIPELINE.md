# NUCLEI SCAN PIPELINE

> File: `backend/app/services/nuclei.py`. API: `backend/app/api/v1/scan.py`.
> This is the conventional vulnerability-scanner subsystem (distinct from the AI
> Logic Hunter). It wraps the external `nuclei` binary and enriches findings with
> Gemini remediation patches.

## Trigger

```
POST /api/v1/scan/start  { target_url, cookie? }
  → ScanTask persisted as status="running"
  → BackgroundTasks.add_task(execute_nuclei_scan_async, target_url, cookie, scan_id)
  → 202 Accepted (returns scan_id immediately)
```

Polling:
- `GET /api/v1/scan/{scan_id}` → status
- `GET /api/v1/scan/{scan_id}/findings` → findings list

## The 3-phase (+ phase 0) orchestrator

`execute_nuclei_scan_async(target_url, cookie, scan_id, traffic_feed)`:

### Phase 0 — Target profiling & adaptive template selection
`_fingerprint_target` determines the tech stack to **narrow** which Nuclei
templates run (so it doesn't fire 4000+ global rules):
- **Passive**: inspect response headers/bodies in a provided `traffic_feed` for
  framework signatures (`_FINGERPRINT_SIGNATURES`: WordPress, Laravel/PHP,
  Django, Express/Node, ASP.NET, Spring/Java, Rails/Ruby, nginx, Apache).
- **Active fallback**: if no corpus is available, do **one** benign `GET` probe
  to the target — **only if the host matches the approved scope**
  (`SCOPE-LOCK`). Third-party hosts are never probed.
- `_build_adaptive_nuclei_args`: detected tags → `-tags tag1,tag2`; nothing
  detected → safe default `-tags cves,generic`.

### Phase 0.5 — mark ScanTask `running`
Idempotent: updates the row, or creates it if missing.

### Phase 1 — spawn Nuclei + fast DB ingest (NO AI)
- `subprocess.Popen([nuclei, -target, -severity, -jsonl, -nc,
  -disable-update-check, ...adaptive tags, -header Cookie:...])`.
  No `shell=True` (injection-safe). `-jsonl` = one JSON finding per stdout line.
- A daemon `threading.Thread` (`_nuclei_reader_thread`) reads stdout line-by-line
  and dispatches each parsed finding to the event loop via
  `asyncio.run_coroutine_threadsafe(_persist_finding_fast(...))`.
- `_persist_finding_fast` inserts the `VulnerabilityFinding` immediately with
  `ai_patch=None`. **No Gemini calls here** → the reader is never blocked on
  network I/O, maximizing ingest throughput.
- Why threads (not asyncio subprocess)? Windows compatibility + simple line
  streaming. The loop is captured up front and used for cross-thread dispatch.

### Phase 2 — finalize status
After Nuclei exits, the `ScanTask` is set to `completed` (exit 0) or `failed`
(non-zero / `FileNotFoundError` if the binary is missing / any exception).

### Phase 3 — batch AI enrichment (rate-limited)
`_batch_enrich_with_gemini(scan_id)` runs **only on success**:
- Query all findings for this scan with severity ∈ {CRITICAL, HIGH} and
  `ai_patch IS NULL`.
- For each, call `generate_gemini_remediation_patch(...)` (model
  `GEMINI_PRO_MODEL`, temp 0.2, Chinese security-expert system prompt producing
  root-cause + before/after diff + mitigation), write `ai_patch` back. Each call
  is bounded by `asyncio.wait_for(..., GEMINI_REQUEST_TIMEOUT_SECONDS)`; a timeout
  degrades to a Chinese fallback string instead of stalling the batch (D3).
- Sleep `GEMINI_BATCH_COOLDOWN_SECONDS` (default 3) between calls to respect rate
  limits. Missing key / errors degrade gracefully to a Chinese fallback string.

## Design rationale
- **Scan/AI decoupling**: the frontend sees `completed` fast (Phase 2), while AI
  patches trickle in afterward (Phase 3). Polling `/findings` shows `ai_patch`
  filling in over time.
- **Isolated sessions**: the background job uses its own `async_session_factory`
  contexts, not a request-scoped session (which would be closed when the HTTP
  response returns).

## Gotchas for the next agent
- The reader thread dispatches each DB write and waits up to 10s
  (`future.result(timeout=10)`). Very high finding rates serialize on this.
- `NUCLEI_BINARY_PATH` existence is **not** checked at startup. The config
  validator (`config.py` `validate_nuclei_path`) only enforces an absolute,
  normalized path — it does **not** verify the file exists (despite an inline
  comment promising a startup existence check; that check is not implemented). A
  missing binary therefore surfaces only at **scan time** as a Phase-1
  `FileNotFoundError` → scan marked `failed` with a clear log; the server still
  boots normally.
- `traffic_feed` (passive profiling input) is plumbed through the function
  signature but the `/scan/start` endpoint does not currently pass one — it's an
  extension hook (e.g. feed HAR-derived traffic for passive fingerprinting).
