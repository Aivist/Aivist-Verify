# DATA MODEL

> Source of truth: `backend/app/models/scan.py`. SQLite database file:
> `security_platform.db` (created in the process working directory; the URL is
> `sqlite+aiosqlite:///./security_platform.db`, overridable via `DATABASE_URL`).

## Tables overview

```
scan_tasks (1) ──< vulnerability_findings (1) ──< fuzzing_records

captured_flows            (Step 9 — standalone; no FK, optional one-way
                           promoted_finding_id back-reference into findings)
```

- A **ScanTask** is one Nuclei scan run.
- A **VulnerabilityFinding** is one issue. It comes from EITHER a Nuclei scan
  (`source="nuclei"`, has a `scan_id`) OR the AI Logic Hunter
  (`source="hunter"`, `scan_id=NULL`). This is single-table inheritance by
  convention.
- A **FuzzingRecord** is one differential-fuzz attempt (one payload) against a
  finding, with its verdict + diff.
- A **CapturedFlow** (Step 9) is one HTTP exchange intercepted by the passive
  proxy radar. It is intentionally **decoupled** — not FK-linked to the other
  tables — with only an optional one-way `promoted_finding_id` recording that an
  operator pushed the flow into the Hunter pipeline.

---

## `scan_tasks`

| Column | Type | Null | Notes |
|---|---|---|---|
| `id` | String(36) PK | no | UUID4 string |
| `target_url` | String(1024) | no | |
| `status` | String(32) | no | `pending` → `running` → `completed`/`failed` |
| `cookie` | Text | yes | optional auth cookie passed to Nuclei |
| `created_at` | DateTime | no | `utcnow` default |
| `updated_at` | DateTime | no | `utcnow`, `onupdate=utcnow` |

Relationship: `findings` → `VulnerabilityFinding` with
`cascade="all, delete-orphan"`, `passive_deletes=True` (relies on the DB-level
`ON DELETE CASCADE`).

---

## `vulnerability_findings`

| Column | Type | Null | Notes |
|---|---|---|---|
| `id` | Integer PK | no | autoincrement |
| `scan_id` | String(36) FK→scan_tasks | **yes** | **NULL for Hunter findings** (Step D made this nullable) |
| `source` | String(16) | no | discriminator: `"nuclei"` (default) or `"hunter"` (Step D) |
| `template_id` | String(256) | no | Nuclei template id, or `"logic-hunter:<type>"` for Hunter (e.g. `logic-hunter:BOLA`) |
| `severity` | String(64) | no | upper-cased real level (`CRITICAL`…`INFO`). Hunter rows store `"INFO"`; their vuln *type* lives in `template_id` + the payload JSON (D6) |
| `matched_at` | String(2048) | no | URL; for Hunter this is the derived base URL used as the fuzz target |
| `poc_request` | Text | yes | Nuclei request capture (legacy fuzz input lived here) |
| `poc_response` | Text | yes | Nuclei response capture |
| `ai_patch` | Text | yes | Gemini remediation (Nuclei) or Hunter `report_markdown` |
| `parsed_request` | **JSON** | yes | **Step D** — structured request the fuzzer mutates |
| `automation_payloads` | **JSON** | yes | **Step D** — list of payload instructions for the fuzzer |
| `auth_refresh_request` | **JSON** | yes | **Step D** — optional cached re-auth request (Identity Anchor) |
| `created_at` | DateTime | no | |

Relationships: `task` (back to ScanTask), `fuzz_records` → `FuzzingRecord`
(cascade delete).

### Step D: why the three JSON columns exist
Before Step D, the only way to feed structured data to the fuzzer was to embed
JSON inside the `ai_patch` / `poc_request` **text** columns. The Hunter `analyze`
endpoint produced `automation_payloads` but there was **no path to persist them**
where `verify` could read them — the Hunter→Verify link was broken.

Step D added explicit typed columns. The fuzzer's extraction helpers now read
**column-first, then fall back to legacy text-embedded JSON** for backward
compatibility:
- `_extract_payloads` → `automation_payloads` column, else JSON in `ai_patch`/`poc_request`
- `_extract_parsed_request` → `parsed_request` column, else legacy text
- `_extract_auth_refresh_request` → `auth_refresh_request` column, else legacy text

(All three live in `backend/app/services/fuzzer.py`.)

---

## `fuzzing_records`

| Column | Type | Null | Notes |
|---|---|---|---|
| `id` | String(36) PK | no | UUID4 string |
| `finding_id` | Integer FK→vulnerability_findings | no | |
| `payload_index` | Integer | no | index into the finding's payload list; `-1` is reserved (see below) |
| `sent_request` | Text | yes | serialized mutated request that was sent |
| `received_response` | Text | yes | sanitized response (capped at `FUZZER_RESPONSE_BODY_MAX_LENGTH`) |
| `verification_status` | String(32) | no | `untested` / `verified` / `suspicious` / `failed` / `running` |
| `diff_details` | JSON | yes | oracle output — fuller key set: `verdict`, `length_deviation_ratio`, `status_code_baseline`/`status_code_test`, `content_length_baseline`/`content_length_test`, `elapsed_ms_baseline`/`elapsed_ms_test`, `is_blocked`, `similarity_ratio`, `sanitized_body_capped`, `analysis_notes` (error paths add an `error` key) |
| `created_at` | DateTime | no | |

> **`payload_index = -1` is a sentinel.** The results endpoint synthesizes a
> *transient* in-memory record with `id="__custody_diagnostic__"`,
> `payload_index=-1`, `verification_status="running"` while a session re-auth is
> in flight. It is **never persisted**; the E2E driver and frontend filter it by
> `payload_index >= 0`.

> **Shadow-mode AI deep-verify is LOG-ONLY.** The deep verifier's results — the new
> `inconclusive` verdict plus `ai_verdict_raw` and `guard_override` — are emitted by
> the fuzzer's read-only Phase-7 shadow pass to logs only. They are **never
> persisted** to `fuzzing_records`; there are **no DB columns** for them. See
> [`DEEP_VERIFY.md`](./DEEP_VERIFY.md).

---

## `captured_flows` (Step 9 — Passive Traffic Ingestion Proxy Radar)

A single HTTP request/response pair intercepted by the `mitmdump` proxy radar,
enriched by the Tier-2 pipeline, and persisted by the unified `WriterService`.

| Column | Type | Null | Notes |
|---|---|---|---|
| `id` | String(36) PK | no | UUID4 string |
| `flow_id` | String(64) | yes | addon-assigned correlation id for the originating mitmproxy flow |
| `captured_at` | DateTime | no | naive UTC `utcnow` default |
| `scheme` | String(8) | no | `http` / `https`; default `http` |
| `method` | String(16) | no | HTTP method; default `GET` |
| `host` | String(255) | no | target host |
| `port` | Integer | yes | target port |
| `path` | String(4096) | no | request path; default `/` |
| `url` | String(4096) | no | denormalized fully-qualified URL (for display / re-issue) |
| `request_headers` | JSON | yes | captured request headers |
| `request_query` | JSON | yes | parsed query params |
| `request_body` | Text | yes | request body (capped at `PROXY_BODY_CAP`) |
| `response_status` | Integer | yes | response status code |
| `response_headers` | JSON | yes | captured response headers |
| `response_body` | Text | yes | response body (capped at `PROXY_BODY_CAP`) |
| `elapsed_ms` | Float | yes | round-trip time reported by the addon |
| `exposure_score` | Float | yes | **Tier-2** heuristic exposure score (`pruner.calculate_exposure_score`) |
| `is_login_candidate` | Boolean | no | deterministic login/identity hint (powers Identity Anchor pre-fill); default `false` |
| `in_scope` | Boolean | no | Tier-1 scope verdict; default `true`. Out-of-scope flows are *captured-but-inert* |
| `source` | String(16) | no | always `"proxy"`; default `"proxy"` |
| `promoted_finding_id` | Integer | yes | **decoupled, non-FK** back-reference set when the flow is promoted into a Hunter finding via `POST /hunter/findings` |

### Why a dedicated table (not a reuse of the existing three)
- `vulnerability_findings` models a *triaged finding* (severity, `template_id`,
  AI payloads) with NOT NULL semantics that don't fit raw traffic.
- `fuzzing_records` is *verification output* bound to a `finding_id`.
- Neither captures a live request/response pair with timing, scope, and the
  Tier-2 exposure score the radar needs.

`promoted_finding_id` is intentionally **not** a ForeignKey: capture and analysis
stay loosely coupled and migration-free. `captured_flows` is a brand-new table,
so `create_all` provisions it cleanly and the D1 drift guard never trips on it
(the guard only fires on missing columns of *pre-existing* tables — see below).
Defined in `backend/app/models/scan.py`.

---

## Migrations — IMPORTANT GOTCHA

**There is no migration tool (no Alembic).** Schema is created solely by
`Base.metadata.create_all` in the lifespan startup. `create_all`:

- ✅ creates tables that don't exist
- ❌ does **NOT** add/alter/drop columns on tables that already exist

Consequence (this actually bit us during Step D verification): if
`security_platform.db` was created with an older schema, the new Step D columns
(`source`, `parsed_request`, `automation_payloads`, `auth_refresh_request`) will
be **absent**, and inserting a Hunter finding fails with:

```
sqlite3.OperationalError: table vulnerability_findings has no column named source
```

> **Step 9 corollary (observed).** Adding `captured_flows` needed **no
> migration** — it's a brand-new table, so `create_all` builds it and the drift
> guard ignores it. But the guard still fires on *older* DBs missing the earlier
> Step D columns: during Step 9 integration testing a pre-Step-D
> `security_platform.db` was rejected at boot, and the fix was simply to recreate
> the DB (rename the old `.db`/`-wal`/`-shm` aside and let the lifespan build a
> fresh one). New tables are free; altering existing tables is not.

### How to recover a stale dev DB
Pick one:
1. **Recreate (simplest, destructive):** stop the server, delete
   `security_platform.db` (+ `-wal`, `-shm`), restart — the new schema is built
   fresh. ⚠️ On Windows the file is often **locked** by a running server or the
   IDE's DB viewer; make sure no `uvicorn`/python process holds `:8000` and close
   any open DB viewer first.
2. **Side-step (non-destructive):** point at a fresh file via env var, e.g.
   `DATABASE_URL=sqlite+aiosqlite:///./fresh.db`, then start the server.
3. **Manual ALTER (preserve data):** `ALTER TABLE vulnerability_findings ADD
   COLUMN source VARCHAR(16) ...` for each new column. Note `scan_id` going from
   `NOT NULL` to nullable requires a SQLite table rebuild, so option 1/2 is
   usually easier in dev.

### Startup schema drift guard (D1 — implemented)

Since Stage B, `main.py`'s lifespan runs `_verify_schema_integrity` immediately
after `create_all`. It diffs each ORM table's expected columns against live
`PRAGMA table_info` and **refuses to start** with a clear `RuntimeError` naming
missing columns — instead of failing deep inside an INSERT. This does **not**
auto-migrate; it only detects drift.

### Recommendation for the next agent

If the schema changes again, introduce Alembic (or equivalent) for non-destructive
upgrades. The startup guard is a safety net, not a migration tool — see
[`TECH_DEBT.md`](./TECH_DEBT.md) D1.
