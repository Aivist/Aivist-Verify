# DATA MODEL

> Source of truth: `backend/app/models/scan.py`. SQLite database file:
> `security_platform.db` (created in the process working directory; the URL is
> `sqlite+aiosqlite:///./security_platform.db`, overridable via `DATABASE_URL`).

## Tables overview

```
scan_tasks (1) ──< vulnerability_findings (1) ──< fuzzing_records
```

- A **ScanTask** is one Nuclei scan run.
- A **VulnerabilityFinding** is one issue. It comes from EITHER a Nuclei scan
  (`source="nuclei"`, has a `scan_id`) OR the AI Logic Hunter
  (`source="hunter"`, `scan_id=NULL`). This is single-table inheritance by
  convention.
- A **FuzzingRecord** is one differential-fuzz attempt (one payload) against a
  finding, with its verdict + diff.

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
| `template_id` | String(256) | no | Nuclei template id, or `"logic-hunter"` for Hunter |
| `severity` | String(64) | no | upper-cased; Hunter synthesizes from first payload `type` |
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
| `diff_details` | JSON | yes | oracle output (status codes, length deviation, similarity, notes) |
| `created_at` | DateTime | no | |

> **`payload_index = -1` is a sentinel.** The results endpoint synthesizes a
> *transient* in-memory record with `id="__custody_diagnostic__"`,
> `payload_index=-1`, `verification_status="running"` while a session re-auth is
> in flight. It is **never persisted**; the E2E driver and frontend filter it by
> `payload_index >= 0`.

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

### Recommendation for the next agent
Introduce a real migration story before the schema changes again. Lightest
option: add a startup self-check that compares `PRAGMA table_info` against the
ORM and logs/raises a clear "schema drift — recreate or migrate" message instead
of failing deep inside an insert. (Not yet implemented — see
[`TECH_DEBT.md`](./TECH_DEBT.md).)
