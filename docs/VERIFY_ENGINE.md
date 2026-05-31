# VERIFY ENGINE — Differential Fuzzing & Auth Custody

> File: `backend/app/services/fuzzer.py` (~1400 lines, the core of the product).
> This engine takes a persisted `VulnerabilityFinding` + its `automation_payloads`
> and actively replays mutated requests against the live target, then uses a
> **differential oracle** to decide whether each payload exposed a real
> vulnerability. It also self-heals expiring auth sessions mid-run.
>
> Related skill: `.agents/skills/async-session-custody/SKILL.md`. The code is
> organized into "Section 7.x" (custody) and "Step 8" (parallel) blocks that map
> to that skill.

## Entry points

| Function | Trigger | Purpose |
|---|---|---|
| `execute_differential_fuzzing(finding_id)` | `POST /hunter/verify/{id}` | Legacy single-target path. **Thin wrapper** → `execute_parallel_fuzzing([finding_id])`. Scope-lock stays OFF; re-auth harvested from the finding. |
| `execute_parallel_fuzzing(finding_ids, auth_refresh_request, approved_host, max_concurrency)` | `POST /hunter/verify/batch` | True-concurrent multi-endpoint engine. One shared auth custody, one DB writer, single-host scope lock. |
| `dry_run_auth_refresh(auth_refresh_request, approved_host)` | `POST /hunter/auth/dry-run` | Run a re-auth request once, report extracted credential. No persistence. |

> The single-target and batch paths share **the same engine** — single-target is
> just a batch of one. This guarantees identical behavior and zero regression
> between the two.

---

## Pipeline (per `execute_parallel_fuzzing` run)

```
Phase 1  Load findings → build _FindingJob[] (read-only session)
           per finding: _extract_payloads, _extract_parsed_request, _extract_base_url,
           and (first finding) _extract_auth_refresh_request as fallback
Phase 2  Single-host scope lock (Constraint 2)
Phase 3  Build ONE shared AuthCustodyController; register in _ACTIVE_CUSTODY[fid]
         Start the single _db_writer_consumer task draining an asyncio.Queue
Phase 4  Compute baselines concurrently (gated by a shared Semaphore)
Phase 5  Fan out one _execute_single_fuzz coroutine per (finding, payload)
Phase 6  Send sentinel → wait for writer to drain → deregister custody
```

### Concurrency rule (the most important invariant)
- Network I/O is **parallel**: all `_execute_single_fuzz` coroutines run under a
  shared `asyncio.Semaphore` (`_PARALLEL_MAX_CONCURRENCY = 5`) on one shared
  `httpx.AsyncClient`.
- DB writes are **serialized**: every result is `put` on an `asyncio.Queue`; a
  **single** `_db_writer_consumer` coroutine owns the only write `AsyncSession`
  and commits in batches (`_DB_WRITER_BATCH_SIZE = 10` rows **or** every
  `_DB_WRITER_FLUSH_INTERVAL = 1.5s`, whichever first).
- ⚠️ **Never** add a second coroutine that writes to the DB during a run, and
  never share one `AsyncSession` across concurrent tasks. That is the bug class
  this whole design exists to prevent (SQLAlchemy async sessions are not
  concurrency-safe; SQLite has a single writer).

---

## Request mutation (`mutate_request`)

Deep-copies the parsed request and applies **one** payload instruction by
`location`:
- `query_param` → set/replace a query parameter
- `json_key` → set a key in the JSON body (supports nested)
- `header` → set a header
- `path_segment` → replace a path component
- `cookie` → modify the Cookie header

The mutated request is reconstructed into a real URL via `_reconstruct_url`
(base netloc + path + query) and sent by `_send_request`.

---

## Baseline (`_compute_baseline`)

Before fuzzing, the engine sends the **unmutated** request to capture a baseline
`{status_code, content_length, response_body, elapsed_ms}`. The differential
oracle compares each fuzzed response against this baseline. If the baseline
request fails, that finding's payloads are skipped (logged).

---

## Differential Oracle (`_differential_verdict`)

Produces one of `verified` / `suspicious` / `failed`. Steps:

1. **Normalize** both response bodies (`_sanitize_response_text`): strips
   volatile headers, dynamic JSON keys, and regex-matches out timestamps, UUIDs,
   high-entropy hex tokens, and Unix timestamps — so noise doesn't look like a
   diff.
2. **Similarity** via `difflib.SequenceMatcher` ratio (inputs capped at
   `_SEQUENCE_MATCHER_MAX_LEN = 50_000` chars to protect the event loop from
   O(N²) on huge bodies).
3. **Length deviation** = `|test_len - base_len| / max(base_len, 1)`.
4. **Block detection**: response contains any `_BLOCK_KEYWORDS`
   (`access denied`, `forbidden`, `waf`, `captcha`, `rate limit`, …).

### Verdict rules (in order)
| Rule | Condition | Verdict |
|---|---|---|
| 1. Server error | baseline `<500` and test `>=500` | `verified` (possible crash/injection) |
| 2. BOLA/IDOR | type∈{BOLA,IDOR}, test 200, not blocked, length-dev > 5% | `verified`; ≤5% → `suspicious`; blocked → `failed` |
| 3. Mass-assign / param-pollution | test∈{200,201}, not blocked, length-dev > 10% | `verified`; else minor → `suspicious` |
| 4. Generic divergence | length-dev > 15% and not blocked | `suspicious` |
| 5. Status change | baseline status ≠ test status | `suspicious` |

### Post-rules
- **Veto** (anti false-positive): if verdict is verified/suspicious **and** test
  is 200 **and** body contains a `_VETO_KEYWORDS` denial string (`error`,
  `forbidden`, `unauthorized`, `操作无权限`, `login`, …) → downgrade to `failed`.
- **Escalation** (anti false-negative): if `suspicious` + 200 + tiny length-dev
  but a `_ESCALATION_KEYS` sensitive key (`email`, `token`, `password`, `ssn`,
  `admin`, `secret`, `credit_card`, `phone`) appears **only** in the test
  response → promote to `verified` (data-exposure proof).

`diff_details` (persisted JSON) carries `length_deviation_ratio`,
`status_code_baseline/test`, `content_length_*`, `elapsed_ms_*`, `is_blocked`,
`similarity_ratio`, `sanitized_body_capped`, and human-readable `analysis_notes`.

> Example from the real E2E run: a BOLA payload on `?id` against a target whose
> response grew 130% (`length deviation 130.23%`, similarity 59%) →
> `verified`; an identical-length response → `suspicious`; no change → `failed`.

---

## Auth Custody — self-healing sessions (Section 7)

The problem: a long fuzzing run can outlive the auth session; once the cookie/
token expires, every subsequent request silently fails and all verdicts become
garbage. `AuthCustodyController` solves this.

### State
- `session_valid_event` — an `asyncio.Event`, a **barrier**. Set = open/valid;
  cleared = "re-authenticating, hold." Every dispatch awaits this gate.
- `current_active_auth_value` + `auth_kind` (`cookie`|`token`) — the single live
  credential, injected inline right before each request via `_inject_active_auth`
  (overwrites Authorization/Cookie header). When empty it no-ops, so pre-expiry
  requests are byte-identical (zero regression).
- `auth_refresh_request` — cached re-login request (the Identity Anchor).
- `approved_host` — scope lock; re-auth may only target this host.

### Detection (`_is_auth_death`)
A response is "auth death" if status ∈ `{401, 403}` **or** it's a 200 whose body
contains a soft-logout signature (`session expired`, `please login`,
`token invalid`, `unauthenticated`, `authorization required`).

### Recovery (`_refresh_session_and_resume`) — the anti-deadlock contract
1. **Single-flight**: guarded by `_refresh_lock` + `is_refreshing`; only the
   first task that observes auth-death performs the refresh, others bow out.
2. **Guards**: aborts if no cached refresh request, if `reauth_count >=
   _MAX_REAUTH_CYCLES (3)` (anti-thrash), or if the refresh URL host ≠
   `approved_host` (scope lock).
3. **Circuit breaker**: up to `_AUTH_REFRESH_MAX_RETRIES (3)` attempts with
   exponential backoff (`_AUTH_REFRESH_BASE_DELAY = 0.5s`). On success extracts a
   new credential via `_extract_new_auth_value` (Set-Cookie first, else JSON
   `access_token`/`token`).
4. **`finally` ALWAYS** clears `is_refreshing` and re-opens the barrier — success
   or failure. Tasks then either resume with a fresh credential or fail fast.
   **Never gridlock.** Preserve this `finally` contract if you touch this code.

### Live diagnostics
While a refresh is in flight, `GET /verify/{id}/results` injects a transient
record (`payload_index = -1`, `verification_status = "running"`,
`id="__custody_diagnostic__"`) via `get_active_custody(finding_id)` so the UI
shows a recovery state instead of appearing hung. It is never persisted.

---

## Scope lock (Constraint 2)

`execute_parallel_fuzzing` derives the host of every job and refuses
**mixed-host batches** (v1 only supports a single host per batch). Behavior:
- Explicit `approved_host` → enforced, scope lock ON.
- No `approved_host`, single finding → scope lock **OFF** (legacy single-target
  parity).
- No `approved_host`, multiple findings → locked to their shared derived host.
- Any out-of-scope host → the batch is rejected/aborted.

The API layer (`/hunter/verify/batch` in `hunter.py`) enforces the same single-
host rule up front and returns 400 on a mixed-host or out-of-scope selection,
refusing to probe third-party domains.

---

## Resiliency details
- `_send_request` uses `httpx` with `verify=False` and timeouts from settings
  (`FUZZER_HTTP_TIMEOUT_CONNECT=10s`, `FUZZER_HTTP_TIMEOUT_READ=20s`).
- Responses are truncated to `FUZZER_RESPONSE_BODY_MAX_LENGTH=5000` chars before
  storage.
- `_commit_with_retry` retries SQLite "database is locked" up to
  `_DB_COMMIT_MAX_RETRIES=3` with exponential backoff (`base 0.1s`).
- Per-payload jittered delay smooths bursts; 429/503 trigger an adaptive pause
  (`_RATE_LIMIT_DEFAULT_PAUSE=5s`).

---

## Verdict lifecycle for the UI
```
untested → (engine runs) → verified | suspicious | failed
                         ↘ running (transient, only during re-auth)
```
Poll `GET /hunter/verify/{finding_id}/results`; records are ordered by
`payload_index`. The job completes when all payloads have rows and no custody
diagnostic is present.
