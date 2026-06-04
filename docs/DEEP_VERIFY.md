# DEEP VERIFY — AI-in-the-loop Write-then-Read Verifier

> File: `backend/app/services/deep_verifier.py`. Manual script:
> `backend/scripts/deep_verify_live_check.py`.
>
> **Status:** present in tree; **not wired to any HTTP endpoint**. It IS now
> invoked, **read-only**, from the fuzzer as **shadow-mode Phase 7** (see
> [`VERIFY_ENGINE.md`](./VERIFY_ENGINE.md) §Phase 7). Two independent gates, both
> default `False`: `AI_DEEP_VERIFY_ENABLED` (the verifier itself runs / may call
> Gemini) and `AI_DEEP_VERIFY_SHADOW` (the fuzzer calls it after a batch). With the
> defaults, nothing here runs and behavior is byte-identical to before. The
> rule-based HTTP verify still uses `fuzzer.py`.

---

## Purpose (from `deep_verifier.py` module header)

Resolve access-control cases that a single-shot differential oracle cannot
(e.g. silent BOLA with opaque `200 {"status":"ok"}` on write). Two-turn
AI-in-the-loop write-then-read. Does not call `execute_parallel_fuzzing` or
`_differential_verdict`.

---

## How it works

```
Turn 1   Send baseline (authorized/self) + attack (cross-object) requests.
         Present BOTH real HTTP responses to Gemini.
         Model returns either:
           (A) final verdict now, OR
           (B) exactly ONE follow-up HTTP request spec (relative path, same host).

Execute  If (B): run the follow-up for real (scope-locked to approved host).

Turn 2   Feed the follow-up's raw response back in the same conversation.
         Model delivers the final verdict.
```

The returned `DeepVerificationResult` keeps the **full evidence trail**
(baseline response, attack response, optional follow-up request/response) **beside**
the AI verdict — the verdict is never the sole field.

On Gemini timeout, 503, or invalid JSON the function **degrades gracefully**
(never raises through to callers) and records why in the result.

### Reused primitives (read-only from fuzzer)

Only stable, side-effect-free helpers are imported from `fuzzer.py`:

- `mutate_request`, `_send_request`, `_reconstruct_url`, `_host_of`
- `ScopeViolationError` for host lock enforcement

No changes to the fuzzer's verdict path; the existing **73** backend tests are
unaffected.

---

## Configuration

| Setting | Default | Effect |
|---|---|---|
| `AI_DEEP_VERIFY_ENABLED` | `False` | When `False`, `execute_deep_verification` returns a clearly-marked `disabled` result and **never** touches the network. Gates the verifier itself. |
| `AI_DEEP_VERIFY_SHADOW` | `False` | When `False`, the fuzzer's Phase 7 shadow pass is an immediate no-op. When `True`, the fuzzer calls the verifier read-only after a batch. To get a live Gemini second opinion, **both** this and `AI_DEEP_VERIFY_ENABLED` must be `True`. |
| `GEMINI_API_KEY` | optional | If unset, AI steps return degraded output (see module). |
| `GEMINI_PRO_MODEL` | `gemini-2.5-flash` (code default; `.env` may override, e.g. `gemini-2.5-pro`) | Model used for both turns. |
| `GEMINI_REQUEST_TIMEOUT_SECONDS` | `60` | From `settings`; used by Gemini calls in this module. |

Set in `backend/.env` or override at runtime (as the live-check script does).

---

## `execute_deep_verification` parameters (seams)

```
execute_deep_verification(parsed_request, payload, base_url, *,
                          approved_host=None, auth_context=None,
                          context_note="", available_endpoints=None,
                          model_name=None) -> DeepVerificationResult
```

- `parsed_request` — the BASELINE (authorized/self) request; `payload` mutates it
  into the ATTACK request via the fuzzer's `mutate_request` (pass `payload=None`
  for read-only cases so baseline == attack).
- `auth_context` — headers merged into every request (incl. the follow-up); this
  is the **auth seam**.
- `available_endpoints` — the discoverable API surface handed to the model so it
  can request the correct read-back path for its one follow-up; this is the
  **endpoint-catalog seam**.
- `approved_host` — scope lock; a follow-up whose host ≠ this is refused.
- Returns a `DeepVerificationResult` with `status` (`completed`/`degraded`/`disabled`),
  `ai_verdict`, `ai_confidence`, `ai_reasoning`, `ai_requested_follow_up`,
  `follow_up_request`/`follow_up_response`, `baseline`, `attack`, `turns_raw`.

---

## Shadow-mode Phase 7 (read-only integration)

`execute_parallel_fuzzing` appends an additive **Phase 7** after a batch fully
completes (`_run_shadow_deep_verification` in `fuzzer.py`). Gated by
`AI_DEEP_VERIFY_SHADOW` (default off → immediate no-op). When on, it:

1. queries back this run's `FuzzingRecord`s with `verification_status == "suspicious"`;
2. for each, re-runs `execute_deep_verification` against the same target; and
3. **logs** the AI verdict (`[FUZZER · SHADOW] … AI_shadow_verdict=… NOT applied
   (shadow, observe-only)`) **without** changing `verification_status` /
   `diff_details` or anything the user sees.

It never raises — any failure is logged and swallowed, so it cannot affect the
batch result. Phases 1–6, `_execute_single_fuzz`, and `_differential_verdict` are
unchanged. Two seams feed it, both currently minimal:

- **Auth seam** (`_shadow_auth_context`): prefer the live custody controller's
  active credential, else the auth header on the finding's `parsed_request`.
- **Endpoint-catalog seam** (`_shadow_endpoint_catalog`): **KNOWN LIMITATION** —
  there is no real endpoint discovery yet, so the catalog is just the finding's
  own path plus an obvious GET read-back of the same resource. See
  [`TECH_DEBT.md`](./TECH_DEBT.md) D18.

---

## Manual validation (not pytest)

The committed helper `backend/scripts/deep_verify_live_check.py`:

1. Requires the **vulnerable target** on `http://127.0.0.1:8001` (see
   [`../vulnerable_target/README.md`](../vulnerable_target/README.md)).
2. Requires **Gemini network access**.
3. Forces `settings.AI_DEEP_VERIFY_ENABLED = True` for the run only.
4. Exercises three planted cases (blatant BOLA, silent BOLA, SAFE trap) and prints
   verbatim model JSON + structured results.

```powershell
# Terminal 1 — ground-truth target
python -m uvicorn vulnerable_target.main:app --port 8001

# Terminal 2 — from repo root, with GEMINI_API_KEY in backend/.env
python backend/scripts/deep_verify_live_check.py
```

Per `deep_verify_live_check.py` header: not under `backend/tests/` (does not
change the 73-test count).

---

## Related repo paths

- [`../vulnerable_target/README.md`](../vulnerable_target/README.md)
- [`../vulnerable_target/benchmark/README.md`](../vulnerable_target/benchmark/README.md)
- [`../vulnerable_target/benchmark/RESULTS.md`](../vulnerable_target/benchmark/RESULTS.md)
