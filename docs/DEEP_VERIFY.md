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

No changes to the fuzzer's verdict path; the rule-oracle tests stay green (backend
backend suite: **145 passed** — see [`STATUS.md`](./STATUS.md)).

---

## Verdict vocabulary & the decisive-evidence standard

Unlike the rule oracle (`fuzzer.py::_differential_verdict`, which emits **three**
values — `verified` / `suspicious` / `failed`), the AI verifier's verdict
vocabulary is **four** values; it adds `inconclusive`:

- `verified` — the attacked state was demonstrably changed by the unauthorized actor.
- `failed` — the attacked state is provably unchanged (the server enforced authorization).
- `inconclusive` — **NEW** (the rule oracle has no equivalent): cannot confirm from the
  evidence gathered; a human must decide.
- `suspicious` — still ambiguous and the model has not yet spent its one follow-up.

This vocabulary lives in `SYSTEM_PROMPT` (`deep_verifier.py` ~63-96) and is restated
in `_OPTIONS_BLOCK` (~116) and `_TURN2_TEMPLATE` (~159). `SYSTEM_PROMPT` carries a
five-point **DECISIVE-EVIDENCE STANDARD**:

1. An action endpoint's OWN response — above all an opaque success such as
   `200 {"status":"ok"}` — is **never, by itself** evidence that the targeted state
   did or did not change.
2. Return `verified` / `failed` **only** when a follow-up read-back reflects the
   **SAME** attacked state — it returns the exact field/resource that was written (so
   it can be compared against the value the attack sent) or is an explicit record of
   that specific write.
3. If the evidence does not reflect the targeted state (a wrong/unrelated object, a
   read-back missing the written field, or no decisive observation), the model **must**
   answer `inconclusive` — not fall back to `failed`, and not return `verified` on the
   action status alone.
4. `inconclusive` means "cannot confirm from the evidence gathered; a human must
   decide" — the honest answer **only** in a genuine evidence gap (when decisive
   read-back evidence does exist, commit to `verified` / `failed` rather than hedging).
5. **SAME-RESOURCE RULE** — a read-back is decisive only if it queries the **same**
   resource/path the attack targeted (any HTTP method on that resource) or is an
   explicit record of that write. A **different** endpoint that merely exposes a field
   with the *same name* as what was written is **not** the same state and is **not**
   decisive → the model must answer `inconclusive`.

---

## Deterministic cross-resource guard (B-2.2)

The SAME-RESOURCE RULE is **also enforced deterministically in code**, not left to the
model alone. After the model returns, a target-agnostic structural backstop
(`_apply_cross_resource_guard`, `deep_verifier.py` ~213; path key via `_normalize_path`
~201) runs:

- It **downgrades** a `verified` / `failed` verdict to `inconclusive` — with override
  reason `CROSS_RESOURCE_OVERRIDE_REASON = "cross_resource_readback_not_decisive"` (~198)
  — **iff** a follow-up read-back was performed **and** its concrete path differs from
  the attack path (`normalize(follow_up_path) != normalize(attack_path)`).
- It is **method-agnostic** and compares two path strings only (drops query/fragment,
  strips a trailing slash); it holds no knowledge of any target's endpoints/fields.
- It does **nothing** when there was no follow-up (e.g. a read-type/GET BOLA confirmed
  by the attack response itself), when the paths match (a same-resource read-back stays
  fully decisive), or when the verdict is already `suspicious` / `inconclusive`.

It is applied at **both** return sites in `execute_deep_verification`. The result then
records the outcome transparently: `ai_verdict` is the **final** (post-guard) verdict,
`ai_verdict_raw` preserves the model's original pre-guard verdict, and `guard_override`
holds the override reason (or `None` when the guard did not fire).

---

## B-1 — confident cross-path verdict (✅ DONE, committed `37769b3`)

> ✅ **Status:** the machinery below is committed (`37769b3`), **live-measured** (shadow, N=5:
> X-CROSS→`verified` 5/5, X-SAFE→`inconclusive`/safe 5/5, reverse-guards intact —
> `scripts/audit/shadow_b1step3_code_gather_measure.out.txt`), and **locked by an automated
> regression test** — `test_d18_b1_shadow_integration.py` runs the real
> `execute_deep_verification` with a mocked Gemini and pins X-CROSS→`verified` /
> X-SAFE→never-`verified` (closes D22) — plus offline units (`test_d18_b1_write_record.py`).
> **Caveats:** proven on **one vuln shape only**; the final verdict still depends on the model
> reading the log correctly (a model-specific pillar — re-test on any model swap); and the
> content-match's id check is now bound to an owner/subject key (TECH_DEBT **D23**, fixed), with
> the mirror value-side edge tracked as **D23b**. See [`STATUS.md`](./STATUS.md)
> and [`TECH_DEBT.md`](./TECH_DEBT.md) B-1.

The integrity floor (B-2.2) refuses a false verdict on a cross-path write but stops
at `inconclusive` — it cannot yet *confirm*. B-1 aims to let the verifier confirm a
cross-path write whose only evidence is an explicit **write record** (audit log /
history / events feed), without weakening the floor. Three pieces, all
target-agnostic (no concrete path/field/tag is hardcoded):

1. **Catalog semantics** (`endpoint_catalog._format_entry`) — each entry now carries
   the operation's genuine `tags` + `operationId` (when the spec declares them), so a
   record-style endpoint is recognizable as such. Nothing is invented.
2. **Deterministic write-record gathering — HALF 1** (`deep_verifier`,
   `select_write_record_endpoint` / `has_same_path_readback`): when the attack is a
   write (`POST/PUT/PATCH/DELETE`) and the attacked resource has **no same-path
   read-back** in the catalog, the *code* — not the model — picks a record/log-style
   endpoint from the catalog (generic `_WRITE_RECORD_KEYWORDS` vocabulary) and forces
   it as the single follow-up. If none exists, it does **not** fabricate one → the
   flow stays `inconclusive`.
3. **Write-record exemption — HALF 2** (`_write_record_content_match` +
   `_apply_cross_resource_guard(..., write_record_decisive=True)`): a cross-path
   `verified` is normally downgraded by B-2.2. It is **exempted only when** the code
   structurally verifies — against the attack's own runtime params — that a **single
   record** in the read-back contains **both** the attacked object id **and** a value
   this attack wrote (scalar equality, not substring). That presence is decisive proof
   the unauthorized write landed. The exemption applies **only** to `verified` (a
   record's presence proves a write happened; its absence cannot prove the negative),
   so a secure cross-path control (X-SAFE, no matching record) still stays
   `inconclusive`. Override reason: `WRITE_RECORD_EXEMPTION_REASON =
   "write_record_readback_decisive"`.

The model's say-so is never sufficient for the exemption — only the in-code content
match is. This is what keeps the X-SAFE trap from re-opening the integrity hole.

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
  `ai_verdict` (the **final**, post-guard verdict), `ai_verdict_raw` (the model's
  pre-guard verdict), `guard_override` (the structural-guard reason, or `None`),
  `ai_confidence`, `ai_reasoning`, `ai_requested_follow_up`,
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
- **Endpoint-catalog seam** (`_shadow_endpoint_catalog`): real endpoint discovery
  now exists. `endpoint_catalog.py`'s `catalog_from_openapi` derives the surface from
  an OpenAPI/Swagger spec, and `_shadow_endpoint_catalog` **merges** it with the
  placeholder (the finding's own path + a same-resource GET read-back) when a spec
  source is provided — read from `settings.AI_DEEP_VERIFY_OPENAPI_SPEC` via `getattr`
  (a runtime-only seam, **not** a declared `config.py` field); with no source it falls
  back byte-identically to the placeholder. Each catalog entry **leads with
  `METHOD /path`** and, when the spec declares them, now **carries the operation's
  genuine `tags` and `operationId`** (nothing invented — see the B-1 section below),
  so the model can tell what an endpoint *is* (e.g. that an audit/log endpoint is a
  record of writes). See [`TECH_DEBT.md`](./TECH_DEBT.md) D18 / D21.

---

## Manual validation (not pytest)

The committed helper `backend/scripts/deep_verify_live_check.py`:

1. Requires the **vulnerable target** on `http://127.0.0.1:8001` (see
   [`../vulnerable_target/README.md`](../vulnerable_target/README.md)).
2. Requires **Gemini network access**.
3. Forces `settings.AI_DEEP_VERIFY_ENABLED = True` for the run only.
4. Exercises three cases (per `CASES` in the script) and prints verbatim model JSON
   + structured results:
   - **Vuln D** — `POST /api/users/{id}/settings` BOLA write (path `1`→`2`; expect `verified`),
   - **SAFE** — `POST /api/users/{id}/avatar` BOLA attempt (expect `failed` / not vulnerable), and
   - **Vuln C** — `GET /api/admin/users` admin-only access, read-only (`payload=None`; expect `verified`).

```powershell
# Terminal 1 — ground-truth target
python -m uvicorn vulnerable_target.main:app --port 8001

# Terminal 2 — from repo root, with GEMINI_API_KEY in backend/.env
python backend/scripts/deep_verify_live_check.py
```

Per `deep_verify_live_check.py` header: not under `backend/tests/` (it is not part
of the pytest count).

---

## Related repo paths

- [`../vulnerable_target/README.md`](../vulnerable_target/README.md)
- [`../vulnerable_target/benchmark/README.md`](../vulnerable_target/benchmark/README.md)
- [`../vulnerable_target/benchmark/RESULTS.md`](../vulnerable_target/benchmark/RESULTS.md)
