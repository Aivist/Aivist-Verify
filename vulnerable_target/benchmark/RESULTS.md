# Verification Benchmark — Results

> Ground-truth benchmark for dynamic black-box verification of broken-access-control
> vulnerabilities on the `vulnerable_target/` app. **Append-only**: add new cases as
> new entries below and update the summary counters. See [`README.md`](./README.md).
>
> Target: `http://127.0.0.1:8001`. Attacker identity for all cases so far: **Alice**
> (id=1, role=`user`, token `alice-token-aaaa`) — a normal, non-admin user.
> Model for AI-in-the-loop: `gemini-2.5-pro` (two-turn loop; may request ONE
> follow-up HTTP request, executed for real and fed back).

## Summary

| Metric | Count |
|---|---|
| Total cases | 11 (A, B, C, D, SAFE, T-REAL, T-TRAP, T-WEAK, T-SILENT2, X-CROSS, X-SAFE) |
| Ground truth: REAL vulnerabilities | 8 (A, B, C, D, T-REAL, T-WEAK, T-SILENT2, X-CROSS) |
| Ground truth: SECURE controls | 3 (SAFE, T-TRAP, X-SAFE) |
| **AI-in-the-loop cases evaluated** | 10 (B, C, D, SAFE, T-REAL, T-TRAP, T-WEAK, T-SILENT2, X-CROSS, X-SAFE) |
| **AI confident-correct** (same-path; `verified`/`failed` matches truth) | 8 / 8 |
| **AI integrity floor met** (cross-path; no false verdict, result = `inconclusive`) | 2 (X-CROSS, X-SAFE) — confident verdict deferred to B-1 |
| **AI false positives** (AI = REAL on a SECURE case) | 0 |
| **AI false negatives** (AI = SECURE/failed on a REAL case) | 0 |
| AI cases not yet run | 1 (A) |
| **Rule-based oracle cases measured** | 4 (A, B, X-CROSS, X-SAFE) |
| Rule-based oracle correct (confirmed the truth) | 1 / 4 — A `verified` ✓; B / X-CROSS / X-SAFE `suspicious` ✗ (stalled — did not confirm the truth either way) |
| Rule-based oracle cases not yet measured | 7 (C, D, SAFE, T-REAL, T-TRAP, T-WEAK, T-SILENT2) |

**Key finding so far:** on the "silent" write cases (B, D, SAFE) the POST response
is a byte-identical opaque `200 {"status":"ok"}` for both a legitimate self-write
and a cross-user attempt — and for both the REAL vulnerabilities **and** the SECURE
control. A single-shot rule-based diff oracle stalls at `suspicious` (it did so on
B) and cannot separate REAL from SECURE. The AI-in-the-loop verifier, given the
option to gather one more piece of evidence, requested a **write-then-read** on
every silent case and used the read-back to correctly classify all of them —
including declining to flag the SECURE look-alike (no false positive).

### Verdict matrix

| Case | Ground truth | Rule-based oracle | AI-in-the-loop | AI correct? |
|------|--------------|-------------------|----------------|-------------|
| A    | REAL         | `verified`        | not run        | — (rule ✓)  |
| B    | REAL         | `suspicious`      | `verified`     | ✅ |
| C    | REAL         | not measured      | `verified`     | ✅ |
| D    | REAL         | not measured      | `verified`     | ✅ |
| SAFE | SECURE       | not measured      | `failed` (= not vulnerable) | ✅ |
| T-REAL    | REAL    | not measured | `verified` | ✅ |
| T-TRAP    | SECURE  | not measured | `failed` (= not vulnerable) | ✅ |
| T-WEAK    | REAL    | not measured | `verified` | ✅ |
| T-SILENT2 | REAL    | not measured | `verified` | ✅ |
| X-CROSS | REAL   | `suspicious` | `inconclusive` (raw model `failed`, structurally guarded) | ◐ floor only |
| X-SAFE  | SECURE | `suspicious` | `inconclusive`                                            | ◐ floor only |

> ◐ = **integrity floor met** (the system never emits a false verdict — no false-negative
> on X-CROSS, no false-positive on X-SAFE), but a **confident** verdict (`verified`/`failed`)
> is **not yet reached**. These two cross-path cases have no same-path GET; the decisive
> confirmation is the cross-path write record (`GET /api/audit-log`), which the model does
> not yet choose (0/20). Promoting `inconclusive` → `verified`/`failed` is deferred to B-1.

---

## Case entries

<!-- ENTRY TEMPLATE (copy for each new case):
### Case <ID> — <short title>
- **Endpoint / method:** ...
- **Vulnerability class:** ...
- **Ground truth:** REAL | SECURE
- **Evidence gap:** ...
- **Rule-based oracle verdict:** verified | suspicious | failed | not measured  (+ key metrics)
- **AI-in-the-loop verdict:** ...  | requested follow-up? yes/no — <what>
- **Correct?:** yes/no
- **Notes (AI reasoning, verbatim):** ...
-->

### Case A — blatant BOLA (object-level read)
- **Endpoint / method:** `GET /api/orders/{order_id}`
- **Vulnerability class:** BOLA / object-level read (horizontal)
- **Ground truth:** **REAL**
- **Evidence gap:** **Low.** Alice's order (id=1) and Bob's order (id=2) differ in
  item/amount/currency, so the cross-user read returns a clearly different body and
  Content-Length. A single-shot size/diff oracle can catch it.
- **Rule-based oracle verdict:** **`verified`.** Baseline `GET /api/orders/1`
  (200, content_length 88) vs. mutated `GET /api/orders/2` (200, content_length 118).
  `diff_details`: `length_deviation_ratio=0.3409`, `similarity_ratio=0.6607`,
  `status_baseline=200`, `status_test=200`, `is_blocked=false`,
  notes: *"IDOR/BOLA confirmed: status 200, length deviation 34.09%, similarity 66.07%, no blocking detected"* (Rule 2 fired).
- **AI-in-the-loop verdict:** **not run** (no two-turn AI loop was executed for A).
- **Correct?:** Rule-based: **yes** (matches REAL). AI: n/a.
- **Notes:** This is the "easy" baseline — the one case where the existing
  rule-based differential oracle alone is sufficient, because the side effect is
  directly visible in the response body.

### Case B — silent BOLA (object-level write)
- **Endpoint / method:** `POST /api/users/{user_id}/profile` (+ read-back `GET /api/users/{user_id}/profile`)
- **Vulnerability class:** silent BOLA / object-level write
- **Ground truth:** **REAL**
- **Evidence gap:** **High.** The write endpoint always returns an opaque
  `200 {"status":"ok"}` — byte-identical for a self-write vs. a cross-user write,
  and regardless of whether anything changed. The cross-user effect is **only**
  observable via a second request (write-then-read).
- **Rule-based oracle verdict:** **`suspicious`** (did NOT confirm). Baseline
  `POST /api/users/1/profile` (200, content_length 15, `{"status":"ok"}`) vs.
  mutated `POST /api/users/2/profile` (200, content_length 15, `{"status":"ok"}`).
  `diff_details`: `length_deviation_ratio=0.0`, `similarity_ratio=1.0`,
  notes: *"IDOR/BOLA possible: status 200, length deviation 0.00%, similarity 100.00%"*.
  No escalation keys leaked → stayed `suspicious`. The engine has no write-then-read
  capability, so it cannot upgrade to `verified`.
- **AI-in-the-loop verdict:** **`verified`.** Requested follow-up? **Yes** —
  `GET /api/users/2/profile`. Read-back showed `display_name` changed to `HACKED`
  (after the attack write was actually executed against the live target).
- **Correct?:** **Yes** (REAL). The rule-based oracle was *not* correct here — it
  could only reach `suspicious`.
- **Notes (AI reasoning, verbatim):** *"The initial attack, where Alice attempted to
  modify Bob's profile (POST /api/users/2/profile), returned a 200 OK. The follow-up
  GET request to /api/users/2/profile confirmed that the modification was successful,
  as it returned Bob's profile with the display_name changed to 'HACKED'. This
  demonstrates that an authenticated user can modify the resources of another user,
  confirming a Broken Object Level Authorization (BOLA) vulnerability."*
  (An earlier run that only *described* the attack without executing it returned
  `failed` — a true reading of a false premise — which is why the corrected run
  executes the write for real before the read-back.)

### Case C — vertical privilege escalation
- **Endpoint / method:** `GET /api/admin/users`
- **Vulnerability class:** vertical privilege escalation (missing role check)
- **Ground truth:** **REAL**
- **Evidence gap:** **Medium.** The response is a normal `200`; recognizing the
  violation requires knowing the endpoint is admin-only and the caller is
  `role=user`. The returned data is richer than any normal-user endpoint (the full
  roster incl. every user's role), so the boundary is genuinely crossed.
- **Rule-based oracle verdict:** **not measured.**
- **AI-in-the-loop verdict:** **`verified`** (confidence 1.0). Requested follow-up?
  **No** — delivered the verdict in Turn 1; the single GET was conclusive. Evidence:
  Alice (`role=user`) `GET /api/admin/users` → `200`,
  `{"count":3,"users":[{"id":1,...,"role":"user"},{"id":2,...,"role":"user"},{"id":3,"username":"carol","role":"admin"}]}`.
- **Correct?:** **Yes** (REAL).
- **Notes (AI reasoning, verbatim):** *"The user, Alice, who has a 'user' role,
  successfully accessed the GET /api/admin/users endpoint. According to the documented
  authorization model, this endpoint is 'ADMIN-ONLY'. The server responded with a 200
  OK and the full user roster, confirming that the access control check for the user's
  role was either missing or incorrect. This is a direct and conclusive proof of a
  broken access control vulnerability."*

### Case D — silent BOLA, regression (object-level write)
- **Endpoint / method:** `POST /api/users/{user_id}/settings` (+ read-back `GET /api/users/{user_id}/settings`)
- **Vulnerability class:** silent BOLA / object-level write (same shape as B, fresh endpoint)
- **Ground truth:** **REAL**
- **Evidence gap:** **High.** Same as B — opaque `200 {"status":"ok"}`, byte-identical
  for self vs. cross writes; only observable via write-then-read. Regression check that
  the write-then-read oracle still works on a new endpoint.
- **Rule-based oracle verdict:** **not measured** (same shape as B, which measured
  `suspicious`).
- **AI-in-the-loop verdict:** **`verified`** (confidence 1.0). Requested follow-up?
  **Yes** — `GET /api/users/2/settings`. Real responses presented: baseline
  `POST /api/users/1/settings` and attack `POST /api/users/2/settings` (body
  `{"notifications":"PWNED_CHANNEL"}`) both `200 {"status":"ok"}` (byte-identical).
  Read-back returned `{"user_id":2,"notifications":"PWNED_CHANNEL"}`.
- **Correct?:** **Yes** (REAL).
- **Notes (AI reasoning, verbatim):** *"The initial attack (POST /api/users/2/settings)
  returned a 200 OK, suggesting a potential vulnerability. The follow-up GET request to
  the same endpoint confirmed that the unauthorized change was successfully persisted.
  The response body `{\"user_id\":2,\"notifications\":\"PWNED_CHANNEL\"}` shows that
  Alice (user 1) was able to modify the settings of user 2. This is a direct violation
  of the intended authorization policy."*

### Case SAFE — secured look-alike control
- **Endpoint / method:** `POST /api/users/{user_id}/avatar` (+ read-back `GET /api/users/{user_id}/avatar`)
- **Vulnerability class:** secure look-alike control (ownership IS enforced)
- **Ground truth:** **SECURE** (NOT vulnerable)
- **Evidence gap:** **High / adversarial.** Returns the **same** opaque
  `200 {"status":"ok"}` as the vulnerable B/D — and deliberately does **not** return
  403 on a cross-user attempt. It silently drops the unauthorized write. Only a
  write-then-read reveals the value was **unchanged**. A single-shot oracle (or any
  verifier trusting the POST response) is designed to be fooled into a false positive.
- **Rule-based oracle verdict:** **not measured** (would see the same byte-identical
  `200 {"status":"ok"}` as B/D → at best `suspicious`, cannot exonerate).
- **AI-in-the-loop verdict:** **`failed`** (= not vulnerable; confidence 1.0).
  Requested follow-up? **Yes** — `GET /api/users/2/avatar`. Real responses presented:
  baseline `POST /api/users/1/avatar` and attack `POST /api/users/2/avatar` (body
  `{"avatar_url":"https://evil.example/pwn.png"}`) both `200 {"status":"ok"}`
  (byte-identical). Read-back returned the **original** value
  `{"user_id":2,"avatar_url":"https://avatars.local/bob.png"}` — unchanged.
- **Correct?:** **Yes** (SECURE). **No false positive** despite the trap.
- **Notes (AI reasoning, verbatim):** *"The initial attack to modify another user's
  resource (POST /api/users/2/avatar) misleadingly returned a 200 OK status, suggesting
  a vulnerability. However, the follow-up verification request (GET /api/users/2/avatar)
  confirmed that the state of the resource was not actually changed. The avatar_url
  remained the original value, not the value from the attack payload. This proves that
  while the API's response was ambiguous, the backend correctly enforced the access
  control policy and prevented the unauthorized modification. The vulnerability is not
  present."* This is the decisive case: same opaque response as the REAL silent BOLA
  (D), no hint given, identical prompt template — the AI separated them purely on the
  write-then-read evidence.

### Case T-REAL — strong-signal IDOR (object-level read)
- **Endpoint / method:** `GET /api/invoices/{invoice_id}`
- **Vulnerability class:** IDOR / object-level read (horizontal)
- **Ground truth:** **REAL**
- **Evidence gap:** **Low.** No ownership check; Bob's invoice body is clearly
  larger/different than Alice's (content_length 89 vs. 331), so even a single-shot
  size/diff oracle would catch it. Baseline-for-contrast case.
- **Rule-based oracle verdict:** **not measured.**
- **AI-in-the-loop verdict:** **`verified`** (confidence 1.0). Requested follow-up?
  **No** — delivered the verdict in Turn 1. Evidence presented: baseline
  `GET /api/invoices/1` (200, Alice's small invoice) vs. attack `GET /api/invoices/2`
  (200, `owner_id:2`, Bob's large invoice).
- **Correct?:** **Yes** (REAL).
- **Notes (AI reasoning, verbatim):** *"The baseline request shows that Alice (user 1)
  can access her own invoice (ID 1). The attack request shows that Alice can also access
  Bob's invoice (ID 2), confirmed by the `owner_id: 2` in the response body. The server
  responded with a 200 OK and the full invoice details for another user's resource, which
  is a clear violation of the specified authorization model. Access should have been denied."*

### Case T-TRAP — soft-200 denial (false-positive killer)
- **Endpoint / method:** `GET /api/documents/{document_id}`
- **Vulnerability class:** secure look-alike (cross-user read DENIED, but with HTTP 200 + error body instead of 403)
- **Ground truth:** **SECURE** (NOT vulnerable)
- **Evidence gap:** **High / adversarial.** A cross-user read returns `200 OK` (the
  surface signal a status-code oracle trusts), but the body is `{"error":"forbidden"}`
  and the confidential content is never disclosed. A verifier must read the *body*, not
  the status line, to avoid a false positive.
- **Rule-based oracle verdict:** **not measured.**
- **AI-in-the-loop verdict:** **`failed`** (= not vulnerable; confidence 1.0). Requested
  follow-up? **No** — verdict in Turn 1. Evidence presented: baseline `GET /api/documents/1`
  (200, Alice's own content) vs. attack `GET /api/documents/2` (200, body `{"error":"forbidden"}`).
- **Correct?:** **Yes** (SECURE). **No false positive** despite the misleading `200`.
- **Notes (AI reasoning, verbatim):** *"The baseline request for the user's own document
  (ID 1) succeeded as expected. The attack request for another user's document (ID 2)
  returned a response body of `{\"error\":\"forbidden\"}`. This indicates that although
  the HTTP status code was an unconventional 200 OK, the application-level logic correctly
  identified the unauthorized access attempt and denied it. The access control mechanism
  is functioning correctly."* The verifier judged on the **body**, not the status code.

### Case T-WEAK — weak-signal IDOR (object-level read)
- **Endpoint / method:** `GET /api/notes/{note_id}`
- **Vulnerability class:** IDOR / object-level read (horizontal), faint signal
- **Ground truth:** **REAL**
- **Evidence gap:** **High (for size-based oracles).** Cross-user read IS allowed (real
  vuln), but every user's note is the same length/shape — only the last word differs
  (`milk` vs `eggs`), so both responses are content_length 56 (delta 0). A length/diff
  threshold oracle would likely miss it.
- **Rule-based oracle verdict:** **not measured.**
- **AI-in-the-loop verdict:** **`verified`** (confidence 1.0). Requested follow-up?
  **No** — verdict in Turn 1. Evidence presented: baseline `GET /api/notes/1` (200,
  Alice's note) vs. attack `GET /api/notes/2` (200, `owner_id:2`, Bob's note).
- **Correct?:** **Yes** (REAL). Caught on **semantics**, not magnitude.
- **Notes (AI reasoning, verbatim):** *"The user, acting as Alice (user_id=1), made a
  request for a resource belonging to another user (`GET /api/notes/2`). The server
  responded with a HTTP 200 OK and the full content of the note, which the response body
  confirms is owned by user_id=2. This violates the specified authorization model where a
  user should only be able to access their own objects. This is a classic Insecure Direct
  Object Reference (IDOR) vulnerability."* The verifier keyed on `owner_id:2`, not the
  (identical) response size — the reason it did not miss the faint signal.

### Case T-SILENT2 — silent BOLA, theme family (object-level write)
- **Endpoint / method:** `POST /api/users/{user_id}/theme` (+ read-back `GET /api/users/{user_id}/theme`)
- **Vulnerability class:** silent BOLA / object-level write (same family as B and D)
- **Ground truth:** **REAL**
- **Evidence gap:** **High.** No ownership check; opaque `200 {"status":"ok"}` on the
  write, byte-identical for self vs. cross writes. Cross-user effect only observable via
  write-then-read. Probes whether the follow-up step is still triggered on a fresh endpoint.
- **Rule-based oracle verdict:** **not measured.**
- **AI-in-the-loop verdict:** **`verified`** (confidence 1.0). Requested follow-up?
  **Yes** — `GET /api/users/2/theme`. Real responses presented: baseline
  `POST /api/users/1/theme` and attack `POST /api/users/2/theme` (body `{"theme":"PWNED_THEME"}`)
  both `200 {"status":"ok"}` (byte-identical). Read-back returned
  `{"user_id":2,"theme":"PWNED_THEME"}` (baseline pre-attack value was `dark`).
- **Correct?:** **Yes** (REAL).
- **Notes (AI reasoning, verbatim):** *"The initial attack, where user 1 sent a POST
  request to modify user 2's theme, returned a 200 OK status, which was suspicious. The
  follow-up GET request to /api/users/2/theme confirmed that the theme was indeed changed
  to 'PWNED_THEME'. This proves that a user can successfully modify another user's data,
  which is a clear broken access control vulnerability."*

---

## Phase-2 cross-path additions (MEASURED — D18 §5 fix B-2.2)

> Ground truth byte-verified (`scripts/audit/capture_phase2_crosspath.py`, GT-A..GT-E).
> Verdicts measured under the §5 integrity fix (prompt evidence-standard B-2/B-2.1 +
> deterministic structural cross-resource guard B-2.2), 5 runs each, shadow/observe-only,
> gemini-2.5-pro. Transcript: `scripts/audit/shadow_d18_fixb22_measure.out.txt`.
>
> **Integrity floor, not confirmation.** On these no-same-path-GET cases the system's
> correct behaviour is to refuse a false verdict, not (yet) to confirm. Both resolve to a
> stable `inconclusive`. Promoting them to `verified`/`failed` requires the model to find
> and use the cross-path write record (audit-log) — deferred to B-1.

### Case X-CROSS — REAL cross-path BOLA (display-name)
- **Endpoint / method:** `POST /api/users/{user_id}/display-name` (confirm via cross-path
  `GET /api/audit-log`; there is **no** same-path GET)
- **Vulnerability class:** cross-path BOLA / object-level write
- **Ground truth:** **REAL**
- **Evidence gap:** opaque `200 {"status":"ok"}`; the written object (`Identity.display_name`)
  has no same-path GET, so the only decisive confirmation is the cross-path write record. A
  *different* object exposes a same-named field (`Profile.display_name`="Bob"), which invites
  a wrong-object read.
- **Rule-based oracle verdict:** **`suspicious`** (200, length deviation 0.00%, similarity
  100% → stalls, as designed).
- **AI-in-the-loop verdict:** **`inconclusive`** (stable 5/5). Requested follow-up? **Yes** —
  all 5 chose `GET /api/users/2/profile` (a DIFFERENT resource than the attacked
  `/display-name`); **0/5** chose the decisive `GET /api/audit-log`.
- **Correct?:** **Integrity floor met** — never the false-negative `failed`; honest
  `inconclusive`. **Not** `verified` (confirmation deferred to B-1).
- **How the verdict is produced (honest):** the model's RAW judgment still false-negatives
  this case **4/5** (`failed` @ conf 1.0 — it over-trusts the same-named `Profile.display_name`).
  Integrity comes from the **deterministic structural guard (B-2.2), not model compliance**:
  on each lapse run the guard downgraded `failed` → `inconclusive` because the follow-up path
  (`/api/users/2/profile`) ≠ the attack path (`/api/users/2/display-name`). Run 3 the model
  complied on its own (raw `inconclusive`).
- **Measured progression (false-negative rate):** before-fix `failed`×5 → B-2 `failed`×5 →
  B-2.1 `failed`×1 / `inconclusive`×4 → **B-2.2 `inconclusive`×5**.

### Case X-SAFE — SECURE cross-path control (nickname)
- **Endpoint / method:** `POST /api/users/{user_id}/nickname` (confirm via cross-path
  `GET /api/audit-log`; there is **no** same-path GET)
- **Vulnerability class:** cross-path BOLA look-alike, ownership enforced; cross-user write
  silently dropped, no audit row
- **Ground truth:** **NOT vulnerable (SECURE control)**
- **Evidence gap:** identical opaque `200 {"status":"ok"}` to a real BOLA; the only decisive
  exoneration is the *absence* of a write record (inherently weaker than a positive read-back).
- **Rule-based oracle verdict:** **`suspicious`**.
- **AI-in-the-loop verdict:** **`inconclusive`** (stable 5/5). Requested follow-up? **Yes** —
  `/profile`×4 and `/nickname`×1 (the same-path GET → 405); **0/5** chose `GET /api/audit-log`.
- **Correct?:** **Integrity floor met** — never the false-positive `verified` (the pre-fix
  failure mode); honest `inconclusive`. Not yet a confident `failed`/safe (deferred to B-1).
- **How the verdict is produced (honest):** the prompt evidence-standard alone suffices here —
  `Profile` has no `nickname` field, so the model honestly admits it cannot confirm. The
  structural guard did **not** need to fire (0/5 overrides).
- **Measured progression (false-positive rate):** before-fix `verified`×4 / `suspicious`×1 →
  **B-2 onward `inconclusive`×5** (false positive removed by the prompt standard).

### Reverse-guard — same-path controls (same B-2.2 run, 5 runs each)

> Confirms the §5 fix did **not** weaken same-path decisiveness (`inconclusive` is not an
> escape hatch): when the read-back IS the same resource the attack targeted, the structural
> guard never fires and the verifier still commits to a confident verdict.

- **P0-PROFILE** (REAL silent BOLA, `POST /api/users/{user_id}/profile`) → **`verified`×5**.
- **P0-AVATAR** (SECURE look-alike, `POST /api/users/{user_id}/avatar`) → **`failed`×5**.
- Structural-guard overrides: **0/5** each (same-resource read-back → guard never triggers).

---

## Provenance

- Rule-based oracle (A, B): driven through the real, unmodified
  `backend/app/services/fuzzer.py` functions (`mutate_request`, `_compute_baseline`,
  `_send_request`, `_differential_verdict`) against the live target with
  deterministic, hand-supplied `path_segment` payloads (id `1 → 2`, type `BOLA`).
- AI-in-the-loop (B, C, D, SAFE): two-turn loop using the same `google-genai` SDK /
  settings / `asyncio.wait_for` pattern as the app; one shared prompt template across
  C/D/SAFE with no hint about which is vulnerable; the model's follow-up request was
  executed for real against the live target and fed back in the same conversation.
- AI-in-the-loop (T-REAL, T-TRAP, T-WEAK, T-SILENT2): run via the **isolated
  `backend/app/services/deep_verifier.py` `execute_deep_verification`** component
  (gated behind `AI_DEEP_VERIFY_ENABLED`, default off; NOT wired into any product
  flow), with an identical setup across all four — Alice's token as `auth_context`,
  the full discoverable endpoint catalog in `available_endpoints`, the same
  identity/authz `context_note`, and no hint about which is vulnerable. Baseline +
  attack were executed for real against a freshly re-seeded target; the model's one
  follow-up (when requested) was executed live and fed back in the same conversation.
- Maintainer confirmed the T-* verdicts (2026-06-05): T-TRAP judged secure specifically
  on reading the `{"error":"forbidden"}` body; T-WEAK judged REAL specifically on the
  `owner_id:2` semantics (not response size).
- AI-in-the-loop (X-CROSS, X-SAFE): run via the same isolated `deep_verifier.py`
  `execute_deep_verification` component under the D18 §5 integrity fix (prompt
  evidence-standard + deterministic cross-resource guard), shadow/observe-only (never
  persisted), 5 runs each against a freshly re-seeded target, with the real OpenAPI
  catalog supplied as the spec source and Alice's token as `auth_context`; gemini-2.5-pro.
  The model's one follow-up was executed live and fed back. Transcript:
  `scripts/audit/shadow_d18_fixb22_measure.out.txt`.
- Integrity note (X-CROSS): the model's RAW judgment still false-negatives this case 4/5
  (`failed` @ conf 1.0); the recorded `inconclusive` comes from the deterministic structural
  guard (it downgrades a cross-resource read-back), not model compliance — preserved in the
  result as `ai_verdict_raw` + `guard_override`.
