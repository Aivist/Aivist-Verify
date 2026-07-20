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
| Total cases | 18 (A, B, C, D, SAFE, T-REAL, T-TRAP, T-WEAK, T-SILENT2, X-CROSS, X-SAFE, X-EQUIV-VULN, X-EQUIV-SAFE, X-SILENT-VULN, X-SILENT-SAFE, X-DELETE-VULN-HARD, X-DELETE-VULN-SOFT, X-DELETE-SAFE) |
| Ground truth: REAL vulnerabilities | 12 (A, B, C, D, T-REAL, T-WEAK, T-SILENT2, X-CROSS, X-EQUIV-VULN, X-SILENT-VULN, X-DELETE-VULN-HARD, X-DELETE-VULN-SOFT) |
| Ground truth: SECURE controls | 6 (SAFE, T-TRAP, X-SAFE, X-EQUIV-SAFE, X-SILENT-SAFE, X-DELETE-SAFE) |
| **M1.1 read-type (equal-length, MEASURED)** | X-EQUIV-VULN `verified` 5/5 (anchoring `confirmed`) · X-EQUIV-SAFE `failed` 5/5 — **0 false positives**, judged by semantics not size |
| **M1.2 silent-write / object-STATE (MEASURED)** | X-SILENT-VULN `verified` **5/5** (code-gathered state read; causality `confirmed_at_path` 5/5) · X-SILENT-SAFE **`verified` 0/5** (causality `absent` 5/5 → no exemption → `inconclusive`) — **0 false positives**; B-1 X-CROSS still `verified` 5/5 |
| **Shapes confirmed with zero FP** | **4** — write→write-record (B-1), read-type semantic equivalence (M1.1), write→object-STATE (M1.2), delete→NEGATIVE ASSERTION (M1.3) |
| **M1.3 delete-type (MEASURED)** | X-DELETE-VULN-HARD `verified` **5/5** (`confirmed_physical`) · X-DELETE-VULN-SOFT `verified` **5/5** (`confirmed_logical`) · X-DELETE-SAFE **`verified` 0/5** (`still_present`) · X-DELETE-CONTROL (never existed) **`verified` 0/5** (`preflight_absent`) — **0 false positives** |
| **Post-B-1 update (not re-run here)** | X-CROSS is now `verified` (code-gathered audit-log + content-match exemption, N=5, `shadow_b1step3_code_gather_measure.out.txt`); the "deferred to B-1" rows below are historical (pre-B-1). |
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
| X-EQUIV-VULN | REAL   | `suspicious` | `verified` (5/5; evidence_path `owner_id`, anchoring `confirmed`) | ✅ |
| X-EQUIV-SAFE | SECURE | `suspicious` | `failed` (5/5; 0 verified — zero false positives) | ✅ |
| X-SILENT-VULN | REAL   | `suspicious` | `verified` (5/5; code-gathered state read, causality `confirmed_at_path`) | ✅ |
| X-SILENT-SAFE | SECURE | `suspicious` | `inconclusive` (5/5; causality `absent` → no exemption; **0 verified**) | ✅ |
| X-DELETE-VULN-HARD | REAL | not measured | `verified` (5/5; pre-flight 200 → AFTER 404, `confirmed_physical`) | ✅ |
| X-DELETE-VULN-SOFT | REAL | not measured | `verified` (5/5; `status` active→revoked, `confirmed_logical`) | ✅ |
| X-DELETE-SAFE | SECURE | not measured | `inconclusive` (5/5; object still present; **0 verified**) | ✅ |

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

## M1.1 read-type semantic-equivalence additions (MEASURED)

> A DIFFERENT vuln shape from B-1's silent write: two read paths expose the SAME underlying
> object via different path shapes, so the decisive signal is SEMANTIC ("whose object is
> this?"), not a write-then-read. Both responses are shaped **EQUAL-LENGTH** (identity differs
> only in `owner_id` and a fixed-width UUID `account_ref`), so the rule oracle cannot decide by
> size and leaves both `suspicious` → they reach the AI verifier. That is the point: the AI must
> judge by content, exactly where deterministic size heuristics can't. 5 runs each, shadow/
> observe-only, gemini-2.5-pro, real OpenAPI catalog. Transcript:
> `scripts/audit/shadow_m1_xequiv_run.out.txt`.
>
> **Structured evidence (new in M1.1):** the verdict now carries `evidence_path` (a JSON path
> the model cites as decisive) and a CODE-computed `anchoring_result` — the engine resolves that
> path in the read-back and checks its value against the attacked victim's runtime id. This
> **corroborates** the model's cited evidence; it is **not** an independent oracle (see limits).

### Case X-EQUIV-VULN — REAL read-type semantic-equivalence BOLA
- **Endpoint / method:** `GET /api/statements/{statement_id}` (flat path, NO ownership check).
  The SAME object is also reachable via the owner-scoped `GET /api/users/{user_id}/statement`.
- **Vulnerability class:** read-type cross-path BOLA (semantic equivalence)
- **Ground truth:** **REAL**
- **Evidence gap:** the attack response is **equal-length** to the baseline (both content-length
  109; differ only in `owner_id` 1→2 and a fixed-width UUID) → the rule oracle stalls at
  `suspicious`. The leak is visible in the attack response itself (`owner_id: 2` returned to
  user 1) — **no follow-up needed**.
- **Rule-based oracle verdict:** `suspicious` (200/200, length-dev ~0) → reached the AI verifier.
- **AI-in-the-loop verdict:** **`verified` 5/5** (`guard_override` None — no follow-up, so the
  cross-resource guard is correctly a no-op). `evidence_path='owner_id'`,
  `anchoring_result='confirmed'` **5/5** (the cited path resolves and its value == the attacked
  id 2).
- **Correct?:** **Yes** (REAL). 0 misses.
- **AI reasoning (verbatim, run 1):** *"The baseline request for `/api/statements/1` returned a
  resource with `owner_id: 1`, establishing the identity of the requester. The attack request for
  `/api/statements/2` successfully retrieved the resource and the response body confirmed it
  belongs to `owner_id: 2`. The server should have denied access to a resource owned by another
  user, but instead returned the data. This directly demonstrates a broken access control
  vulnerability."*

### Case X-EQUIV-SAFE — SECURE read-type control (equal-length soft-200 denial)
- **Endpoint / method:** `GET /api/ledgers/{ledger_id}` (flat path, ownership **IS** enforced;
  a cross-user read returns an equal-length soft-200 denial, never 403). Parallel to the VULN case.
- **Vulnerability class:** read-type cross-path look-alike, ownership enforced
- **Ground truth:** **SECURE** (NOT vulnerable)
- **Evidence gap:** the denial is **equal-length** to a real record and returns **200** (not
  403) — only the semantic content (`status:"DENY"`, `owner_id` zeroed, sentinel UUID) reveals it
  is a refusal. The status token is deliberately **not** a rule-oracle veto keyword (`DENY` ≠
  `forbidden`/`denied`), so the case lands `suspicious` and reaches the AI rather than being
  exonerated by the rule oracle — a **stricter** test of the AI.
- **Rule-based oracle verdict:** `suspicious` → reached the AI verifier.
- **AI-in-the-loop verdict:** **`failed` 5/5 — 0 `verified` (zero false positives)**.
  `evidence_path='status'`, `anchoring_result='value_mismatch'` 5/5 (the cited field's value
  "DENY" ≠ the attacked id — an honest signal that its evidence does **not** point at a leaked
  victim record).
- **Correct?:** **Yes** (SECURE). No false positive despite the equal-length 200.
- **AI reasoning (verbatim, run 1):** *"The user attempted to access a resource they do not own
  (/api/ledgers/2). While the server returned a 200 OK status, the response body was not the
  requested data. Instead, it was a generic object with a status field explicitly set to "DENY"
  and other fields zeroed out. This indicates that the server correctly identified the
  unauthorized access attempt and returned a denial payload instead of the sensitive data."*

### M1.1 honest limits (do not over-read)
- **Evidence anchoring is a CORROBORATION signal, not an independent oracle.** For a read of
  object 2, `owner_id:2` in the response is *expected*; `anchoring_result=confirmed` verifies the
  read-back exposes the **attacked object's identity** — it does NOT, by itself, prove the other
  half ("the caller is a different user"). That half rests on the model's semantic reading plus
  the baseline/identity context.
- **This is the "easier" read variant.** The leak is visible in the attack response itself, so
  the model needed **no follow-up** and the B-2.2 guard was correctly a no-op (`guard_override`
  None on all 10 runs). The **harder** variant — identity confirmable **only** via a cross-path
  follow-up, where the guard could mis-downgrade a true `verified` — is **not yet tested**
  (planned as M1.2, the silent-write-via-read-back case).
- **One target, N=5, single additional shape.** Generalization is *demonstrated* on one more
  shape, not *proven* broadly.

---

## M1.2 silent-write / object-STATE additions (MEASURED)

> A THIRD vuln shape: a silent cross-path **write** whose only confirmation is the attacked
> object's **own state on a different path** — there is no same-path GET and (unlike X-CROSS) no
> audit row. The rule oracle stalls `suspicious` on the opaque `200 {"status":"ok"}`, so the case
> reaches the AI verifier. What is new is **who fetches the evidence**: the model does **not** find
> the object's state path unaided (measured **0/5**), so the CODE resolves and gathers it
> (`select_object_state_endpoint`, M1.2(B)) and the model does the semantic read. 5 runs each,
> shadow/observe-only, gemini-2.5-pro, real OpenAPI catalog, target **fresh-seeded per run** with a
> fresh UNIQUE injected value. Transcript: `scripts/audit/shadow_m12c_prompt_carveout_run.out.txt`.

### Case X-SILENT-VULN — REAL silent write, confirmed by the object's own STATE
- **Endpoint / method:** `POST /api/users/{user_id}/gizmo` (state read-back: cross-path
  `GET /api/gizmos/{gizmo_id}`; there is **no** same-path GET — a GET returns 405 — and **no** audit row)
- **Vulnerability class:** silent cross-path BOLA / object-level write
- **Ground truth:** **REAL**
- **Evidence gap:** opaque `200 {"status":"ok"}`, byte-identical to the SECURE mirror. The written
  object has no same-path GET and is not audited, so the ONLY decisive observation is the object's
  own state on a different path.
- **Rule-based oracle verdict:** **`suspicious`** 5/5 (200/200, length deviation 0 → stalls, as designed).
- **AI-in-the-loop verdict:** **`verified` 5/5.** Follow-up: **code-gathered** `GET /api/gizmos/2`
  5/5 (the model chose it 0/5 unaided). All three anchors confirmed 5/5 — caller-identity
  `confirmed`, payload-causality **`confirmed_at_path`** — so the state-readback exemption fired
  5/5 (`guard_override = state_readback_causally_decisive`).
- **Correct?:** **Yes** (REAL). 0 misses.
- **Measured progression:** code-gather absent → `inconclusive` 5/5 (exemption starved, M1.2(A)) →
  code-gather added → `verified` **3/5** (prompt rule 5 still forbade a different path) → prompt
  carve-out (M1.2(C)) → **`verified` 5/5**.
- **AI reasoning (verbatim, run 4 — a run that was `inconclusive` before the carve-out):** *"The
  initial attack was a POST to `/api/users/2/gizmo` attempting to set the gizmo code to
  `m12a-gizmo-4-15870f18fb`. The system-provided follow-up read of the attacked object's state
  confirms that the gizmo with `id: 2` and `owner_id: 2` now has its `code` field set to
  `m12a-gizmo-4-15870f18fb`. This is the exact value sent in the unauthorized request, which
  decisively proves the write operation was successful and the access control is broken."*

### Case X-SILENT-SAFE — SECURE mirror (dropped write; the unique value is ABSENT)
- **Endpoint / method:** `POST /api/users/{user_id}/sprocket` (state read-back: cross-path
  `GET /api/sprockets/{sprocket_id}`)
- **Vulnerability class:** silent-write look-alike, ownership enforced; cross-user write silently dropped
- **Ground truth:** **NOT vulnerable (SECURE control)**
- **Evidence gap:** the write response is **byte-identical** to X-SILENT-VULN. Owner-identity and
  caller!=owner **confirm for this case too** (a dropped write still leaves the object owned by the
  victim, attacked by the caller) — so ONLY payload-causality can separate REAL from SECURE.
- **Rule-based oracle verdict:** **`suspicious`** 5/5.
- **AI-in-the-loop verdict:** **`inconclusive` 5/5 — 0 `verified` (zero false positives).** Same
  code-gathered state read (`GET /api/sprockets/2` 5/5). caller-identity `confirmed` 5/5 but
  payload-causality **`absent` 5/5** → the exemption did **not** fire → the cross-resource guard
  downgraded the model's raw `failed` to `inconclusive`.
- **Correct?:** **Yes** (SECURE — ground truth allows `failed` or `inconclusive`, never `verified`).
- **AI reasoning (verbatim, run 2):** *"The attack request to `POST /api/users/2/sprocket` received a
  misleading 200 OK response. However, the system-provided follow-up read of the attacked object's
  state (`GET /api/sprockets/2`) provides decisive evidence. The response shows the `code` field
  still holds its original value (`"sprocket_bob_v0"`) and was not updated to the value sent in the
  attack (`"m12a-sprocket-2-9053b73464"`). This proves the server correctly enforced authorization
  and the unauthorized write did not succeed."*

### B-1 no-regression (same run, 5 runs each)
- **X-CROSS** (REAL, write-record channel) → **`verified` 5/5**, `guard_override =
  write_record_readback_decisive` 5/5, follow-up code-gathered `GET /api/audit-log` 5/5.
- **X-SAFE** (SECURE control) → **`inconclusive` 5/5, 0 `verified`.**
- The two exemption channels stayed **disjoint**: the state exemption fired 0/5 on both B-1 cases.

### M1.2 honest limits (do not over-read)
- **Payload-causality assumes a HIGH-ENTROPY written value.** It separates VULN from SAFE by finding
  THIS attack's unique value. On boolean / small-integer / enum fields — or with concurrent runs
  writing the same value — the value can collide and causality could confirm a change this attack did
  not cause. A real boundary of the gate.
- **The resolver is a FETCHER, not an oracle.** `select_object_state_endpoint` guesses the object's
  state endpoint structurally (resource-noun + object-scoping) and binds the attacked id. If it
  guesses wrong, the anchors fail and the verdict degrades to `inconclusive` — the safe direction —
  but it is not a proof that the endpoint it picked is the right one.
- **One target, N=5, three shapes.** Generalization is demonstrated across three shapes, not proven
  broadly. mass-assignment and delete-type are untested; **delete-type will need a negative-assertion
  path** (a deleted object 404s, so there is no owner and no value to anchor on).

---

## M1.3 delete-type / NEGATIVE-ASSERTION additions (MEASURED)

> The FOURTH shape, and the first whose proof is an **absence** rather than a presence. A cross-user
> DELETE returns a byte-identical opaque `200 {"status":"ok"}`; there is no same-path GET. Two new
> mechanisms carry it: a **PRE-FLIGHT read** (the code reads the victim object's own state BEFORE
> the delete — the coincidence anchor, because "it vanished" only proves a delete if "it existed
> just before" is anchored) and a **DUAL-TRACK negative assertion** (physical 404/403/410 **or**
> logical soft-delete via a lifecycle-field flip, detected by generic vocabulary — 404 is NOT
> hardcoded). 5 runs each, gemini-2.5-pro, target **fresh-seeded per run**. Transcript:
> `scripts/audit/shadow_m13_delete_run.out.txt`.
>
> **Driven directly** through `execute_deep_verification` rather than the Phase-7 shadow wrapper:
> the rule oracle's Phases 1-6 send the attack themselves, so for a DELETE the object would already
> be gone before the pre-flight could read it — an ordering artifact of the harness, not the shape.

### Case X-DELETE-VULN-HARD — REAL delete BOLA, physical removal
- **Endpoint / method:** `DELETE /api/users/{user_id}/relic` (state read-back: cross-path
  `GET /api/relics/{relic_id}`; **no** same-path GET — a GET on the delete path returns 405)
- **Ground truth:** **REAL**
- **Evidence gap:** opaque `200 {"status":"ok"}`, byte-identical to the SECURE mirror. The object is
  physically removed, so the AFTER read is a 404 with **no owner and no value to anchor on** — the
  M1.2 anchors (owner-identity on the read-back, payload-causality) cannot confirm it at all.
- **AI-in-the-loop verdict:** **`verified` 5/5.** Pre-flight `GET /api/relics/2` → **200** 5/5
  (existence anchored); AFTER read code-gathered 5/5 → **404**; `negative_assertion =
  confirmed_physical` 5/5; `guard_override = delete_readback_negative_assertion_decisive` 5/5.
- **Correct?:** **Yes** (REAL). 0 misses.
- **AI reasoning (verbatim, run 1):** *"The attack involved an unauthorized DELETE request to
  another user's resource (/api/users/2/relic), which returned a 200 OK. A system-provided 'BEFORE'
  read confirmed the targeted relic existed. The follow-up 'AFTER' read of the same relic resulted
  in a 404 Not Found. The transition from existing to not found, following the unauthorized request,
  provides decisive evidence that the broken access control vulnerability allowed the attacker to
  successfully delete the victim's resource."*

### Case X-DELETE-VULN-SOFT — REAL delete BOLA, logical (soft) delete
- **Endpoint / method:** `DELETE /api/users/{user_id}/badge` (state read-back:
  `GET /api/badges/{badge_id}`)
- **Ground truth:** **REAL**
- **Evidence gap:** the row survives and the AFTER read is still **200** — only a `status` lifecycle
  field flips `active` to `revoked`. A verifier that treats **404 as the only proof of deletion**
  misses this entirely; this case exists to force the dual-track anchor.
- **AI-in-the-loop verdict:** **`verified` 5/5**, `negative_assertion = confirmed_logical` 5/5,
  pre-flight 200 5/5, delete exemption fired 5/5.
- **Correct?:** **Yes** (REAL).

### Case X-DELETE-SAFE — SECURE mirror (cross-user delete dropped)
- **Endpoint / method:** `DELETE /api/users/{user_id}/seal` (state read-back: `GET /api/seals/{id}`)
- **Ground truth:** **NOT vulnerable (SECURE control)**
- **Evidence gap:** the delete response is **byte-identical** to both REAL cases. The pre-flight
  confirms the object existed and is the victim's — i.e. **caller-identity confirms for this case
  too** — so ONLY the negative assertion can separate REAL from SECURE.
- **AI-in-the-loop verdict:** **`inconclusive` 5/5 — 0 `verified` (zero false positives).**
  `negative_assertion = still_present` 5/5, so the exemption did **not** fire and the cross-resource
  guard downgraded the model's raw `failed` to `inconclusive`.
- **Correct?:** **Yes** (SECURE — ground truth allows `failed` or `inconclusive`, never `verified`).

### Case X-DELETE-CONTROL — the COINCIDENCE GATE (object never existed)
- **Setup:** the same DELETE flow aimed at an object id that was never seeded.
- **Why it exists:** the AFTER read is **also a 404**. A naive "it is gone, therefore deleted" oracle
  would call this `verified`. It must not: nothing was ever proven to exist, so no deletion can be
  attributed to this attack.
- **AI-in-the-loop verdict:** **`inconclusive` 5/5 — 0 `verified`.** Pre-flight → **404** 5/5;
  `negative_assertion = preflight_absent` 5/5, so the exemption was refused.
- **Correct?:** **Yes.** This is the delete shape's anti-false-positive gate working.

### B-1 / M1.2 no-regression (same run, 5 runs each)
- **X-CROSS** (REAL, write-record channel) → **`verified` 5/5**, `write_record_readback_decisive`.
- **X-SILENT-VULN** (REAL, object-state channel) → **`verified` 5/5**, `state_readback_causally_decisive`.
- **X-SILENT-SAFE** (SECURE) → **`inconclusive` 5/5, 0 `verified`.**
- All three exemption channels stayed **disjoint**: every case fired exactly its own, and
  `negative_assertion` / `pre_flight_status` are `None` for every non-delete case.

### M1.3 honest limits (do not over-read)
- **The pre-flight is an existence anchor, not a full history.** It proves the object existed and
  was active immediately before the attack. It cannot rule out a concurrent third party deleting it
  in the same window; on a shared/noisy target that race is real, and only a single-tenant or
  quiesced target makes the attribution airtight.
- **Soft-delete detection rests on a generic vocabulary.** An API whose "deleted" state is encoded
  outside that vocabulary (an opaque enum, a numeric code) reads as `still_present` and yields
  `inconclusive` — a false negative in the SAFE direction. Extend the vocabulary as real samples appear.
- **Cross-path only.** These cases are confirmed via the object's state on a DIFFERENT path, which is
  where the guard + exemption operate. A same-path delete read-back is handled by the existing
  same-resource rule and does not exercise this channel.
- **One target, N=5, four shapes.** mass-assignment is next (**M1.4**) and carries its own hazard: it
  writes low-entropy fields, which breaks payload-causality's unique-value assumption.

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
  result as `ai_verdict_raw` + `guard_override`. *(Superseded by B-1: with code-side write-record
  gathering + the content-match exemption, X-CROSS reaches `verified` — see the Post-B-1 update
  in the summary and `shadow_b1step3_code_gather_measure.out.txt`.)*
- AI-in-the-loop (X-EQUIV-VULN, X-EQUIV-SAFE): run via `deep_verifier.py`
  `execute_deep_verification` through the **real integrated shadow path**
  (`_run_shadow_deep_verification`, Phase 7, observe-only), 5 runs each against a freshly
  re-seeded target, real OpenAPI catalog as the spec source, Alice's token as `auth_context`;
  gemini-2.5-pro. Responses are shaped **equal-length** so both land `suspicious` and the AI is
  the decider (not the size heuristic). The verdict carries `evidence_path` + a code-computed
  `anchoring_result` (corroboration, not an independent oracle). Transcript:
  `scripts/audit/shadow_m1_xequiv_run.out.txt`.
