# Real-Target Result Matrix

Live measurement of the Aivist Verify engine against third-party public vulnerable targets.
Every verdict below is recorded verbatim (raw output files alongside this doc), including
[REFUTED], [NOT DATA], false positives, and misses. **The engine was not tuned to make any
target pass.** Runs use the non-interactive `aivist run --config` path (env tokens → structured
JSON); the `tier` field maps to the human verdict badge: `confirmed`→[CONFIRMED],
`refuted`→[REFUTED], `broken_for_all`→[INCONCLUSIVE broken-for-all], `notdata`→[NOT DATA].

Model: `gemini-2.5-pro`. Run date: 2026-08-12 (UTC).

---

## TARGET 1 — VAmPI

- **Image:** `erev0s/vampi:latest` @ `sha256:0a5a224b6e14ae7da6a6ea265178ff71286ff903aec74adee98f660bb0e4ca12`
- **Setup:** `GET /createdb` → seeded users `name1/pass1`, `name2/pass2`, `admin/pass1`; I registered `name3/pass3` (bystander). Created two books with a genuine owner→resource relationship:
  - `attacker_book_a1` — owner **name1**, secret `ATTACKER-SECRET-a1`
  - `victim_book_b2` — owner **name2**, secret `VICTIM-SECRET-b2-ownedbyname2`
- **Manual BOLA confirmation (ground truth):** `name1` (attacker) `GET /books/v1/victim_book_b2` → HTTP 200 `{"book_title":"victim_book_b2","owner":"name2","secret":"VICTIM-SECRET-b2-ownedbyname2"}` — the attacker reads the victim's book + secret. **The endpoint has no ownership check at all: every authenticated user can read every book (broken-for-all).** An anonymous request is 401.

### Results

| Endpoint | Config | What it should be (ground truth + source) | Verdict recorded | Correct? | Raw file |
|---|---|---|---|---|---|
| `GET /books/v1/{book_title}` | attacker+owner, **no bystander** | REAL BOLA — books are owner-private (secret); VAmPI docs list **BOLA** here (erev0s/VAmPI README "Vulnerabilities" → *Broken Object Level Authorization*) | **[CONFIRMED]** `verified` (`owner_view_corroborated=true`, `guard_override=null`) | **True positive** — attacker really read the victim's private book across accounts | `vampi_books-bola_no-bystander_20260812_153710.txt` |
| `GET /books/v1/{book_title}` | attacker+owner+**bystander** | same BOLA — but the endpoint is broken-for-all | **[REFUTED]** `inconclusive` (`guard_override=public_resource_read_not_cross_user`) | **Miss (by design)** — the bystander (name3) can also read it, so the D30 gate treats it as public/shared and declines to confirm | `vampi_books-bola_with-bystander_20260812_153618.txt` |
| `GET /books/v1/{book_title}` | attacker+owner+bystander **+`assert_owner_only`** | same BOLA — operator asserts the resource should be owner-private | **[INCONCLUSIVE broken-for-all]** (`guard_override=broken_for_all_owner_assertion_human_review`, `broken_for_all_suspected=true`) | **Correct handling** — engine logged: *"every AUTHENTICATED principal read this resource, but an anonymous request did NOT (401) … LOCKED inconclusive; surfaced as a CONDITIONAL finding for HUMAN REVIEW (never confirmed)"* | `vampi_books-bola_assert-owner-only_20260812_153756.txt` |
| `GET /users/v1/{username}` | attacker+owner+bystander | **NOT a cross-user BOLA** — endpoint is **public / no-auth** (returns `{username,email}` with no token, HTTP 200). It is an *unauthenticated data-exposure* (out of this tool's BOLA scope). | **[REFUTED]** `inconclusive` (`guard_override=public_resource_read_not_cross_user`) | **Correct (true negative)** — the tool does not mislabel a public endpoint as a cross-user BOLA | `vampi_users-getuser_20260812_153932.txt` |

### VAmPI takeaways (honest)

- **The `/books` BOLA is real but broken-for-all.** The engine's verdict is config-dependent: it **CONFIRMS** with two accounts, **REFUTES as public** the moment a bystander is supplied, and surfaces **[broken-for-all / human review]** when the operator asserts owner-privacy.
- **This is a genuine limitation to state plainly:** by default (with a bystander), the D30 public-resource gate **misses** VAmPI's documented `/books` BOLA — because "readable by every authenticated user" is, black-box, indistinguishable from "shared by design." The *correct* way to catch a broken-for-all BOLA with this tool is `--assert-owner-only`, which flags it for human review rather than confirming it.
- No run degraded — VAmPI's 60-second JWT expiry did not bite (each verify finished well under 60 s).

---

## TARGET 2 — crAPI

- **Version:** official OWASP crAPI docker-compose, `VERSION=latest`. Pulled digests:
  `crapi-identity@sha256:5d1db5b3…`, `crapi-community@sha256:8ba0c7ed…`, `crapi-workshop@sha256:d4d2d94d…`,
  `crapi-web@sha256:b27d246c…`, `gateway-service@sha256:97dade9d…` (+ mongo:4.4, postgres:14, chroma).
  Gateway on `http://localhost:8888`; mailhog on `:8025`. All core services Healthy.
- **Setup:** signed up + logged in three users `attacker@crapi.io` / `owner@crapi.io` / `bystander@crapi.io`
  (password `Crapi@1234`). crAPI JWTs are long-lived (no expiry issue). Created real resources per endpoint.

### Results

| Endpoint | Config | What it should be (ground truth + source) | Verdict recorded | Correct? | Raw file |
|---|---|---|---|---|---|
| `GET /community/api/v2/community/posts/{postId}` | attacker+owner+bystander | **PUBLIC community feed** — every user sees every post by design; reading another's post is NOT a violation. (This is the endpoint that produced the **D30 false positive** in the prior session; the D30 fix was only fixture-validated → live re-confirmation was pending.) | **[REFUTED]** `inconclusive` (`guard_override=public_resource_read_not_cross_user`) | **Correct (true negative)** — ✅ **THE PENDING D30 LIVE RE-CONFIRMATION PASSES**: the false positive is fixed on the real target | `crapi_community-post_D30_20260812_154703.txt` |
| `GET /workshop/api/shop/orders/{order_id}` | attacker+owner+bystander | **REAL BOLA** — crAPI docs list BOLA on orders. Auth-required; the attack response leaked the owner's **email + partial card number** (`XXXXXXXXXXXX6374`, MasterCard) + transaction id. But it is **broken-for-all** (the bystander also read order #6 → HTTP 200). | **[REFUTED]** `inconclusive` (`guard_override=public_resource_read_not_cross_user`) | **Miss (by design)** — a real, sensitive BOLA the tool does **not** confirm because it's readable by every authenticated user (same D30 tradeoff as VAmPI books) | `crapi_shop-orders_20260812_154834.txt` |
| `GET /workshop/api/mechanic/mechanic_report?report_id=` | — (engine run **not** completed) | **REAL BOLA** — crAPI docs list BOLA on mechanic_report (query-string id). Manually confirmed present: `owner@crapi.io` (a non-owner) read seed `report_id=1` → HTTP 200, obtaining `robot001@example.com`'s vehicle report (VIN `0NKPZ09IHOP508673`, phone, problem details). | **NOT MEASURED** (setup-blocked) | n/a — see note | `crapi_mechanic-report_MANUAL_setup-blocked_20260812_155237.txt` |

**mechanic_report — why not measured (honest):** the engine's D24 owner-view gate needs the **report owner's** token to corroborate a confirm. crAPI's readable report (`report_id=1`) is owned by seed user `robot001@example.com` (no credentials available), and creating a report owned by a credential-controlled user requires crAPI's vehicle-claim → `contact_mechanic` flow — which needs a VIN/pincode that the seeded welcome emails (mailhog) did **not** contain (empty bodies). So a clean owner-corroborated run was not completable this session. The BOLA is present; the engine confirmation is pending a proper report-owner setup. (Prior session had it **[CONFIRMED]** after the D29 fix, with a controlled owner.)

---

## Bottom line (honest)

- **The single most important run passed:** the crAPI **community-post D30 false positive is fixed on the live target** — [REFUTED] as public, not a spurious [CONFIRMED]. The previously fixture-only validation now holds live.
- **The tool produced ZERO false positives across all 6 completed engine runs** — no public/shared resource was ever confirmed as a cross-user BOLA.
- **The dominant limitation, measured on two real targets:** the D30 public-resource gate **misses genuine broken-for-all BOLAs** — VAmPI `/books` (secret disclosure) and crAPI `/shop/orders` (email + partial card-number disclosure) are both real, serious BOLAs that the tool **[REFUTED]** by default, because "readable by every authenticated user" is black-box-indistinguishable from "shared by design." The correct way to surface these is `--assert-owner-only`, which flags them as **[INCONCLUSIVE broken-for-all / human review]** (demonstrated on VAmPI) rather than confirming them.
- **Clean private cross-user BOLA (attacker+owner, no bystander):** confirmed on VAmPI `/books` ([CONFIRMED] verified). No crAPI endpoint tested here was a *private* cross-user resource (community = public; orders/mechanic_report = broken-for-all), so no crAPI [CONFIRMED] was produced — consistent with the prior session's "crAPI did not yield a clean cross-user BOLA headline."
- **No engine tuning, no retries-until-green.** Every verdict is the first/only run, archived verbatim.

---

## Known BOLAs NOT covered this session

- **crAPI GraphQL / multi-step BOLAs** (e.g. the coupon/GraphQL flows) — the engine confirms a
  single REST operation with a path/query id swap; GraphQL and multi-request business flows are
  out of scope for this run.
- **VAmPI write-side issues** — mass-assignment on register (`admin:true`), `PUT /users/v1/{username}/email|password`,
  unauthenticated `GET /users/v1/_debug` (all-passwords dump), and JWT weaknesses — not object-read
  BOLAs, not probed here.
