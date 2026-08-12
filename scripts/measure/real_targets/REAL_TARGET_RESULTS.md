# Real-Target Result Matrix

Live measurement of the Aivist Verify engine against third-party public vulnerable targets.
Every verdict below is recorded verbatim (raw output files alongside this doc), including
[REFUTED], [NOT DATA], false positives, and misses. **The engine was not tuned to make any
target pass.** Runs use the non-interactive `aivist run --config` path (env tokens → structured
JSON); the `tier` field maps to the human verdict badge: `confirmed`→`[CONFIRMED]`,
`refuted`→`[REFUTED]`, `notdata`→`[NOT DATA]`, and `broken_for_all`→`[INCONCLUSIVE]` (the renderer
prints the badge as `[INCONCLUSIVE]  <shape> - <METHOD> <path>`; the broken-for-all framing and the
"human review" wording appear in the body lines beneath it, not in the badge itself). Below, the
shorthand "[INCONCLUSIVE broken-for-all]" is a DESCRIPTION of that tier, never a quote of CLI output.

Model: `gemini-2.5-pro`. Run dates: 2026-08-12 (UTC) — VAmPI + crAPI community/orders in the first
session, crAPI `mechanic_report` in a second session the same day (see the session note under TARGET 2).

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
- **This is a genuine limitation to state plainly:** by default (with a bystander), the D30 public-resource gate **misses** VAmPI's documented `/books` BOLA — because "readable by every authenticated user" is, black-box, indistinguishable from "shared by design." The *correct* way to catch a broken-for-all BOLA with this tool is the owner-only assertion **plus a bystander token** (`--assert-owner-only` on `scan`, or `"assert_owner_only": true` on a `run --config` op) — the assertion on its own is inert, because the disclosure path only runs after the bystander probe has shown that a third identity can read the object. It flags the finding for human review rather than confirming it.
- No run degraded — VAmPI's 60-second JWT expiry did not bite (each verify finished well under 60 s).

---

## TARGET 2 — crAPI

- **Version:** official OWASP crAPI docker-compose, `VERSION=latest`. Pulled digests:
  `crapi-identity@sha256:5d1db5b3…`, `crapi-community@sha256:8ba0c7ed…`, `crapi-workshop@sha256:d4d2d94d…`,
  `crapi-web@sha256:b27d246c…`, `gateway-service@sha256:97dade9d…` (+ mongo:4.4, postgres:14, chroma).
  Gateway on `http://localhost:8888`; mailhog on `:8025`. All core services Healthy.
- **Setup:** signed up + logged in three users `attacker@crapi.io` / `owner@crapi.io` / `bystander@crapi.io`
  (password `Crapi@1234`). crAPI JWTs are long-lived (no expiry issue). Created real resources per endpoint.

> **Session note — `mechanic_report` was measured in a SECOND session, on a FRESH database state.**
> The `mechanic_report` rows below did **not** continue the first session. When that endpoint was
> re-attempted, the crAPI stack had been torn down and brought back up, and the first session's
> `@crapi.io` accounts were **no longer in the database** (the persisted volume held a different set of
> users). Same target, same image digests, same `VERSION=latest` — but a **new** run with **new**
> accounts (`mrAtk…@crapi.io` / `mrOwn…@crapi.io` / `mrBys…@crapi.io`) and new resources. It is
> recorded as a new run, not as a resumed one. The community-post, orders, `/books` and `/users` rows
> are untouched first-session results.

### Results

| Endpoint | Config | What it should be (ground truth + source) | Verdict recorded | Correct? | Raw file |
|---|---|---|---|---|---|
| `GET /community/api/v2/community/posts/{postId}` | attacker+owner+bystander | **PUBLIC community feed** — every user sees every post by design; reading another's post is NOT a violation. (This is the endpoint that produced the **D30 false positive** in the prior session; the D30 fix was only fixture-validated → live re-confirmation was pending.) | **[REFUTED]** `inconclusive` (`guard_override=public_resource_read_not_cross_user`) | **Correct (true negative)** — ✅ **THE PENDING D30 LIVE RE-CONFIRMATION PASSES**: the false positive is fixed on the real target | `crapi_community-post_D30_20260812_154703.txt` |
| `GET /workshop/api/shop/orders/{order_id}` | attacker+owner+bystander | **NOT a cross-user BOLA — fully public / missing auth.** ⚠️ **Corrected 2026-08-12, see the note below.** The endpoint requires **no token at all**: an anonymous request returns the complete owner order (email, phone, `transaction_id`, partial card number). It is an *unauthenticated data exposure*, out of this tool's BOLA scope — the same class as VAmPI `/users`, not the same class as VAmPI `/books`. | **[REFUTED]** `inconclusive` (`guard_override=public_resource_read_not_cross_user`) | **Correct (true negative)** — the tool does not mislabel a public endpoint as a cross-user BOLA | `crapi_shop-orders_20260812_154834.txt` |
| `GET /workshop/api/mechanic/mechanic_report?report_id=` | attacker+owner, **no bystander** | **REAL BOLA** — crAPI docs list BOLA on mechanic_report (**query-string** id). Ground truth re-established by hand before the engine ran: the attacker read the owner's report → HTTP 200 disclosing the owner's email, phone, VIN `7R5XWJ6HCY2FJUR03` and the private work-order text. | **[CONFIRMED]** `verified` (`owner_view_corroborated=true`, `guard_override=null`) | **True positive** — the attacker really read the victim's private work order across accounts | `crapi_mechanic-report_no-bystander_20260812_163905.txt` |
| `GET /workshop/api/mechanic/mechanic_report?report_id=` | attacker+owner+**bystander** | same BOLA — but the endpoint is broken-for-all (the bystander also read the owner's `report_id` → HTTP 200) | **[REFUTED]** `inconclusive` (`guard_override=public_resource_read_not_cross_user`) | **Miss (by design)** — the same D30 tradeoff as VAmPI `/books` and crAPI `/shop/orders` | `crapi_mechanic-report_with-bystander_20260812_163928.txt` |
| `GET /workshop/api/mechanic/mechanic_report?report_id=` | attacker+owner+bystander **+`assert_owner_only`** | same BOLA — operator asserts the work order should be owner-private | **`broken_for_all` tier** — `inconclusive` (`guard_override=broken_for_all_owner_assertion_human_review`, `broken_for_all_suspected=true`) | **Correct handling** — engine logged the anonymous probe as a clean denial (`anon_status=401 reason='non_2xx:401'`) and LOCKED the verdict inconclusive for human review; never confirmed | `crapi_mechanic-report_assert-owner-only_20260812_163948.txt` |

**mechanic_report — measured, and what it took (honest).** The first session recorded this endpoint as
**NOT MEASURED (setup-blocked)**; it has now been run. Both blockers were **target-environment problems,
not engine limits**, and neither required any change to Aivist Verify:

1. **The VIN/pincode source.** The engine's D24 owner-view gate needs the **report owner's** token to
   corroborate a confirm, so the report must belong to a credential-controlled user. That needs crAPI's
   vehicle-claim → `contact_mechanic` flow, which needs a VIN + pincode normally delivered by the signup
   welcome email — and this deployment's mailhog delivered **empty bodies**. **Worked around by reading
   the pincode directly out of crAPI's own `vehicle_details` table** (unclaimed vehicles sit in a pool
   with their pincodes in plaintext), then claiming the vehicle through the **real `add_vehicle` API**
   exactly as a user would. **This is target-environment setup, not engine behaviour** — a reproducer
   who gets working welcome emails will not need the database step, and the database was read only to
   obtain a credential crAPI intended to mail to its own user.
2. **`contact_mechanic` requires https.** crAPI's own OpenAPI example gives the callback as
   `mechanic_api: http://localhost:8000/workshop/api/mechanic/receive_report`, but this deployment runs
   with `TLS_ENABLED=true`, so the workshop service serves **HTTPS** on port 8000 and every `http://`
   callback fails with `400 {"message":"Could not connect to mechanic api."}`. Using
   `https://localhost:8000/...` succeeds. This blocker was **not** diagnosed in the first session — even
   with a valid VIN, the earlier attempt would still have failed here.

**Query-string coverage.** `mechanic_report` carries its object id in the **query string**
(`?report_id=`), not in the path. These three runs therefore extend the archive to the query-param id
path (`build_op` → `location: "query_param"`); the earlier VAmPI/crAPI runs all exercised path-segment
ids only.

The first session's manual observation of the seed report (`report_id=1`, owned by `robot001@example.com`)
is kept alongside as `crapi_mechanic-report_MANUAL_setup-blocked_20260812_155237.txt` — the record of the
block, not of a verdict.

> **⚠️ CORRECTION (2026-08-12, second session) — `/shop/orders` was mis-annotated as a BOLA.**
> The first session's row for `GET /workshop/api/shop/orders/{order_id}` described the endpoint as
> "**REAL BOLA** … Auth-required … but broken-for-all." **That ground-truth annotation was wrong.** While
> the crAPI stack was still up for the `mechanic_report` runs, the endpoint was re-probed directly:
> an **anonymous request with no `Authorization` header returns HTTP 200 with the full owner order**
> (verified on two separate order ids). So it is **fully public / missing authentication**, not a
> cross-user BOLA at all, and it is **out of scope** for a BOLA confirmer — the same class as VAmPI
> `/users`. The first session's hand-verification only compared *authenticated* identities and never
> issued an anonymous probe, which is how the mislabel survived.
>
> **What does NOT change:** the engine's recorded verdict, `[REFUTED]` /
> `public_resource_read_not_cross_user`, was and remains **correct** — and is now correct for an even
> more clear-cut reason. The archived capture is untouched.
>
> **What DOES change:** `/shop/orders` must **not** be cited as an example of a real BOLA the tool
> misses. The genuine broken-for-all misses, both with an archived clean **anonymous 401** proving the
> resource is not public, are **VAmPI `/books`** and **crAPI `mechanic_report`**. This also matches what
> [`../../../docs/AUDIT.md`](../../../docs/AUDIT.md) and [`../../../docs/ROADMAP.md`](../../../docs/ROADMAP.md)
> already recorded ("that endpoint is fully public / missing-auth"); this file was the outlier.

---

## Bottom line (honest)

- **The single most important run passed:** the crAPI **community-post D30 false positive is fixed on the live target** — [REFUTED] as public, not a spurious [CONFIRMED]. The previously fixture-only validation now holds live.
- **The tool produced ZERO false positives across all 9 completed engine runs** (6 in the first session + 3 `mechanic_report` runs in the second) — no public/shared resource was ever confirmed as a cross-user BOLA.
- **The dominant limitation, measured on two real targets:** the D30 public-resource gate **misses genuine broken-for-all BOLAs** — **VAmPI `/books`** (secret disclosure) and **crAPI `mechanic_report`** (email, phone, VIN, private work-order text) are real, serious BOLAs that the tool **[REFUTED]** once a bystander token is supplied, because "readable by every authenticated user" is black-box-indistinguishable from "shared by design." Both are genuinely broken-for-all rather than public: each has an archived **anonymous probe cleanly denied with 401**. The way to surface these is the owner-only assertion — `--assert-owner-only` on `scan`, or `"assert_owner_only": true` on a `run --config` op — **together with a bystander token** (the assertion alone is inert: the disclosure path only runs after the bystander probe has established that a third identity can read the object). It then reports them as the `broken_for_all` tier — inconclusive, flagged for human review — rather than confirming them. Demonstrated live on **both** targets. (crAPI `/shop/orders` is **not** an example of this limitation — it is public / missing-auth, see the correction above.)
- **Clean cross-user BOLA (attacker+owner, no bystander): confirmed on BOTH targets** — VAmPI `/books` and crAPI `mechanic_report`, each **[CONFIRMED]** `verified` through the D24 owner-view channel. Neither endpoint is a *private-by-design* resource: both are **broken-for-all**, so on both targets the verdict is **config-dependent in exactly the same way** — `verified` with two accounts, `[REFUTED]` as public the moment a bystander is supplied, and `broken_for_all` / human review when the operator asserts owner-privacy. crAPI's remaining endpoints are both correctly refuted for the same reason — they are not cross-user resources at all (community post = public by design; `/shop/orders` = public / missing auth).
- **No engine tuning, no retries-until-green.** Every verdict is the first/only run, archived verbatim.

---

## Known BOLAs NOT covered this session

- **crAPI GraphQL / multi-step BOLAs** (e.g. the coupon/GraphQL flows) — the engine confirms a
  single REST operation with a path/query id swap; GraphQL and multi-request business flows are
  out of scope for this run.
- **VAmPI write-side issues** — mass-assignment on register (`admin:true`), `PUT /users/v1/{username}/email|password`,
  unauthenticated `GET /users/v1/_debug` (all-passwords dump), and JWT weaknesses — not object-read
  BOLAs, not probed here.
