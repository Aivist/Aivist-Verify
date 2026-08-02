# ROADMAP (HUMAN-OWNED)

## Where we are (quick anchor)

- **Main axis:** make the engine usable against progressively more real targets, up to publication.
- **Done along the axis (verified against code 2026-08-02):** engine core (5 vuln shapes, dual-lab
  GOLDEN 430/430, 0 FP); CLI confirmer (spine + plain-language/color presentation pass); operator
  front door (`pip install -e .` → `lanivist`, `lanivist config` + relay/中转站 support, per-user
  config source); external real-target path (`lanivist verify --target/--spec/--op`, three red lines)
  — **live-confirmed a real BOLA against VAmPI** (unfamiliar third-party target; an engineering signal,
  **not** a zero-FP claim); YAML `--spec` support.
- **Current station:** real-target coverage — just added YAML spec support.
- **Next station:** multi-step auth (auto-relogin / token refresh, narrow scope) — VAmPI's 60-second
  token TTL exposed the static-token ceiling. **Slow-lane: plan-first, signed-off** (it touches auth +
  attacker/owner identity isolation), NOT an auto batch.
- Full **DONE / NEXT / PLANNED / DEFERRED / REJECTED** detail is in the **§0 status board** just below.

> The single source of truth for what this project is, what it is not, and where it's going.
> Anchored on code reality, not aspiration. If a claim here drifts from code, the code wins —
> update this file. Future nodes (human or AI): read this before proposing direction.
>
> **Reading order for the doc set:** this file (why / where) → [`PROJECT_OVERVIEW.md`](./PROJECT_OVERVIEW.md)
> (what exists now + run/verify) → [`ARCHITECTURE.md`](./ARCHITECTURE.md) (how it's built)
> → component docs ([`VERIFY_ENGINE.md`](./VERIFY_ENGINE.md), [`DEEP_VERIFY.md`](./DEEP_VERIFY.md), …)
> → [`TECH_DEBT.md`](./TECH_DEBT.md) (known gaps & priorities).

## 0. Status board — authoritative done / next / planned / deferred / rejected

> **This board is the single authoritative answer** to "what's done, what's next, what's deferred,
> what's rejected." It owns **status, ordering, and decisions**; **code facts** (test counts, shipped
> modules, commit hashes) live in [`STATUS.md`](./STATUS.md). Every `DONE` below was **re-verified
> against the repo on 2026-08-02** (backend suite = **507 passed**; the external-path commit
> **`c0956d0`** confirmed against its touched files). Sections §1–§8 below are the detailed rationale
> the board summarizes; the tags here win for status.

### ✅ DONE (re-verified against code)
Engine-side (detail in §3/§4 and [`STATUS.md`](./STATUS.md)): **M1 complete** — five vuln shapes,
0 FP on the GOLDEN two-target record; **D21** (declared spec field); **D24** (read-semantic owner-view
gate); **D19** promotion (default OFF, acceptance-passed); **scope-lock hardening** (one audited
`ScopePolicy`); **provider abstraction** (Gemini / OpenAI-compatible / Anthropic).

Operator front door (this node's line — all re-verified 2026-08-02):
- **CLI confirmer spine** (`run.py`) — reuses the existing `execute_deep_verification` path; verdict
  read only from `final_verdict`/`ai_verdict`.
- **Presentation pass** — plain-language channel/anchor translation + ANSI color + confirmed/refuted
  tally (`confirm_render.py`; no `rich` dependency).
- **Console entry point** — `pip install -e .` → `lanivist verify` / `lanivist config`
  (`pyproject.toml` → `run:main`); `python run.py` still works.
- **Config flow + relay/中转站 support** — `lanivist config` writes `~/.<brand>/config.toml` (0600),
  masked key entry; relays ride the existing `openai` provider via `base_url`.
- **`config.py` user-config source** — per-user TOML source **below env/.env**, above defaults;
  fail-safe, `SecretStr` key, no default/flag change.
- **External real-target verify path** — `--target/--spec/--op` assembling into the same engine call;
  **three red lines** (scope fail-closed from `--target`; attacker/owner identity isolation; `SecretStr`
  tokens redacted); commit **`c0956d0`**. A real BOLA was **live-confirmed on VAmPI** (unfamiliar
  third-party target) as an **engineering signal, NOT a zero-FP claim** (real targets have no ground truth).
- **`API_HOST` default → `127.0.0.1` (loopback)** — safe-by-default bind; set `API_HOST=0.0.0.0` to
  expose (env/.env still override). Commit **`da05351`** ([`TECH_DEBT.md`](./TECH_DEBT.md) D26). Was
  the pre-release "API_HOST → 127.0.0.1" item.

### ▶️ NEXT (one item)
- **YAML spec support** — `external_verify._load_json` should also accept `.yml`/`.yaml` so targets that
  ship **only** a YAML OpenAPI are usable. VAmPI exposed this: feeding its `openapi_specs/openapi3.yml`
  produced `[NOT DATA] could not read --spec / --op: JSONDecodeError: Expecting value: line 1 column 1`.
  (Workaround today: fetch a served JSON spec, e.g. connexion's `/openapi.json`.)

### 📋 PLANNED (ordered)
1. **Multi-step auth / auto-login token acquisition** — VAmPI's 60-second token TTL exposed the
   static-token ceiling (a token can expire mid-run → NOT DATA). Acquire/refresh tokens via a login
   flow. *(DISTINCT from item 9 — that is request-sequence orchestration, not login; different work.)*
2. **Remote arbitrary targets + full SSRF / DNS-rebinding / rate-limit hardening** — beyond localhost.
   *(Subsumes the "WAF circuit-breaker": detect a WAF/rate-limiter has started blocking and stop rather
   than hammering the target and poisoning verdicts — same rate-limit-hardening work, one item.)*
3. **Passive endpoint discovery (proxy radar)** — feed observed flows into the catalog. *(This is the
   open half of **D18** "automated attack-surface discovery" ≡ the `catalog_from_har` stub,
   `backend/app/services/endpoint_catalog.py:154` — one item, not three.)*
4. **Live crAPI acceptance run** — the Docker-based target, pending a machine that can run it.
5. **Frontend — the product UI.** *(Subsumes **D5**: retire the divergent Vite `frontend/`
   (`docs/TECH_DEBT.md:67`) — likely the same work as building the product UI; director ruling: PLANNED.)*
6. **README (dual positioning) + comparison report** — this engine's verification vs a detection-side tool.
7. **GitHub publication + promotion.**
8. **Umbrella brand name finalization** — `lanivist` is a provisional placeholder (single constant
   `BRAND_NAME`); the `verify` suffix is locked.
9. **Multi-step request-sequence orchestration (M2)** — the engine composing a sequence like "user A
   creates → user B reads" to set up and confirm a cross-actor access-control bug. *(DISTINCT from
   item 1 — this is request orchestration, not authentication. M2 phase; see §7 strategic (b).)*
10. **A second *measured* model** — the zero-FP evidence is measured on **gemini-2.5-pro only**;
    non-Gemini SAFE-case (false-positive) behavior is **unvalidated** (the provider seam gives
    connectivity, not a correctness/zero-FP guarantee). See §4 / [`LLM_PROVIDERS.md`](./LLM_PROVIDERS.md).

### ⏸️ DEFERRED (with trigger)
- **D2 — no authentication/authorization on any API route** (`docs/TECH_DEBT.md:38`) — acceptable for
  **local, single-tenant** use. **Distinct from the REJECTED multi-tenant/SaaS item** (that is a
  scaling model; this is a local-security gap). **Interaction:** it mattered more while the host default
  was `0.0.0.0`; it is now **mitigated (not closed) by the loopback `API_HOST` default** (commit
  `da05351`, D26) — still no auth. *Trigger:* before any shared / hosted / non-localhost deployment.
- **Internal Python module rename** (`backend.app…` imports) — high churn, low user value. *Trigger:*
  before real users / formal packaging.
- **`run.py` vs `backend/run.py` top-level module-name collision** — both are importable as top-level
  `run` (CLI entry vs uvicorn launcher); the installed entry point resolves correctly today (verified),
  but it is a latent footgun (pytest needs a path-import workaround). **Now filed as
  [`TECH_DEBT.md`](./TECH_DEBT.md) D27.** *Trigger:* must-fix before formal packaging.
- **flash→pro default correction** — `GEMINI_PRO_MODEL` defaults to `"gemini-2.5-flash"`
  (`backend/app/core/config.py`), a name/value mismatch. *Trigger:* before it misleads a user/model choice.
- **`Reproduce`-line auth placeholder + filled `$UNIQUE` value** — the CLI's Reproduce line prints the
  `$UNIQUE` template and no redacted auth placeholder (CLI_ORIENTATION "open observations").
- **Two UI tails** — the dead nuclei button and the `.agents` skills. *Trigger:* frontend cleanup.
- **Chinese → English pass** — mixed-language docs/comments (and the Chinese hunter prompt, which is a
  functional change requiring re-validation, kept separate).
- **D1 — no Alembic migrations** (`docs/TECH_DEBT.md:28`) — a startup schema-guard exists; a schema
  change means recreating / repointing the DB by hand. *Trigger:* if schemas start churning.
- **D25 — DNS-TOCTOU IP-pinning follow-up** (`docs/TECH_DEBT.md:829`) — a known scope-lock **residual**:
  the resolved-IP guard resolves+validates before the request, but httpx re-resolves at connect time
  (a small time-of-check-to-time-of-use window); httpx has no clean resolver hook. *Trigger:* hardening
  before untrusted remote rebinding scenarios.
- **D24 — three open read-gate boundaries** (`docs/TECH_DEBT.md:426`), listed explicitly so they are not
  lost: (a) **public / shared resources** legitimately return the same content to both identities, so the
  downgrade-only owner-view gate permits them (no upstream exclusion); (b) **owner credentials are
  per-DEPLOYMENT, not per-finding** (≡ the roadmap's "per-finding ownership baseline" — one item; a real
  target whose findings belong to different owners would need per-finding creds, which do not exist); (c)
  the **`0.95` read-gate threshold** is calibrated on deterministic lab data / raw bodies and is
  **unvalidated against real-target volatility**. *Trigger:* real-target read-semantic use.
- **D10–D17 cluster** (`docs/TECH_DEBT.md:114-168`) — single-table inheritance (D10), single-host batch
  (D11), global `verify=False` TLS (D13), proxy Tier-1 scope drop (D14), mitmproxy CA trust (D15),
  mitmproxy-forced dep pins (D16), internal-ingest loopback guard (D17). **Intentional / low-priority
  per TECH_DEBT** — parked, no action now.

### ❌ REJECTED (reason — do NOT re-litigate without new evidence)
- **Multi-tenant / Postgres / SaaS** — conflicts with the single-tenant, local verification
  differentiation; scaling before the moat is proven is the wrong order.
- **Code-patch generator** — black-box, no source; a patch cannot be sent-and-proven, so it imports
  exactly the hallucination risk the whole verification discipline exists to avoid. Remediation stays
  non-code guidance.
- **WAF-bypass / offensive scanner** — red-ocean, and there is no ground truth on real targets to make
  such output trustworthy.
- **Chasing zero-FP via probability / a stronger model / multi-round reflection** — only a
  **deterministic code gate** reaches zero. Measured: the model chose the decisive evidence **0/20**
  unaided; more model or more rounds adds cost and hallucination surface, not zero-FP.
- **"Zero-credential full auto"** — logically impossible (the engine needs **two real identities** to
  prove a cross-user effect) and against the authorized-target ethic.

### 🧭 STRATEGIC NOTE (informs where to deepen — NOT a to-do)
The **target-agnostic owner-view differential gate** (D24) is the **portable moat**: on VAmPI (an
unfamiliar schema whose object identity is a username **string**, not a numeric id) it **carried the
confirmation** (`owner_view_corroborated=True`). The **id-shaped anchors** (M1.1/M1.2 caller-identity /
evidence-anchoring) proved **less portable** there — they read `owner_not_found` / `value_mismatch` and
were observe-only, doing no work. Implication: deepen toward the **owner-view differential and
business-context** confirmation, not more id-shaped anchors; and the README positioning should
**emphasize the portable owner-view confirmation**, not the id-anchors. (See also §7 strategic (a)/(b).)

> **Not yet board-tagged (recorded in §7, pending a director ruling — no status assigned):** the
> 2-minute "magic demo" + recorded HAR sample; `run_in_executor` for the similarity compute; the
> **UUID wall** (let the user supply the victim's alternative IDs); M2's full resource/dependency
> graph; and strategic (a) "depth ≠ more shapes, go toward business-context complexity". These stay in
> §7 as written; they are listed here only so they are not lost.

---

## 1. What this is (the thesis)

An **access-control vulnerability verification engine** for web apps / APIs. It does not
merely flag a possible BOLA/IDOR (every scanner does that, with heavy false positives); it
actively **confirms** whether a candidate is a real, exploitable access-control bug or a
safe look-alike, and produces a verdict backed by reproducible evidence
(`verified` / `failed` / `inconclusive` / `suspicious`).

The **moat is the verification layer.** Detection (flip an object ID) is commodity. The hard,
valuable, human-punted step is confirmation — knowing whether a `200 {"status":"ok"}` actually
changed/leaked another user's state. Everything else (proxy capture, endpoint discovery, fuzzing,
catalog) is plumbing that feeds the verifier. The product lives or dies on the verifier being
trustworthy — better than a human with two test accounts.

Primary target class: **BOLA / Broken Object Level Authorization** (OWASP API #1; the most
reported and highest-impact API bug class). Adjacent: BFLA / vertical access control.

## 2. What this is NOT (explicit non-goals — do not re-litigate without a strong reason)

- **Not a fix-code generator.** Generating patch code is unverifiable AI output (you can't send a
  request to prove a patch is correct) — it imports exactly the hallucination risk the whole
  verification discipline exists to avoid. At most: generic, non-code remediation guidance.
  > Code reality (at HEAD): with the nuclei subsystem removed, its Gemini remediation-patch path
  > is gone; only the Hunter `report_markdown` analysis remains (non-code). This non-goal continues
  > to mean keeping remediation output as non-code guidance.
- **Not a generic CVE/template scanner — ✅ RESOLVED by removal.** nuclei was a category mismatch
  for stateful, auth-context BOLA — quarantined, isolated from the verification core, excluded from
  the core product story, with keep-vs-cut deferred until the moat was proven. The moat (M1 + D19)
  is now acceptance-passed, so the nuclei scan subsystem has been **removed entirely** (commit
  `refactor: remove the nuclei scan subsystem`). The product is now solely the BOLA/IDOR
  verification engine.
- **No AI free-chat box in the UI** (re-introduces the trust problem at the UI layer). If ever
  added, it must be read-only and grounded strictly in a finding's evidence trail.
- **No new external tools.** Existing auth-testing tools (Burp Autorize/AuthMatrix; stateful
  fuzzers like RESTler/fuzz-lightyear) are detection-side approaches this engine aims to surpass;
  integrating them is redundant with the core. Keep the dependency surface lean.

## 3. Honest current status (at HEAD)

The verifier is **built and wired into the pipeline (Phase 7), but dormant**: gated off by
default (`AI_DEEP_VERIFY_ENABLED` / `AI_DEEP_VERIFY_SHADOW` both default `False`), observe-only
(judges and logs, never changes the persisted verdict), and the real endpoint catalog/spec is
**not auto-discovered** (read from the **declared** `AI_DEEP_VERIFY_OPENAPI_SPEC` config field (D21) —
settable from `.env`/env, unset ⇒ byte-identical placeholder; an in-process spec dict is still accepted
by measurement harnesses).

**Verified so far:** same-path cases resolve correctly — AI **8/8** on the same-path set it
judged (case A is confirmed by the rule oracle, not AI-run), **0 false-pos / 0 false-neg**.
Cross-path cases (`X-CROSS` real / `X-SAFE` secure) reach the **integrity floor**: never a false
verdict, stable `inconclusive` — achieved by a prompt evidence-standard + a deterministic
structural cross-resource guard (B-2.2). The verifier's **raw judgment still false-negatives**
the hard cross-path case; the **guard, not model compliance, holds the line**.

**Now confirmed (B-1, committed `37769b3`):** it *does* confirm the hard cross-path case —
catalog semantics + deterministic code-side write-record gathering + a structural guard
exemption. X-CROSS→`verified`, X-SAFE→`inconclusive`/safe, no false verdict, reverse-guards intact
— and **locked by an automated regression test** (`test_d18_b1_shadow_integration.py`, D22 closed).

**Now confirmed on four further shapes:** **M1.1** (read-type semantic-equivalence, equal-length),
**M1.2** (silent write confirmed via a **code-gathered object-STATE** read-back), **M1.3**
(**delete**-type confirmed by a **NEGATIVE ASSERTION**), and **M1.4** (**mass-assignment** confirmed
by a **LOW-ENTROPY STATE JUMP**). B-1 not regressed throughout.

**Measurement (authoritative — the GOLDEN two-target record).** Five shapes × **two structurally-
different targets** (`vulnerable_target` integer-id, `depot_target` UUID-id) × real gemini-2.5-pro,
N=20 SAFE/control, N=10 VULN, fresh-seeded per run: **300 SAFE/control runs → FINAL `verified` = 0**
(0 false positives) and **130 VULN runs → FINAL `verified` = all** via their expected channel;
**430/430 usable, 0 degraded**. Artifact `scripts/measure/results/sweep_highN.jsonl`. **Headline:**
across all SAFE cases the model **raw-said `verified` on 79 runs** and the gate refused **every one**
— on the read shape `DP-READ-SAFE`/`-ECHO` 20/20 each (D24 owner-view gate), on mass `X-MASS-SAFE` ×2,
and on `X-EQUIV-SAFE` **1/20** (the model flipped to `verified` once on target #1's read shape — without
the D24 gate that would have been a false positive). *This supersedes the earlier single-target record
(140 SAFE / 70 VULN), kept as history in `RESULTS.md`.*
**D24 (RESOLVED, `033fc9e`):** the read-semantic shape had **no code gate at all** — correct only
because the model was, and the second target false-positived it **20/20** deterministically. The
**owner-view differential gate**, built on the two-account ownership baseline (`5a33cb2`), closed it:
code reads the same object **as the owner** and a `verified` survives only if the attack response
corroborates that authentic view. **All five shapes are now code-gated on both targets. Still bounded,
do not over-read:** the 0.95 threshold is calibrated on
deterministic lab data with raw bodies and is unvalidated against real-target volatility;
public/shared resources are a residual gap; owner credentials are per-deployment, not per-finding;
and the real-model confirmation is N=1, not at scale. See TECH_DEBT **D24**.

**Not yet on by default:** promotion (D19) is **implemented but default OFF** — the shipped persisted
verdict is still the rule oracle's until `AI_DEEP_VERIFY_PROMOTE` is enabled; and it is proven on
**five vuln shapes, one target, one model** — the remaining thin dimensions are target- and
model-diversity, not N.

**Bottom line:** the moat's hard-case proof point is met and committed, and now generalizes across
**five shapes with zero false positives** — including one (delete) whose proof is an *absence*
rather than a presence, and one (mass-assignment) that **broke the previous causality gate and
forced it to be narrowed** — a real false positive found and closed, not a hypothetical.
**M1 is complete**, and **promotion (D21 → D19) has now landed as a default-OFF capability**
(acceptance-passed clean 430/430); what's left is turning it on and the pre-real-target work (Node 3)
— not the core "can it confirm?" question.

> Detailed current snapshot (maturity, API summary, run/verify checklist) lives in
> [`PROJECT_OVERVIEW.md`](./PROJECT_OVERVIEW.md); known gaps in [`TECH_DEBT.md`](./TECH_DEBT.md);
> the live current-state snapshot in [`STATUS.md`](./STATUS.md).

## 4. The main line (3 nodes — B-1, D19, scope-lock; not separate tracks)

1. **Judge correctly — milestone M1: prove the mechanism generalizes across shapes, zero FP.**
   §5 (done): integrity floor — never a false verdict. Then confirm the hard case on shape after
   shape:
   - **M1.0 (B-1, ✅ done, `37769b3`):** silent cross-path **write**, confirmed via a **write-record**
     — catalog semantics + deterministic write-record gathering + a structural guard exemption
     (answer key §8). Live-measured (`X-CROSS`→`verified` 5/5, `X-SAFE`→safe 5/5), locked by a
     regression test (D22 closed); gate hardened (D23/D23b).
   - **M1.1 (✅ done, this commit):** read-type **semantic-equivalence**, equal-length — the rule
     oracle can't decide by size, so the **AI judges by semantic content**; the verdict now carries
     structured **`evidence_path` + code-computed `anchoring_result`** (AI makes the semantic call,
     code anchors it — corroboration, observe-only). Live-measured: X-EQUIV-VULN→`verified` 5/5,
     X-EQUIV-SAFE→`failed` 5/5 (**0 FP**), N=5, one target.
   - **M1.2 (✅ done):** silent cross-path **write** confirmed via a **code-gathered object-STATE
     read-back** (not a write-record). Prerequisites: caller-identity + payload-causality anchoring
     (`2cac345`), object-scoped HALF-1 (`3e949cb`). Three parts landed:
     **(A) state-readback exemption** — a SECOND guard channel (`STATE_READBACK_EXEMPTION_REASON`,
     **disjoint** from B-1, `verified`-only) that keeps a correct cross-path STATE read `verified`
     **iff** code AND-confirms three anchors: owner==attacked ∧ caller!=owner **and** payload-causality
     (THIS attack's unique value present — the non-negotiable false-positive gate).
     **(B) deterministic object-state gather** (`select_object_state_endpoint`) — target-agnostic
     resource-noun + object-scoping resolver mirroring B-1's HALF-1; the model found that path **0/5**
     on its own, code now gathers it **5/5**. The resolver is only a FETCHER; the three-AND gate stays
     the VERIFIER, so a wrong gather degrades to `inconclusive`, never to a false positive.
     **(C) prompt carve-out** — rule 5 (plus turn-2 and the options-block definitions) now names a
     *system-gathered* read of the attacked object's own state as decisive alongside same-path and
     write-record; this resolved a genuine prompt/code contradiction (the model held decisive evidence
     but obeyed rule 5 and answered `inconclusive`) and lifted VULN **3/5 → 5/5**.
     **Live-measured** (N=5, gemini-2.5-pro): X-SILENT-VULN→`verified` **5/5**; **X-SILENT-SAFE→
     `verified` 0/5** (causality `absent` 5/5 → no exemption → `inconclusive`); B-1 X-CROSS still
     `verified` 5/5. *(A "forced-follow-up read" shape was rejected as a pseudo-problem — a read is
     self-decisive or not a leak; do not pursue it.)*
     **Optional hardening (recorded, NOT done):** the prompt restricts case (c) by *provenance*
     (system-gathered) while the code gate keys on *evidence* (the three anchors). Aligning them =
     adding `followup_is_code_gathered` to the gate — one line, only ever stricter.
   - **M1.3 (✅ done):** **delete-type**, whose confirmation is a **NEGATIVE ASSERTION** — the proof
     is a from-EXISTS-to-ABSENT jump, not a value appearing, so payload-causality does not apply.
     Two mechanisms: **(1) a PRE-FLIGHT read** — code GETs the victim object (scope-locked) BEFORE
     the DELETE to prove it existed and was active. This is the **coincidence gate**: "it vanished"
     only proves a delete if "it existed just before" is anchored; no pre-flight existence proof →
     **never** `verified`. **(2) a DUAL-TRACK absence anchor** — decisive on **physical** removal
     (404/403/410) **or** **logical/soft** deletion (200 with a lifecycle field flipped, by generic
     vocabulary); **404 is deliberately not hardcoded**, because real APIs mostly soft-delete. A
     **third, disjoint** exemption channel is gated on pre-flight caller-identity AND the negative
     assertion. Live (N=5): VULN hard+soft `verified` 5/5 each; **SAFE 0**; **CONTROL (object never
     existed) 0** — the AFTER read was also 404, but nothing was proven to exist.
   - **M1.4 (✅ done):** **mass-assignment** — the attacker sneaks a privileged field (role/flag)
     into a write on the VICTIM's object. Payload-causality BREAKS here: the value is LOW-ENTROPY,
     so its mere presence cannot separate "I set it" from "it was already that". Causality is
     proven instead by a **STATE JUMP** — every field the attack sent moved from a **KNOWN**
     pre-flight state to the injected value. **MISSING** (absent from a SUCCESSFUL 2xx pre-flight)
     is a VALID original state, so hidden-field escalation (`missing→injected`) verifies; a request
     failure is **UNKNOWN** and never does. Live (N=5): VULN present + missing→injected `verified`
     5/5; **SAFE present + missing 0/5**; control (injected == pre-flight) 0/5.
     **Also fixed a real false positive:** on a securely-stripped case a legitimate co-submitted
     field still satisfied payload-causality, so M1.2's channel would have exempted a SECURE case.
     Routing now **prefers the state-jump gate whenever a pre-flight baseline exists** — strictly
     fewer exemptions (proven by `test_HAZARD_...` and `test_RESIDUAL_FIX_...`).
   - **M1.x (optional):** further shapes (nested-object, multi-step) — breadth, not a gate.

   > **M1 IS COMPLETE.** Five shapes confirmed with zero false positives: write→write-record
   > (B-1), read→semantics (M1.1), silent write→object-state (M1.2), delete→negative assertion
   > (M1.3), mass-assignment→low-entropy state jump (M1.4). The "prove generalization"
   > milestone that gated D19 is met. **Next line: D21 → D19 → pre-release → pre-real-target.**
   >
   > *(The per-shape figures in the rows above are the original N=5 runs. Authoritative headline = the
   > GOLDEN two-target record: **300 SAFE/control → 0 FP, 130 VULN → all `verified`**, five shapes ×
   > two structurally-different targets × gemini-2.5-pro, N=20/10, 430/430 usable —
   > `scripts/measure/results/sweep_highN.jsonl`. Supersedes the single-target 140/70. §3.)*

   > **M2 — Shared Domain Model (later, NOT started):** a resource/endpoint relationship graph — sink
   > upstream observations (proxy / HAR / spec) into a shared layer every module can query, so the
   > verifier isn't guessing which paths relate (precedent: RESTler-style request-dependency graph
   > from OpenAPI). **Gated on** M1 proving generalization + an evidence-backed list of "what downstream
   > needs from upstream." **Minimal slice pulled forward:** M1.2(B)'s "find the attacked object's own
   > state endpoint" is the smallest slice of this graph — build only that slice now; the full graph stays M2.
   >
   > **Black-box boundary (mapped at M1.2(A)):** a silent write with **no same-path GET and no relevant
   > write-record** is not confirmable by the model's **unaided** follow-up — confirmation requires code to
   > steer it to the object's state path (M1.2(B)). A truly-silent write whose effect surfaces through *no*
   > endpoint remains the fundamental black-box ceiling below.
   >
   > **Strategic radar (decide later, do NOT act now):** black-box (deployable, but a fundamental ceiling
   > on truly-silent writes whose effect surfaces through *no* endpoint) vs. an optional gray-box mode
   > (log/instrumentation ingestion, à la BACFuzz) for higher-assurance confirmation.
2. **Act.** **D19 — ✅ landed (default OFF):** the verifier can promote the rule oracle's `suspicious`
   band to `verified` under a deterministic authorizer (choke point + single writer +
   `owner_view_corroborated`), acceptance-passed clean 430/430. Off by default; enabling it in a real
   flow is Node 3. *(TECH_DEBT.md D19.)*
3. **Be safe on real targets. ✅ SCOPE-LOCK HARDENING COMPLETE.** The duplicated host-scope checks
   are converged onto ONE audited `ScopePolicy` (`scope.py`): active enforcement at the
   `_send_request` chokepoint (fail-closed, per-hop redirect validation, resolved-IP
   DNS-rebinding/SSRF guard) AND the passive proxy (`pruner`/`radar_addon`) now share the SAME
   matcher — one decision tree, proven by test (passive == active for the same host). Delivered
   with it: a unified run-time `scope`+`model` declaration (`approved_host` a legacy alias);
   over-broad-wildcard rejection via a vendored Public Suffix List; port rules; the adversarial
   suite (substring / protocol-relative / userinfo / IDN / IP-encoding tricks); and SecretStr key
   privacy so no secret leaks via repr/log/serialization. **Honest residuals (recorded, not
   closed):** IP-pinning is a follow-up — a small DNS TOCTOU window remains (TECH_DEBT.md D25); the
   0.95 read-gate threshold stays unvalidated against real-target volatility. *(Relates to
   TECH_DEBT.md D2 — no-auth; the scope-lock is a traffic-EGRESS guardrail, NOT authentication.)*

> **Prove the shadow path (✅ done, D22, `37769b3`):** the verifier's integration is now a
> regression asset, not a manual harness — `test_d18_b1_shadow_integration.py` runs the real
> `execute_deep_verification` with a mocked Gemini and pins X-CROSS→`verified` /
> X-SAFE→never-`verified`. Fits the §6 discipline "a green test proves nothing unless something
> was allowed to fail" (the X-SAFE safety assertion is the allowed-to-fail line).

**Later / optional:** cost & latency budget; model-degradation handling.
**Provider abstraction (multi-provider / BYO-model) — ✅ IMPLEMENTED** (`services/llm/`: Gemini default +
OpenAI-compatible + Anthropic; see [`LLM_PROVIDERS.md`](./LLM_PROVIDERS.md)). Decoupled from
"re-validate zero-FP on model X": the zero-FP claim stays measured on gemini-2.5-pro; BYO-model users get
provider freedom (connectivity), not a zero-FP guarantee. A second *measured* model is still open.

## 5. Authorization reality (binding — shapes what the tool is for)

This tool **sends real attack requests, including writes that modify state.** That makes
authorization the central constraint, not an afterthought:

- **Real-target use requires explicit authorization**; legality is the operator's (ideally a
  lawyer's) call. The scope-lock is a technical guardrail, **not a grant of permission**.
- Many bug-bounty programs prohibit automated scanners outright; those that allow them require
  strict rate-limiting; and they broadly forbid accessing or modifying real users' data — you
  must use **test accounts you control**. The engine's most novel capability — **write-then-read
  confirmation across users** — is precisely what programs forbid against real data.
- Safest homes for this tool: **authorized penetration-test engagements, self-built labs, and
  systems you own.** It is not a "point it at any program and farm bounties" tool, and used that
  way it will get you banned or worse.

## 6. Disciplines (carry into every step) 
no claim trusted without being verified against code; small, reversible,
zero-regression steps; every override logged transparently (raw verdict preserved). **A green test
proves nothing unless something was allowed to fail.**

**Confirmation must not depend on the model self-discovering evidence.** Code deterministically
*gathers* the decisive read-back (B-1's write-record; M1.2(B)'s object-state read); the model only
does the irreplaceable *semantic* read of what code fetched. Prompt-nudging the model to choose the
decisive follow-up on its own was tried and measured — it chose it **0/20** at B-1 and **0/5** at
M1.2(A) — so it is a proven dead end, not a tuning problem. New evidence types = new deterministic
gatherers, never "ask the model to realize it should look."

**Keep the prompt and the code in agreement.** M1.2 shipped a code path (gather a cross-path object
state, exempt it structurally) that the prompt still forbade — the model held decisive evidence and
answered `inconclusive` 2/5 because rule 5 told it to. When code learns a new decisive evidence
shape, the decisive-evidence standard in the prompt must learn it too, or the two silently fight.

---

## 7. Future / deferred (RECORDED, NOT scheduled — do NOT act on these)

> Parking lot, grouped by the phase that unlocks each item. Nothing here is approved work. Do not
> start any of it without an explicit decision; it is written down so it is not rediscovered or
> silently re-litigated.

### Phase — next vuln shapes (M1.x, the near ones)
- **Mass-assignment — ✅ DONE (M1.4).** Kept as the worked precedent for the hazard it hit: this shape writes *existing, low-entropy* fields (an owner/role id, a boolean flag), which
  **breaks payload-causality's unique-value assumption**. The injected value can equal a value that
  was already there (or that another run wrote), so "the value is present in the read-back" would no
  longer prove *this* attack caused it — the anti-false-positive gate would be asserting a
  coincidence. Like the delete shape, it will likely need **its own decisive-evidence anchor** (e.g.
  a pre-flight before/after diff of the *specific* field, proving it changed *and* changed to what we
  sent) rather than reusing payload-causality as-is. Do not assume the M1.2 gate transfers.
- **Delete-type — ✅ DONE (M1.3).** Kept here only as the worked precedent: its confirmation is a
  **negative assertion** (pre-flight existence + dual-track absence), which is why a new shape may
  need a new anchor rather than a stretch of the existing one.

### Phase — known gate boundary (applies now)
- **Payload-causality can false-collide on LOW-ENTROPY values.** The anti-false-positive gate rests
  on THIS attack's injected value being effectively unique. On boolean / small-integer / enum fields —
  or with concurrent runs writing the same value — that assumption breaks and causality could confirm
  a change this attack did not cause. A real boundary of the current gate, recorded honestly.
  **This is precisely what M1.4 (mass-assignment) will hit head-on**, since that shape writes exactly
  such fields — treat it as M1.4's central design problem, not an afterthought. (M1.3's delete shape
  sidesteps it entirely: its anchor is existence/absence, not a value.)

### Phase — before public release
- **Default `API_HOST` to `127.0.0.1`** (the user may override). Do **NOT** hard-lock or `sys.exit`
  on a non-loopback bind — that would kill authorized remote testing, which is a legitimate use.
- **A 2-minute "magic demo"** plus a **recorded HAR sample** of `vulnerable_target/`, so the value is
  visible without a full manual setup.
- **`run_in_executor` for the similarity computation** (minor; it is CPU-bound on the event loop).

### Phase — before any real / non-lab target
- **Scope-lock hardening — ✅ DONE (§4 node 3):** the duplicated host-scope checks are converged
  onto one audited `ScopePolicy` (active `_send_request` chokepoint: fail-closed + per-hop redirect
  + resolved-IP DNS-rebinding guard; the passive proxy shares the same matcher), with the
  adversarial suite + a one-decision-tree test + SecretStr key privacy. Residual: IP-pinning
  follow-up to close a small DNS TOCTOU window (TECH_DEBT.md D25).
- **The UUID wall** — object ids in real APIs are frequently UUIDs, which cannot be enumerated by
  incrementing. Let the **user supply the victim's alternative IDs** rather than guessing them.
- **WAF circuit-breaker** — detect that a WAF/rate-limiter has started blocking and stop, instead of
  hammering a target and poisoning every subsequent verdict.
- **Multi-step auth-macro recording** — logins that are not a single request (multi-step / MFA /
  token exchange) cannot currently be replayed.
- **A two-account resource-ownership baseline.** The fuzzer today holds **one shared auth custody**
  and has **no map proving `id=2` belongs to a different user** — it is inferred from the attack's own
  path shape. Real targets need an explicit two-account ownership baseline.

### Phase — next line now that M1 is complete (in order)
- **D21 ✅ DONE** — the OpenAPI spec source is now a declared `Optional[str]` config field
  (`AI_DEEP_VERIFY_OPENAPI_SPEC`, a path settable from `.env`; resolved to a parsed spec with a
  fail-safe to the placeholder at the fuzzer consumption point, in-process dict injection still
  accepted for measurement drivers). The real catalog is reachable in normal use, not only from
  harnesses; zero-regression locked by `test_d21_spec_config.py`.
- **D19 — ✅ DONE (default OFF).** The AI verdict can now be promoted to authoritative — but only for
  the rule oracle's `suspicious` band, only under a deterministic authorizer, and only when
  `AI_DEEP_VERIFY_PROMOTE` is enabled (shipped default `False`). Acceptance-passed **clean 430/430**
  (`scripts/measure/results/sweep_highN_d19.jsonl`); full evidence trail retained under
  `diff_details['ai_promotion']`. Enabling it on real targets is Node 3.
- **Then the pre-release register** (default `API_HOST` to 127.0.0.1, the 2-minute demo + recorded
  HAR, `run_in_executor` for the similarity compute) and the **pre-real-target register**
  (scope-lock hardening, the UUID wall, WAF circuit-breaker, multi-step auth macro, the two-account
  ownership baseline) — both below.

### Phase — M2 (later)
- **Shared resource/dependency graph** (RESTler-style request-dependency graph from OpenAPI /
  proxy / HAR), so every module can query which paths relate instead of guessing. **Still gated on**
  M1 proving generalization across shapes. M1.2(B)'s object-state resolver is the minimal slice and
  is already built — do **not** expand it into the full graph now.

### Phase — strategic direction (RECORDED post-scope-lock; do NOT act now)
> Direction-setting for a future node, written down so it is not rediscovered or silently
> re-litigated. Nothing here is approved work — do NOT start any of it.
- **(a) Depth ≠ more shapes.** The five decisive-evidence anchors (write-record, read-semantics,
  object-state, delete negative-assertion, mass-assignment state-jump) are **sufficient**; adding
  more M1.x shape-anchors is NOT the next depth move. Real depth goes toward **business-context
  complexity** (multi-actor, multi-step, stateful workflows), not raising the shape count.
- **(b) M2's first step is multi-step request-sequence orchestration**, NOT a full dependency graph
  up front — the engine autonomously composing a sequence like "user A creates → user B reads" to
  set up and confirm a cross-actor access-control bug. Build that capability before (and as the
  concrete driver of) any broader resource/dependency graph.
- **(c) A crAPI-vs-Autorize comparison report** (this engine's zero-FP verification vs a detection
  -side tool on a public vulnerable target) is a **go-to-market / exposure asset** — produced ONLY
  **after real-target capability exists** (post-scope-lock, once the pre-real-target register is
  cleared), never now. It is evidence for "can it be sold", not a milestone gate.

---

## 8. Considered and rejected (do NOT re-propose without new evidence)

> Each of these was evaluated — several were measured — and rejected for the recorded reason.
> Re-proposing one costs a node's time re-deriving the same answer.

- **Letting the model "realize" it should fetch other evidence.** Measured at B-1: the model chose
  the decisive endpoint **0/20** unaided, and **0/5** again at M1.2(A). Code gathers the evidence
  deterministically instead. (Now a standing discipline — see §6.)
- **An external LLM "judge" over the whole process.** Pushes the trust problem up a layer: you would
  then need to verify the judge. Determinism is the process check — the structural guard, the code-side
  anchors, "a green test proves nothing unless something was allowed to fail", and regression tests.
- **A JSON tree-edit-distance oracle / making the rule oracle smarter.** Conflicts with the deliberate
  **equal-length** benchmark strategy, which exists precisely to force cases into the semantic gap where
  only the AI can decide. A smarter size/diff oracle would paper over the gap the product must own.
- **Multi-round reflection loops.** More cost and more hallucination surface for no demonstrated
  verdict gain; the two-turn write-then-read plus deterministic gathering is the shape that works.
- **Building the full dependency graph now.** The minimal object-state resolver is what M1.2 needed;
  the full graph is M2 and stays gated.
