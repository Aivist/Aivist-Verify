# STATUS — where the project stands right now

> The single **current-state snapshot**: progress, what is proven, what is deferred.
> Grounded in the code and the test suite as of this writing — if a line here drifts
> from the source, the code wins, update this file. For *why / where it's going* read
> [`ROADMAP.md`](./ROADMAP.md); for *what exists + how to run it* read
> [`PROJECT_OVERVIEW.md`](./PROJECT_OVERVIEW.md); for the full gap register read
> [`TECH_DEBT.md`](./TECH_DEBT.md).

## One line

A single-tenant, locally-run access-control verification engine whose core is
**built, wired into the pipeline as a read-only shadow pass, and dormant by
default**. The integrity floor (never emit a false verdict) is proven. The engine now
confirms the hard case on **five distinct vuln shapes with zero false positives** —
**M1.0/B-1** (silent cross-path *write*, confirmed via a write-record), **M1.1**
(read-type *semantic-equivalence*, equal-length, confirmed by semantics + evidence
anchoring), **M1.2** (silent cross-path *write* confirmed via a code-gathered
object-**STATE** read-back), and **M1.3** (**delete**-type, confirmed by a **NEGATIVE
ASSERTION** — a code-anchored from-EXISTS-to-ABSENT jump), and **M1.4** (**mass-assignment**,
confirmed by a **LOW-ENTROPY STATE JUMP** from a known pre-flight state). **M1 — proving the
mechanism generalizes across shapes — is COMPLETE.** **D19 is now implemented and acceptance-passed** —
the verifier *can* promote a rule-oracle `suspicious`→`verified` under a deterministic code authorizer,
but is **default OFF** (`AI_DEEP_VERIFY_PROMOTE=False`, clean 430/430 vs golden in `sweep_highN_d19.jsonl`),
so shadow/observe-only stays the shipped default. Proven on **five shapes × two structurally-different
targets × one model**.
**Authoritative record — the GOLDEN two-target zero-FP run** (real gemini-2.5-pro, N=20 SAFE/control,
N=10 VULN, fresh-seeded per run, `scripts/measure/results/sweep_highN.jsonl`): **300 SAFE/control
runs → 0 false positives; 130 VULN runs → all `verified`** via their expected channel; **430/430
usable, 0 degraded**. **Headline:** across all SAFE cases the model **raw-said `verified` on 79 runs**
and code held the line on **every one** (`DP-READ-SAFE`/`-ECHO` 20/20 each via the D24 owner-view
gate; `X-MASS-SAFE` ×2 via state-jump; **`X-EQUIV-SAFE` 1/20** — the model flipped to `verified` once
on target #1's read shape, which without the D24 gate would have been a false positive). *Supersedes
the earlier single-target record (140 SAFE / 70 VULN, one target), kept as history in `RESULTS.md`.*
> ✅ **All five shapes are now code-gated (D24 RESOLVED, `033fc9e`).** This used to read "but not on
> every shape": 20 of those 140 SAFE runs (read-semantic) had **no code gate at all** and were correct
> only because the model was, and the second target false-positived that shape **20/20**. The
> **owner-view differential gate** closed it — code now reads the same object **as the owner** (via
> the two-account baseline, `5a33cb2`) and a `verified` survives only if the attack response
> corroborates that authentic view. Downgrade-only by construction.
>
> **Confirmed against the REAL model at scale** — the D24 gate is now exercised in the GOLDEN
> two-target run above, not just the initial N=1 check: `DP-READ-SAFE`/`-ECHO` held to `inconclusive`
> **20/20 each** while the model raw-said `verified`, and on `X-EQUIV-SAFE` the model flipped to
> `verified` **1/20** and the gate caught it. The loop is closed — the fix is confirmed at scale the
> same way the failure was found.
>
> ⚠️ **Do not read this as "the shape is solved."** Four boundaries stand, unchanged (TECH_DEBT D24):
> the **0.95 threshold is calibrated on deterministic lab data comparing raw bodies** and is
> **unvalidated against real-target volatility** (timestamps/ETags would push a true positive down;
> the obvious remedy — the existing sanitizer — was measured and *raises* SECURE similarity instead,
> so it was rejected); **public/shared resources remain a residual gap** the downgrade-only gate does
> not address; owner credentials are **per-deployment, not per-finding**; and the real-model
> confirmation is **N=1, not at scale**.

## Open decisions

- **Umbrella brand name — NOT finalized (pending director).** The CLI ships under a
  **provisional** brand token defined once, as `BRAND_NAME` in
  [`backend/app/cli/branding.py`](../backend/app/cli/branding.py) (currently `"lanivist"`).
  Every user-facing brand string — the console command, `--help`/banner, and the per-user
  config dir `~/.<brand>/` — **derives from that one constant**, so finalizing the name is a
  one-line change, never a repo-wide find-replace (a test asserts the derivation; the only
  static copies are the `pyproject.toml` `[project.scripts]` key + `project.name`, tagged
  `TODO(naming)`). The **`verify` suffix is LOCKED** — the product is "`<Brand> Verify`",
  invoked as `<brand> verify` (`confirm` kept as a back-compat alias).

## Test suite

| Suite | Command (from repo root) | Result |
|---|---|---|
| Backend | `python -m pytest backend/tests -q` | **587 passed** |
| Ground-truth target (`vulnerable_target`, integer-id) | `python -m pytest vulnerable_target -q` | **31 passed** |
| Ground-truth target (`depot_target`, UUID-id) | `python -m pytest depot_target -q` | **23 passed** |

> Re-verified against the repo 2026-08-03 (all three suites run). The backend count was **473** while
> only the confirmer spine had landed; it is now **587** after the presentation pass, entry point,
> config flow, `config.py` user-config source, the external real-target path, YAML `--spec` support,
> and the `--auth` auto-relogin path (see the next section).

## Operator front door — CLI, packaging, config, external targets (code facts, re-verified 2026-08-02)

A human-walkable front door over the EXISTING confirmation path. The engine's judgment is
untouched throughout — `deep_verifier` (four channels / cross-resource guard / D24 / D19),
`fuzzer._differential_verdict`, and `scope.py`'s enforcement are reused verbatim. The one core
file touched is `config.py`, and only to ADD a settings source (below). What ships now:

- **CLI confirmer spine** (`run.py`, commits `94d1fd5` + `8727b12`). Reuses
  `verdict_measure._run_one`'s `execute_deep_verification` path and renders the returned
  `DeepVerificationResult`. The verdict is read ONLY from `final_verdict`/`ai_verdict` — the
  renderer **structurally cannot manufacture `verified`**; `ground_truth` feeds only the separate
  `[lab oracle]` line. Exit codes: `0` nothing confirmed · `1` ≥1 confirmed · `2` NOT DATA.
- **Presentation pass** (`backend/app/cli/confirm_render.py`, commits `ef8fe3b` + `2e3f736`).
  Plain-language translation of every channel/anchor token (raw token kept alongside), ANSI color
  (CONFIRMED red / REFUTED green, TTY-autodetected, **no `rich` dependency**, `NO_COLOR`/`FORCE_COLOR`
  honored), and a one-line confirmed/refuted `render_tally` for full-caseset mode. Pure + offline;
  tested against committed golden rows at zero API cost.
- **Console entry point** (`pyproject.toml` → `[project.scripts] lanivist = "run:main"`, commit
  `4bb643b`). After `pip install -e .` the command is **`lanivist verify …`** / **`lanivist config`**;
  `python run.py …` still works. `verify` is primary, `confirm` a back-compat alias. The brand token
  is provisional and derived from ONE constant `BRAND_NAME` in `backend/app/cli/branding.py`
  (currently `"lanivist"`); the `verify` suffix is locked (see Open decisions).
- **Interactive config flow + relay/中转站 support** (`backend/app/cli/config_flow.py`, commit
  `4bb643b`). `lanivist config` prompts for provider / API key (masked via `getpass`) / base_url /
  model and writes `~/.<brand>/config.toml` at `0600` (where the OS honors it); the key is never
  echoed/printed/logged. Relay/中转站/DeepSeek/Kimi/GLM/Qwen/Grok/Ollama all ride the existing
  `openai` (OpenAI-compatible) provider via `base_url` — the capability already existed at the
  provider layer; the flow surfaces it.
- **`config.py` user-config source** (`_UserConfigTomlSource` + `settings_customise_sources`, commit
  `e9a8e10`). A per-user TOML source inserted **below** env and `.env`, **above** field defaults, so
  explicit env / `backend/.env` always win and the file only fills gaps; a missing/malformed file
  contributes nothing (byte-identical). No existing default or flag semantic changed; a file
  `LLM_API_KEY` is coerced to `SecretStr`. First-run detection guides to `lanivist config` instead of
  a stack trace.
- **External real-target verify path** (`backend/app/cli/external_verify.py` + `run.py`, commit
  **`c0956d0`** — verified: touches `external_verify.py`, `test_external_verify.py`, `run.py`, +524/−3).
  `lanivist verify --target <base_url> --spec <openapi.json> --op <op.json>` assembles a locally-run
  real target into the **same** `execute_deep_verification` call the lab path uses (lab `--caseset`
  path unchanged). Three red lines hold structurally, with tests: (1) **scope fail-closed** —
  `approved_host` is derived from `--target` and the engine `.check()`s every request, no exemption;
  (2) **attacker/owner identity isolation** — the attacker token is the attack `auth_context` only,
  the owner token is an `OwnerCredential` consumed only by the GET-only custody-free `fetch_owner_view`,
  never merged; (3) **both tokens are `SecretStr`, redacted, never logged**. A real target has **no
  ground truth**, so there is **NO zero-FP claim**; timeout / 429 / 401 / 403 / transport → **NOT DATA**
  (a challenge is not a security signal).
- **VAmPI live confirm (engineering signal, NOT a zero-FP claim).** A real BOLA
  (`GET /books/v1/{book_title}`) was live-confirmed against **VAmPI** — an unfamiliar third-party
  OWASP target run locally in a sandbox — via the read-semantic **owner-view gate**
  (`owner_view_corroborated=True`), reproducibly (2 of 3 runs CONFIRMED; the third a transient Gemini
  timeout → correctly NOT DATA). This is recorded as evidence the external path **runs end-to-end on an
  unfamiliar API**, explicitly **not** a zero-false-positive claim (real targets have no ground truth
  to measure against). The exploratory run was throwaway — not committed.
- **crAPI real-target validation (engineering signal, NOT a zero-FP claim — a DISTINCT run from the
  VAmPI one above; do not conflate the two).** OWASP **crAPI** was stood up locally via Docker on the
  director's Windows machine (an earlier probe had failed only because Docker Desktop's engine was not
  running — briefly misdiagnosed as "no Docker", then corrected: it was installed in a per-user path),
  and an **execution agent** (not a manual director run) drove `lanivist verify` (real gemini-2.5-pro)
  against three hand-verified endpoints — each verdict judged against hand-verification done FIRST, since
  a real target carries no ground-truth label:
  - `GET /workshop/api/shop/orders/{order_id}` (declared path id) — hand-verified **REAL BOLA** →
    **CONFIRMED**, matched (a true positive), carried by the **owner-view gate**
    (`owner_view_corroborated=True`) with the id-shaped anchors observe-only.
  - `GET /community/api/v2/community/posts/{postId}` (inline id, a **public** community feed) —
    hand-verified **TRUE-NEGATIVE** → **CONFIRMED = a real FALSE POSITIVE**: the first real-target
    trigger of the D24 public/shared-resource gap, which **motivated D30** (now ✅ RESOLVED, commit
    `ea65372`, default OFF — an opt-in bystander probe flips the public post CONFIRMED→not-confirmed
    while a private BOLA still confirms, proven on faithful crAPI-shaped fixtures driving the real
    engine; **live crAPI re-confirmation is pending the director's machine**). See TECH_DEBT **D30** / [`AUDIT.md`](./AUDIT.md).
  - `GET /workshop/api/mechanic/mechanic_report?report_id=` (query-string id) — hand-verified **REAL
    IDOR** → first **REFUTED** (a false negative from an assembly-layer gap), then **CONFIRMED** and
    matched after the **D29** fix (query-string ids now carried on the baseline + owner-view; commit
    `227b9c6`). See TECH_DEBT **D29**.
  The **owner-view gate carried every crAPI confirmation; the id-shaped anchors stayed observe-only** —
  the same portable-moat pattern seen on VAmPI. **Still pending:** a purely-manual director acceptance
  run, and the post-D30 live order-endpoint re-check (does that endpoint deny an unrelated third account,
  or is it broken for everyone? — the D30 residual, `AUDIT.md`).
- **YAML `--spec` support** (`external_verify._load_spec_file`, commit `5a6cf52`). `--spec` accepts
  `.yml`/`.yaml` (parsed with `yaml.safe_load` ONLY — never the unsafe loader) as well as `.json`; JSON
  stays byte-identical and feeds the same `catalog_from_openapi`. Suite 507→510.
- **Multi-step auth slice 1 — auto re-login / token refresh** (`backend/app/cli/relogin.py` + the `--auth`
  branch in `external_verify.py`, commit **`675835ff`**). OPTIONAL: instead of static tokens, each account
  logs in independently (its own client + credential) to obtain its own JWT and re-logs-in near/at expiry —
  a fresh login per run plus a reactive retry once on a baseline/attack `401`. The three red lines hold
  (identity isolation incl. after refresh — the owner token never appears in an attack header; credentials
  AND tokens `SecretStr`, redacted; the login endpoint is scope-checked, fail-closed). Login failure → NOT
  DATA. The **static-token path is unchanged and the engine is untouched** — only the token *source*
  changes; `_verify_external`'s `execute_deep_verification` call is byte-identical. Live-proven against
  **VAmPI at a 60-second token TTL**: `--auth` auto-re-logged-in and CONFIRMED a real BOLA without the run
  breaking on token expiry. Known limitation (safe-direction, non-blocking): owner-view mid-run 401 —
  TECH_DEBT **D28**. Suite 510→**523**.

## The main line (three nodes)

The product's spine is three sequential nodes (see [`ROADMAP.md`](./ROADMAP.md) §4).
Node 1 ("judge correctly") is now organized as milestone **M1** — prove the verification
mechanism generalizes across vuln shapes with **zero false positives**. Where each stands:

| Node | Goal | State |
|---|---|---|
| **1. Judge correctly (= M1)** | Never a false verdict; confirm the hard case across *shapes* | **✅ COMPLETE — 5 shapes confirmed, 0 FP.** See the M1 breakdown below. |
| **2. Act** (`D19`) | Promote the AI verdict from observe-only/log to **authoritative** | **✅ IMPLEMENTED, default OFF, acceptance-passed.** Promotion writes `suspicious→verified` only under a deterministic authorizer (four channels or the D24 owner-view corroboration); clean 430/430 vs the golden record, 0 SAFE promoted. Not on by default — shadow stays shipped; enabling on real targets still gated on Node 3. |
| **3. Be safe on real targets** | Consolidate scope-lock checks + adversarial tests before any non-localhost use | **✅ SCOPE-LOCK HARDENING COMPLETE.** One audited `ScopePolicy` governs ALL host decisions — active (`_send_request`: fail-closed + per-hop redirect + resolved-IP rebinding guard) AND passive (proxy/pruner share the SAME matcher). Unified `scope`+`model` declaration; SecretStr key privacy; adversarial + one-decision-tree tests. **Residuals (recorded, not closed):** IP-pinning is a follow-up (small DNS TOCTOU window remains — TECH_DEBT D25); the 0.95 read-gate threshold is still unvalidated against real-target volatility. Enabling promotion on a real target still also waits on model/target diversity. |

### M1 — Verifiable benchmark & reference engine (generalize across shapes, zero FP)

| Milestone | Shape / how confirmed | State |
|---|---|---|
| **M1.0 (B-1)** | silent cross-path **write**, confirmed via a **write-record** | **DONE, committed `37769b3`.** X-CROSS→`verified` 5/5, X-SAFE→safe 5/5; regression test locks it. |
| **M1.1** | read-type **semantic-equivalence**, equal-length, confirmed by **semantics + evidence anchoring** | **DONE, committed `002b33c`.** X-EQUIV-VULN→`verified` 5/5, X-EQUIV-SAFE→`failed` 5/5 — **0 FP**, N=5, one target. |
| **M1.2** | silent cross-path **write** confirmed via a code-gathered object-**STATE** read-back (not a write-record) | **DONE, committed `e4d5317`.** Three parts: **(A)** a SECOND guard exemption channel (`STATE_READBACK_EXEMPTION_REASON`, **disjoint from B-1**, `verified`-only) gated on three structural anchors AND-ed — owner==attacked ∧ caller!=owner (`caller_identity=confirmed`) **and payload-causality** (THIS attack's UNIQUE value present; causality is the false-positive gate). **(B)** a **deterministic object-state gather** (`select_object_state_endpoint`, target-agnostic resource-noun + object-scoping; mirrors B-1's HALF-1) — the model never found that path on its own (**0/5**), code now gathers it **5/5**. **(C)** a **prompt carve-out** (rule 5 / turn-2 / options-block) so a *system-gathered* read of the attacked object's own state counts as decisive — lifted VULN **3/5 → 5/5**. **Live-measured** (shadow, N=5, gemini-2.5-pro): X-SILENT-VULN→`verified` **5/5** (all 3 anchors confirmed, causality `confirmed_at_path` 5/5); **X-SILENT-SAFE→`verified` 0/5** (causality `absent` 5/5 → no exemption → `inconclusive`); B-1 X-CROSS still `verified` 5/5 — `scripts/audit/shadow_m12c_prompt_carveout_run.out.txt`. Offline both ways: `test_m12_state_readback_exemption.py`, `test_m12b_state_gather.py` (incl. a foreign-spec genericity proof). **⚠️ NARROWED by M1.4:** this channel yields whenever a pre-flight baseline exists (the state-jump gate governs), because payload-causality alone would have false-positived a securely-stripped mass-assignment case. Verdicts unchanged; strictly fewer exemptions. |
| **M1.3** | **delete-type**, confirmed by a **NEGATIVE ASSERTION** (from-EXISTS-to-ABSENT), dual-track physical *or* logical | **DONE (this commit).** Two new mechanisms: a **PRE-FLIGHT read** (code GETs the victim object, scope-locked, BEFORE the DELETE — the **coincidence gate**: "it vanished" only proves a delete if "it existed & was active just before" is anchored) and a **dual-track negative-assertion anchor** (`_anchor_negative_assertion`) accepting **physical** removal (404/403/410) **or** **logical/soft** deletion (200 with a lifecycle field flipped, by generic vocabulary — **404 is NOT hardcoded**). A **third, disjoint** exemption channel (`DELETE_READBACK_EXEMPTION_REASON`) gated on pre-flight caller-identity **AND** the negative assertion. **Live-measured** (N=5, gemini-2.5-pro, fresh-seeded per run): X-DELETE-VULN-HARD→`verified` **5/5** (`confirmed_physical`), X-DELETE-VULN-SOFT→`verified` **5/5** (`confirmed_logical`), **X-DELETE-SAFE→`verified` 0/5** (`still_present`), **X-DELETE-CONTROL (object never existed)→`verified` 0/5** (`preflight_absent` — the coincidence gate held even though the AFTER read was also 404) — `scripts/audit/shadow_m13_delete_run.out.txt`. Offline: `test_m13_delete.py` (incl. foreign-spec genericity). |
| **M1.4** | **mass-assignment** — the attacker sneaks a privileged field (role/flag) into a write on the VICTIM's object; confirmed by a **LOW-ENTROPY STATE JUMP** | **DONE (this commit).** Payload-causality breaks here: the injected value is low-entropy, so "the field reads admin" cannot tell "I set it" from "it was already admin". Causality is instead proven by a **STATE JUMP** — every field the attack sent moved from a **KNOWN pre-flight state** to the injected value. **MISSING** (absent from a SUCCESSFUL 2xx pre-flight — privileged fields are commonly hidden) is a VALID original state, so `missing→injected` verifies (hidden-field escalation); `missing→missing` does not. A **request failure / non-2xx / unparseable** read is **UNKNOWN**, never MISSING → never `verified`, never a crash. New disjoint channel `STATE_JUMP_EXEMPTION_REASON`, gated on caller-identity AND the jump. **Live (N=5):** X-MASS-VULN present-value→`verified` 5/5 and MISSING→injected→`verified` 5/5; **X-MASS-SAFE present + missing→`verified` 0/5**; control (injected==pre-flight)→0/5. On SAFE the model raw-said `verified` and the gate refused every time. |
| **M1.x (optional)** | further shapes (nested-object, multi-step) | Not started. M1's goal — *prove the mechanism generalizes* — is met at five shapes; more shapes are breadth, not a gate. |

> **Authoritative measurement (supersedes the per-shape `N=5` in the rows above).** Each row records
> the *original* per-shape run (still on disk, still valid). The current headline is the **GOLDEN
> two-target record** (real gemini-2.5-pro, N=20 SAFE/control, N=10 VULN, fresh-seeded,
> `scripts/measure/results/sweep_highN.jsonl`): **300 SAFE/control runs → FINAL `verified` = 0** (0
> false positives) and **130 VULN runs → FINAL `verified` = all** via their expected channel;
> **430/430 usable, 0 degraded**, across `vulnerable_target` (integer-id) and `depot_target` (UUID-id).
> Across all SAFE cases the model **raw-wanted `verified` 79 times** and the gate held every one.
> *(This supersedes the earlier single-target 140/70 high-N run, kept as history in `RESULTS.md`.)*

> **M2 — Shared Domain Model (later, NOT started):** a resource/endpoint relationship graph —
> sink upstream observations (proxy/HAR/spec) into a shared layer every module can query, so the
> verifier isn't guessing which paths relate (precedent: RESTler-style request-dependency graph
> from OpenAPI). **Gated on** M1 proving generalization + an evidence-backed list of "what
> downstream actually needs from upstream." **Minimal slice already built (M1.2(B)):** "find the
> attacked object's own state endpoint" (`select_object_state_endpoint`) is the smallest slice of
> this graph and is DONE. The full dependency graph stays M2 — do NOT build it now.
>
> **Strategic radar (decide later, do NOT act now):** black-box (deployable, but a fundamental
> ceiling on truly-silent writes whose effect surfaces through *no* endpoint) vs. an optional
> gray-box mode (log/instrumentation ingestion, à la BACFuzz) for higher-assurance confirmation.

## What is proven (committed, in tests / measured)

- **Rule oracle** (`fuzzer._differential_verdict`, 3-value `verified`/`suspicious`/`failed`)
  — unchanged, offline-tested (`test_verdict_oracle.py`).
- **Deep verifier integrity floor** — the 4th verdict `inconclusive`, the prompt
  decisive-evidence / same-resource standard, and the deterministic
  `_apply_cross_resource_guard` (B-2.2). Offline-tested (`test_d18_b22_guard.py`).
- **B-1 — confident cross-path verdict** (`37769b3`): catalog semantics
  (`tags`/`operationId`) + deterministic code-side write-record gathering (HALF 1) +
  a structural content-match guard exemption (HALF 2). **Live-measured** (shadow, N=5,
  gemini-2.5-pro): X-CROSS→`verified` 5/5, X-SAFE→`inconclusive`/safe 5/5 (**no false
  positive**), reverse-guards intact (P0-PROFILE `verified`×5 / P0-AVATAR `failed`×5) —
  `scripts/audit/shadow_b1step3_code_gather_measure.out.txt`. **Locked by** an
  automated mock-Gemini regression test that runs the real `execute_deep_verification`
  end-to-end (`test_d18_b1_shadow_integration.py`, closes D22) plus offline unit tests
  (`test_d18_b1_write_record.py`).
- **M1.1 — read-type semantic-equivalence** (this commit): two read paths expose the SAME
  object; responses shaped **equal-length** so the rule oracle stalls at `suspicious` and the
  **AI must judge by semantic content, not size**. Adds structured evidence — the verdict
  carries `evidence_path` + a code-computed `anchoring_result` (AI makes the semantic call,
  code anchors it; **corroboration, observe-only, not an oracle**). **Live-measured** (shadow,
  N=5): X-EQUIV-VULN→`verified` 5/5 (`owner_id` anchoring `confirmed`), X-EQUIV-SAFE→`failed`
  5/5 (**0 false positives**) — `scripts/audit/shadow_m1_xequiv_run.out.txt`. Offline test:
  `test_m1_evidence_anchoring.py`.
- **M1.2 anchoring** (`2cac345`): evidence anchoring extended (observe-only) to bind
  **caller-identity** (`_anchor_caller_identity` — the read-back object is the victim's, not the
  caller's) and **payload-causality** (`_anchor_payload_causality` — THIS attack's unique value
  actually landed). Tests pin that caller-identity `confirms` for **both** a real leak and a
  securely-dropped write, so only **payload-causality** separates them (the D19 gating constraint).
- **M1.2 HALF-1 object-scope** (this commit): B-1's HALF-1 used to force-gather the single
  **global** write-record for ANY silent write, even one it doesn't record — hijacking the
  follow-up. HALF-1 now **probes the candidate once and gathers only if the record holds the
  caller's own (baseline, definitely-landed) write** (`_record_is_relevant_to_write`, reusing the
  B-1 content-match unchanged with the caller's id); otherwise it **steps back** and the model
  reads the object's own state. B-1 preserved (X-CROSS/X-SAFE audit carries the caller row);
  offline-tested both ways (`test_m12_object_scope.py`). No guard / content-match / verdict change.
- **M1.2 — silent write confirmed via a code-gathered object-STATE read-back** (`e4d5317`).
  Three parts, all target-agnostic:
  - **(A) state-readback exemption** (`STATE_READBACK_EXEMPTION_REASON`) — a SECOND guard-exemption
    channel, **DISJOINT** from B-1's write-record exemption (never fires on a write-record path),
    `verified`-only, cross-path-only. It exempts a cross-path STATE read-back from the B-2.2
    downgrade **only** when code AND-confirms all three anchors: **(1)** owner==attacked ∧
    **(2)** caller!=owner (`_anchor_caller_identity == "confirmed"`) **and (3)** payload-causality
    (`_anchor_payload_causality` confirmed — THIS attack's UNIQUE value present). **(3) is the
    non-negotiable false-positive gate:** (1)+(2) hold for BOTH a real leak and a securely-dropped
    write; only the unique value landing separates them.
  - **(B) deterministic object-state gather** (`endpoint_catalog.select_object_state_endpoint`) —
    resolves the attacked object's own state endpoint GENERICALLY (resource-noun + object-scoped
    `{template}` bound to the attacked id; record/log endpoints excluded so the two channels stay
    disjoint; returns `None` rather than fabricating). Mirrors B-1's HALF-1. **The resolver is only a
    FETCHER — the three-AND gate remains the VERIFIER**, so a wrong gather degrades to `inconclusive`,
    never to a false positive. Gather went **0/5 → 5/5**.
  - **(C) prompt carve-out** — `SYSTEM_PROMPT` rule 5 (plus `_TURN2_TEMPLATE` and the options-block
    verdict definitions) now names three decisive cases: same-path, an explicit write-record, **or a
    read of the attacked object's own state that the SYSTEM ITSELF gathered**. Restricted to
    system-gathered reads; a model-chosen different path is still non-decisive. This resolved a real
    prompt/code contradiction (the model was obeying rule 5 and answering `inconclusive` while holding
    decisive evidence) and lifted VULN **3/5 → 5/5**.
  - **Live-measured** (shadow, N=5, gemini-2.5-pro, `scripts/audit/shadow_m12c_prompt_carveout_run.out.txt`):
    X-SILENT-VULN→`verified` **5/5** (causality `confirmed_at_path` 5/5, exemption 5/5);
    **X-SILENT-SAFE→`verified` 0/5** (causality `absent` 5/5 → no exemption → `inconclusive`);
    B-1 X-CROSS→`verified` 5/5 and B-1 X-SAFE→0 `verified` (**not regressed**). Offline both ways:
    `test_m12_state_readback_exemption.py` + `test_m12b_state_gather.py` (foreign-spec genericity proof,
    B-1 precedence, no-fabrication, and a model-chosen cross-path read that stays `inconclusive`).
  - New target ground truth X-SILENT-VULN (`POST /api/users/{id}/gizmo`) / X-SILENT-SAFE (`.../sprocket`),
    byte-verified in `vulnerable_target/test_vulns.py`.
  - **Design principle (reinforced):** confirmation must NOT rely on the model *realizing* it should
    fetch other evidence — code deterministically gathers the evidence, the model only does the
    irreplaceable semantic read (prompt-nudging to self-discover was tried at B-1, 0/20 — not the path).
  - **OPTIONAL hardening (recorded, NOT done):** the prompt restricts case (c) by **provenance**
    (system-gathered) while the code gate keys on **evidence** (the three anchors, not provenance).
    Aligning them = adding `followup_is_code_gathered` to `_state_readback_decisive` — one line, and it
    could only ever make the gate **stricter**. Not required for correctness (a unique fuzzer value can
    only appear in the victim's object if this attack put it there, whoever chose the path).
- **M1.3 — delete-type confirmed by a NEGATIVE ASSERTION** (this commit). The proof is a
  from-EXISTS-to-ABSENT jump, not a value appearing, so payload-causality does not apply:
  - **PRE-FLIGHT read (the coincidence gate).** For a DELETE attack the CODE reads the victim
    object's own state BEFORE issuing the delete (scope-locked, reusing the M1.2(B) resolver) and
    caches it. "It vanished" only proves a delete if "it existed and was active just before" is
    anchored. **No pre-flight existence proof -> NEVER `verified`.** A pre-flight failure is not
    fatal: it just leaves existence unproven, so the verdict stays `inconclusive`.
  - **DUAL-TRACK negative assertion** (`_anchor_negative_assertion`): decisive on **physical**
    removal (404/403/410) **or** **logical/soft** deletion (200 with a lifecycle field flipped to a
    deleted value — detected by a generic vocabulary via `_deletion_signal`: string statuses,
    boolean flags `is_deleted`/`is_active`, timestamp markers `deleted_at`). **404 is deliberately
    NOT hardcoded as the only proof of vanishing** — real APIs mostly soft-delete.
  - **A THIRD, DISJOINT exemption channel** (`DELETE_READBACK_EXEMPTION_REASON`), `verified`-only,
    cross-path-only, gated on caller-identity computed on the **PRE-FLIGHT body** (the AFTER read of
    a physical delete is a 404 with no owner to anchor on) **AND** the negative assertion. Disjoint
    by construction: a DELETE carries no written value, so the M1.2 state channel (payload-causality)
    and B-1's write-record channel can never fire for it.
  - **Also fixed:** a DELETE no longer triggers B-1's write-record gather. With no written values the
    M1.2 object-scope probe was skipped and `_object_scoped` defaulted to the B-1-safe `True`, so
    HALF-1 wrongly grabbed the audit-log and preempted the object-state gather. Provably safe:
    B-1's exemption *requires* written values, so that channel was unreachable for a delete anyway.
  - **Live-measured** (N=5 each, gemini-2.5-pro, fresh-seeded per run,
    `scripts/audit/shadow_m13_delete_run.out.txt`): X-DELETE-VULN-HARD→`verified` **5/5**
    (`confirmed_physical`, pre-flight 200); X-DELETE-VULN-SOFT→`verified` **5/5**
    (`confirmed_logical`); **X-DELETE-SAFE→`verified` 0/5** (`still_present`);
    **X-DELETE-CONTROL→`verified` 0/5** (`preflight_absent`: the AFTER read was *also* 404, but
    nothing was proven to exist — the coincidence gate held). **No regression**: B-1 X-CROSS
    `verified` 5/5, X-SILENT-VULN `verified` 5/5, X-SILENT-SAFE 0 `verified`. All three exemption
    channels stayed disjoint (each case fired exactly its own).
  - **Auditability (observe-only):** the result also surfaces `preflight_caller_identity_anchor` —
    the caller-identity value the delete gate ACTUALLY used (pre-flight body), because the
    general-purpose `caller_identity_anchor` is computed on the AFTER read and reads
    `owner_not_found` on a 404, which would misrepresent the evidence chain in a transcript.
  - New target ground truth: X-DELETE-VULN-HARD (`DELETE /api/users/{id}/relic`),
    X-DELETE-VULN-SOFT (`.../badge`), X-DELETE-SAFE (`.../seal`), byte-verified in
    `vulnerable_target/test_vulns.py`. Offline: `test_m13_delete.py` (incl. foreign-spec genericity).
- **Same-path cases resolve correctly** — AI **8/8**, 0 false-pos / 0 false-neg. See
  `vulnerable_target/benchmark/RESULTS.md`.

## Honest limits (do not over-read the green)

- **Five vuln shapes, TWO targets, one model.** X-CROSS (write→write-record), X-EQUIV (read-type
  semantic equivalence), X-SILENT (write→object-state), X-DELETE (delete→negative assertion), X-MASS (mass-assignment→
  low-entropy state jump). nested-object, multi-step, and noisier real audit logs are untested.
  "Mechanism proven on these classes," not "verifier finished." **N and target-diversity are no longer
  the thin dimensions:** the GOLDEN record is **300 SAFE/control + 130 VULN runs, 0 FP** across
  **two structurally-different targets** (`vulnerable_target` integer-id + `depot_target` UUID-id).
  The genuine remaining gaps are now **model-diversity** (only gemini-2.5-pro), **arbitrary real
  APIs** (these are two self-built labs), and the D24 read-gate boundaries (threshold calibrated on
  lab data / raw bodies; public-shared-resource residual gap; per-deployment credentials).
- **Post-fix live no-regression: CONFIRMED across all five shapes, now on two targets.** The
  authoritative record is the GOLDEN two-target run (`scripts/measure/results/sweep_highN.jsonl`);
  the single-target high-N run below (`scripts/audit/shadow_highN_*`) is superseded history. With
  the M1.4 routing fix in place: B-1 X-CROSS `verified` **10/10** (still `write_record_readback_decisive`),
  X-SILENT-VULN `verified` **10/10**, X-EQUIV-VULN `verified` **10/10**, X-DELETE-VULN-HARD/SOFT
  `verified` **10/10** each (`confirmed_physical` / `confirmed_logical`), X-MASS-VULN present + missing
  `verified` **10/10** each, and **every SAFE/control case 0 `verified`** across N=20 (X-SILENT-SAFE
  `no_jump`, X-DELETE-SAFE `still_present`, X-EQUIV-SAFE `value_mismatch`, both X-MASS-SAFE, the
  no-jump CONTROL, and B-1 X-SAFE). X-SILENT-VULN now exempts via `state_jump_causally_decisive` rather
  than `state_readback_causally_decisive` — **that is the routing fix working as designed** (a pre-flight
  baseline exists, so the stricter gate governs); the verdict is unchanged.
- **Black-box boundary (mapped, M1.2):** a silent write with **no same-path GET and no relevant
  write-record** is **NOT confirmable by the model's unaided follow-up** — the model does not, on its
  own, fetch a *different* resource path that exposes the attacked object's state (measured 0/5; it
  tried the same-path GET → 405, or an empty log). M1.2(B) closes this by having **code** steer it to
  the object's state path. What remains a fundamental black-box limit is a truly-silent write whose
  effect surfaces through *no* endpoint at all.
- **Payload-causality assumes a HIGH-ENTROPY written value.** The anti-false-positive gate works by
  finding THIS attack's unique injected value in the read-back. On **low-entropy** fields (booleans,
  small integers, enums) — or under concurrent runs writing the same value — the value can collide and
  the gate could confirm causality it did not cause. Real boundary; see ROADMAP "Future / deferred".
- **The final verdict still leans on the model reading the log.** Code *gathers* the
  evidence (deterministic); Gemini still *interprets* it (raw `verified` 5/5 here). A
  model-specific pillar — re-run the benchmark on any model swap.
- **Gate hardened (D23 + D23b ✅ both fixed):** `_write_record_content_match` used to match
  against *any* scalar of a record — including the record's own primary key — on **both** axes,
  so a dirty/accumulated log could false-match and fire the exemption on a SECURE control.
  Now: the **id** check binds to an **owner/subject-style key** (D23) and the **value** check
  binds to **non-primary-key content fields** (D23b) — both by generic, camelCase-aware
  vocabulary; bare `id`/`pk` excluded from both. Each is a strict subset of the old scalar set,
  so the gate only got **stricter**; both are proven by offline tests that fail against the
  pre-fix code. One narrow sibling accepted on purpose (see TECH_DEBT D23b).
- **Promotion (D19) — implemented, default OFF.** The capability to promote `suspicious→verified`
  exists and passed acceptance (clean 430/430, golden-anchored, 0 SAFE promoted;
  `scripts/measure/results/sweep_highN_d19.jsonl`), but `AI_DEEP_VERIFY_PROMOTE` defaults `False`,
  so the shipped default is still observe-only and the persisted verdict is the rule oracle's unless
  promotion is explicitly enabled.

## Uncommitted right now (working tree)

- **Proxy Radar tab (frontend)** — `preview_dashboard.html` gains the Step-9 proxy UI
  (start/stop, live SSE stream, flows list, "send to Hunter"). Backend `/proxy/*` routes
  already existed and are tested; this is the UI wiring. **Left uncommitted on purpose** —
  it belongs to the later frontend phase, not the verification milestones.
- `scripts/audit/` measurement drivers + `*.out.txt` transcripts — kept untracked
  (throwaway harnesses / evidence), not committed.

> Everything else (docs restructure, B-1/M1.0, D22, D23, D23b, M1.1, and M1.2 A/B/C) is committed.

## Runtime posture (defaults)

- **AI deep verifier is OFF by default.** Two gates, both default `False`:
  `AI_DEEP_VERIFY_ENABLED` and `AI_DEEP_VERIFY_SHADOW`. Both must be `True` for a live
  Gemini call. With defaults, Phase 7 is a no-op and the engine behaves as the committed
  rule-oracle path.
- **The real spec source is now a declared config field (D21 ✅).** The shadow pass reads its
  OpenAPI spec from `settings.AI_DEEP_VERIFY_OPENAPI_SPEC` — a first-class `Optional[str]` path
  settable from `.env`/env (resolved to a parsed spec + fail-safe to placeholder at the fuzzer
  consumption point). **With nothing set, the catalog stays the byte-identical placeholder.**
- **No authentication** on any API route (TECH_DEBT **D2**) — keep bound to localhost.

## Deferred on purpose (do not invest until the moat is broadened)

Authentication (D2), multi-tenancy, Alembic migrations (D1), Postgres, hosted
deployment — parked until a benchmark justifies them.

## Immediate next steps

> **M1 is COMPLETE — all five shapes done** (B-1/M1.0, M1.1, M1.2, M1.3, M1.4), live-measured at high N,
> **0 FP**. The design principle they proved — **code deterministically gathers the evidence; the model
> only does the irreplaceable semantic read** — is a standing discipline in
> [`ROADMAP.md`](./ROADMAP.md) §6. The full deferred/rejected register lives in ROADMAP "Future /
> deferred" and "Considered and rejected". The ordered next line mirrors ROADMAP §7.

1. **D21 ✅ DONE** — the spec source is now a declared `Optional[str]` config field
   (`AI_DEEP_VERIFY_OPENAPI_SPEC`), a path resolved to a parsed spec at the fuzzer consumption
   point with a fail-safe to the placeholder; in-process dict injection still works (back-compat).
   Zero regression (unset → byte-identical placeholder), locked by `test_d21_spec_config.py` (8).
2. **Broaden the proof — ✅ SECOND TARGET DONE.** The mechanism is now proven on a **second,
   structurally-different target** (`depot_target`, UUID ids): the GOLDEN two-target run is
   **300 SAFE/control + 130 VULN runs, 0 FP** (`scripts/measure/results/sweep_highN.jsonl`). Building
   the second lab also surfaced and closed a SEV-1 (D24: the read-semantic shape had no code gate).
   **Still open on this axis:** a **second model** (only gemini-2.5-pro), and **arbitrary real APIs**
   (these remain two self-built labs). The reproducible harness is `scripts/measure/` (see REPRODUCE.md).
3. **D19 — ✅ landed as a default-OFF capability** (choke point + single writer + `owner_view_corroborated`;
   clean 430/430 golden reproduction). Promotion resolves only the rule oracle's `suspicious` band, only
   under a deterministic authorizer. **Enabling it in a real-target flow still waits on the proof being
   broadened (Node 3).**
   - **Gating constraint (from M1.2 anchoring, narrowed by M1.4):** the authoritative gate must key on
     **payload-causality — or, whenever a pre-flight baseline exists, the stricter state-jump gate** —
     **never caller-identity**, which `confirms` for BOTH VULN and SAFE (a dropped cross-user write
     still leaves the object owned by the victim). Only the causality / state-jump anchor separates a
     real leak from a securely-dropped write.
4. **Scope-lock hardening — ✅ DONE.** One audited `ScopePolicy` now governs active
   (`_send_request`: fail-closed + per-hop redirect + resolved-IP DNS-rebinding guard) AND
   passive (proxy/pruner) host decisions; unified `scope`+`model` declaration; over-broad-wildcard
   rejection (vendored PSL); SecretStr key privacy; adversarial + one-decision-tree tests.
   Residual: IP-pinning follow-up (small DNS TOCTOU window) — see TECH_DEBT D25. Still before a
   real target: model/target diversity; retire the legacy `frontend/` (D5).
