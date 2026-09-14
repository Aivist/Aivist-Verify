# Aivist Verify — Architecture

> Audience: a developer reading the code for the first time. This describes what the system
> **is** and how the pieces fit, grounded in the current source tree. It is a **local
> command-line tool** — a BOLA/IDOR access-control *confirmation* engine. There is **no server,
> HTTP API, or web UI**; `run.py` (the `aivist` command) is the only entry point.
>
> Companion docs: [`VERIFY_ENGINE.md`](./VERIFY_ENGINE.md) (the differential oracle),
> [`DEEP_VERIFY.md`](./DEEP_VERIFY.md) (the deep verifier + guard), [`PROJECT_OVERVIEW.md`](./PROJECT_OVERVIEW.md)
> (orientation), [`../RESULTS.md`](../RESULTS.md) / [`../REPRODUCE.md`](../REPRODUCE.md) (the evidence).

---

## 1. What it is

You give Aivist Verify a **candidate** — an endpoint plus two identities (an attacker and an
owner) — and it tells you, with a reproducible evidence chain, whether the attacker identity
actually crosses a user boundary into the owner's resource. It is a *confirmation* layer, not a
scanner and not a red-team tool, and it runs locally against targets you control.

The whole value is that **a model can never talk it into a false positive.** That property is
structural, and it lives in the two-layer verdict pipeline below.

## 2. The verdict pipeline — AI proposes, code disposes (downgrade-only)

```
 candidate (endpoint + attacker/owner identities)
        │
        ▼
 [ AI proposes ]   the model reads the real baseline/attack traffic and proposes a candidate
        │          verdict; it may request ONE extra evidence fetch, executed for real.
        ▼
 [ CODE disposes ] deterministic gates re-check the proposal against the attack's own runtime
        │          bytes. They can only DOWNGRADE. A `verified` survives only if a structural
        │          exemption, computed in code, actually holds.
        ▼
 verdict + evidence chain   (raw model verdict AND the gate's decision, recorded separately)
```

### Layer 1 — the differential oracle (`backend/app/services/fuzzer.py`)

`_differential_verdict(baseline, test_result, payload_instruction)` is deterministic. It sizes
the baseline vs. attack responses and applies Rules 1–5 (server-error; BOLA/IDOR status+length
divergence; mass-assignment; generic divergence; status change), then a **Veto** (a 200 OK whose
body carries an explicit denial string is forced back to `failed`) and an **Escalation** (a
`suspicious` row becomes `verified` only when sensitive keys appear in the attack response that
were absent from the baseline). No model output is an input to this function.

### Layer 2 — the cross-resource guard + four exemption channels (`backend/app/services/deep_verifier.py`)

`_apply_cross_resource_guard(...)` is the structural backstop. If a decisive verdict rests on a
follow-up read-back of a **different concrete resource** than the one attacked, it is downgraded
to `inconclusive`. The guard never upgrades. A cross-path `verified` is kept decisive **only**
when one of four exemptions — each computed in code from the attack's own runtime parameters and
the read-back bytes, never the model's say-so — holds:

| Channel (engine constant) | Shape it confirms |
|---|---|
| `write_record_readback_decisive` | cross-user write (a record carries the victim's id + this attack's written value) |
| `state_readback_causally_decisive` | silent write / object-state (attacked object's own state now carries the injected value) |
| `delete_readback_negative_assertion_decisive` | delete (pre-flight proved it existed; post-attack read shows it gone/soft-deleted) |
| `state_jump_causally_decisive` | mass-assignment (every sent field jumped from a known pre-flight state to the injected value) |

A fifth shape, **read-type semantic equivalence**, is confirmed by a separate owner-view
corroboration gate (D24): the attacker's response must match an independent re-fetch of the
victim's object *as the victim*. The result object records the model's **raw** verdict
(`ai_verdict_raw`) and the gate's decision (`guard_override`) as **separate fields**, so the
evidence chain literally reads "the model proposed X; code decided Y." Neither the engine nor the
CLI renderer (`backend/app/cli/confirm_render.py`, which reads the verdict from engine fields
only) can manufacture a `verified`.

## 3. The CLI surface (`run.py` → `backend/app/cli/`)

`run.py` at the repo root is the `aivist` command (registered via `pyproject.toml`
`[project.scripts]`). With no arguments it opens the interactive console; otherwise it dispatches
subcommands:

- **`verify`** — confirm one finding. *Golden path* (recommended, real target): `--target-file` — a
  saved Target whose op is built via `build_op` / `Target.to_op()` and whose spec is synthesized via
  `spec_from_endpoints` when absent, so no hand-authored `--op` / `--spec` is needed (standalone; combining
  it with the advanced flags is a fail-loud error). *Lab mode* (`--caseset [--case]`) against a built-in
  ground-truth caseset; *advanced external mode* (`--target --spec --op [--auth]`) for a custom body /
  accounts / exotic shapes. Code: `backend/app/cli/external_verify.py`
  (`run_verify_from_target_file` builds the inputs, then the unchanged core runs).
- **`scan`** — non-interactive auto-discovery + confirm; the model proposes candidates, code vets
  each, and the same confirm runs on every one. Code: `backend/app/cli/scan_run.py`,
  `scan_discovery.py`, `scan_ids.py`, `scan_report.py`.
- **`run --config <json>`** — the fully non-interactive CI entry: JSON in, structured JSON to
  stdout, tokens from env only. Code: `backend/app/cli/run_command.py`.
- **`ssrf --config <json>`** — confirm SSRF out-of-band (the first non-access-control type); a
  CONFIRMED requires a real interactsh callback. Code: `backend/app/cli/ssrf_command.py`. See §9.
- **`demo`** — zero-setup confirmation of a real cross-user write on the built-in lab.
- **`target` / `config`** — save a reusable target file; set the AI provider/key/model.

The interactive console is a presentation layer only (`backend/app/cli/console/`:
`controller.py` holds the logic with I/O injected; `text_view.py` / `tui_view.py` are the stdlib
and prompt_toolkit front-ends; `launcher.py` owns terminal-restore safety). It reuses the same
engine calls — it structurally cannot manufacture a verdict.

## 4. Supporting layers (inputs to the engine, not the verdict)

- **Endpoint discovery** (`services/endpoint_catalog.py`) — builds a catalog from an OpenAPI
  spec, a plain `METHOD /path` list, a captured-traffic file (`cli/scan_traffic.py`, HAR /
  raw-HTTP), or a live mitmproxy capture (`cli/scan_capture.py` + `proxy/capture_addon.py`, a
  standalone mitmdump addon with clean process-tree teardown).
- **Token sourcing** — the three roles come from `TARGET_ATTACKER_TOKEN` / `TARGET_OWNER_TOKEN` /
  `TARGET_BYSTANDER_TOKEN` (or a `--tokens-file` read at use-time, never persisted). Each becomes
  a `SecretStr`, routed per-account; an `attacker == owner` collision is refused fail-closed
  before the engine runs.
- **Authenticated re-login (`--auth`)** (`cli/relogin.py`) — instead of static tokens, `verify`
  and `scan` can obtain (and refresh) tokens from a login flow described in a JSON `LoginSpec`.
  Three independent per-account `TokenProvider`s (attacker / owner / bystander) are built with
  **zero shared state** (identity isolation), each proactively refreshing on JWT expiry and
  reactively on a 401. What it supports:
  - **Token location** `body` / `header` / `cookie` (`_extract_token`, `_TOKEN_LOCATIONS`) — the
    token is read from a JSON field, a response header, or a `Set-Cookie`.
  - **Multi-step / CSRF login** (`_run_login_sequence`) — an ordered step list that can extract a
    value (body / header / cookie / regex — e.g. an anti-CSRF token) and inject it into a later
    step, per-account, with each hop scope-re-checked.
  - **OAuth 2.0** (`_run_oauth_grant`) — both **resource-owner-password** and **authorization_code
    + PKCE (S256)** grants, with the authorization-code capture scope-checked per redirect hop.
  - **D28 owner-only mid-run refresh** (`external_verify._owner_view_auth_degraded` /
    `_verify_external_relogin`) — if the owner token expires mid-run (the owner-view read returns
    401), only the **owner** provider is refreshed and the run retried once; the attacker/bystander
    providers are untouched, and the fresh owner token flows only into `owner_credential`, never an
    attack request.
  Deliberate non-goals (never built): MFA/2FA bypass, captcha solving, third-party consent-screen
  scraping, credential brute-force — a failed/misconfigured flow yields `NOT DATA`, never a verdict.
- **Scope lock + remote hardening** (`services/scope.py`, `scope_psl.py`, `services/remote_safety.py`)
  — one audited host-scope policy; every outbound request is scope-checked fail-closed at the
  `_send_request` chokepoint. For remote use it also refuses cloud-metadata / link-local addresses,
  refuses a public name that resolves to a private/loopback IP (DNS rebinding), pins the connection
  to the scope-validated IP with `Host`/SNI preserved (closes the DNS-TOCTOU), and re-validates each
  redirect hop. `remote_safety.preflight()` runs this same policy once up front for a clear early
  refusal. See §7.
- **AI provider seam** (`services/llm/`) — a small `get_provider()` factory over Gemini
  (default), OpenAI-compatible, and Anthropic. Only the model *call* sits behind it; the verdict
  logic is untouched. See [`LLM_PROVIDERS.md`](./LLM_PROVIDERS.md).
- **DB/ORM as support, not verdict path** — `core/database.py` (SQLAlchemy async + aiosqlite) and
  `models/scan.py` (the ORM) are imported by the fuzzer at module load, but the `verify` /
  confirmation path does not depend on persisted state to reach a verdict; the DB is optional
  support, not part of the adjudication.

## 5. The labs and their independent ground truth

The engine is graded against **four** structurally different, self-contained vulnerable labs, each
shipping its **own** ground-truth pytest suite (no API key required):

- `vulnerable_target/` (integer ids) + `vulnerable_target/test_vulns.py`
- `depot_target/` (UUID ids) + `depot_target/test_vulns.py`
- `query_target/` (query-string / non-path IDOR, **D29**: `GET /reports?report_id=` REAL vs
  `GET /notes?note_id=` SAFE) + `query_target/test_vulns.py` — the confirmer expresses, attacks, and
  owner-view-corroborates an id carried in the **query string** exactly as one in the path.
- `ssrf_target/` (SSRF: `GET /fetch?url=` REAL vs allow-listed `GET /fetch-safe?url=` SAFE) +
  `ssrf_target/test_vulns.py` — ground truth for the OOB SSRF detector (§9), proven with a local
  canary, no interactsh needed.

These suites prove — against the live target's real bytes, with no involvement from the verifier —
that every case labelled REAL is genuinely exploitable and every case labelled SECURE genuinely
resists it. They are the oracle: the engine is measured against them, never the reverse. The
**access-control** zero-FP measurement harness (`scripts/measure/verdict_measure.py`) drives the real
`execute_deep_verification` across the two original labs and writes the committed evidence artifact
(`scripts/measure/results/sweep_highN.jsonl`, 430 rows); SSRF is confirmed model-free out-of-band and
is deliberately not part of that model-graded benchmark. See [`../RESULTS.md`](../RESULTS.md).

## 6. End-to-end flow

```
candidate ──► assemble op (endpoint + ids + tokens)  [cli/external_verify or scan_run]
          ──► execute_deep_verification                [services/deep_verifier]
                 ├─ baseline + attack sent (scope-locked, SecretStr auth)  [services/fuzzer]
                 ├─ AI proposes a verdict (may request ONE follow-up)      [services/llm]
                 └─ code disposes: differential oracle + cross-resource guard + 4 channels
          ──► DeepVerificationResult (ai_verdict_raw, guard_override, anchors, evidence)
          ──► render evidence chain                    [cli/confirm_render]
```

It is a local CLI tool end to end: no listening socket, no authentication of its own, and it only
ever acts as the identities whose tokens you supply, against the single target you point it at.

## 7. Remote-target support & safety

The confirmer targets a **local or an authorized remote** base URL with the SAME verdict logic — the
host being remote changes nothing about how a verdict is reached. What remote use requires is egress
safety on the confirmer's *own* requests, and that lives entirely in the scope/networking layer
(never the verdict path):

- **Scope-lock fail-closed** to the declared target (`ScopePolicy`); an out-of-scope request raises
  `ScopeViolationError` before the socket opens.
- **SSRF / DNS-rebinding guard**: cloud-metadata (`169.254.169.254`) and link-local addresses are
  always refused; a *public registrable* name that resolves to a private/loopback IP is refused as
  rebinding. An explicitly-declared private/loopback target (a lab, an authorized internal host) is
  honored.
- **Resolved-IP pinning** (`fuzzer._pin_kwargs`): the connection dials the scope-validated IP with
  `Host`/SNI preserved, so httpx does not re-resolve the name at connect time (closes the DNS-TOCTOU).
  Pinning can only *narrow* to an already-validated address — it can never widen scope.
- **Per-hop redirect re-validation** and the **challenge/rate-limit circuit-breaker** (aborts to
  `NOT DATA` rather than hammer a host). A second, related guard (`_CHALLENGE_PAGE_REASON` in
  `deep_verifier.py`) protects the D24 owner-view corroboration itself: when a would-be
  corroboration rests on a WAF/challenge page — the attack **or** the owner-view response detected
  as a challenge by `_is_challenge_response` — the confirmation is forced to `NOT DATA`. It is
  downgrade-only and gated on a would-be corroboration, so a genuine 200-denial still stays
  `[REFUTED]` unchanged.
- **`remote_safety.preflight()`** runs this one audited policy against the target BEFORE the run, so
  a remote operator gets a single clear "refused: DNS rebinding / metadata / unresolvable" up front
  instead of a mid-run failure. It reuses `ScopePolicy` — it adds no new guard and makes no verdict
  decision; loopback/lab/intranet targets are never resolved by it.

**What remote does NOT change:** the access-control zero-false-positive gate does not depend on
whether the host is remote — the verdict logic reads HTTP evidence, not the address, so a run over
loopback and over a non-loopback address is **designed and code-gated to reach the same verdict**.
That equivalence is exercised by the scope/networking tests (non-loopback hosts driven through the
real `_send_request` via a mock transport + injected resolvers) and was observed in a live session,
but it is **not yet locked by a committed end-to-end test against a real non-loopback socket** —
treat it as designed-and-expected, not demonstrated at that layer. Remote is a networking/scope
capability, not a new class of finding.

## 8. Tiered-verdict framework (`services/verdict_tiers.py`)

An explicit verdict-**strength** layer OVER the existing tiers, so a future vuln type can report at
the right confidence without diluting the access-control guarantee. Tiers: `CONFIRMED` (deterministic
proof) · `SIGNAL` (evidence-inferred lead, needs human review) · `INCONCLUSIVE` (conditional, e.g.
broken-for-all) · `REFUTED` · `NOT_DATA` · `SKIPPED`.

- **Access control maps to `CONFIRMED` exactly as today.** `access_control_verdict()` *delegates* to
  `confirm_render.case_outcome` — there is no second verdict implementation to drift.
- **`CONFIRMED` is reserved by construction** (mirroring how the engine reserves `verified`): (1)
  `Verdict.confirmed()` requires a `DeterministicProof`, which a model opinion cannot mint; (2) every
  finding is emitted through `classify(detector, evidence)`, which refuses any verdict above the
  detector's declared `max_tier`. A non-deterministic detector declares `max_tier = SIGNAL` and
  therefore *cannot* emit `CONFIRMED`.
- **Extension point**: implement the `Detector` protocol (`name`, `max_tier`, `assess`) and emit via
  `classify()`. `InferenceSignalDetector` is a worked, non-wired example of a future response-
  inference detector — it renders `SIGNAL` and is structurally barred from `CONFIRMED`.

The framework is a layer the CLI and future types build on; it does not alter the access-control
confirm / scan output. **Two detectors are wired to it today:** the access-control confirmer
(`AccessControlDetector`, reaching `CONFIRMED` via its code gate) and the **SSRF detector**
(`SsrfOobDetector`, reaching `CONFIRMED` via a real out-of-band callback — see §9). `SIGNAL` remains a
reserved slot for a future inference-only detector (`InferenceSignalDetector` is its non-wired example).

## 9. SSRF confirmation via out-of-band callback (`services/ssrf_detector.py`) — first non-access-control type

The FIRST non-access-control vuln type, and it earns `CONFIRMED` the same way access control does — only
with a physical, code-observed proof. Here the proof is a real **out-of-band callback**: the detector
mints a UNIQUE [interactsh](https://github.com/projectdiscovery/interactsh) domain via the OOB client
(`services/oob/`), injects `http://<domain>/` into the candidate request's URL parameter, sends that ONE
request to the target, and polls the OOB session. A correlated DNS/HTTP interaction — the target's server
actually reaching out to the unique domain — is the `DeterministicProof`; no interaction means `REFUTED`
(probed, nothing came back) or `NOT_DATA` (no reachable interactsh server), **never** a bluffed
`CONFIRMED`. It is ADDITIVE and ISOLATED: it composes the OOB client + `verdict_tiers` and does not import
or touch the access-control engine, its gate, or its verdict path. Reachable via `aivist ssrf --config`.
Needs outbound network + a reachable public interactsh server (the self-test uses `oast.*`; no
self-hosting). See [`SSRF.md`](./SSRF.md).
