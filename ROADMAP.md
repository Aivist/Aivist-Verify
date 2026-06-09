# ROADMAP (HUMAN-OWNED)

> The single source of truth for what this project is, what it is not, and where it's going.
> Anchored on code reality, not aspiration. If a claim here drifts from code, the code wins —
> update this file. Future nodes (human or AI): read this before proposing direction.
>
> **Reading order for the doc set:** this file (why / where) → [`PROJECT_OVERVIEW.md`](./PROJECT_OVERVIEW.md)
> (what exists now + run/verify) → [`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md) (how it's built)
> → component docs ([`docs/VERIFY_ENGINE.md`](./docs/VERIFY_ENGINE.md), [`docs/DEEP_VERIFY.md`](./docs/DEEP_VERIFY.md), …)
> → [`docs/TECH_DEBT.md`](./docs/TECH_DEBT.md) (known gaps & priorities).

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
  > Code reality (at HEAD): nuclei Phase 3 (`nuclei.py::generate_gemini_remediation_patch`) and the
  > Hunter `ai_patch` field still emit Gemini-generated remediation. This non-goal means **winding
  > that down / relabeling it as non-code guidance**, not that it's already gone.
- **Not a generic CVE/template scanner.** nuclei is MIT-licensed (no commercialization blocker)
  but is a category mismatch for stateful, auth-context BOLA. It is quarantined: optional, off by
  default, isolated from the verification core, excluded from the core product story. Final
  keep-vs-cut is a later product call once the moat is proven; invest nothing more in it now.
  > Code reality: nuclei is optional (the binary is not required to boot) and dormant unless
  > `POST /api/v1/scan/start` is called, but it is still a **first-class HTTP route today** —
  > "off by default" is the product stance/quarantine, not a runtime flag-gate.
- **No AI free-chat box in the UI** (re-introduces the trust problem at the UI layer). If ever
  added, it must be read-only and grounded strictly in a finding's evidence trail.
- **No new external tools.** Existing auth-testing tools (Burp Autorize/AuthMatrix; stateful
  fuzzers like RESTler/fuzz-lightyear) are detection-side approaches this engine aims to surpass;
  integrating them is redundant with the core. Keep the dependency surface lean.

## 3. Honest current status (at HEAD)

The verifier is **built and wired into the pipeline (Phase 7), but dormant**: gated off by
default (`AI_DEEP_VERIFY_ENABLED` / `AI_DEEP_VERIFY_SHADOW` both default `False`), observe-only
(judges and logs, never changes the persisted verdict), and the real endpoint catalog/spec is
**not auto-wired** into the flow (read from `AI_DEEP_VERIFY_OPENAPI_SPEC` via `getattr`; set
manually by throwaway harnesses during measurement).

**Verified so far:** same-path cases resolve correctly — AI **8/8** on the same-path set it
judged (case A is confirmed by the rule oracle, not AI-run), **0 false-pos / 0 false-neg**.
Cross-path cases (`X-CROSS` real / `X-SAFE` secure) reach the **integrity floor**: never a false
verdict, stable `inconclusive` — achieved by a prompt evidence-standard + a deterministic
structural cross-resource guard (B-2.2). The verifier's **raw judgment still false-negatives**
the hard cross-path case; the **guard, not model compliance, holds the line**.

**Not yet:** it does not yet *confirm* cross-path bugs (only `inconclusive`); it does not *act*
(shadow-only); it has **no automated test** for the Phase-7 shadow path.

**Bottom line:** the right thing is being built, but the moat is **not yet proven on the hard
case**. B-1 is the proof point.

> Detailed current snapshot (maturity, API summary, run/verify checklist) lives in
> [`PROJECT_OVERVIEW.md`](./PROJECT_OVERVIEW.md); known gaps in [`docs/TECH_DEBT.md`](./docs/TECH_DEBT.md).

## 4. The main line (3 nodes — B-1, D19, scope-lock; not separate tracks)

1. **Judge correctly.** §5 (done): integrity floor — never a false verdict. **B-1 (next):** make it
   actually *confirm* cross-path bugs — carry OpenAPI semantics into the catalog + wire a real spec
   source into Phase 7 + extend the B-2.2 guard with a structural *"write-record read is decisive"*
   exemption (answer key §8). Goal: promote `X-CROSS`/`X-SAFE` from `inconclusive` →
   `verified`/`failed` **without regressing §5 or the reverse-guards**. *(Track in TECH_DEBT.md.)*
2. **Act.** **D19:** promote the AI verdict from observe-only/log to **authoritative** — take over
   the `suspicious` records in the real flow; decide the gating defaults. First time the product
   "does the job." *(TECH_DEBT.md D19.)*
3. **Be safe on real targets.** **Scope-lock hardening** (hard prerequisite before pointing at
   anything beyond localhost / self-built labs): consolidate the duplicated host-scope checks —
   the fuzzer's `_send_request` / `ScopeViolationError` enforcement (`fuzzer.py`) **and** the deep
   verifier's own follow-up pre-check (`deep_verifier.py`), plus the proxy's separate capture-side
   `in_scope` — into one audited implementation; add an adversarial test suite
   (substring / protocol-relative / userinfo tricks); and add runtime out-of-scope probes (don't
   trust config alone). *(Relates to TECH_DEBT.md D2 — no-auth.)*

> **Prove the shadow path (proposed prerequisite for B-1/D19):** there is currently **no automated
> test** for the Phase-7 shadow path; add one so the verifier's integration is a regression asset,
> not a manual harness. Fits the §6 discipline "a green test proves nothing unless something was
> allowed to fail."

**Later / optional:** cost & latency budget; model-degradation handling; the nuclei keep-vs-cut decision.

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

Human owns answer keys (sourced outside the target); verdicts judged on verbatim bytes; the AI
never grades its own work; no claim trusted without being verified against code; small, reversible,
zero-regression steps; every override logged transparently (raw verdict preserved). **A green test
proves nothing unless something was allowed to fail.**
