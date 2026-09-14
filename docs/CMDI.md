# CMDI — OS command injection, confirmed out-of-band

OS command injection is the **third** vulnerability type Aivist Verify confirms, and the **second**
to use the out-of-band (OOB) proof shape pioneered by [SSRF](./SSRF.md). The discipline is identical:
`CONFIRMED` is reserved, by construction, for a **deterministic proof** — here, a real interactsh
callback whose unique token matches the one the detector injected on that candidate. There is no other
path to `CONFIRMED`; a weaker inference lead is `SIGNAL` at most, and no callback is `REFUTED`.

Reachable via `aivist cmdi`. Code: [`backend/app/services/cmdi_detector.py`](../backend/app/services/cmdi_detector.py)
and [`backend/app/cli/cmdi_command.py`](../backend/app/cli/cmdi_command.py); lab
[`cmdi_target/`](../cmdi_target/). No LLM key is needed — cmdi is confirmed by a physical callback, not a model.

## How it confirms (and why a bluff can't)

1. The detector opens an interactsh session and mints a **unique** probe domain carrying a per-probe
   **token** (reusing the audited OOB client [`services/oob/`](./OOB.md) — it is not forked).
2. It builds a battery of command-injection payloads — every shell **context** (`;` `|` `&` `&&` `||`
   newline `$(…)` backticks, covering POSIX sh and Windows cmd.exe) crossed with a callback **command**
   (`nslookup <domain>` for DNS, `curl` / `wget http://<domain>/` for HTTP). It mints a **unique domain
   (hence a unique token) per payload** and injects each into the candidate parameter (query or body).
3. It sends the requests to the target, recording a token as **injected** only when its request was
   **actually dispatched**, then polls the OOB session. When the target's shell executes an injected
   command, it resolves/fetches that payload's unique domain, and interactsh records the interaction.
4. **`CONFIRMED` only when a received interaction's token corresponds one-to-one to a payload we
   ACTUALLY INJECTED into this candidate on this probe** (`matched_token ∈ injected_tokens`) — an
   **injection-causal** link, not merely "a token belonging to this session." The OOB session's own
   correlation drops any interaction against an id we never minted (a confused-deputy / replay); and a
   token we minted but never dispatched — a send that errored, a token from a different candidate's probe,
   or a coincidental / polluted-infra callback carrying some other session token — is **not** in
   `injected_tokens` and therefore cannot confirm. Because tokens are unique per injection, the confirmed
   proof also names *which* payload landed. The interaction is handed to the tiered framework as a
   `DeterministicProof` (channel `cmdi_oob_callback`); `Verdict.confirmed` refuses to exist without one,
   and the detector's `max_tier = CONFIRMED` ceiling is enforced by `classify()`
   ([`verdict_tiers.py`](../backend/app/services/verdict_tiers.py) — unchanged, shared).

**What `CONFIRMED` means (and its precondition):** "a command **we injected** into this candidate
triggered a **token-matched** out-of-band callback." **Trusted OOB infrastructure is a precondition** —
the guarantee holds against the *target*, not against a malicious interactsh server that fabricates a
callback for a token it observed us inject; a self-hosted or trusted public interactsh instance is
assumed. This is the honest boundary of the deterministic claim.

**Weaker signals are `SIGNAL`, never `CONFIRMED`:** an echoed command marker in the response, or a
response slow enough to suggest a blocking injected command (a time delay), is reported as `SIGNAL` — a
lead to verify by hand. No callback and no lead → `REFUTED`. Could not probe (no reachable interactsh
server) → `NOT DATA`. The weaponized payload strings and raw tokens are never logged; the result carries
the matched proof domain and the counts (payloads tried / actually injected), not the raw commands.

## Run it

```powershell
python -m uvicorn cmdi_target.main:app --port 8005          # a local lab (REAL /diag, SAFE /diag-safe)
python run.py cmdi --config examples\run.cmdi_real.json     # -> [CONFIRMED] on a real callback (exit 1)
python run.py cmdi --config examples\run.cmdi_safe.json     # -> [REFUTED] (no callback; exit 0)
python run.py cmdi --target-file mytarget.toml              # a saved query-param Target (like verify)
```

Config: `base_url`, `path`, `param`, `method`, `param_location` (`query`|`body`), optional
`scheme` / `oob_server` / `poll_seconds`. Exit codes: **1** CONFIRMED · **0** refuted or signal ·
**2** NOT DATA. Needs **outbound network** and a reachable public interactsh server; an optional
`TARGET_ATTACKER_TOKEN` (env only, never logged) is sent if the sink sits behind auth.

## The lab (ground truth)

[`cmdi_target/`](../cmdi_target/) is a deliberately-insecure, self-contained FastAPI app:

- `GET /diag?host=` — **REAL**: concatenates `host` straight into a shell command with no
  sanitization, so an injected separator runs whatever it likes (returns only a status, never the
  command output — confirmation is purely out-of-band).
- `GET /diag-safe?host=` — **SECURE**: validates `host` against a strict allow-list regex
  (`[A-Za-z0-9.-]` only) and refuses any payload carrying a space or shell metacharacter with 400, so no
  command runs and no callback can occur.

Ground truth is proven independently by [`cmdi_target/test_vulns.py`](../cmdi_target/test_vulns.py)
(a marker-file side effect stands in for the OOB server — no network), which is **not** part of the
statistical zero-false-positive benchmark. The cmdi detector's reservation is locked by
[`backend/tests/test_cmdi_detector.py`](../backend/tests/test_cmdi_detector.py) — including that a
non-matching-token callback never confirms, that the SAFE control is never `CONFIRMED`, and that a
time-delay-only lead classifies as `SIGNAL`.

> **Honesty boundary.** cmdi confirmations are a real, deterministic capability, but they are **not**
> folded into the 430-run statistical zero-false-positive benchmark (which is access-control on two
> controlled labs). cmdi's guarantee is structural: `CONFIRMED` requires the token-matched OOB callback.
