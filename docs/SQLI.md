# SQLI — blind SQL injection, confirmed out-of-band

Blind SQL injection is the **fourth** vulnerability type Aivist Verify confirms, and the **third** to
use the out-of-band (OOB) proof shape (after [SSRF](./SSRF.md) and OS command injection — cmdi, which
lands via its own branch, `docs/CMDI.md`). The discipline is
identical and the injection-causal lesson from cmdi is baked in from the start: `CONFIRMED` is reserved,
by construction, for a **deterministic proof** — a real interactsh callback whose unique token
corresponds one-to-one to a payload **we actually injected** into this candidate. There is no other path
to `CONFIRMED`; error-based / boolean / time-based blind inference is `SIGNAL` at most, and a callback we
cannot tie to our own injection is `REFUTED`.

Reachable via `aivist sqli`. Code: [`backend/app/services/sqli_detector.py`](../backend/app/services/sqli_detector.py)
and [`backend/app/cli/sqli_command.py`](../backend/app/cli/sqli_command.py); lab
[`sqli_target/`](../sqli_target/). No LLM key is needed — sqli is confirmed by a physical callback, not a model.
(cmdi's `docs/CMDI.md` lands with its own branch; on a tree that has it, see it for the sibling OOB type.)

## How it confirms (and why a bluff can't)

1. The detector opens an interactsh session and, for **each** payload variant, mints a **unique** probe
   domain carrying a per-payload **token** (reusing the audited OOB client [`services/oob/`](./OOB.md) — not forked).
2. It builds a battery of **DBMS out-of-band primitives** — MySQL `LOAD_FILE(CONCAT('\\',…))` (UNC → SMB/DNS),
   MSSQL `xp_dirtree '\\…'`, Oracle `UTL_INADDR.get_host_address(…)` / `UTL_HTTP.request('http://…')`,
   PostgreSQL `dblink_connect('host=…')` — wrapped in common **injection contexts** (string, numeric,
   `UNION`, stacked, Oracle-concat). Each references that payload's unique domain, injected into the
   candidate parameter (query or body).
3. It sends the requests, recording a token as **injected** only when its request was **actually
   dispatched**, then polls the OOB session. When the target's DBMS parses and executes an injected
   primitive, it resolves/fetches that payload's unique domain, and interactsh records the interaction.
4. **`CONFIRMED` only when a received interaction's token corresponds one-to-one to a payload we ACTUALLY
   INJECTED into this candidate on this probe** (`matched_token ∈ injected_tokens`) — an
   **injection-causal** link, not merely "a token belonging to this session." A token we minted but never
   dispatched, a token from a different candidate's probe, or a coincidental / polluted-infra callback,
   cannot confirm. The interaction is handed to the tiered framework as a `DeterministicProof` (channel
   `sqli_oob_callback`); `Verdict.confirmed` refuses to exist without one, and the detector's
   `max_tier = CONFIRMED` ceiling is enforced by `classify()`
   ([`verdict_tiers.py`](../backend/app/services/verdict_tiers.py) — unchanged, shared).

**What `CONFIRMED` means (and its precondition):** "SQL **we injected** into this candidate drove the
DBMS to make a **token-matched** out-of-band callback." **Trusted OOB infrastructure is a precondition** —
the guarantee holds against the *target*, not against a malicious interactsh server that fabricates a
callback for a token it observed us inject.

**Weaker signals are `SIGNAL`, never `CONFIRMED`:** a surfaced SQL error (error-based), or a response slow
enough to suggest a time-based blind, is reported as `SIGNAL` — a lead to verify by hand. No callback and
no lead → `REFUTED`. Could not probe (no reachable interactsh server) → `NOT DATA`. The weaponized SQL
payload strings and raw tokens are never logged; the result carries the matched proof domain and the
counts (payloads tried / actually injected), not the raw SQL.

## Run it

```powershell
python -m uvicorn sqli_target.main:app --port 8006          # a local lab (REAL /report, SAFE /report-safe)
python run.py sqli --config examples\run.sqli_real.json     # -> [CONFIRMED] on a real callback (exit 1)
python run.py sqli --config examples\run.sqli_safe.json     # -> [REFUTED] (parameterized; exit 0)
python run.py sqli --target-file mytarget.toml              # a saved query-param Target (like verify)
```

Config: `base_url`, `path`, `param`, `method`, `param_location` (`query`|`body`), optional
`oob_server` / `poll_seconds`. Exit codes: **1** CONFIRMED · **0** refuted or signal · **2** NOT DATA.
Needs **outbound network** and a reachable public interactsh server; an optional `TARGET_ATTACKER_TOKEN`
(env only, never logged) is sent if the sink sits behind auth.

## The lab (ground truth)

[`sqli_target/`](../sqli_target/) is a deliberately-insecure, self-contained FastAPI app with an
in-process **simulated DBMS** (not a real database — it models the one property that matters: a DBMS
executes SQL *text*, and an OOB primitive in that text drives a reach-out):

- `GET /report?id=` — **REAL**: concatenates `id` straight into the SQL text, so an injected OOB primitive
  is parsed and the DB reaches out (returns only a row count — confirmation is purely out-of-band).
- `GET /report-safe?id=` — **SECURE**: a **parameterized** query — the SQL text is fixed and `id` is bound
  as data, never spliced into the text, so an injected primitive stays inert and no callback can occur.

Ground truth is proven independently by [`sqli_target/test_vulns.py`](../sqli_target/test_vulns.py)
(a local HTTP canary stands in for the OOB server — no interactsh), which is **not** part of the
statistical zero-false-positive benchmark. The detector's reservation is locked by
[`backend/tests/test_sqli_detector.py`](../backend/tests/test_sqli_detector.py) — including that a
non-matching / non-injected-token callback never confirms, that the SAFE control is never `CONFIRMED`, and
that a time-based-blind lead classifies as `SIGNAL`.

> **Honesty boundary.** sqli confirmations are a real, deterministic capability, but they are **not**
> folded into the 430-run statistical zero-false-positive benchmark (which is access-control on two
> controlled labs). sqli's guarantee is structural: `CONFIRMED` requires an injection-causal,
> token-matched OOB callback, against trusted OOB infrastructure.
