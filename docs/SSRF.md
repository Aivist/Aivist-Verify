# SSRF confirmation via out-of-band (OOB) callback — the first non-access-control type

Aivist Verify's confirmation discipline — *AI/heuristics propose, a deterministic code channel
disposes; `CONFIRMED` is reserved for a real proof* — is not specific to access control. The SSRF
detector (`backend/app/services/ssrf_detector.py`) is the **first non-access-control vuln type**, and
it earns `CONFIRMED` the same way the access-control engine does: only with a **physical, code-observed
proof**. Here the proof is a **real out-of-band callback**.

## How it confirms

1. Open a session against a public [interactsh](https://github.com/projectdiscovery/interactsh) server
   (`services/oob/`, e.g. `oast.online`) and mint a **unique** interaction domain.
2. Inject `http://<unique-domain>/` into the candidate request's URL parameter and send that ONE request
   to the target (the injected URL is payload *data* the target is expected to fetch — it is not fetched
   by us).
3. Poll the OOB session. **Iff** a DNS/HTTP interaction whose id matches our unique token arrives, the
   target's server made the callback — it fetched the attacker-supplied URL. That interaction is the
   `DeterministicProof`.

It is wired through the tiered-verdict framework (`services/verdict_tiers.py`):

- **OOB hit → `Verdict.confirmed(...)`** carrying the interaction as the `DeterministicProof`
  (`channel="ssrf_oob_callback"`). `[CONFIRMED]`.
- **No hit → `Verdict.refuted(...)`** — probed, nothing came back. `[REFUTED]`.
- **Could not probe** (no reachable interactsh server, transport error) → `Verdict.not_data(...)`.
  `[NOT DATA]`.

`SsrfOobDetector` declares `max_tier = CONFIRMED` (it is deterministic), and `classify()` enforces that
ceiling. Because `Verdict.confirmed` cannot exist without a `DeterministicProof` and `assess()` only
builds one when a correlated interaction is present, **a no-callback result can never be `CONFIRMED`** —
there is no bluffed confirmation.

## Running it

```bash
python -m uvicorn ssrf_target.main:app --port 8004          # a local lab (REAL /fetch, SAFE /fetch-safe)
python run.py ssrf --config examples/run.ssrf_real.json     # -> [CONFIRMED] on a real callback (exit 1)
python run.py ssrf --config examples/run.ssrf_safe.json     # -> [REFUTED] (no callback; exit 0)
```

Config fields: `base_url`, `path`, `url_param`, `method`, `url_location` (`query`|`body`), optional
`scheme`/`oob_server`/`poll_seconds`. An optional `TARGET_ATTACKER_TOKEN` (env) is sent as a bearer
header if the SSRF endpoint needs auth. Exit codes: `1` CONFIRMED, `0` refuted, `2` NOT DATA.

## Honest requirements and limits

- **Needs outbound network AND a reachable interactsh server.** With no reachable OOB server the result
  is `NOT DATA`, never a guess. The public servers are used for the self-test; no infra is self-hosted.
- **Confirms the callback, not the full exploit chain.** A `CONFIRMED` proves the server fetched the
  attacker-controlled URL out-of-band (the SSRF primitive). It does not itself enumerate what internal
  targets are reachable.
- **A blind SSRF with no server-side fetch of the domain yields no callback → `REFUTED`/`NOT DATA`.**
  This is the safe direction: the tool never reports SSRF it did not physically observe.
- **Additive + isolated.** The SSRF path does not touch the access-control engine, its gate, or its
  verdict path; the access-control zero-false-positive guarantee is unaffected. Ground truth for the lab
  is proven independently by `ssrf_target/test_vulns.py` (no engine imports); the detector/probe wiring
  is proven offline by `backend/tests/test_ssrf_detector.py` (a stub OOB transport), and the real
  public-interactsh callback is exercised as a live acceptance run.
