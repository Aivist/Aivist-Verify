# Out-of-band (OOB) interaction client — infrastructure for a future SSRF detector

`backend/app/services/oob/` is a small client for a [ProjectDiscovery
interactsh](https://github.com/projectdiscovery/interactsh) session: register a session, mint
a **unique interaction domain** per probe, poll for received DNS/HTTP/SMTP interactions, and
**correlate** each received interaction back to the exact probe that caused it.

> **Infrastructure only — NOT wired to any verdict path.** Nothing in `deep_verifier`,
> `fuzzer`, `verdict_tiers`, or any confirmer imports this module. It gathers evidence a
> **future** blind-SSRF / out-of-band-injection detector could consume; it makes **no claim
> and produces no verdict** today. Shipping it now is plumbing, not a zero-false-positive
> statement, and it does not touch the access-control confirmation path in any way.

## Why a seam

The design mirrors `services/llm/`: a transport-agnostic **session** facade over an injectable
**transport**.

- **`OOBSession`** (in `__init__.py`) owns the session identity (a 20-char correlation id + a
  secret) and the issued-probe registry, and does all **correlation** — pure, in-process, no
  network, no crypto. `new_payload()` mints a domain `"<token><correlation_id>.<server>"` with a
  fresh 13-char per-probe token; `correlate()` attributes a received interaction to a probe iff
  its `unique_id` exactly equals that probe's — so a replayed or scanned id we never minted is
  dropped, never misattributed.
- **`InteractshTransport`** (`interactsh.py`) speaks the interactsh HTTP API and owns the
  network + crypto: it registers an RSA public key, polls `/poll`, RSA-OAEP-SHA256 decrypts the
  AES key, and AES-CFB decrypts each interaction. Lazy-imports `cryptography`.
- **`StubTransport`** (`stub.py`) is an in-memory fake server for deterministic offline tests —
  no network, no crypto. It is how the correlation plumbing is proven (`backend/tests/test_oob.py`).

## Usage (once a server is available)

```python
from backend.app.services.oob import open_session

session = open_session("https://oast.pro", token="<interactsh-auth-token-if-required>")
probe = session.new_payload()          # plant probe.domain / probe.url in a request under test
# ... later, poll for hits ...
for token, interactions in session.poll_and_correlate().items():
    if interactions:
        print(token, "was reached out-of-band:", interactions)
session.close()
```

## What is and is not exercised

- **Proven offline** (`backend/tests/test_oob.py`, no network/crypto): registration,
  unique-token minting, exact correlation, noise rejection, DNS 0x20 case-insensitivity, poll
  draining, fail-closed poll-before-register, lifecycle.
- **NOT exercised here:** a real end-to-end OOB round trip. That needs a **reachable interactsh
  server** (self-hosted, or a public `oast.*` instance) and is an operator/infrastructure step —
  this repo stands up no public infra. The `InteractshTransport` implements the protocol so it is
  ready to use against such a server when one is provided.
