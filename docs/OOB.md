# Out-of-band (OOB) interaction client — the callback substrate for OOB confirmation

`backend/app/services/oob/` is a small client for a [ProjectDiscovery
interactsh](https://github.com/projectdiscovery/interactsh) session: register a session, mint
a **unique interaction domain** per probe, poll for received DNS/HTTP/SMTP interactions, and
**correlate** each received interaction back to the exact probe that caused it.

> **Now consumed by the SSRF detector.** The **SSRF confirmer** (`services/ssrf_detector.py`,
> [`SSRF.md`](./SSRF.md)) uses this client to prove SSRF out-of-band: a real callback to the unique
> probe domain is the `DeterministicProof`. It remains **isolated from the access-control path** —
> `deep_verifier`, `fuzzer`, `confirm_render`, and the owner-view gate neither import nor depend on it,
> so it changes no access-control verdict. `verdict_tiers` does not import it either; the SSRF detector
> composes the two (OOB client + tiered framework) without coupling them.

## Why a seam

The design mirrors `services/llm/`: a transport-agnostic **session** facade over an injectable
**transport**.

- **`OOBSession`** (in `__init__.py`) owns the session identity (a 20-char correlation id + a
  secret) and the issued-probe registry, and does all **correlation** — pure, in-process, no
  network, no crypto. `new_payload()` mints a domain `"<correlation_id><token>.<server>"` — the
  **correlation id FIRST**, then a fresh 13-char per-probe token, because the interactsh server
  reads the correlation id from the **leading 20 chars** of the label to find the session;
  `correlate()` attributes a received interaction to a probe iff its `unique_id` exactly equals
  that probe's `<correlation_id><token>` — so a replayed or scanned id we never minted is dropped,
  never misattributed.
- **`InteractshTransport`** (`interactsh.py`) speaks the interactsh HTTP API and owns the
  network + crypto: it registers an RSA public key, polls `/poll`, RSA-OAEP-SHA256 decrypts the
  AES key, and **AES-CTR** decrypts each interaction (the interactsh server encrypts each
  interaction with AES-256-CTR, prepending the IV — verified against the live public servers; a
  CFB reading decodes only the first 16-byte block, then diverges). Lazy-imports `cryptography`.
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
- **Consumed live by the SSRF detector.** `services/ssrf_detector.py` opens a real session (via
  `open_session`, which builds an `InteractshTransport`) against a public `oast.*` server
  (`DEFAULT_OOB_SERVERS`) to confirm SSRF out-of-band — a real callback to the minted domain is the
  `DeterministicProof`. That path needs **outbound network + a reachable interactsh server**; with
  none reachable the SSRF result is `NOT DATA`, never a guess. This repo self-hosts no OOB
  infrastructure — it uses the public ProjectDiscovery servers for the self-test. See
  [`SSRF.md`](./SSRF.md).
