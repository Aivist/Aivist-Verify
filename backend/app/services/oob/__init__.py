# ==============================================================================
# Out-of-band (OOB) interaction client — INFRASTRUCTURE ONLY.
#
# A small internal seam over a ProjectDiscovery interactsh session so a FUTURE
# SSRF / blind-injection detector can: register a session, mint a UNIQUE interaction
# domain per probe, poll for received DNS/HTTP/SMTP interactions, and CORRELATE each
# received interaction back to the exact probe that caused it (by its unique token).
#
# ─────────────────────────────────────────────────────────────────────────────
# NOT WIRED TO ANY VERDICT PATH. This module is deliberately standalone: no confirmer,
# no gate, no `verdict_tiers`, and nothing in `deep_verifier` / `fuzzer` imports it. It
# gathers evidence a detector could later consume; it makes NO claim and produces NO
# verdict. Shipping it now is plumbing, not a zero-false-positive statement.
#
# The seam mirrors `services/llm/`: a transport-agnostic session facade (correlation
# lives here) over an injectable `Transport` (network + crypto live there). The real
# `InteractshTransport` speaks the interactsh protocol; a `StubTransport` (services/oob/
# stub.py) lets the correlation logic be proven offline with no server and no crypto.
# A real end-to-end OOB run needs a REACHABLE interactsh server (self-hosted or a public
# oast.* instance) — that is an operator/infra step, provided later; nothing here stands
# up public infra.
# ==============================================================================
from __future__ import annotations

import secrets
import string
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Protocol, runtime_checkable
from urllib.parse import urlsplit

# interactsh id lengths (match the ProjectDiscovery client): a 20-char per-session
# correlation id and a 13-char per-payload random prefix. token+correlation = the 33-char
# leftmost DNS label (<= 63, always a legal label).
_CORRELATION_ID_LEN = 20
_PAYLOAD_TOKEN_LEN = 13
_ID_ALPHABET = string.ascii_lowercase + string.digits


class OOBError(Exception):
    """Base class for any OOB failure."""


class OOBConfigError(OOBError):
    """The client is unusable as configured — a required dependency is missing
    (e.g. `cryptography`), or the server URL is malformed. Callers treat this as a
    fail-safe: no OOB evidence, never a crash of the surrounding run."""


class OOBTransportError(OOBError):
    """A transport-level failure (register/poll/deregister could not complete, or a
    poll response could not be decrypted/parsed)."""


def _random_id(length: int) -> str:
    """A lowercase-alphanumeric id of `length` chars, drawn from a CSPRNG so a payload
    token is unpredictable (an attacker must not be able to guess another probe's domain)."""
    return "".join(secrets.choice(_ID_ALPHABET) for _ in range(length))


@dataclass(frozen=True)
class OOBPayload:
    """One minted probe target. `domain` is what you plant in a request you want the
    target to resolve/fetch; `token` is the per-payload nonce that makes correlation exact."""
    token: str                 # 13-char per-payload nonce (the leftmost label prefix)
    correlation_id: str        # the owning session's 20-char id
    domain: str                # "<token><correlation_id>.<server>" (lowercased)

    @property
    def unique_id(self) -> str:
        """The 33-char leftmost DNS label an interaction against this payload carries —
        `<token><correlation_id>`. Correlation matches an interaction's id against THIS."""
        return f"{self.token}{self.correlation_id}"

    @property
    def url(self) -> str:
        return f"https://{self.domain}"


@dataclass(frozen=True)
class OOBInteraction:
    """One received interaction, as parsed by a transport. `unique_id` is the 33-char
    leftmost label the interaction hit — the value correlation keys on."""
    protocol: str                       # "dns" | "http" | "smtp" | ...
    unique_id: str                      # "<token><correlation_id>" (lowercased)
    remote_address: Optional[str] = None
    timestamp: Optional[str] = None
    q_type: Optional[str] = None        # DNS query type, when protocol == "dns"
    raw_request: Optional[str] = None   # the raw request the server captured, if any


@runtime_checkable
class Transport(Protocol):
    """The network + crypto boundary. The real transport speaks the interactsh HTTP API
    and does the RSA/AES decryption; a stub returns canned interactions offline. `poll`
    returns already-decrypted, already-parsed `OOBInteraction`s so the session never sees
    ciphertext — correlation is a pure, transport-agnostic operation on `unique_id`."""

    def register(self, session: "OOBSession") -> None: ...
    def poll(self, session: "OOBSession") -> List[OOBInteraction]: ...
    def deregister(self, session: "OOBSession") -> None: ...


@dataclass
class OOBSession:
    """A registered OOB session and the probes minted under it. Transport-agnostic:
    all correlation happens here; the injected `transport` owns network + crypto.

    Lifecycle: `open_session(...)` (or `register()`) → `new_payload()` per probe →
    `poll_and_correlate()` in a loop → `close()`.
    """
    server: str                              # interaction domain, e.g. "oast.pro"
    correlation_id: str                      # 20-char session id (in every payload domain)
    secret: str                              # per-session secret returned on poll auth
    transport: Transport
    _issued: Dict[str, OOBPayload] = field(default_factory=dict, repr=False)
    registered: bool = False

    # -- lifecycle -------------------------------------------------------------
    def register(self) -> "OOBSession":
        """Register the session with the transport (idempotent)."""
        if not self.registered:
            self.transport.register(self)
            self.registered = True
        return self

    def close(self) -> None:
        """Deregister; never raises (best-effort teardown)."""
        try:
            self.transport.deregister(self)
        except OOBError:
            pass
        finally:
            self.registered = False

    def __enter__(self) -> "OOBSession":
        return self.register()

    def __exit__(self, *exc) -> None:
        self.close()

    # -- probes ----------------------------------------------------------------
    def new_payload(self) -> OOBPayload:
        """Mint a UNIQUE interaction domain. Each call gets a fresh 13-char token, so two
        probes never collide and a received interaction pins to exactly one probe."""
        token = _random_id(_PAYLOAD_TOKEN_LEN)
        while token in self._issued:                 # astronomically unlikely; still exact
            token = _random_id(_PAYLOAD_TOKEN_LEN)
        payload = OOBPayload(
            token=token,
            correlation_id=self.correlation_id,
            domain=f"{token}{self.correlation_id}.{self.server}".lower(),
        )
        self._issued[token] = payload
        return payload

    @property
    def issued(self) -> Dict[str, OOBPayload]:
        """A copy of the token → payload registry (read-only view)."""
        return dict(self._issued)

    # -- correlation (pure) ----------------------------------------------------
    def correlate(
        self, interactions: List[OOBInteraction]
    ) -> Dict[str, List[OOBInteraction]]:
        """Group received interactions by the ISSUED payload token that caused them.

        An interaction is attributed to a payload iff its `unique_id` equals that payload's
        `unique_id` (`<token><correlation_id>`) — an exact match on a per-probe nonce, so a
        confused-deputy or replayed interaction against an id we never minted is dropped, not
        misattributed. Returns {token: [interactions...]} for every issued token (possibly
        empty); interactions matching no issued payload are omitted."""
        by_uid = {p.unique_id: token for token, p in self._issued.items()}
        grouped: Dict[str, List[OOBInteraction]] = {token: [] for token in self._issued}
        for it in interactions:
            token = by_uid.get((it.unique_id or "").lower())
            if token is not None:
                grouped[token].append(it)
        return grouped

    def poll_and_correlate(self) -> Dict[str, List[OOBInteraction]]:
        """Poll the transport once and correlate the batch. Correlation is pure; only the
        poll touches the transport."""
        return self.correlate(self.poll())

    def poll(self) -> List[OOBInteraction]:
        """Fetch the interactions received since the last poll (transport-decrypted)."""
        return list(self.transport.poll(self))


def new_correlation_id() -> str:
    return _random_id(_CORRELATION_ID_LEN)


def new_secret() -> str:
    return uuid.uuid4().hex


def _server_domain(server_url: str) -> str:
    """Extract the interaction domain (host) from a server URL or bare host. `oast.pro`,
    `https://oast.pro`, and `https://oast.pro/` all yield `oast.pro`."""
    raw = (server_url or "").strip()
    if not raw:
        raise OOBConfigError("an interactsh server URL/host is required")
    host = urlsplit(raw if "://" in raw else "https://" + raw).hostname
    if not host:
        raise OOBConfigError(f"could not parse an interaction domain from {server_url!r}")
    return host.lower()


def open_session(
    server_url: str,
    *,
    transport: Optional[Transport] = None,
    token: Optional[str] = None,
    correlation_id: Optional[str] = None,
    secret: Optional[str] = None,
) -> OOBSession:
    """Build and REGISTER an OOB session.

    `server_url` is the interactsh server (self-hosted or a public oast.* instance). With
    no `transport`, the real `InteractshTransport` is built (needs `cryptography`; raises
    `OOBConfigError` if absent) — this is the only path that touches the network. Inject a
    `transport` (e.g. `StubTransport`) to exercise the session offline.

    `token` is the interactsh server auth token, if the server requires one. Returns a
    registered session ready for `new_payload()` / `poll_and_correlate()`.
    """
    server = _server_domain(server_url)
    if transport is None:
        from backend.app.services.oob.interactsh import InteractshTransport
        transport = InteractshTransport(server_url, token=token)
    session = OOBSession(
        server=server,
        correlation_id=(correlation_id or new_correlation_id()),
        secret=(secret or new_secret()),
        transport=transport,
    )
    return session.register()
