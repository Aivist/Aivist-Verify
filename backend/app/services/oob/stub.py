# ==============================================================================
# In-memory stub transport for the OOB seam — TEST/PLUMBING ONLY.
#
# Simulates an interactsh server with ZERO network and ZERO crypto, so the session's
# registration + correlation logic can be proven deterministically offline. This is
# explicitly NOT a zero-false-positive claim about OOB detection — it exercises the
# plumbing (session → unique token → interaction correlation), nothing more.
#
# A real end-to-end OOB run uses `InteractshTransport` against a reachable interactsh
# server; that path is not exercised here.
# ==============================================================================
from __future__ import annotations

from collections import defaultdict
from typing import Dict, List, Optional

from backend.app.services.oob import OOBInteraction, OOBPayload, OOBSession, OOBTransportError


class StubTransport:
    """A fake interactsh server. `register`/`deregister` track which correlation ids are
    live; `poll` drains interactions queued for that id (fail-closed: polling an
    unregistered session raises, exactly as the real server rejects an unknown id).

    Tests drive it with `deliver(...)`, which simulates a DNS/HTTP hit against a minted
    payload's domain — the ONLY way to enqueue an interaction is to name a real payload,
    so a test cannot accidentally fabricate an id the session never issued."""

    def __init__(self) -> None:
        self._registered: set[str] = set()
        self._queue: Dict[str, List[OOBInteraction]] = defaultdict(list)

    # -- Transport protocol ----------------------------------------------------
    def register(self, session: OOBSession) -> None:
        self._registered.add(session.correlation_id)

    def deregister(self, session: OOBSession) -> None:
        self._registered.discard(session.correlation_id)
        self._queue.pop(session.correlation_id, None)

    def poll(self, session: OOBSession) -> List[OOBInteraction]:
        if session.correlation_id not in self._registered:
            raise OOBTransportError(
                f"correlation id {session.correlation_id!r} is not registered"
            )
        drained = self._queue.pop(session.correlation_id, [])
        return list(drained)

    # -- test-only injection ---------------------------------------------------
    def deliver(
        self,
        payload: OOBPayload,
        *,
        protocol: str = "dns",
        remote_address: str = "203.0.113.7",
        timestamp: str = "2026-01-01T00:00:00Z",
        q_type: Optional[str] = "A",
        raw_request: Optional[str] = None,
    ) -> OOBInteraction:
        """Simulate an interaction hitting `payload.domain` and queue it for the payload's
        session. Returns the queued interaction. Enqueues under the payload's correlation
        id, so it surfaces only when the owning session polls."""
        interaction = OOBInteraction(
            protocol=protocol,
            unique_id=payload.unique_id,
            remote_address=remote_address,
            timestamp=timestamp,
            q_type=q_type if protocol == "dns" else None,
            raw_request=raw_request,
        )
        self._queue[payload.correlation_id].append(interaction)
        return interaction

    def deliver_raw(self, correlation_id: str, interaction: OOBInteraction) -> None:
        """Queue an arbitrary interaction under a correlation id — used to simulate NOISE:
        an interaction whose unique_id matches no payload the session ever minted."""
        self._queue[correlation_id].append(interaction)
