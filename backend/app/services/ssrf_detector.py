# ==============================================================================
# SSRF confirmation via out-of-band (OOB) interaction — the FIRST non-access-control
# vuln type. It is CONFIRMED only by a REAL callback: the target server, when it fetches
# an attacker-supplied URL, must reach out to a UNIQUE interactsh domain we minted, and
# that interaction (DNS/HTTP) must arrive at the OOB session. The interaction IS the
# DeterministicProof; there is no other way to reach CONFIRMED.
#
# ADDITIVE + ISOLATED. This module does NOT import or touch the access-control path
# (deep_verifier / fuzzer verdict logic / confirm_render / the owner-view gate). It composes
# two existing, audited pieces — the OOB client (`services/oob/`) and the tiered-verdict
# framework (`services/verdict_tiers.py`) — and adds an SSRF-specific probe + detector.
#
# THE RESERVATION (why a bluff can never be CONFIRMED):
#   * `SsrfOobDetector` declares `max_tier = CONFIRMED` (it is deterministic — a real
#     callback is a physical fact), and `classify()` enforces that ceiling.
#   * `assess()` calls `Verdict.confirmed(...)` ONLY when a correlated OOB interaction is
#     present, handing the interaction as the `DeterministicProof`. No interaction ->
#     REFUTED (probed, no callback) or NOT_DATA (could not probe). `Verdict.confirmed`
#     itself refuses to exist without a proof. So "no OOB hit" can never be CONFIRMED.
# ==============================================================================
from __future__ import annotations

import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from backend.app.services.oob import OOBError, OOBInteraction, OOBSession, open_session
from backend.app.services.verdict_tiers import (
    DeterministicProof, Detector, Tier, Verdict, classify,
)

# Public ProjectDiscovery interactsh servers (no self-hosting). Tried in order; the first
# that registers wins. A reachable server is REQUIRED for a real OOB confirmation.
DEFAULT_OOB_SERVERS = ("oast.online", "oast.fun", "oast.me", "oast.pro", "oast.live", "oast.site")

_HTTP_TIMEOUT = 15.0


@dataclass
class SsrfProbeResult:
    """The full record of one SSRF probe: what we injected, where we sent it, and every
    OOB interaction that correlated back to our unique payload. `interactions` non-empty
    == a real callback arrived == the only path to CONFIRMED."""
    target: str
    method: str
    url_param: str
    url_location: str
    injected_url: str
    payload_domain: str
    payload_token: str
    oob_server: Optional[str]
    request_status: Optional[int] = None
    request_error: Optional[str] = None      # error sending the probe to the target (not fatal)
    probe_error: Optional[str] = None        # could not run the probe at all -> NOT DATA
    interactions: List[OOBInteraction] = field(default_factory=list)
    polls: int = 0

    @property
    def confirmed(self) -> bool:
        return bool(self.interactions) and not self.probe_error


def _interaction_view(it: OOBInteraction) -> Dict[str, Any]:
    """A structural, secret-free view of one OOB interaction (for the proof/evidence)."""
    return {
        "protocol": it.protocol,
        "unique_id": it.unique_id,
        "q_type": it.q_type,
        "remote_address": it.remote_address,
        "timestamp": it.timestamp,
    }


class SsrfOobDetector(Detector):
    """SSRF via OOB callback. Deterministic (a real interaction is a physical fact), so it
    MAY reach CONFIRMED — but only when `assess` is handed a probe result that actually
    carries a correlated interaction. No interaction -> REFUTED / NOT_DATA, never CONFIRMED."""
    name = "ssrf-oob"
    max_tier = Tier.CONFIRMED

    def assess(self, evidence: SsrfProbeResult) -> Verdict:
        if evidence.probe_error:
            return Verdict.not_data(
                f"the SSRF OOB probe could not run: {evidence.probe_error}. No callback could be "
                f"observed, so nothing is confirmed or refuted (NOT DATA).")
        if evidence.interactions:
            it = evidence.interactions[0]
            proof = DeterministicProof(
                channel="ssrf_oob_callback",
                basis=(f"the target server made an out-of-band {it.protocol.upper()} callback to the "
                       f"unique probe domain {evidence.payload_domain} "
                       f"(interaction id {it.unique_id}"
                       + (f", q-type {it.q_type}" if it.q_type else "")
                       + (f", from {it.remote_address}" if it.remote_address else "")
                       + f") — proving it fetched the attacker-supplied URL {evidence.injected_url}."))
            return Verdict.confirmed("ssrf", proof)
        return Verdict.refuted(
            "ssrf",
            f"no out-of-band callback arrived for the unique probe domain {evidence.payload_domain} "
            f"within the poll window ({evidence.polls} polls) — the target did not fetch the injected "
            f"URL server-side (or cannot reach the interactsh server).")


def ssrf_verdict(result: SsrfProbeResult) -> Verdict:
    """The single emit path: run the detector through `classify` so the CONFIRMED ceiling
    and the proof requirement are structurally enforced."""
    return classify(SsrfOobDetector(), result)


# ------------------------------------------------------------------------------
# The probe: mint a unique OOB domain, inject it into the candidate request, send the
# request to the target, then poll the OOB session for a correlated callback.
# ------------------------------------------------------------------------------
def _open_default_session(servers) -> OOBSession:
    last: Optional[Exception] = None
    for server in servers:
        try:
            return open_session(server)
        except Exception as e:  # OOBError / transport / network
            last = e
    raise OOBError(f"no public interactsh server reachable (tried {list(servers)}): {last}")


def _build_target_url(base_url: str, path: str, url_param: str, injected_url: str) -> str:
    """Compose the target URL with the injected payload URL in a QUERY parameter."""
    base = base_url.rstrip("/")
    p = path if path.startswith("/") else "/" + path
    parts = urllib.parse.urlsplit(p)
    query = dict(urllib.parse.parse_qsl(parts.query, keep_blank_values=True))
    query[url_param] = injected_url
    return f"{base}{parts.path}?{urllib.parse.urlencode(query)}"


def _default_http_send(*, target_url: str, method: str, headers: Dict[str, str],
                       body: Optional[Dict[str, Any]]) -> int:
    """Send the probe request to the TARGET (a plain in-scope request; the injected URL is
    payload DATA the target is expected to fetch, not something we fetch). Returns the status
    code. Uses verify=False for self-signed lab/pentest targets, mirroring the engine."""
    import httpx
    with httpx.Client(timeout=_HTTP_TIMEOUT, verify=False) as client:
        resp = client.request(method.upper(), target_url, headers=headers or None, json=body)
        return resp.status_code


def run_ssrf_probe(
    *,
    base_url: str,
    method: str = "GET",
    path: str = "/",
    url_param: str = "url",
    url_location: str = "query",
    scheme: str = "http",
    oob_servers = DEFAULT_OOB_SERVERS,
    attacker_token: Optional[str] = None,
    poll_seconds: float = 25.0,
    poll_interval: float = 3.0,
    # test seams (offline; no network):
    session_factory: Optional[Callable[[], OOBSession]] = None,
    http_send: Optional[Callable[..., int]] = None,
    sleep: Callable[[float], None] = time.sleep,
) -> SsrfProbeResult:
    """Confirm SSRF by out-of-band callback. Opens an interactsh session, mints a UNIQUE
    payload domain, injects `scheme://<domain>/` into `url_param`, sends the request to the
    target, and polls the OOB session; a correlated interaction is the proof. Never raises
    for expected failures — a probe that cannot run returns `probe_error` (NOT DATA)."""
    scheme = scheme if scheme in ("http", "https") else "http"
    # 1) open the OOB session (a reachable interactsh server is required to confirm anything).
    try:
        session = (session_factory or (lambda: _open_default_session(oob_servers)))()
    except Exception as e:
        return SsrfProbeResult(
            target=base_url, method=method.upper(), url_param=url_param, url_location=url_location,
            injected_url="", payload_domain="", payload_token="", oob_server=None,
            probe_error=f"OOB session unavailable: {type(e).__name__}: {e}")

    payload = session.new_payload()
    injected = f"{scheme}://{payload.domain}/"
    result = SsrfProbeResult(
        target=base_url, method=method.upper(), url_param=url_param, url_location=url_location,
        injected_url=injected, payload_domain=payload.domain, payload_token=payload.token,
        oob_server=session.server)
    try:
        # 2) build + send the probe request to the target.
        headers: Dict[str, str] = {}
        if attacker_token:
            from backend.app.cli.external_verify import _auth_header
            headers.update(_auth_header(attacker_token))
        if url_location == "body":
            target_url = f"{base_url.rstrip('/')}{path if path.startswith('/') else '/' + path}"
            body: Optional[Dict[str, Any]] = {url_param: injected}
        else:
            target_url = _build_target_url(base_url, path, url_param, injected)
            body = None
        sender = http_send or _default_http_send
        try:
            result.request_status = sender(target_url=target_url, method=method.upper(),
                                           headers=headers, body=body)
        except Exception as e:
            result.request_error = f"{type(e).__name__}: {e}"

        # 3) poll the OOB session for a correlated callback (the proof).
        elapsed = 0.0
        while elapsed < poll_seconds and not result.interactions:
            sleep(poll_interval)
            elapsed += poll_interval
            result.polls += 1
            try:
                grouped = session.poll_and_correlate()
            except OOBError as e:
                result.probe_error = f"OOB poll failed: {type(e).__name__}: {e}"
                break
            hits = grouped.get(payload.token, [])
            if hits:
                result.interactions = hits
        return result
    finally:
        try:
            session.close()
        except Exception:
            pass


def result_view(result: SsrfProbeResult, verdict: Verdict) -> Dict[str, Any]:
    """Machine-readable, secret-free view of an SSRF probe + its tiered verdict."""
    from backend.app.services.verdict_tiers import badge
    return {
        "vuln_type": "ssrf",
        "tier": verdict.tier.name.lower(),
        "badge": badge(verdict),
        "confirmed": verdict.tier is Tier.CONFIRMED,
        "basis": verdict.basis,
        "proof_channel": verdict.proof.channel if verdict.proof else None,
        "target": result.target,
        "method": result.method,
        "injected_url": result.injected_url,
        "payload_domain": result.payload_domain,
        "oob_server": result.oob_server,
        "request_status": result.request_status,
        "request_error": result.request_error,
        "probe_error": result.probe_error,
        "polls": result.polls,
        "interactions": [_interaction_view(i) for i in result.interactions],
    }
