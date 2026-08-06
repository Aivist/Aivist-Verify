# ==============================================================================
# Scope-lock enforcement in the outbound chokepoint (fuzzer._send_request), commit
# 2a. Drives the REAL _send_request through an httpx MockTransport (no network, no
# DNS: IP-literal scopes avoid resolution) and proves:
#   * UNLOCKED (no scope, no custody) => pass-through + httpx auto-follow (byte-identical).
#   * LOCKED  => fail-closed on the initial URL, and per-hop redirect validation that
#     refuses the FIRST out-of-scope hop while following in-scope redirects.
#   * The scope is derived from custody.approved_host when no explicit scope is passed.
# Written to FAIL against the pre-2a behavior (always follow_redirects=True; scope
# checked only when custody is present).
# ==============================================================================
import asyncio

import httpx
import pytest

from backend.app.services import fuzzer
from backend.app.services.fuzzer import _send_request, _effective_scope_policy, ScopeViolationError
from backend.app.services.scope import ScopePolicy


def _client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def _send(handler, parsed_request, base_url, **kw):
    async with _client(handler) as client:
        return await _send_request(client, parsed_request, base_url, **kw)


# ------------------------------------------------------------------------------
# UNLOCKED (lab mode): pass-through + auto-follow, byte-identical to pre-2a
# ------------------------------------------------------------------------------
def test_unlocked_passthrough_autofollows_redirect():
    def handler(request):
        if request.url.path == "/start":
            return httpx.Response(302, headers={"Location": "/final"})
        return httpx.Response(200, text="final-body")

    res = asyncio.run(_send(handler, {"method": "GET", "path": "/start"},
                            "http://10.11.12.13:80"))
    # No scope, no custody => httpx auto-follow reaches the final 200.
    assert res["status_code"] == 200
    assert res["response_body"] == "final-body"


def test_unlocked_reaches_any_host():
    # Pass-through must not refuse anything when nothing is declared.
    def handler(request):
        return httpx.Response(200, text="ok")
    res = asyncio.run(_send(handler, {"method": "GET", "path": "/x"},
                            "http://198.51.100.9:80"))
    assert res["status_code"] == 200


# ------------------------------------------------------------------------------
# LOCKED: fail-closed on the initial URL
# ------------------------------------------------------------------------------
def test_locked_in_scope_allowed():
    def handler(request):
        return httpx.Response(200, text="ok")
    pol = ScopePolicy.from_declaration(["127.0.0.1:9"])
    res = asyncio.run(_send(handler, {"method": "GET", "path": "/x"},
                            "http://127.0.0.1:9", scope=pol))
    assert res["status_code"] == 200


def test_locked_out_of_scope_initial_refused():
    def handler(request):                      # pragma: no cover - must never be called
        raise AssertionError("out-of-scope request must never open a socket")
    pol = ScopePolicy.from_declaration(["127.0.0.1:9"])
    with pytest.raises(ScopeViolationError):
        asyncio.run(_send(handler, {"method": "GET", "path": "/x"},
                          "http://10.0.0.5:80", scope=pol))


# ------------------------------------------------------------------------------
# LOCKED: per-hop redirect enforcement
# ------------------------------------------------------------------------------
def test_locked_redirect_to_out_of_scope_refused():
    def handler(request):
        if request.url.path == "/start":
            return httpx.Response(302, headers={"Location": "http://10.0.0.5:80/evil"})
        raise AssertionError("must not follow the redirect off-scope")
    pol = ScopePolicy.from_declaration(["127.0.0.1:9"])
    with pytest.raises(ScopeViolationError):
        asyncio.run(_send(handler, {"method": "GET", "path": "/start"},
                          "http://127.0.0.1:9", scope=pol))


def test_locked_redirect_in_scope_followed():
    def handler(request):
        if request.url.path == "/start":
            return httpx.Response(302, headers={"Location": "/final"})
        return httpx.Response(200, text="final-in-scope")
    pol = ScopePolicy.from_declaration(["127.0.0.1:9"])
    res = asyncio.run(_send(handler, {"method": "GET", "path": "/start"},
                            "http://127.0.0.1:9", scope=pol))
    assert res["status_code"] == 200
    assert res["response_body"] == "final-in-scope"


def test_locked_redirect_chain_capped():
    # An endless in-scope redirect loop must terminate at _MAX_REDIRECTS, returning the
    # last 3xx rather than looping forever.
    def handler(request):
        return httpx.Response(302, headers={"Location": "/next"})
    pol = ScopePolicy.from_declaration(["127.0.0.1:9"])
    res = asyncio.run(_send(handler, {"method": "GET", "path": "/start"},
                            "http://127.0.0.1:9", scope=pol))
    assert res["status_code"] == 302


# ------------------------------------------------------------------------------
# Policy derived from custody.approved_host (no explicit scope passed)
# ------------------------------------------------------------------------------
class _StubCustody:
    def __init__(self, approved_host):
        self.approved_host = approved_host


def test_effective_policy_prefers_explicit_scope():
    explicit = ScopePolicy.from_declaration(["127.0.0.1:9"])
    got = _effective_scope_policy(explicit, _StubCustody("example.com"))
    assert got is explicit


def test_effective_policy_derives_from_custody():
    pol = _effective_scope_policy(None, _StubCustody("127.0.0.1:9"))
    assert pol is not None and pol.locked
    assert pol.check("http://127.0.0.1:9/x").allowed
    assert not pol.check("http://10.0.0.5:80/x").allowed


def test_effective_policy_unlocked_when_nothing_declared():
    assert _effective_scope_policy(None, None) is None
    assert _effective_scope_policy(None, _StubCustody("")) is None


# ------------------------------------------------------------------------------
# Positive reachability: a legitimately-declared target IS reachable (zero real traffic).
# This is the "allowed-to-fail" freedom anchor — if the scope wrongly blocked the
# declared lab target, this fails.
# ------------------------------------------------------------------------------
def test_declared_localhost_lab_target_is_reachable():
    def handler(request):
        return httpx.Response(200, text='{"id":2,"owner":"victim"}')
    # Built exactly as the entry builds it from the unified declaration: scope=[host].
    pol = ScopePolicy.from_declaration(["127.0.0.1:8001"])
    res = asyncio.run(_send(handler, {"method": "GET", "path": "/api/users/2"},
                            "http://127.0.0.1:8001", scope=pol))
    assert res["status_code"] == 200
    assert res["response_body"] == '{"id":2,"owner":"victim"}'


# ------------------------------------------------------------------------------
# ONE DECISION TREE (commit 4): passive capture (proxy/pruner) and active fuzzing
# (the ScopePolicy the _send_request chokepoint uses) must give the IDENTICAL host
# decision for the same host + scope. That is the whole point of the convergence.
# ------------------------------------------------------------------------------
import backend.app.services.pruner as pruner   # noqa: E402


@pytest.mark.parametrize("scope,host,expected", [
    (["example.com"], "example.com", True),
    (["example.com"], "api.example.com", False),   # apex-only (unified semantics)
    (["example.com"], "evil.com", False),
    (["example.com"], "notexample.com", False),    # substring trap
    (["*.example.com"], "api.example.com", True),
    (["*.example.com"], "example.com", True),       # apex auto-include
    (["*.example.com"], "evilexample.com", False),  # endswith trap
    ([], "anything.example.org", True),             # empty => all (unlocked)
    (["10.0.0.5:8443"], "10.0.0.5:8443", True),
    (["10.0.0.5:8443"], "10.0.0.5:9000", False),    # port strict
])
def test_active_and_passive_agree_one_decision_tree(scope, host, expected):
    passive = pruner.host_in_scope(host, scope)                      # proxy / radar path
    active = ScopePolicy.from_declaration(scope).netloc_allowed(host)  # _send_request path
    assert passive == active == expected


def test_passive_over_broad_scope_fails_safe():
    # A malformed / over-broad passive scope is refused (out of scope), never captured.
    assert pruner.host_in_scope("anything.com", ["*.com"]) is False


# ==============================================================================
# D25 — DNS-rebinding TOCTOU: the scope-validated IP is PINNED to the connection, so httpx does NOT
# re-resolve the hostname at connect time (an attacker cannot flip DNS between check() and connect).
# Direction-SAFE: pinning can only RESTRICT the connection to an already-validated address.
# ==============================================================================
from backend.app.services import scope as _scope
from backend.app.services.scope import ScopeDecision
from backend.app.services.fuzzer import _pin_kwargs, _build_request_kwargs


def test_toctou_connection_is_pinned_to_validated_ip_not_the_rebind(monkeypatch):
    """LOAD-BEARING. An injected resolver returns a VALIDATED public IP at check() time; an attacker
    then flips DNS so the hostname would resolve to an INTERNAL IP at connect time. Assert the
    connection is dialed to the PINNED public IP (Host preserved) and the malicious internal IP is
    NEVER reached. MUST FAIL for a no-pin impl (which dials the hostname -> connect-resolve ->
    internal IP)."""
    HOST = "target.example.com"
    VALIDATED_PUBLIC_IP = "93.184.216.34"     # what check() validated (global, in scope)
    REBIND_INTERNAL_IP = "127.0.0.1"          # what the attacker flips DNS to at connect time

    # check() sees ONLY the safe validated public IP (patch the module resolver check() consults)
    monkeypatch.setattr(_scope, "_system_resolver", lambda host: [VALIDATED_PUBLIC_IP])

    connected, host_headers = [], []
    # the MockTransport simulates connect-time DNS: a HOSTNAME url would be re-resolved (attacker-
    # controlled) to the internal IP; an IP-literal url is dialed as-is (the pin took effect).
    connect_dns = {HOST: REBIND_INTERNAL_IP}

    def handler(request):
        dialed = request.url.host
        connected.append(connect_dns.get(dialed, dialed))
        host_headers.append(request.headers.get("host"))
        return httpx.Response(200, text="ok")

    res = asyncio.run(_send(handler, {"method": "GET", "path": "/data"},
                            f"http://{HOST}:80", scope=ScopePolicy.from_declaration([HOST])))

    assert res["status_code"] == 200
    assert connected == [VALIDATED_PUBLIC_IP]          # dialed the scope-validated PINNED IP
    assert REBIND_INTERNAL_IP not in connected         # the DNS-rebind was NEVER reached
    assert host_headers == [HOST]                      # Host routing preserved (app still sees the name)
    assert res["url"] == f"http://{HOST}:80/data"      # the record keeps the LOGICAL url, not the IP


def test_toctou_redirect_hop_is_also_pinned(monkeypatch):
    # a relative redirect must resolve against the LOGICAL hostname (not the pinned-IP url we dialed)
    # AND itself be pinned -> both hops dial the validated IP, never the rebind.
    HOST = "target.example.com"
    PUB, REBIND = "93.184.216.34", "127.0.0.1"
    monkeypatch.setattr(_scope, "_system_resolver", lambda host: [PUB])
    connected = []
    connect_dns = {HOST: REBIND}

    def handler(request):
        connected.append(connect_dns.get(request.url.host, request.url.host))
        if request.url.path == "/start":
            return httpx.Response(302, headers={"Location": "/next"})     # relative -> same host
        return httpx.Response(200, text="ok")

    res = asyncio.run(_send(handler, {"method": "GET", "path": "/start"},
                            f"http://{HOST}:80", scope=ScopePolicy.from_declaration([HOST])))
    assert res["status_code"] == 200
    assert connected == [PUB, PUB]                     # BOTH the initial and the redirect hop pinned
    assert REBIND not in connected


def test_check_returns_validated_ips_and_omits_them_on_a_rebind():
    pol = ScopePolicy.from_declaration(["target.example.com"])
    ok = pol.check("http://target.example.com/x", resolver=lambda h: ["93.184.216.34"])
    assert ok.allowed and ok.resolved_ips == ("93.184.216.34",)          # pin the validated global IP
    bad = pol.check("http://target.example.com/x", resolver=lambda h: ["10.0.0.5"])
    assert not bad.allowed and bad.reason == "rebinding_private_ip" and bad.resolved_ips is None
    # multi-IP public name: all global -> all returned for pinning
    multi = pol.check("http://target.example.com/x", resolver=lambda h: ["93.184.216.34", "8.8.8.8"])
    assert multi.allowed and set(multi.resolved_ips) == {"93.184.216.34", "8.8.8.8"}


def test_ip_literal_and_intranet_targets_carry_no_pin():
    # labs / declared internal targets are dialed as-is (no DNS, no TOCTOU) -> resolved_ips is None
    d = ScopePolicy.from_declaration(["127.0.0.1"]).check("http://127.0.0.1:5000/x")
    assert d.allowed and d.resolved_ips is None                          # IP-literal lab target
    d2 = ScopePolicy.from_declaration(["myhost"]).check("http://myhost:8000/x")
    assert d2.allowed and d2.resolved_ips is None                        # intranet single-label host


def test_pin_kwargs_without_a_pin_is_byte_identical_to_the_hostname_build():
    # unlocked (decision None) and a decision with no resolved_ips both -> byte-identical kwargs,
    # so the lab / IP-literal / intranet connect path is unchanged.
    base = _build_request_kwargs("GET", "http://127.0.0.1:5000/x", {}, None, False)
    assert _pin_kwargs("GET", "http://127.0.0.1:5000/x", {}, None, None, False) == base
    d = ScopeDecision(True, "ok", "127.0.0.1", 5000, "127.0.0.1", resolved_ips=None)
    assert _pin_kwargs("GET", "http://127.0.0.1:5000/x", {}, None, d, False) == base


def test_pin_kwargs_rewrites_to_ip_and_preserves_host_and_sni():
    d = ScopeDecision(True, "ok", "target.example.com", 443, "target.example.com",
                      resolved_ips=("93.184.216.34",))
    # implicit (scheme-default) port: omitted from BOTH the dialed netloc and Host, mirroring httpx
    kw = _pin_kwargs("GET", "https://target.example.com/a?b=1", {"X": "y"}, None, d, False)
    assert kw["url"] == "https://93.184.216.34/a?b=1"                     # dialed IP (no re-resolution)
    assert kw["headers"]["Host"] == "target.example.com"                 # HTTP routing preserved
    assert kw["headers"]["X"] == "y"                                     # caller headers carried through
    assert kw["extensions"]["sni_hostname"] == "target.example.com"      # TLS SNI routing preserved
    # explicit NON-default port is kept on both
    kw2 = _pin_kwargs("GET", "https://target.example.com:8443/a", {}, None, d, False)
    assert kw2["url"] == "https://93.184.216.34:8443/a"
    assert kw2["headers"]["Host"] == "target.example.com:8443"


def test_direction_safe_unreachable_pinned_ip_raises_never_a_verdict(monkeypatch):
    # a stale / unreachable pinned IP -> connection error propagates out of _send_request; the caller
    # turns it into NOT DATA. It can NEVER be swallowed into a 'safe'/'vulnerable' verdict.
    HOST = "target.example.com"
    monkeypatch.setattr(_scope, "_system_resolver", lambda h: ["93.184.216.34"])

    def handler(request):
        raise httpx.ConnectError("pinned IP unreachable")

    with pytest.raises(httpx.ConnectError):
        asyncio.run(_send(handler, {"method": "GET", "path": "/x"},
                          f"http://{HOST}:80", scope=ScopePolicy.from_declaration([HOST])))
