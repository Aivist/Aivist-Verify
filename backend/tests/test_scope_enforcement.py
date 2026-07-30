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
