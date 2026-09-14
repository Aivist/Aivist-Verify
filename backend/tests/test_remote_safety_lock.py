# ==============================================================================
# C4 LOCK — the remote / NON-LOOPBACK safety machinery, proven HERMETICALLY (no real
# internet target, no real DNS, no real socket). This is the reproducible-in-CI test the
# audit flagged as missing: the remote path was verified live ONCE against a LAN IP, but
# nothing LOCKED non-loopback behavior. This file locks it end to end.
#
# It REUSES the shipped safety functions verbatim — ScopePolicy.check / remote_safety.preflight
# (both already take an injected `resolver`) and fuzzer._send_request (whose check() consults the
# module-level scope._system_resolver, monkeypatched here). NO refusal logic is added or changed;
# NO source seam is introduced. If any refusal below did NOT actually fail closed, the assertion
# fails RED — it is never weakened to pass (that would be a security finding, not a test bug).
#
# Coverage (the brief's a/b/c):
#   A. a NON-loopback target is classified REMOTE and the scope lock + preflight actually run;
#   b. every refusal is FAIL-CLOSED — DNS-rebinding flipped AFTER a clean preflight (the TOCTOU
#      sequence), cloud-metadata (169.254.169.254), link-local, out-of-scope host, unresolvable —
#      each refuses (no socket / engine never runs), never proceeds;
#   c. a legitimate in-scope NON-loopback confirmation still completes (positive control), so the
#      rails do not over-block real remote use.
# Layers: the request chokepoint (fuzzer._send_request) AND the end-to-end verify CLI
# (external_verify.run_external_verify), so the guarantee holds where it actually matters.
# ==============================================================================
import asyncio
import json
import os
import sys
import types

import httpx
import pytest
from pydantic import SecretStr

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, _REPO_ROOT)

from backend.app.services import scope as _scope
from backend.app.services.scope import ScopePolicy
from backend.app.services.remote_safety import preflight, classify_target
from backend.app.services.fuzzer import _send_request, ScopeViolationError
from backend.app.cli.external_verify import run_external_verify
from backend.app.core.config import settings


# ------------------------------------------------------------------ hermetic helpers
def _client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def _send(handler, parsed_request, base_url, **kw):
    async with _client(handler) as client:
        return await _send_request(client, parsed_request, base_url, **kw)


def _never_called(_request):                    # a MockTransport handler that MUST never fire
    raise AssertionError("a refused target must NEVER open a socket")


def _resolver(mapping):
    """host -> [ip]; raises for an unmapped host so 'unresolvable' is exercisable."""
    def resolve(host):
        if host in mapping:
            return mapping[host]
        raise OSError(f"unresolved: {host}")
    return resolve


# ============================================================================
# A. A NON-LOOPBACK target is REMOTE, and the scope lock + preflight run on it.
# ============================================================================
def test_non_loopback_addresses_classify_as_remote():
    # private LAN / RFC1918 and a public name are REMOTE (non-loopback); loopback/localhost are not.
    assert classify_target("http://10.0.0.5") == (True, False)          # private v4 -> remote
    assert classify_target("http://192.168.1.50:8080") == (True, False)  # LAN -> remote
    assert classify_target("http://172.16.0.9") == (True, False)         # RFC1918 -> remote
    assert classify_target("https://app.example.com") == (True, True)    # public name -> remote+public
    assert classify_target("http://127.0.0.1:8001") == (False, False)    # loopback -> NOT remote
    assert classify_target("http://localhost:8888") == (False, False)    # localhost -> NOT remote


def test_declared_non_loopback_lan_target_runs_the_lock_and_is_honored():
    # An explicitly-declared private LAN target is authorized internal testing: the preflight RUNS
    # the audited ScopePolicy on it (not the unlocked lab pass-through) and honors it -> not blocked,
    # and it is flagged REMOTE (the loopback-only assumption is gone).
    pf = preflight("http://10.0.0.5:8002", "10.0.0.5:8002")
    assert pf.blocked is False and pf.is_remote is True and pf.is_public is False
    assert pf.reason == "ok"                                             # the lock ran and allowed it


# ============================================================================
# b. FAIL-CLOSED refusals at the REQUEST chokepoint (fuzzer._send_request).
#    Each MUST raise ScopeViolationError before any socket opens.
# ============================================================================
def test_toctou_rebind_flip_after_clean_preflight_is_refused_at_request_time(monkeypatch):
    """THE TOCTOU LOCK. Preflight resolves the public name to a SAFE global IP and passes; the
    attacker then flips DNS so it resolves to an INTERNAL IP. The request-time re-check MUST refuse
    the flip (rebinding_private_ip) and open no socket — a clean preflight can never grant a pass
    that outlives the resolution it was based on."""
    HOST = "rebind.example.com"
    # Phase 1 — preflight sees the safe, validated public IP and ALLOWS (would proceed).
    pf = preflight(f"https://{HOST}", HOST, resolver=_resolver({HOST: ["93.184.216.34"]}))
    assert pf.blocked is False and pf.resolved_ips == ("93.184.216.34",)
    # Phase 2 — DNS flips to an internal IP; the chokepoint re-resolves via the system resolver.
    monkeypatch.setattr(_scope, "_system_resolver", lambda h: ["10.0.0.5"])
    with pytest.raises(ScopeViolationError):
        asyncio.run(_send(_never_called, {"method": "GET", "path": "/data"},
                          f"http://{HOST}:80", scope=ScopePolicy.from_declaration([HOST])))


def test_metadata_ip_target_is_refused_at_request_time(monkeypatch):
    HOST = "meta.example.com"
    monkeypatch.setattr(_scope, "_system_resolver", lambda h: ["169.254.169.254"])  # cloud metadata
    with pytest.raises(ScopeViolationError):
        asyncio.run(_send(_never_called, {"method": "GET", "path": "/x"},
                          f"http://{HOST}:80", scope=ScopePolicy.from_declaration([HOST])))


def test_link_local_target_is_refused_at_request_time(monkeypatch):
    HOST = "ll.example.com"
    monkeypatch.setattr(_scope, "_system_resolver", lambda h: ["169.254.1.1"])      # link-local
    with pytest.raises(ScopeViolationError):
        asyncio.run(_send(_never_called, {"method": "GET", "path": "/x"},
                          f"http://{HOST}:80", scope=ScopePolicy.from_declaration([HOST])))


def test_out_of_scope_host_is_refused_at_request_time():
    # host miss is decided before any resolution; the socket never opens.
    pol = ScopePolicy.from_declaration(["app.example.com"])
    with pytest.raises(ScopeViolationError):
        asyncio.run(_send(_never_called, {"method": "GET", "path": "/x"},
                          "http://evil.example.com:80", scope=pol))


def test_unresolvable_public_name_is_refused_at_request_time(monkeypatch):
    HOST = "ghost.example.com"
    def _boom(_h):
        raise OSError("no such host")
    monkeypatch.setattr(_scope, "_system_resolver", _boom)
    with pytest.raises(ScopeViolationError):
        asyncio.run(_send(_never_called, {"method": "GET", "path": "/x"},
                          f"http://{HOST}:80", scope=ScopePolicy.from_declaration([HOST])))


# ============================================================================
# c. POSITIVE CONTROL at the chokepoint: a legit in-scope NON-loopback public target
#    completes and is PINNED to its validated IP (the rails do not over-block).
# ============================================================================
def test_in_scope_remote_public_target_completes_and_is_pinned(monkeypatch):
    HOST = "app.example.com"
    GLOBAL_IP = "93.184.216.34"
    monkeypatch.setattr(_scope, "_system_resolver", lambda h: [GLOBAL_IP])
    dialed, host_headers = [], []

    def handler(request):
        dialed.append(request.url.host)
        host_headers.append(request.headers.get("host"))
        return httpx.Response(200, text="in-scope-remote-ok")

    res = asyncio.run(_send(handler, {"method": "GET", "path": "/data"},
                            f"http://{HOST}:80", scope=ScopePolicy.from_declaration([HOST])))
    assert res["status_code"] == 200 and res["response_body"] == "in-scope-remote-ok"
    assert dialed == [GLOBAL_IP]                    # dialed the scope-validated pinned IP (D25)
    assert host_headers == [HOST]                   # Host routing preserved (app still sees the name)
    assert res["url"] == f"http://{HOST}:80/data"   # the record keeps the LOGICAL url, not the IP


# ============================================================================
# END-TO-END verify CLI (external_verify.run_external_verify): the preflight is
# fail-closed for a REMOTE SSRF target BEFORE the engine runs, and lets a legit
# remote target through to a verdict. scope._system_resolver is monkeypatched so the
# CLI's own preflight (which uses the default resolver) is hermetic.
# ============================================================================
_SPEC = {"openapi": "3.0.0", "paths": {"/api/users/{id}": {"get": {"operationId": "u"}}}}
_OP = {"method": "GET", "baseline_path": "/api/users/1", "body": None,
       "payload": {"location": "path_segment", "target_param": "1", "payload_string": "2",
                   "type": "BOLA"},
       "shape": "read_semantic"}


class _CountingEngine:
    """Records whether the engine was EVER called. A blocked preflight must leave calls == 0."""
    def __init__(self, verdict="verified"):
        self.calls = 0
        self._verdict = verdict

    async def __call__(self, **kwargs):
        self.calls += 1
        return types.SimpleNamespace(
            status="completed", ai_verdict=self._verdict, ai_verdict_raw=self._verdict,
            guard_override=None, degraded_reason=None,
            caller_identity_anchor=None, payload_causality_anchor=None, state_jump_anchor=None,
            negative_assertion_anchor=None, anchoring_result=None, pre_flight_status=None,
            owner_view_corroborated=True, follow_up_response=None,
            baseline={"response": {"status_code": 200}}, attack={"response": {"status_code": 200}})


def _write(tmp_path, name, obj):
    p = tmp_path / name
    p.write_text(json.dumps(obj), encoding="utf-8")
    return str(p)


def _run_cli(tmp_path, monkeypatch, engine, *, target, resolver, atk="ATK-TOK", own="OWN-TOK"):
    """Drive the REAL run_external_verify against `target`, with the CLI's own preflight made
    hermetic by monkeypatching scope._system_resolver. Returns (exit_code, combined_output)."""
    monkeypatch.setattr(settings, "LLM_API_KEY", SecretStr("test-key"))
    monkeypatch.setattr(settings, "AI_DEEP_VERIFY_ENABLED", False)
    monkeypatch.setattr(_scope, "_system_resolver", resolver)
    monkeypatch.setenv("TARGET_ATTACKER_TOKEN", atk)
    monkeypatch.setenv("TARGET_OWNER_TOKEN", own)
    monkeypatch.delenv("TARGET_BYSTANDER_TOKEN", raising=False)
    lines = []

    def _boom(*_a):
        raise AssertionError("must NOT prompt — tokens come from the environment")

    code = run_external_verify(
        target=target, spec_path=_write(tmp_path, "spec.json", _SPEC),
        op_path=_write(tmp_path, "op.json", _OP), prompt_secret=_boom,
        config_path=str(tmp_path / "no-config.toml"), engine=engine,
        echo=lambda *a: lines.append(" ".join(str(x) for x in a)),
        err=lambda *a: lines.append(" ".join(str(x) for x in a)))
    return code, "\n".join(lines)


def test_cli_refuses_rebinding_remote_target_before_engine(tmp_path, monkeypatch):
    eng = _CountingEngine()
    code, out = _run_cli(tmp_path, monkeypatch, eng,
                         target="https://rebind.example.com",
                         resolver=lambda h: ["10.0.0.5"])          # public name -> private IP
    assert code == 2                                               # NOT DATA (fail-closed)
    assert eng.calls == 0                                          # engine NEVER ran
    assert "[NOT DATA]" in out and "rebinding" in out.lower()


def test_cli_refuses_cloud_metadata_remote_target_before_engine(tmp_path, monkeypatch):
    eng = _CountingEngine()
    code, out = _run_cli(tmp_path, monkeypatch, eng,
                         target="https://meta.example.com",
                         resolver=lambda h: ["169.254.169.254"])
    assert code == 2 and eng.calls == 0
    assert "[NOT DATA]" in out and ("metadata" in out.lower() or "ssrf" in out.lower())


def test_cli_refuses_unresolvable_remote_target_before_engine(tmp_path, monkeypatch):
    def _boom(_h):
        raise OSError("no such host")
    eng = _CountingEngine()
    code, out = _run_cli(tmp_path, monkeypatch, eng,
                         target="https://ghost.example.com", resolver=_boom)
    assert code == 2 and eng.calls == 0
    assert "[NOT DATA]" in out and "resolve" in out.lower()


def test_cli_allows_legit_in_scope_remote_target_through_to_verdict(tmp_path, monkeypatch):
    # POSITIVE CONTROL end-to-end: a public name resolving to a global IP is in scope -> the preflight
    # lets it through and the (injected) engine's CONFIRMED verdict renders. Proves the rails do not
    # over-block a legitimate remote target at the CLI boundary.
    assert classify_target("https://app.example.com") == (True, True)   # it IS remote+public
    eng = _CountingEngine(verdict="verified")
    code, out = _run_cli(tmp_path, monkeypatch, eng,
                         target="https://app.example.com",
                         resolver=lambda h: ["93.184.216.34"])          # global -> in scope
    assert eng.calls == 1                                               # the engine WAS reached
    assert code == 1 and "[CONFIRMED]" in out                           # a verdict rendered (not over-blocked)
