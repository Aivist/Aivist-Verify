# ==============================================================================
# 3b E2E REMOTE PROOF — the verify path works over the AUTHORIZED-REMOTE (non-loopback) rails,
# not just the loopback lab pass-through. Two deterministic, hermetic parts (no external host):
#
#   Part 1a (REAL SOCKET, non-loopback): a tiny HTTP server bound to this machine's primary
#     NON-loopback interface; the REAL fuzzer._send_request drives a LOCKED ScopePolicy declared to
#     that non-loopback host — an in-scope request reaches it over a real socket, and an out-of-scope
#     host is refused (ScopeViolationError) before any socket. Self-SKIPS where no non-loopback
#     interface is bindable (CI without one), so it never destabilizes the default suite.
#
#   Part 1b (FULL CLI, hermetic engine): the actual `verify --target-file` entry
#     (external_verify.run_verify_from_target_file) drives a NON-loopback target to a real CONFIRMED,
#     with the engine injected (no LLM / no socket) so it is deterministic. A spy on the REAL
#     remote_safety.preflight proves the preflight RAN and classified the target REMOTE (is_remote,
#     scope LOCKED) — i.e. the authorized-remote path, not the unlocked loopback pass-through.
#
# REUSES the shipped safety + verify functions verbatim; adds NO source seam and changes NO
# safety logic. A companion real-socket + real-LLM run over a LAN IP is archived verbatim at
# scripts/measure/real_targets/REMOTE_TARGET_RESULTS.md (an engineering signal, not a benchmark entry).
# ==============================================================================
import asyncio
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest
from pydantic import SecretStr

import os
import sys
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, _REPO_ROOT)

from backend.app.services.scope import ScopePolicy
from backend.app.services.fuzzer import _send_request, ScopeViolationError
from backend.app.services import remote_safety as _remote_safety
from backend.app.services.remote_safety import classify_target
from backend.app.cli import external_verify as _ev
from backend.app.cli.external_verify import run_verify_from_target_file
from backend.app.core.config import settings


# ------------------------------------------------------------------ real-socket helpers (Part 1a)
def _primary_non_loopback_ipv4():
    """This machine's primary non-loopback IPv4, or None. Uses a UDP 'connect' (no packet is sent)
    to pick the egress interface address; returns None when there is no non-loopback interface
    (e.g. a locked-down CI box) so the caller can SKIP rather than fail."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))          # selects the egress iface; sends nothing for UDP
            ip = s.getsockname()[0]
        finally:
            s.close()
        return ip if ip and not ip.startswith("127.") else None
    except Exception:
        return None


class _OkHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'{"ok":true,"note":"real socket, non-loopback"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_a):                 # keep the test output clean
        pass


class _RealServer:
    """A ThreadingHTTPServer bound to `ip:0` (ephemeral port), started in a daemon thread."""
    def __init__(self, ip):
        self.httpd = ThreadingHTTPServer((ip, 0), _OkHandler)
        self.ip, self.port = self.httpd.server_address
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()


async def _send_once(base_url, path, scope):
    async with httpx.AsyncClient() as client:
        return await _send_request(client, {"method": "GET", "path": path}, base_url, scope=scope)


# ------------------------------------------------------------------ Part 1a: REAL socket, non-loopback
def test_real_socket_non_loopback_scope_lock_enforces_and_reaches():
    ip = _primary_non_loopback_ipv4()
    if ip is None:
        pytest.skip("no non-loopback interface bindable in this environment (real-socket e2e skipped)")
    assert classify_target(f"http://{ip}") == (True, False)      # the bound addr IS remote (non-loopback)

    with _RealServer(ip) as srv:
        base = f"http://{srv.ip}:{srv.port}"
        # IN-SCOPE: the LOCKED policy declared to the non-loopback host allows it AND it reaches the
        # server over a REAL socket (proves the locked remote path is live, not a loopback pass-through).
        pol_ok = ScopePolicy.from_declaration([f"{srv.ip}:{srv.port}"])
        assert pol_ok.locked is True
        res = asyncio.run(_send_once(base, "/api/thing", pol_ok))
        assert res["status_code"] == 200 and '"ok":true' in res["response_body"]

        # OUT-OF-SCOPE: the SAME real server, but the scope is declared to a DIFFERENT host -> the
        # chokepoint refuses before any socket (fail-closed), so the request never reaches the server.
        pol_other = ScopePolicy.from_declaration(["192.0.2.1:9"])    # TEST-NET-1, not our host
        with pytest.raises(ScopeViolationError):
            asyncio.run(_send_once(base, "/api/thing", pol_other))


# ------------------------------------------------------------------ Part 1b: FULL CLI over the remote path
class _FakeEngine:
    """Injected execute_deep_verification: records kwargs, returns a CONFIRMED-shaped result. No LLM,
    no socket -> deterministic. The zero-FP judge itself is exercised elsewhere; here we prove the
    REMOTE PATH assembly + preflight, not the verdict logic."""
    def __init__(self):
        self.calls = 0
        self.captured = None

    async def __call__(self, **kwargs):
        self.calls += 1
        self.captured = kwargs
        import types
        return types.SimpleNamespace(
            status="completed", ai_verdict="verified", ai_verdict_raw="verified",
            guard_override=None, degraded_reason=None,
            caller_identity_anchor=None, payload_causality_anchor=None, state_jump_anchor=None,
            negative_assertion_anchor=None, anchoring_result=None, pre_flight_status=None,
            owner_view_corroborated=True, follow_up_response=None,
            baseline={"response": {"status_code": 200}}, attack={"response": {"status_code": 200}})


_REMOTE_TARGET_TOML = (
    'name = "remote-stmt"\n'
    'base_url = "http://10.0.0.5:8002"\n'          # a NON-loopback (private LAN) target -> remote path
    'spec_path = ""\n'
    'method = "GET"\n'
    'path_template = "/api/statements/{id}"\n'
    'id_location = "path"\n'
    'id_param = "id"\n'
    'attacker_id = "1"\n'
    'victim_id = "2"\n'
    'auth_spec_path = ""\n'
)


def test_full_cli_verify_target_file_confirms_over_remote_path(tmp_path, monkeypatch):
    # Spy the REAL preflight so we can PROVE it ran on the remote target (not bypassed) and treated it
    # as remote + scope-locked (not the unlocked loopback pass-through).
    seen = {}
    _real_preflight = _remote_safety.preflight

    def _spy(base_url, approved_host, **kw):
        r = _real_preflight(base_url, approved_host, **kw)
        seen["pf"] = r
        seen["approved_host"] = approved_host
        return r

    monkeypatch.setattr(_remote_safety, "preflight", _spy)
    monkeypatch.setattr(settings, "LLM_API_KEY", SecretStr("test-key"))
    monkeypatch.setattr(settings, "AI_DEEP_VERIFY_ENABLED", False)
    monkeypatch.setenv("TARGET_ATTACKER_TOKEN", "ATK-REMOTE")
    monkeypatch.setenv("TARGET_OWNER_TOKEN", "OWN-REMOTE")
    monkeypatch.delenv("TARGET_BYSTANDER_TOKEN", raising=False)

    tf = tmp_path / "remote_target.toml"
    tf.write_text(_REMOTE_TARGET_TOML, encoding="utf-8")

    def _boom(*_a):
        raise AssertionError("must NOT prompt — tokens come from the environment")

    eng = _FakeEngine()
    lines = []
    code = run_verify_from_target_file(
        str(tf), prompt_secret=_boom, config_path=str(tmp_path / "no-config.toml"),
        engine=eng, echo=lambda *a: lines.append(" ".join(str(x) for x in a)),
        err=lambda *a: lines.append(" ".join(str(x) for x in a)))
    out = "\n".join(lines)

    # the REAL preflight RAN, on a REMOTE target, and did not block a legit in-scope private target
    assert "pf" in seen, "remote_safety.preflight was not called by the verify path"
    assert seen["pf"].is_remote is True and seen["pf"].blocked is False
    assert seen["approved_host"] == "10.0.0.5:8002"                        # scope derived from the target
    # the scope handed to the engine is LOCKED (not the unlocked/loopback pass-through)
    assert ScopePolicy.from_declaration([eng.captured["approved_host"]]).locked is True
    assert eng.captured["approved_host"] == "10.0.0.5:8002"
    assert eng.captured["base_url"] == "http://10.0.0.5:8002"
    # and the full CLI reached a CONFIRMED over that remote path
    assert eng.calls == 1 and code == 1 and "[CONFIRMED]" in out
