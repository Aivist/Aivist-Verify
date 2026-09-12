# ==============================================================================
# Remote-safety preflight — offline tests (injected resolver; no real network).
#
# Proves the preflight REUSES ScopePolicy correctly: loopback/lab targets pass untouched
# (and are never resolved), a genuine remote target is allowed + pinned, and the SSRF /
# DNS-rebinding / metadata threats are refused EARLY. Nothing here asserts a verdict — the
# preflight makes no verdict decision.
# ==============================================================================
import os
import sys

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, _REPO_ROOT)

from backend.app.services.remote_safety import preflight, classify_target, PreflightResult


def _resolver(mapping):
    """A ScopePolicy resolver stub: host -> list[ip]. Raises for an unmapped host so an
    'unresolvable' path is testable too."""
    def resolve(host):
        if host in mapping:
            return mapping[host]
        raise OSError(f"unresolved: {host}")
    return resolve


# ---- lab / localhost: pass through, never resolved -------------------------------------------
def test_loopback_ip_target_passes_and_is_not_remote():
    pf = preflight("http://127.0.0.1:8002", "127.0.0.1:8002")
    assert pf.blocked is False
    assert pf.is_remote is False and pf.is_public is False
    assert bool(pf) is True                     # __bool__ => safe to proceed


def test_localhost_name_target_passes():
    pf = preflight("http://localhost:8888", "localhost:8888")
    assert pf.blocked is False and pf.is_remote is False


def test_intranet_name_is_not_resolved(monkeypatch):
    # crapi.local is an intranet TLD -> ScopePolicy never resolves it. Prove no resolver is called.
    def _boom(_host):
        raise AssertionError("intranet name must not be resolved")
    pf = preflight("http://crapi.local", "crapi.local", resolver=_boom)
    assert pf.blocked is False


def test_unlocked_scope_passes():
    pf = preflight("http://anything", "")       # no declared host => unlocked (lab mode)
    assert pf.blocked is False and pf.reason == "unlocked"


# ---- genuine remote: allowed + pinned --------------------------------------------------------
def test_public_name_resolving_global_is_allowed_and_pinned():
    r = _resolver({"shop.example.com": ["93.184.216.34"]})
    pf = preflight("https://shop.example.com", "shop.example.com", resolver=r)
    assert pf.blocked is False
    assert pf.is_remote is True and pf.is_public is True
    assert pf.resolved_ips == ("93.184.216.34",)     # the connection will be pinned to this


def test_private_lan_ip_target_is_honored_and_remote():
    # An explicitly-declared private LAN target is authorized internal testing -> allowed, and it
    # is non-loopback so it proves the loopback assumption is gone.
    pf = preflight("http://10.0.0.5:8002", "10.0.0.5:8002")
    assert pf.blocked is False and pf.is_remote is True and pf.is_public is False


# ---- SSRF / rebinding threats: refused early -------------------------------------------------
def test_public_name_resolving_private_is_rebinding_blocked():
    r = _resolver({"evil.example.com": ["10.0.0.5"]})
    pf = preflight("https://evil.example.com", "evil.example.com", resolver=r)
    assert pf.blocked is True and pf.reason == "rebinding_private_ip"
    assert "rebinding" in pf.message.lower()


def test_public_name_resolving_metadata_is_blocked():
    r = _resolver({"evil.example.com": ["169.254.169.254"]})
    pf = preflight("https://evil.example.com", "evil.example.com", resolver=r)
    assert pf.blocked is True and pf.reason == "metadata_ip"


def test_link_local_ip_target_is_blocked():
    pf = preflight("http://169.254.169.253:80", "169.254.169.253:80")
    assert pf.blocked is True and pf.reason in ("link_local_ip", "metadata_ip")


def test_unresolvable_public_name_is_blocked_early():
    r = _resolver({})                            # nothing resolves
    pf = preflight("https://ghost.example.com", "ghost.example.com", resolver=r)
    assert pf.blocked is True and pf.reason == "dns_resolution_failed"


# ---- classify_target ------------------------------------------------------------------------
def test_classify_target():
    assert classify_target("http://127.0.0.1:8002") == (False, False)     # loopback
    assert classify_target("http://10.0.0.5") == (True, False)            # private, remote
    assert classify_target("https://shop.example.com") == (True, True)    # public
    assert classify_target("http://localhost") == (False, False)
