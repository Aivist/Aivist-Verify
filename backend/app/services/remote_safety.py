# ==============================================================================
# Remote-target safety preflight (ROADMAP PLANNED #1: "beyond localhost").
#
# The confirmer's OUTBOUND requests are ALREADY hardened for remote use by the
# audited request path — nothing here re-implements a guard:
#   * scope-lock fail-closed .......... services/scope.py  (ScopePolicy)
#   * metadata / link-local refusal ... services/scope.py  (_classify_ip)
#   * DNS-rebinding refusal ........... services/scope.py  (public name -> private IP)
#   * resolved-IP pinning (D25 TOCTOU)  services/fuzzer.py (_pin_kwargs / _send_request)
#   * challenge / rate-limit breaker .. services/deep_verifier.py (challenge_break)
# Those all fire at REQUEST time inside `_send_request`, so a run against a remote
# host is protected today whether or not this module is called.
#
# What THIS module adds is a thin, EARLY, human-readable preflight that runs the
# SAME `ScopePolicy` decision against the target BEFORE the engine starts — so a
# remote operator gets one clear "refused: DNS rebinding / metadata / unresolvable"
# up front instead of a mid-run scope violation. It is pure orchestration over the
# existing policy: it makes NO verdict decision and changes NO access-control result.
#
# Behavior-preservation: the preflight resolves DNS ONLY for a PUBLIC registrable
# name (exactly as ScopePolicy.check does) — an IP literal (the labs' 127.0.0.1),
# a single-label host, or an intranet-TLD name is never resolved, so localhost /
# lab / offline-test targets reach the engine byte-identically.
# ==============================================================================
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple
from urllib.parse import urlsplit

from backend.app.services.scope import (
    ScopePolicy,
    Resolver,
    _classify_ip,
    _is_public_registrable,
    _maybe_ip,
    _normalize_host,
)

# The refusal reasons that are a genuine SSRF / egress threat — the ONLY ones this
# preflight blocks on. Every other not-allowed reason (a bad scope declaration, a
# port mismatch, an unresolvable name) is left to the existing engine flow so behavior
# is unchanged; those already surface as NOT DATA there.
_SSRF_BLOCK_REASONS = frozenset({"metadata_ip", "link_local_ip", "rebinding_private_ip"})

# A public name that cannot be resolved is a dead remote target: surface it early with
# a clear message (same NOT-DATA outcome the engine's transport error would produce).
_BLOCK_REASONS = _SSRF_BLOCK_REASONS | {"dns_resolution_failed"}

_REASON_HELP = {
    "metadata_ip": "resolves to a cloud metadata endpoint (169.254.169.254) - refused as SSRF.",
    "link_local_ip": "resolves to a link-local address - refused.",
    "rebinding_private_ip": "is a public name that resolves to a private/loopback IP - "
                            "refused as DNS rebinding.",
    "dns_resolution_failed": "could not be resolved (no reachable address).",
}


@dataclass(frozen=True)
class PreflightResult:
    """Outcome of the remote-safety preflight. `blocked` is True ONLY for a genuine
    egress threat (SSRF/rebinding/metadata/unresolvable-public). A non-blocked result
    always proceeds to the engine, which re-checks and pins every request itself."""
    blocked: bool
    reason: str                          # ScopeDecision.reason ("ok" | "unlocked" | ...)
    is_remote: bool                      # target host is NOT loopback (LAN / private / public)
    is_public: bool                      # target is a public registrable name or a global IP
    resolved_ips: Optional[Tuple[str, ...]]
    message: str

    def __bool__(self) -> bool:          # `if preflight(...):` -> True when it is SAFE to proceed
        return not self.blocked


def classify_target(base_url: str) -> Tuple[bool, bool]:
    """(is_remote, is_public) for a target base URL, using the SAME host classification
    the scope policy uses. is_remote = the host is not loopback. is_public = a public
    registrable name, or an IP that classifies as global. Never resolves DNS; never raises."""
    host = _normalize_host(urlsplit(base_url if "://" in base_url else "http://" + base_url).hostname or "")
    if not host:
        return (False, False)
    ip = _maybe_ip(host)
    if ip is not None:
        cls = _classify_ip(ip)
        return (cls != "loopback", cls == "global")
    if host in ("localhost",):
        return (False, False)
    return (True, _is_public_registrable(host))


def preflight(base_url: str, approved_host: Optional[str], *,
              resolver: Optional[Resolver] = None) -> PreflightResult:
    """Run the audited `ScopePolicy` decision against the target BEFORE the run.

    `approved_host` is the SAME scope declaration the engine will enforce (the caller
    passes what it hands `execute_deep_verification`). Empty => unlocked (lab mode):
    nothing is blocked, byte-identical to today. Otherwise the target is checked; the
    result is blocked ONLY on a real egress threat (SSRF / rebinding / metadata /
    unresolvable public name). `resolver` is an injection seam for offline tests.
    """
    is_remote, is_public = classify_target(base_url)

    if not approved_host:
        return PreflightResult(False, "unlocked", is_remote, is_public, None,
                               "scope unlocked (no declared host) - lab / localhost mode")

    policy = ScopePolicy.from_declaration([approved_host])
    decision = policy.check(base_url, resolver=resolver)
    reason = decision.reason

    if reason in _BLOCK_REASONS:
        help_txt = _REASON_HELP.get(reason, f"refused ({reason}).")
        return PreflightResult(True, reason, is_remote, is_public, None,
                               f"remote-safety preflight: target {base_url!r} {help_txt}")

    where = "remote" if is_remote else "local"
    pin = f"; connection will be pinned to {decision.resolved_ips[0]}" if decision.resolved_ips else ""
    return PreflightResult(False, reason, is_remote, is_public, decision.resolved_ips,
                           f"remote-safety preflight: {where} target in scope{pin}")
