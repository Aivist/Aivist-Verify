# ==============================================================================
# Scope policy — THE single audited host-scope decision for the whole engine.
#
# This module is the "one audited implementation" the scope-lock hardening
# milestone (ROADMAP node 3) converges on. Today the engine has multiple
# hand-rolled host checks (the fuzzer's custody-gated `_host_of()==approved`, the
# deep verifier's four inline pre-checks, and the proxy's separate suffix-match
# `pruner.host_in_scope`). They will all be replaced by ONE ScopePolicy so passive
# capture and active fuzzing share a single decision tree that cannot drift.
#
# THIS COMMIT (1) adds only the PURE core + its adversarial test suite. Nothing
# imports it yet, so it has zero blast radius; the enforcement wiring into
# `_send_request` (active) and the proxy (passive) lands in later commits.
#
# GUIDING PRINCIPLE — resolve ambiguity toward USER FREEDOM, not maximal lockdown.
# The common case ("I want to test this domain") is ONE simple declaration; the
# DNS / port / wildcard / redirect defenses run underneath automatically. We never
# push configuration complexity onto the user, and we never block what they
# legitimately authorized — we only guarantee traffic never leaves that authority.
#
#   * ZERO declaration => UNLOCKED (lab / localhost mode). check() allows everything,
#     byte-identically to today, so the two labs + the 430/430 harness stay green.
#     A user opts IN to strict, fail-closed enforcement by declaring a scope — the
#     same opt-in shape the D24 owner gate uses.
#   * Explicitly-declared private / loopback targets (the labs' 127.0.0.1, an
#     authorized internal host) are HONORED. The SSRF / DNS-rebinding guard only
#     fires when a PUBLIC registrable name resolves to a non-global address — the
#     signature of rebinding, not of a user's own declared target.
#   * Port: no port declared => any port allowed (permissive); explicit port =>
#     strict host+port lock.
#   * A bare host `example.com` matches the apex only; subdomains require the
#     explicit wildcard `*.example.com`, which ALSO matches the apex (a documented
#     convenience matching pentest-authorization intent). Over-broad wildcards
#     (`*`, `*.com`, `*.co.uk`) are rejected at declaration time.
#
# Pure + stdlib-only (no FastAPI / SQLAlchemy / httpx import) so the proxy addon,
# which runs inside mitmproxy's own interpreter, can import the matcher later.
# ==============================================================================
from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from typing import Callable, Iterable, List, Optional, Tuple
from urllib.parse import urlsplit

from backend.app.services.scope_psl import MULTI_LABEL_PUBLIC_SUFFIXES

# Non-public "intranet" pseudo-TLDs: a name under one of these is an internal target,
# NOT a registrable public domain, so a private/loopback resolution is EXPECTED and
# allowed (authorized internal testing). A single-label bare hostname ("myhost") is
# likewise treated as intranet. Everything else that looks like a real domain has the
# rebinding guard applied — the secure default for anything that could be an attack.
_INTRANET_TLDS = frozenset({
    "local", "internal", "intranet", "lan", "corp", "home", "localdomain",
    "test", "example", "invalid", "localhost",
})

# Well-known cloud metadata endpoints — NEVER a legitimate target, refused even when
# explicitly named (the crown jewel of SSRF).
_METADATA_IPS = frozenset({"169.254.169.254", "fd00:ec2::254"})

_PORT_RE = re.compile(r"^[0-9]{1,5}$")
_DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}


class ScopeError(ValueError):
    """A malformed or over-broad scope DECLARATION. Raised at construction so a bad
    scope fails fast at declaration time, never silently at request time."""


# ------------------------------------------------------------------------------
# Decision object — carries a machine-readable reason so callers can log the exact
# refusal and build a good error (the ScopeViolationError message in commit 2).
# ------------------------------------------------------------------------------
@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    reason: str                     # "unlocked" | "ok" | "host_not_in_scope"
                                    # | "port_mismatch" | "invalid_url"
                                    # | "metadata_ip" | "link_local_ip"
                                    # | "rebinding_private_ip" | "dns_resolution_failed"
    host: Optional[str] = None
    port: Optional[int] = None
    matched_entry: Optional[str] = None

    def __bool__(self) -> bool:      # so `if policy.check(url):` reads naturally
        return self.allowed


# ------------------------------------------------------------------------------
# Low-level, pure helpers (host normalization, IP encoding canonicalization, IP
# classification). All target-agnostic; none touch the network.
# ------------------------------------------------------------------------------
def _normalize_host(raw: Optional[str]) -> str:
    """Canonical comparison key for a host. Applied IDENTICALLY to every scope entry
    and every candidate host so an attacker cannot slip past via encoding/casing:
    strip brackets + surrounding whitespace, drop a trailing FQDN dot, lower-case,
    and best-effort IDN->ASCII (punycode). Never raises."""
    h = (raw or "").strip().strip("[]").strip()
    h = h.rstrip(".")               # FQDN root: "example.com." -> "example.com"
    h = h.lower()
    if any(ord(c) > 127 for c in h):
        try:
            h = h.encode("idna").decode("ascii")
        except Exception:
            # Undecodable IDN (e.g. underscores): keep the lowercased raw. Both sides
            # use this same fallback, so comparison stays consistent.
            pass
    return h


def _maybe_ip(host: str) -> Optional[str]:
    """If `host` is an IP address in ANY common encoding, return its CANONICAL string;
    else None. Defuses decimal ('2130706433') and hex ('0x7f000001') encodings of
    loopback that would otherwise dodge an IP-based scope or the rebinding guard.
    Dotted-octal/hex mixes are not decoded here (documented gap): in a LOCKED policy
    such an exotic host simply fails to match any entry and is denied by default."""
    if not host:
        return None
    try:
        return str(ipaddress.ip_address(host))          # standard v4/v6 (and bare "::1")
    except ValueError:
        pass
    if re.fullmatch(r"[0-9]+", host):                   # bare decimal integer
        try:
            return str(ipaddress.ip_address(int(host)))
        except (ValueError, OverflowError):
            return None
    if re.fullmatch(r"0x[0-9a-fA-F]+", host):           # bare hex integer
        try:
            return str(ipaddress.ip_address(int(host, 16)))
        except (ValueError, OverflowError):
            return None
    return None


def _classify_ip(ip_str: str) -> str:
    """Classify a concrete IP: 'metadata' | 'link_local' | 'loopback' | 'private'
    | 'reserved' | 'global' | 'invalid'. Order matters — metadata and link-local are
    checked before the broader private/loopback buckets."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return "invalid"
    if ip_str in _METADATA_IPS:
        return "metadata"
    if getattr(ip, "is_link_local", False):
        return "link_local"
    if ip.is_loopback:
        return "loopback"
    if ip.is_private:
        return "private"
    if ip.is_reserved or ip.is_unspecified or ip.is_multicast:
        return "reserved"
    return "global" if ip.is_global else "private"


def _parse_port(text: str) -> int:
    if not _PORT_RE.match(text or ""):
        raise ScopeError(f"invalid port: {text!r}")
    port = int(text)
    if not (1 <= port <= 65535):
        raise ScopeError(f"port out of range [1,65535]: {port}")
    return port


def _split_host_port(s: str) -> Tuple[str, Optional[int]]:
    """Split an authority string into (host, port|None). Handles bracketed IPv6
    (`[::1]:8000`), bare IPv6 (`::1`, no port), and `host:port`."""
    s = s.strip()
    if s.startswith("["):
        end = s.find("]")
        if end == -1:
            raise ScopeError(f"unterminated IPv6 literal: {s!r}")
        host = s[1:end]
        rest = s[end + 1:]
        if rest.startswith(":"):
            return host, _parse_port(rest[1:])
        if rest:
            raise ScopeError(f"junk after IPv6 literal: {s!r}")
        return host, None
    if s.count(":") == 1:
        host, _, port_s = s.partition(":")
        return host, _parse_port(port_s)
    if s.count(":") > 1:
        return s, None                                   # bare IPv6, no port
    return s, None


def _is_public_registrable(host: str) -> bool:
    """True iff `host` looks like a PUBLIC registrable domain (so the DNS-rebinding
    guard applies). A single-label hostname or a name under an intranet pseudo-TLD is
    treated as internal (guard does not apply -> private resolution allowed). Any
    other multi-label name is treated as public — the SECURE default, since a real
    domain resolving to a private IP is the rebinding signature we must block; the
    user's escape for an exotic internal name is to declare it by IP."""
    labels = host.split(".")
    if len(labels) < 2:
        return False                                     # bare hostname -> intranet
    if labels[-1] in _INTRANET_TLDS:
        return False
    return True


def _reject_if_overbroad(base: str, raw: str) -> None:
    """A wildcard `*.<base>` must not span an entire registrable-domain space. Reject
    when the base is a single label (`*`, `*.com`, `*.io`) or is itself a multi-label
    public suffix (`*.co.uk`). A base like `example.com` / `example.co.uk` is fine."""
    labels = base.split(".")
    if len(labels) < 2:
        raise ScopeError(
            f"over-broad wildcard {raw!r}: a wildcard must be at least '*.domain.tld'"
        )
    if base in MULTI_LABEL_PUBLIC_SUFFIXES:
        raise ScopeError(
            f"over-broad wildcard {raw!r}: '{base}' is a public suffix (would span "
            f"every registrable domain under it)"
        )


# ------------------------------------------------------------------------------
# A single normalized scope entry.
# ------------------------------------------------------------------------------
@dataclass(frozen=True)
class ScopeEntry:
    host: str                       # normalized host (canonical IP when is_ip_literal)
    is_wildcard: bool               # `*.host` form (subdomains + apex)
    port: Optional[int]             # None => any port
    is_ip_literal: bool
    raw: str                        # the original declaration string (for diagnostics)

    def matches(self, nhost: str, port: Optional[int]) -> bool:
        """Host + port + wildcard/apex match against an already-normalized host."""
        if self.port is not None and self.port != port:
            return False
        if self.is_ip_literal:
            cand = _maybe_ip(nhost)
            return cand is not None and cand == self.host
        if self.is_wildcard:
            return nhost == self.host or nhost.endswith("." + self.host)
        return nhost == self.host


def _parse_entry(raw: str) -> Optional[ScopeEntry]:
    """Parse ONE declaration string into a normalized ScopeEntry, or None if blank.
    Lenient on input shape (tolerates a scheme/path/userinfo a user may paste), strict
    on the result. Raises ScopeError on anything malformed or over-broad."""
    s = (raw or "").strip()
    if not s:
        return None
    if "://" in s:                  # tolerate a pasted URL: keep the authority
        s = s.split("://", 1)[1]
    s = s.split("/", 1)[0]          # drop any path
    if "@" in s:                    # a scope entry must not carry userinfo
        raise ScopeError(f"scope entry must not contain userinfo: {raw!r}")

    is_wild = False
    if s.startswith("*."):
        is_wild = True
        s = s[2:]
    elif s.startswith("*"):
        raise ScopeError(
            f"over-broad wildcard {raw!r}: a wildcard must be at least '*.domain.tld'"
        )

    host, port = _split_host_port(s)
    nhost = _normalize_host(host)
    if not nhost:
        raise ScopeError(f"empty host in scope entry: {raw!r}")

    ip = _maybe_ip(nhost)
    is_ip = ip is not None
    if is_ip:
        nhost = ip                  # canonicalize (e.g. decimal/hex -> dotted)
        if is_wild:
            raise ScopeError(f"wildcard on an IP address is not allowed: {raw!r}")
    if is_wild:
        _reject_if_overbroad(nhost, raw)

    return ScopeEntry(host=nhost, is_wildcard=is_wild, port=port,
                      is_ip_literal=is_ip, raw=s)


# A resolver maps a hostname to a list of resolved IP strings. Injected so the core
# stays pure and offline-testable; the default uses the system resolver and is only
# reached once enforcement is wired into the network path (commit 2).
Resolver = Callable[[str], List[str]]


def _system_resolver(host: str) -> List[str]:
    infos = socket.getaddrinfo(host, None)
    return list({ai[4][0] for ai in infos})


# ------------------------------------------------------------------------------
# The policy.
# ------------------------------------------------------------------------------
class ScopePolicy:
    """An immutable set of scope entries plus the audited decision logic.

    Construct via `from_declaration([...])`. An empty declaration yields an UNLOCKED
    policy (lab mode): every check is allowed, byte-identically to pre-scope-lock
    behavior. A non-empty declaration is LOCKED and fail-closed.
    """

    __slots__ = ("_entries", "_locked")

    def __init__(self, entries: Tuple[ScopeEntry, ...]) -> None:
        self._entries = entries
        self._locked = bool(entries)

    # -- construction ------------------------------------------------------
    @classmethod
    def from_declaration(cls, scope: Optional[Iterable[str]]) -> "ScopePolicy":
        """Build a policy from the unified run-time declaration (a list of host
        patterns). None/empty => unlocked. Raises ScopeError on a malformed entry."""
        entries: List[ScopeEntry] = []
        for raw in (scope or []):
            entry = _parse_entry(raw)
            if entry is not None:
                entries.append(entry)
        return cls(tuple(entries))

    @property
    def locked(self) -> bool:
        return self._locked

    @property
    def entries(self) -> Tuple[ScopeEntry, ...]:
        return self._entries

    # -- passive-side check (host/port only; no DNS resolution) ------------
    def host_allowed(self, host: str, port: Optional[int] = None) -> bool:
        """Host + port + wildcard/apex match ONLY. Used by the passive proxy addon,
        which observes flows the browser already originated and so needs no
        resolved-IP guard. Unlocked => always True."""
        if not self._locked:
            return True
        nhost = _normalize_host(host)
        return any(e.matches(nhost, port) for e in self._entries)

    # -- active-side check (full guard: host + port + resolved-IP) ---------
    def check(self, url: str, *, resolver: Optional[Resolver] = None) -> ScopeDecision:
        """The authoritative active-side decision for a concrete request URL.

        Unlocked => allowed (lab pass-through). Otherwise: parse the real host
        (urlsplit.hostname strips userinfo/port/brackets), match host+port, then apply
        the resolved-IP guard — refuse metadata/link-local always, and refuse a PUBLIC
        registrable name that resolves to a non-global address (DNS rebinding). An
        explicitly-declared IP target, or an intranet name, keeps its private view.
        """
        if not self._locked:
            return ScopeDecision(True, "unlocked")

        parts = urlsplit(url)
        raw_host = parts.hostname
        if not raw_host:
            return ScopeDecision(False, "invalid_url", None, None, None)
        nhost = _normalize_host(raw_host)
        try:
            port = parts.port if parts.port is not None else _DEFAULT_PORTS.get(
                (parts.scheme or "").lower()
            )
        except ValueError:
            return ScopeDecision(False, "invalid_url", nhost, None, None)

        matched = next((e for e in self._entries if e.matches(nhost, port)), None)
        if matched is None:
            # Distinguish a pure port mismatch (host WOULD match at another port) from a
            # genuine host miss, so the caller can log the precise refusal reason.
            host_would_match = any(
                self._entry_host_matches(e, nhost) for e in self._entries
            )
            reason = "port_mismatch" if host_would_match else "host_not_in_scope"
            return ScopeDecision(False, reason, nhost, port, None)

        # Host+port are in scope. Now the resolved-IP guard.
        cand_ip = _maybe_ip(nhost)
        if cand_ip is not None:
            cls = _classify_ip(cand_ip)
            if cls == "metadata":
                return ScopeDecision(False, "metadata_ip", nhost, port, matched.raw)
            # An explicitly-declared IP target (labs' loopback, authorized internal)
            # is the user's authorization — honored. Link-local is refused as it is
            # never a legitimate declared target.
            if cls == "link_local":
                return ScopeDecision(False, "link_local_ip", nhost, port, matched.raw)
            return ScopeDecision(True, "ok", nhost, port, matched.raw)

        # DNS name. The rebinding guard applies ONLY to PUBLIC registrable names, so only
        # those are resolved. An intranet / single-label name (an internal host, or an
        # in-process test host) is an explicitly-declared internal target whose private
        # resolution is intended and honored — it is NOT resolved here. Resolving it would
        # be pointless (the guard would never refuse a non-public name) and would wrongly
        # block a non-resolvable in-process host. IP-literals were already handled above.
        # The guard's set of refusable cases is unchanged; we simply do not resolve names
        # it would never act on.
        if not _is_public_registrable(nhost):
            return ScopeDecision(True, "ok", nhost, port, matched.raw)
        resolve = resolver or _system_resolver
        try:
            ips = resolve(nhost)
        except Exception:
            return ScopeDecision(False, "dns_resolution_failed", nhost, port, matched.raw)
        classes = [_classify_ip(ip) for ip in (ips or [])]
        if any(c == "metadata" for c in classes):
            return ScopeDecision(False, "metadata_ip", nhost, port, matched.raw)
        if any(c == "link_local" for c in classes):
            return ScopeDecision(False, "link_local_ip", nhost, port, matched.raw)
        if any(c != "global" for c in classes):
            # A public, registrable domain resolving to loopback/private/reserved is the
            # DNS rebinding signature — refuse even though the NAME is in scope.
            return ScopeDecision(False, "rebinding_private_ip", nhost, port, matched.raw)
        return ScopeDecision(True, "ok", nhost, port, matched.raw)

    @staticmethod
    def _entry_host_matches(entry: ScopeEntry, nhost: str) -> bool:
        """Host-only match for an entry, ignoring its port (used to tell a port
        mismatch apart from a host miss when building the refusal reason)."""
        if entry.is_ip_literal:
            cand = _maybe_ip(nhost)
            return cand is not None and cand == entry.host
        if entry.is_wildcard:
            return nhost == entry.host or nhost.endswith("." + entry.host)
        return nhost == entry.host
