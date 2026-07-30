# ==============================================================================
# Adversarial test suite for the scope policy core (scope.py) — the single audited
# host-scope decision. These tests are written to FAIL against the naive
# implementations this module replaces (exact `host==approved`, substring `in`,
# unbounded `endswith`, "hostname only, never the resolved IP"), so a green run
# proves the hardening, not just that the code runs.
# ==============================================================================
import pytest

from backend.app.services.scope import (
    ScopePolicy,
    ScopeError,
    _classify_ip,
    _maybe_ip,
    _normalize_host,
)


def _resolver(mapping):
    """A fake DNS resolver over a {host: [ips]} map; raises for unknown hosts
    (exercises the dns_resolution_failed path). Keeps the core pure/offline."""
    def resolve(host):
        if host not in mapping:
            raise OSError(f"no fake DNS record for {host!r}")
        return list(mapping[host])
    return resolve


GLOBAL = "93.184.216.34"          # a public/global IPv4 (classic example.com address)
_GLOBAL_RESOLVER = _resolver({
    "example.com": [GLOBAL],
    "api.example.com": [GLOBAL],
    "www.example.com": [GLOBAL],
    "example.co.uk": [GLOBAL],
    "app.example.co.uk": [GLOBAL],
})


# ------------------------------------------------------------------------------
# Declaration parsing & over-broad-wildcard rejection
# ------------------------------------------------------------------------------
@pytest.mark.parametrize("bad", ["*", "*.com", "*.io", "*.dev", "*.co.uk", "*.gov.uk", "*.com.au"])
def test_overbroad_wildcards_rejected(bad):
    with pytest.raises(ScopeError):
        ScopePolicy.from_declaration([bad])


@pytest.mark.parametrize("ok", ["*.example.com", "*.example.co.uk", "*.internal.example.com"])
def test_specific_wildcards_accepted(ok):
    pol = ScopePolicy.from_declaration([ok])
    assert pol.locked


def test_wildcard_on_ip_rejected():
    with pytest.raises(ScopeError):
        ScopePolicy.from_declaration(["*.127.0.0.1"])


def test_userinfo_in_entry_rejected():
    with pytest.raises(ScopeError):
        ScopePolicy.from_declaration(["user@example.com"])


@pytest.mark.parametrize("bad", ["example.com:0", "example.com:70000", "example.com:abc"])
def test_invalid_port_rejected(bad):
    with pytest.raises(ScopeError):
        ScopePolicy.from_declaration([bad])


def test_pasted_url_forms_tolerated():
    # A user may paste a full URL; we keep only the authority.
    pol = ScopePolicy.from_declaration(["https://example.com/some/path"])
    assert pol.check("https://example.com/", resolver=_GLOBAL_RESOLVER).allowed


# ------------------------------------------------------------------------------
# Unlocked (lab) mode — zero declaration is byte-identical pass-through
# ------------------------------------------------------------------------------
@pytest.mark.parametrize("decl", [None, [], [""], ["   "]])
def test_empty_declaration_is_unlocked(decl):
    pol = ScopePolicy.from_declaration(decl)
    assert pol.locked is False
    d = pol.check("http://anything.example.org/x")
    assert d.allowed and d.reason == "unlocked"
    assert pol.host_allowed("literally-anything") is True


def test_unlocked_never_resolves():
    # Lab mode must not touch the network even accidentally: a resolver that would
    # blow up is never called because unlocked short-circuits.
    def boom(host):
        raise AssertionError("resolver must not be called in unlocked mode")
    pol = ScopePolicy.from_declaration([])
    assert pol.check("http://127.0.0.1:8000/", resolver=boom).allowed


# ------------------------------------------------------------------------------
# Host matching: apex-exact vs wildcard, and the classic bypass traps
# ------------------------------------------------------------------------------
def test_apex_exact_matches_apex_only():
    pol = ScopePolicy.from_declaration(["example.com"])
    assert pol.check("http://example.com/", resolver=_GLOBAL_RESOLVER).allowed
    # bare host does NOT cover subdomains (subdomains require *.host)
    assert not pol.check("http://api.example.com/", resolver=_GLOBAL_RESOLVER).allowed


def test_wildcard_matches_subdomain_and_apex():
    pol = ScopePolicy.from_declaration(["*.example.com"])
    assert pol.check("http://api.example.com/", resolver=_GLOBAL_RESOLVER).allowed
    assert pol.check("http://www.example.com/", resolver=_GLOBAL_RESOLVER).allowed
    # apex auto-include (documented convenience)
    assert pol.check("http://example.com/", resolver=_GLOBAL_RESOLVER).allowed


def test_substring_trap_denied():
    pol = ScopePolicy.from_declaration(["example.com"])
    # naive `approved in host` would wrongly allow these
    assert not pol.check("http://notexample.com/", resolver=_resolver({"notexample.com": [GLOBAL]})).allowed
    assert not pol.check("http://example.com.evil.com/", resolver=_resolver({"example.com.evil.com": [GLOBAL]})).allowed


def test_endswith_trap_denied():
    # naive `host.endswith(approved)` would wrongly allow evilexample.com
    pol = ScopePolicy.from_declaration(["*.example.com"])
    assert not pol.check("http://evilexample.com/", resolver=_resolver({"evilexample.com": [GLOBAL]})).allowed


def test_userinfo_host_confusion_denied():
    # The real host of http://example.com@evil.com/ is evil.com — must be refused.
    pol = ScopePolicy.from_declaration(["example.com"])
    d = pol.check("http://example.com@evil.com/", resolver=_resolver({"evil.com": [GLOBAL]}))
    assert not d.allowed
    assert d.host == "evil.com"


def test_case_and_trailing_dot_normalized():
    pol = ScopePolicy.from_declaration(["Example.COM"])
    assert pol.check("http://ExAmPlE.com./", resolver=_GLOBAL_RESOLVER).allowed


# ------------------------------------------------------------------------------
# Port rule: no port => any; explicit port => strict
# ------------------------------------------------------------------------------
def test_no_port_allows_any_port():
    pol = ScopePolicy.from_declaration(["example.com"])
    assert pol.check("https://example.com/", resolver=_GLOBAL_RESOLVER).allowed
    assert pol.check("https://example.com:8443/", resolver=_GLOBAL_RESOLVER).allowed


def test_explicit_port_is_strict():
    pol = ScopePolicy.from_declaration(["example.com:8443"])
    assert pol.check("https://example.com:8443/", resolver=_GLOBAL_RESOLVER).allowed
    d = pol.check("https://example.com/", resolver=_GLOBAL_RESOLVER)   # 443 != 8443
    assert not d.allowed and d.reason == "port_mismatch"


# ------------------------------------------------------------------------------
# Resolved-IP guard: SSRF / DNS rebinding — the "hostname only" bypass this closes
# ------------------------------------------------------------------------------
def test_public_name_to_global_ip_allowed():
    pol = ScopePolicy.from_declaration(["example.com"])
    assert pol.check("http://example.com/", resolver=_resolver({"example.com": [GLOBAL]})).allowed


@pytest.mark.parametrize("rebind_ip", ["127.0.0.1", "10.0.0.5", "192.168.1.10", "172.16.0.9"])
def test_public_name_rebinding_to_private_refused(rebind_ip):
    pol = ScopePolicy.from_declaration(["example.com"])
    d = pol.check("http://example.com/", resolver=_resolver({"example.com": [rebind_ip]}))
    assert not d.allowed and d.reason == "rebinding_private_ip"


def test_public_name_to_metadata_refused():
    pol = ScopePolicy.from_declaration(["example.com"])
    d = pol.check("http://example.com/", resolver=_resolver({"example.com": ["169.254.169.254"]}))
    assert not d.allowed and d.reason == "metadata_ip"


def test_public_name_to_link_local_refused():
    pol = ScopePolicy.from_declaration(["example.com"])
    d = pol.check("http://example.com/", resolver=_resolver({"example.com": ["169.254.10.20"]}))
    assert not d.allowed and d.reason == "link_local_ip"


def test_mixed_resolution_any_bad_ip_refused():
    # If a name resolves to a global AND a private IP, the private one must still refuse
    # (rebinding often returns both).
    pol = ScopePolicy.from_declaration(["example.com"])
    d = pol.check("http://example.com/", resolver=_resolver({"example.com": [GLOBAL, "127.0.0.1"]}))
    assert not d.allowed and d.reason == "rebinding_private_ip"


def test_dns_failure_refused():
    pol = ScopePolicy.from_declaration(["example.com"])
    d = pol.check("http://example.com/", resolver=_resolver({}))   # unknown -> raises
    assert not d.allowed and d.reason == "dns_resolution_failed"


# ------------------------------------------------------------------------------
# Freedom preserved: explicitly-declared private / loopback / intranet targets
# ------------------------------------------------------------------------------
def test_explicit_loopback_ip_allowed_without_resolution():
    # The labs declare 127.0.0.1 — an explicit IP target is the user's authorization.
    def boom(host):
        raise AssertionError("must not resolve an explicit IP target")
    pol = ScopePolicy.from_declaration(["127.0.0.1"])
    assert pol.check("http://127.0.0.1:8000/api/x", resolver=boom).allowed


def test_explicit_ipv6_loopback_allowed():
    pol = ScopePolicy.from_declaration(["[::1]"])
    assert pol.check("http://[::1]:8000/", resolver=_resolver({})).allowed


def test_metadata_ip_refused_even_when_declared():
    # Explicitly scoping the metadata endpoint is still refused (crown-jewel SSRF).
    pol = ScopePolicy.from_declaration(["169.254.169.254"])
    d = pol.check("http://169.254.169.254/latest/meta-data/", resolver=_resolver({}))
    assert not d.allowed and d.reason == "metadata_ip"


def _boom_resolver(host):
    """A resolver that fails if called — proves an intranet name is NOT resolved."""
    raise AssertionError(f"intranet name {host!r} must NOT be resolved")


def test_intranet_single_label_name_not_resolved_and_allowed():
    # A bare hostname is an explicitly-declared intranet target: allowed WITHOUT resolution
    # (the rebinding guard never acts on non-public names). The resolver raises if called,
    # proving no resolution is attempted.
    pol = ScopePolicy.from_declaration(["myhost"])
    assert pol.check("http://myhost/api", resolver=_boom_resolver).allowed


def test_intranet_pseudo_tld_not_resolved_and_allowed():
    pol = ScopePolicy.from_declaration(["printer.local"])
    assert pol.check("http://printer.local/", resolver=_boom_resolver).allowed


def test_decimal_encoded_loopback_does_not_bypass_domain_scope():
    # http://2130706433/ is 127.0.0.1 in decimal — must not slip past a domain scope.
    pol = ScopePolicy.from_declaration(["example.com"])
    d = pol.check("http://2130706433/", resolver=_resolver({}))
    assert not d.allowed and d.reason == "host_not_in_scope"


# ------------------------------------------------------------------------------
# Passive-side host_allowed parity (no resolution) — one decision tree
# ------------------------------------------------------------------------------
def test_host_allowed_passive_parity():
    pol = ScopePolicy.from_declaration(["*.example.com"])
    assert pol.host_allowed("api.example.com") is True
    assert pol.host_allowed("example.com") is True          # apex auto-include
    assert pol.host_allowed("evil.com") is False
    assert pol.host_allowed("evilexample.com") is False     # endswith trap


def test_host_allowed_port_strict():
    pol = ScopePolicy.from_declaration(["example.com:8443"])
    assert pol.host_allowed("example.com", 8443) is True
    assert pol.host_allowed("example.com", 443) is False


# ------------------------------------------------------------------------------
# Low-level helper units
# ------------------------------------------------------------------------------
@pytest.mark.parametrize("raw,expected", [
    ("2130706433", "127.0.0.1"),
    ("0x7f000001", "127.0.0.1"),
    ("127.0.0.1", "127.0.0.1"),
    ("::1", "::1"),
    ("example.com", None),
])
def test_maybe_ip(raw, expected):
    assert _maybe_ip(raw) == expected


@pytest.mark.parametrize("ip,cls", [
    ("169.254.169.254", "metadata"),
    ("169.254.1.1", "link_local"),
    ("127.0.0.1", "loopback"),
    ("10.1.2.3", "private"),
    ("192.168.0.1", "private"),
    ("93.184.216.34", "global"),
    ("::1", "loopback"),
    ("fd00:ec2::254", "metadata"),
])
def test_classify_ip(ip, cls):
    assert _classify_ip(ip) == cls


@pytest.mark.parametrize("raw,expected", [
    ("Example.COM.", "example.com"),
    ("  API.Example.com  ", "api.example.com"),
    ("[::1]", "::1"),
])
def test_normalize_host(raw, expected):
    assert _normalize_host(raw) == expected
