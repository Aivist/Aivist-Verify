# ==============================================================================
# OOB seam — OFFLINE correlation tests (no network, no crypto, no server).
#
# Proves the plumbing the future SSRF detector will rely on: a registered session mints a
# UNIQUE token per probe, and a received interaction correlates back to EXACTLY the probe
# that caused it — never to another probe, and never fabricated for an id we never minted.
# This is plumbing, NOT a zero-false-positive claim (see services/oob/__init__.py).
#
# The real interactsh transport (register/poll/RSA+AES decrypt) needs a reachable server
# and is intentionally not exercised here; StubTransport stands in for the server.
# ==============================================================================
import pytest

from backend.app.services.oob import (
    OOBInteraction,
    OOBSession,
    OOBTransportError,
    open_session,
    _server_domain,
    _CORRELATION_ID_LEN,
    _PAYLOAD_TOKEN_LEN,
)
from backend.app.services.oob.stub import StubTransport


def _session(server="oast.pro"):
    """A registered session backed by a fresh in-memory stub server."""
    return open_session(server, transport=StubTransport())


# -----------------------------------------------------------------------------
# Minting: unique tokens, well-formed domains.
# -----------------------------------------------------------------------------
def test_new_payload_is_unique_and_well_formed():
    s = _session()
    a, b = s.new_payload(), s.new_payload()

    assert a.token != b.token                                   # distinct per-probe nonce
    assert len(a.token) == _PAYLOAD_TOKEN_LEN
    assert len(s.correlation_id) == _CORRELATION_ID_LEN
    # domain == <correlation_id><token>.<server>, all lowercase, one label + server
    # (correlation id FIRST — the interactsh server reads it from the leading 20 chars)
    assert a.domain == f"{s.correlation_id}{a.token}.oast.pro"
    assert a.unique_id == f"{s.correlation_id}{a.token}"        # the 33-char label
    assert len(a.unique_id) == _PAYLOAD_TOKEN_LEN + _CORRELATION_ID_LEN
    assert a.url == f"https://{a.domain}"
    # both probes share the session correlation id but differ only in the token prefix
    assert a.correlation_id == b.correlation_id == s.correlation_id


# -----------------------------------------------------------------------------
# Correlation: an interaction pins to the issuing payload, and ONLY it.
# -----------------------------------------------------------------------------
def test_interaction_correlates_to_the_issuing_payload():
    s = _session()
    a, b = s.new_payload(), s.new_payload()

    s.transport.deliver(a, protocol="dns", q_type="A")          # a DNS hit on payload A only

    grouped = s.poll_and_correlate()
    assert set(grouped) == {a.token, b.token}                   # every issued token is present
    assert len(grouped[a.token]) == 1                           # A caught its interaction
    assert grouped[b.token] == []                               # B caught nothing (no cross-talk)
    assert grouped[a.token][0].protocol == "dns"
    assert grouped[a.token][0].unique_id == a.unique_id


def test_distinct_payloads_do_not_cross_correlate():
    s = _session()
    a, b = s.new_payload(), s.new_payload()

    s.transport.deliver(a, protocol="http")
    s.transport.deliver(b, protocol="dns")

    grouped = s.poll_and_correlate()
    assert len(grouped[a.token]) == 1 and grouped[a.token][0].protocol == "http"
    assert len(grouped[b.token]) == 1 and grouped[b.token][0].protocol == "dns"


def test_multiple_interactions_on_one_payload_all_attach():
    s = _session()
    a = s.new_payload()
    s.transport.deliver(a, protocol="dns")
    s.transport.deliver(a, protocol="http")

    grouped = s.poll_and_correlate()
    assert len(grouped[a.token]) == 2
    assert {i.protocol for i in grouped[a.token]} == {"dns", "http"}


def test_interaction_for_unminted_id_is_dropped_not_misattributed():
    """Noise — an interaction whose unique_id matches NO issued payload (a scan, a stale
    id, or a spoof) — is omitted from the correlation, never charged to a real probe."""
    s = _session()
    a = s.new_payload()
    noise = OOBInteraction(protocol="dns", unique_id="deadbeefcafe" + "0" * 21)
    s.transport.deliver_raw(s.correlation_id, noise)

    grouped = s.poll_and_correlate()
    assert grouped[a.token] == []                               # real probe uninvolved
    assert all(noise not in v for v in grouped.values())        # noise dropped entirely


def test_correlation_survives_dns_case_randomization():
    """DNS 0x20 encoding may return a mixed-case label; correlation lowercases both sides,
    so an UPPERCASED interaction id still pins to its payload."""
    s = _session()
    a = s.new_payload()
    upper = OOBInteraction(protocol="dns", unique_id=a.unique_id.upper())
    s.transport.deliver_raw(s.correlation_id, upper)

    grouped = s.poll_and_correlate()
    assert len(grouped[a.token]) == 1


# -----------------------------------------------------------------------------
# Lifecycle: register / poll-drains / fail-closed / deregister.
# -----------------------------------------------------------------------------
def test_poll_drains_between_calls():
    s = _session()
    a = s.new_payload()
    s.transport.deliver(a)
    assert len(s.poll_and_correlate()[a.token]) == 1            # first poll sees it
    assert s.poll_and_correlate()[a.token] == []               # already drained


def test_poll_before_register_fails_closed():
    unreg = OOBSession(server="oast.pro", correlation_id="c" * _CORRELATION_ID_LEN,
                       secret="s", transport=StubTransport())
    assert unreg.registered is False
    with pytest.raises(OOBTransportError):
        unreg.poll()


def test_open_session_registers_and_close_deregisters():
    s = _session()
    assert s.registered is True
    a = s.new_payload()
    s.transport.deliver(a)
    assert len(s.poll_and_correlate()[a.token]) == 1
    s.close()
    assert s.registered is False
    with pytest.raises(OOBTransportError):                     # deregistered -> poll fails closed
        s.poll()


def test_context_manager_registers_and_closes():
    transport = StubTransport()
    session = OOBSession(server="oast.pro", correlation_id="a" * _CORRELATION_ID_LEN,
                         secret="s", transport=transport)
    with session as s:
        assert s.registered is True
        p = s.new_payload()
        s.transport.deliver(p)
        assert len(s.poll_and_correlate()[p.token]) == 1
    assert session.registered is False


# -----------------------------------------------------------------------------
# Server-domain parsing.
# -----------------------------------------------------------------------------
@pytest.mark.parametrize("given,expected", [
    ("oast.pro", "oast.pro"),
    ("https://oast.pro", "oast.pro"),
    ("https://oast.pro/", "oast.pro"),
    ("http://interact.sh:8080/x", "interact.sh"),
    ("OAST.PRO", "oast.pro"),
])
def test_server_domain_parsing(given, expected):
    assert _server_domain(given) == expected


def test_server_domain_rejects_empty():
    from backend.app.services.oob import OOBConfigError
    with pytest.raises(OOBConfigError):
        _server_domain("")
