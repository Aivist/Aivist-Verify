# ==============================================================================
# SSRF-via-OOB detector — OFFLINE tests (no network, no interactsh server).
#
# Proves the reservation that matters for the FIRST non-access-control type: a CONFIRMED
# SSRF requires a REAL correlated OOB interaction (the DeterministicProof). No callback ->
# REFUTED (probed, nothing came back) or NOT_DATA (could not probe) — NEVER a bluffed
# CONFIRMED. The public-interactsh end-to-end run is the separate live acceptance; here a
# StubTransport stands in for the OOB server and a fake sender simulates the target.
# ==============================================================================
import json
from urllib.parse import urlsplit, parse_qs

import pytest

from backend.app.services.oob import OOBError, OOBSession, new_correlation_id, new_secret
from backend.app.services.oob.stub import StubTransport
from backend.app.services.ssrf_detector import (
    SsrfProbeResult, SsrfOobDetector, ssrf_verdict, run_ssrf_probe,
)
from backend.app.services.verdict_tiers import Tier, TierViolation, classify
from backend.app.cli.ssrf_command import run_ssrf_from_config


def _stub_session(server="oast.test"):
    tr = StubTransport()
    sess = OOBSession(server=server, correlation_id=new_correlation_id(),
                      secret=new_secret(), transport=tr)
    sess.register()
    return sess, tr


def _vulnerable_sender(sess, tr, *, protocol="dns"):
    """A fake target that IS vulnerable: it 'fetches' the injected URL, i.e. it makes the
    minted payload domain receive an OOB interaction (delivered into the stub)."""
    def _send(*, target_url, method, headers, body):
        injected = parse_qs(urlsplit(target_url).query).get("url", [""])[0] or (body or {}).get("url", "")
        dom = urlsplit(injected).hostname
        for _token, p in sess.issued.items():
            if p.domain == dom:
                tr.deliver(p, protocol=protocol, q_type="A")
        return 200
    return _send


def _safe_sender(*, target_url, method, headers, body):
    """A fake target that is SECURE: it refuses/doesn't fetch, so NO callback occurs."""
    return 400


# -----------------------------------------------------------------------------
# Detector verdict mapping (synthetic results) — the core reservation.
# -----------------------------------------------------------------------------
def _result(interactions=None, probe_error=None):
    return SsrfProbeResult(
        target="http://t", method="GET", url_param="url", url_location="query",
        injected_url="http://abc.oast.test/", payload_domain="abc.oast.test",
        payload_token="tok", oob_server="oast.test",
        interactions=interactions or [], probe_error=probe_error, polls=3)


def test_oob_hit_is_confirmed_with_the_interaction_as_proof():
    from backend.app.services.oob import OOBInteraction
    it = OOBInteraction(protocol="dns", unique_id="abc", q_type="A", remote_address="203.0.113.9")
    v = ssrf_verdict(_result(interactions=[it]))
    assert v.tier is Tier.CONFIRMED
    assert v.proof is not None and v.proof.channel == "ssrf_oob_callback"
    assert "out-of-band" in v.proof.basis.lower()


def test_no_callback_is_refuted_never_confirmed():
    v = ssrf_verdict(_result(interactions=[]))
    assert v.tier is Tier.REFUTED
    assert v.proof is None


def test_probe_error_is_not_data():
    v = ssrf_verdict(_result(probe_error="OOB session unavailable: OOBError: boom"))
    assert v.tier is Tier.NOT_DATA
    assert v.proof is None


def test_detector_never_mints_confirmed_without_an_interaction():
    # The reservation: with no interaction the detector cannot produce CONFIRMED, and
    # classify() enforces the ceiling. Try every no-hit shape.
    for res in (_result(interactions=[]), _result(probe_error="x")):
        assert classify(SsrfOobDetector(), res).tier is not Tier.CONFIRMED


# -----------------------------------------------------------------------------
# run_ssrf_probe end-to-end (offline): vulnerable -> CONFIRMED, safe -> REFUTED.
# -----------------------------------------------------------------------------
def test_run_probe_confirms_on_real_oob_hit():
    sess, tr = _stub_session()
    res = run_ssrf_probe(
        base_url="http://target", path="/fetch", url_param="url",
        session_factory=lambda: sess, http_send=_vulnerable_sender(sess, tr),
        poll_seconds=4, poll_interval=1, sleep=lambda _s: None)
    assert res.confirmed and res.interactions
    assert ssrf_verdict(res).tier is Tier.CONFIRMED
    # the injected URL carried our unique payload domain
    assert res.payload_domain in res.injected_url


def test_run_probe_refutes_when_no_callback():
    sess, _tr = _stub_session()
    res = run_ssrf_probe(
        base_url="http://target", path="/fetch", url_param="url",
        session_factory=lambda: sess, http_send=_safe_sender,
        poll_seconds=3, poll_interval=1, sleep=lambda _s: None)
    assert not res.confirmed and res.interactions == []
    assert ssrf_verdict(res).tier is Tier.REFUTED


def test_run_probe_not_data_when_no_oob_server():
    def _boom():
        raise OOBError("no public interactsh server reachable")
    res = run_ssrf_probe(base_url="http://target", path="/fetch", session_factory=_boom,
                         sleep=lambda _s: None)
    assert res.probe_error and ssrf_verdict(res).tier is Tier.NOT_DATA


def test_run_probe_body_location_injects_into_json_body():
    sess, tr = _stub_session()
    res = run_ssrf_probe(
        base_url="http://target", path="/fetch", url_param="url", url_location="body",
        method="POST", session_factory=lambda: sess, http_send=_vulnerable_sender(sess, tr),
        poll_seconds=4, poll_interval=1, sleep=lambda _s: None)
    assert res.confirmed


# -----------------------------------------------------------------------------
# CLI (run_ssrf_from_config) — exit codes + JSON, offline via injected seams.
# -----------------------------------------------------------------------------
def _write_cfg(tmp_path, **over):
    cfg = {"mode": "ssrf", "base_url": "http://target", "path": "/fetch", "url_param": "url"}
    cfg.update(over)
    p = tmp_path / "ssrf.json"
    p.write_text(json.dumps(cfg), encoding="utf-8")
    return str(p)


def test_cli_confirmed_exit_1_and_json(tmp_path):
    sess, tr = _stub_session()
    out_lines = []
    code = run_ssrf_from_config(
        _write_cfg(tmp_path), environ={}, out=out_lines.append, err=lambda *a: None,
        session_factory=lambda: sess, http_send=_vulnerable_sender(sess, tr),
        sleep=lambda _s: None)
    assert code == 1
    payload = json.loads(out_lines[-1])
    assert payload["mode"] == "ssrf"
    assert payload["result"]["tier"] == "confirmed" and payload["result"]["confirmed"] is True
    assert payload["result"]["interactions"]


def test_cli_refuted_exit_0(tmp_path):
    sess, _tr = _stub_session()
    out_lines = []
    code = run_ssrf_from_config(
        _write_cfg(tmp_path, poll_seconds=2, poll_interval=1), environ={},
        out=out_lines.append, err=lambda *a: None,
        session_factory=lambda: sess, http_send=_safe_sender, sleep=lambda _s: None)
    assert code == 0
    assert json.loads(out_lines[-1])["result"]["tier"] == "refuted"


def test_cli_notdata_exit_2_when_oob_unavailable(tmp_path):
    def _boom():
        raise OOBError("unreachable")
    out_lines = []
    code = run_ssrf_from_config(
        _write_cfg(tmp_path), environ={}, out=out_lines.append, err=lambda *a: None,
        session_factory=_boom, sleep=lambda _s: None)
    assert code == 2
    assert json.loads(out_lines[-1])["result"]["tier"] == "not_data"


def test_cli_missing_fields_exit_2(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text(json.dumps({"mode": "ssrf"}), encoding="utf-8")
    out_lines = []
    code = run_ssrf_from_config(str(p), environ={}, out=out_lines.append, err=lambda *a: None)
    assert code == 2 and json.loads(out_lines[-1])["error"] == "missing_fields"
