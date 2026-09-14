# ==============================================================================
# CMDI-via-OOB detector — OFFLINE tests (no network, no interactsh server).
#
# Proves the reservation for the THIRD vuln type: a CONFIRMED cmdi requires a REAL
# TOKEN-CORRELATED OOB interaction (the DeterministicProof). A callback whose token does NOT
# match the one we injected is dropped by the session's correlation and can NEVER confirm; a
# weaker inference lead (echoed output / time delay) is SIGNAL at most; no callback -> REFUTED;
# could not probe -> NOT_DATA. The public-interactsh end-to-end run is the separate live
# acceptance; here a StubTransport stands in for the OOB server and a fake sender simulates the
# target. Mirrors test_ssrf_detector.py.
# ==============================================================================
import json
from urllib.parse import urlsplit, parse_qs

import pytest

from backend.app.services.oob import (
    OOBError, OOBInteraction, OOBSession, new_correlation_id, new_secret,
)
from backend.app.services.oob.stub import StubTransport
from backend.app.services.cmdi_detector import (
    CmdiProbeResult, CmdiOobDetector, cmdi_payloads, cmdi_verdict, run_cmdi_probe,
    _TIME_DELAY_SIGNAL_MS,
)
from backend.app.services.verdict_tiers import Tier, classify
from backend.app.cli.cmdi_command import run_cmdi_from_config


def _stub_session(server="oast.test"):
    tr = StubTransport()
    sess = OOBSession(server=server, correlation_id=new_correlation_id(),
                      secret=new_secret(), transport=tr)
    sess.register()
    return sess, tr


def _vulnerable_sender(sess, tr, *, protocol="dns"):
    """A fake target that IS vulnerable: the shell executes the injected payload, i.e. it makes
    the minted payload domain receive a token-correlated OOB interaction (delivered into the stub)."""
    def _send(*, target_url, method, headers, body):
        injected = ""
        if isinstance(body, dict):
            injected += " ".join(str(v) for v in body.values())
        q = parse_qs(urlsplit(target_url).query)
        injected += " " + " ".join(v for vals in q.values() for v in vals)
        for _token, p in sess.issued.items():
            if p.domain in injected:
                tr.deliver(p, protocol=protocol, q_type="A")
        return {"status_code": 200, "body": "", "elapsed_ms": 5.0}
    return _send


def _safe_sender(*, target_url, method, headers, body):
    """A fake target that is SECURE: it refuses (400) and runs nothing, so NO callback occurs."""
    return {"status_code": 400, "body": "invalid host", "elapsed_ms": 3.0}


def _noise_sender(sess, tr):
    """A fake target that triggers a callback for a token we NEVER minted (a confused-deputy /
    replay against an unrelated id). The session's correlation must DROP it -> never confirm."""
    def _send(*, target_url, method, headers, body):
        bogus_uid = sess.correlation_id + ("z" * 13)     # 20-char corr id + a token we never issued
        tr.deliver_raw(sess.correlation_id,
                       OOBInteraction(protocol="dns", unique_id=bogus_uid, q_type="A"))
        return {"status_code": 200, "body": "", "elapsed_ms": 5.0}
    return _send


# -----------------------------------------------------------------------------
# Payload generation.
# -----------------------------------------------------------------------------
def test_cmdi_payloads_embed_the_domain_and_cover_contexts_and_commands():
    ps = cmdi_payloads("abc.oast.test")
    assert ps and all("abc.oast.test" in p for p in ps)          # every payload targets OUR domain
    joined = "\n".join(ps)
    for sep in (";", "|", "&", "&&", "||", "$(", "`"):           # shell contexts (sh + cmd.exe)
        assert sep in joined
    for cmd in ("nslookup", "curl", "wget"):                     # DNS + HTTP callback commands
        assert cmd in joined


# -----------------------------------------------------------------------------
# Detector verdict mapping (synthetic results) — the core reservation.
# -----------------------------------------------------------------------------
def _result(interactions=None, probe_error=None, echoed=False, ms=None,
            injected=None, matched=None, matched_domain="abc.oast.test"):
    # Injection-causal defaults: an interaction is CONFIRMABLE only if its token is one we injected.
    # By default a synthetic hit is causally-tied (matched token "tok" is in injected_tokens); a caller
    # passes injected=[] or a non-injected `matched` to exercise the causal negative control.
    inj = injected if injected is not None else (["tok"] if interactions else [])
    mtok = matched if matched is not None else ("tok" if interactions else None)
    return CmdiProbeResult(
        target="http://t", method="GET", param="host", param_location="query",
        oob_server="oast.test", correlation_id="corr", injected_tokens=inj,
        matched_token=mtok, matched_domain=matched_domain,
        interactions=interactions or [], probe_error=probe_error,
        echoed_marker=echoed, max_response_ms=ms, polls=3)


def test_token_matched_oob_hit_is_confirmed_with_the_interaction_as_proof():
    it = OOBInteraction(protocol="dns", unique_id="abc", q_type="A", remote_address="203.0.113.9")
    v = cmdi_verdict(_result(interactions=[it]))
    assert v.tier is Tier.CONFIRMED
    assert v.proof is not None and v.proof.channel == "cmdi_oob_callback"
    assert "command execution" in v.proof.basis.lower()


def test_no_callback_is_refuted_never_confirmed():
    v = cmdi_verdict(_result())
    assert v.tier is Tier.REFUTED and v.proof is None


def test_probe_error_is_not_data():
    v = cmdi_verdict(_result(probe_error="OOB session unavailable: OOBError: boom"))
    assert v.tier is Tier.NOT_DATA and v.proof is None


def test_echoed_output_is_signal_not_confirmed():
    v = cmdi_verdict(_result(echoed=True))
    assert v.tier is Tier.SIGNAL and v.proof is None


def test_time_delay_only_is_signal_not_confirmed():
    v = cmdi_verdict(_result(ms=_TIME_DELAY_SIGNAL_MS + 500))
    assert v.tier is Tier.SIGNAL and v.proof is None


def test_small_time_delay_is_refuted_not_signal():
    v = cmdi_verdict(_result(ms=50.0))
    assert v.tier is Tier.REFUTED


def test_detector_never_mints_confirmed_without_a_token_matched_interaction():
    # The reservation: with no correlated interaction the detector cannot produce CONFIRMED, and
    # classify() enforces the ceiling. Try every no-hit shape (incl. inference-only leads).
    for res in (_result(), _result(probe_error="x"), _result(echoed=True),
                _result(ms=_TIME_DELAY_SIGNAL_MS + 9000)):
        assert classify(CmdiOobDetector(), res).tier is not Tier.CONFIRMED


# -----------------------------------------------------------------------------
# run_cmdi_probe end-to-end (offline): vulnerable -> CONFIRMED; safe/none -> REFUTED.
# -----------------------------------------------------------------------------
def test_run_probe_confirms_on_real_token_matched_oob_hit():
    sess, tr = _stub_session()
    res = run_cmdi_probe(
        base_url="http://target", path="/diag", param="host",
        session_factory=lambda: sess, http_send=_vulnerable_sender(sess, tr),
        poll_seconds=4, poll_interval=1, sleep=lambda _s: None)
    assert res.confirmed and res.interactions
    assert cmdi_verdict(res).tier is Tier.CONFIRMED
    assert res.payloads_tried > 0


def test_run_probe_body_location_injects_into_json_body():
    sess, tr = _stub_session()
    res = run_cmdi_probe(
        base_url="http://target", path="/diag", param="host", param_location="body",
        method="POST", session_factory=lambda: sess, http_send=_vulnerable_sender(sess, tr),
        poll_seconds=4, poll_interval=1, sleep=lambda _s: None)
    assert res.confirmed and cmdi_verdict(res).tier is Tier.CONFIRMED


# -----------------------------------------------------------------------------
# NON-VACUITY: a callback whose token does NOT match the injected one must NEVER confirm.
# (The RED-then-GREEN scratch break of run_cmdi_probe's token correlation is in the report.)
# -----------------------------------------------------------------------------
def test_nonmatching_token_callback_is_dropped_and_never_confirms():
    sess, tr = _stub_session()
    res = run_cmdi_probe(
        base_url="http://target", path="/diag", param="host",
        session_factory=lambda: sess, http_send=_noise_sender(sess, tr),
        poll_seconds=4, poll_interval=1, sleep=lambda _s: None)
    assert res.interactions == []                     # the non-matching-token callback was dropped
    assert cmdi_verdict(res).tier is Tier.REFUTED     # never CONFIRMED


# -----------------------------------------------------------------------------
# CAUSAL NEGATIVE-CONTROL: a legitimate session token whose payload was NEVER injected into the
# target must NOT confirm. CONFIRMED requires the interaction's token to be one we ACTUALLY injected
# (`matched_token in injected_tokens`), not merely minted in the session — this closes the hole where
# the target itself, or polluted OOB infra, emits a callback for a session token while our injected
# command never executed. (The RED-then-GREEN scratch break of the causal check is in the report.)
# -----------------------------------------------------------------------------
def test_causal_negative_control_callback_for_a_non_injected_token_never_confirms():
    it = OOBInteraction(protocol="dns", unique_id="corr-noninjected", q_type="A")
    # a real interaction correlated to a token we minted but did NOT inject into the target
    res = _result(interactions=[it], matched="NONINJECTED", injected=[])
    assert res.confirmed is False
    assert cmdi_verdict(res).tier is not Tier.CONFIRMED
    assert cmdi_verdict(res).tier is Tier.REFUTED


def test_causal_positive_a_token_we_actually_injected_confirms():
    it = OOBInteraction(protocol="dns", unique_id="corr-injected", q_type="A", remote_address="203.0.113.9")
    res = _result(interactions=[it], matched="TOKX", injected=["TOKA", "TOKX", "TOKB"])
    assert res.confirmed is True
    assert cmdi_verdict(res).tier is Tier.CONFIRMED and res.matched_token in res.injected_tokens


def test_probe_confirms_only_a_dispatched_token_not_a_send_that_errored():
    # End-to-end at the probe: a sender that RAISES on every send dispatches nothing, so NO token is
    # recorded as injected — even though the session minted them. With no injected token, the probe
    # can never mark a callback as confirming (injected_tokens stays empty).
    sess, tr = _stub_session()
    def _raising_sender(*, target_url, method, headers, body):
        raise ConnectionError("target unreachable")
    res = run_cmdi_probe(
        base_url="http://target", path="/diag", param="host",
        session_factory=lambda: sess, http_send=_raising_sender,
        poll_seconds=2, poll_interval=1, sleep=lambda _s: None)
    assert res.injected_tokens == []                  # nothing was dispatched -> nothing is injected
    assert cmdi_verdict(res).tier is not Tier.CONFIRMED


# -----------------------------------------------------------------------------
# ZERO-FP NAIL: the SAFE control (refuses, no callback) is never CONFIRMED.
# -----------------------------------------------------------------------------
def test_safe_control_endpoint_is_never_confirmed():
    sess, _tr = _stub_session()
    res = run_cmdi_probe(
        base_url="http://target", path="/diag-safe", param="host",
        session_factory=lambda: sess, http_send=_safe_sender,
        poll_seconds=3, poll_interval=1, sleep=lambda _s: None)
    assert not res.confirmed and res.interactions == []
    assert cmdi_verdict(res).tier is not Tier.CONFIRMED
    assert cmdi_verdict(res).tier is Tier.REFUTED


def test_run_probe_not_data_when_no_oob_server():
    def _boom():
        raise OOBError("no public interactsh server reachable")
    res = run_cmdi_probe(base_url="http://target", path="/diag", param="host",
                         session_factory=_boom, sleep=lambda _s: None)
    assert res.probe_error and cmdi_verdict(res).tier is Tier.NOT_DATA


# -----------------------------------------------------------------------------
# CLI (run_cmdi_from_config) — exit codes + JSON, offline via injected seams.
# -----------------------------------------------------------------------------
def _write_cfg(tmp_path, **over):
    cfg = {"mode": "cmdi", "base_url": "http://target", "path": "/diag", "param": "host"}
    cfg.update(over)
    p = tmp_path / "cmdi.json"
    p.write_text(json.dumps(cfg), encoding="utf-8")
    return str(p)


def test_cli_confirmed_exit_1_and_json(tmp_path):
    sess, tr = _stub_session()
    out_lines = []
    code = run_cmdi_from_config(
        _write_cfg(tmp_path), environ={}, out=out_lines.append, err=lambda *a: None,
        session_factory=lambda: sess, http_send=_vulnerable_sender(sess, tr), sleep=lambda _s: None)
    assert code == 1
    payload = json.loads(out_lines[-1])
    assert payload["mode"] == "cmdi"
    assert payload["result"]["tier"] == "confirmed" and payload["result"]["confirmed"] is True
    assert payload["result"]["interactions"]
    # the weaponized payload STRINGS are NOT logged — only the count + the proof domain
    assert "payloads_tried" in payload["result"] and payload["result"]["payloads_tried"] > 0
    assert "payloads" not in payload["result"]


def test_cli_refuted_exit_0(tmp_path):
    sess, _tr = _stub_session()
    out_lines = []
    code = run_cmdi_from_config(
        _write_cfg(tmp_path, poll_seconds=2, poll_interval=1), environ={},
        out=out_lines.append, err=lambda *a: None,
        session_factory=lambda: sess, http_send=_safe_sender, sleep=lambda _s: None)
    assert code == 0
    assert json.loads(out_lines[-1])["result"]["tier"] == "refuted"


def test_cli_notdata_exit_2_when_oob_unavailable(tmp_path):
    def _boom():
        raise OOBError("unreachable")
    out_lines = []
    code = run_cmdi_from_config(
        _write_cfg(tmp_path), environ={}, out=out_lines.append, err=lambda *a: None,
        session_factory=_boom, sleep=lambda _s: None)
    assert code == 2
    assert json.loads(out_lines[-1])["result"]["tier"] == "not_data"


def test_cli_missing_fields_exit_2(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text(json.dumps({"mode": "cmdi", "base_url": "http://t"}), encoding="utf-8")
    out_lines = []
    code = run_cmdi_from_config(str(p), environ={}, out=out_lines.append, err=lambda *a: None)
    assert code == 2 and json.loads(out_lines[-1])["error"] == "missing_fields"


def test_cli_requires_exactly_one_of_config_or_target_file(tmp_path):
    out_lines = []
    code = run_cmdi_from_config(config_path=None, target_file_path=None,
                                environ={}, out=out_lines.append, err=lambda *a: None)
    assert code == 2 and json.loads(out_lines[-1])["error"] == "bad_input"


def test_cli_target_file_maps_a_query_target(tmp_path):
    # a saved Target with a query id maps onto a cmdi config (base_url + path_template + id_param).
    tf = tmp_path / "t.toml"
    tf.write_text(
        'name = "cmdi-diag"\n'
        'base_url = "http://target"\n'
        'spec_path = ""\n'
        'method = "GET"\n'
        'path_template = "/diag"\n'
        'id_location = "query"\n'
        'id_param = "host"\n'
        'attacker_id = "a"\n'
        'victim_id = "b"\n'
        'auth_spec_path = ""\n', encoding="utf-8")
    sess, tr = _stub_session()
    out_lines = []
    code = run_cmdi_from_config(
        target_file_path=str(tf), environ={}, out=out_lines.append, err=lambda *a: None,
        session_factory=lambda: sess, http_send=_vulnerable_sender(sess, tr), sleep=lambda _s: None)
    assert code == 1
    payload = json.loads(out_lines[-1])
    assert payload["result"]["param"] == "host" and payload["result"]["confirmed"] is True
