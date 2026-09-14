# ==============================================================================
# Blind-SQLi-via-OOB detector — OFFLINE tests (no network, no interactsh server, no real DB).
#
# Proves the reservation for the FOURTH vuln type: a CONFIRMED sqli requires a REAL, INJECTION-CAUSAL,
# TOKEN-CORRELATED OOB interaction (the DeterministicProof) — a callback whose token corresponds to a
# payload we ACTUALLY INJECTED into this candidate. A callback for a token we never injected (or one the
# session merely minted) is dropped and can NEVER confirm; error-based / time-based blind leads are
# SIGNAL at most; no callback -> REFUTED; could not probe -> NOT_DATA. A StubTransport stands in for the
# OOB server and a fake sender simulates the target. Mirrors test_cmdi_detector.py.
# ==============================================================================
import json
from urllib.parse import urlsplit, parse_qs

import pytest

from backend.app.services.oob import (
    OOBError, OOBInteraction, OOBSession, new_correlation_id, new_secret,
)
from backend.app.services.oob.stub import StubTransport
from backend.app.services.sqli_detector import (
    SqliProbeResult, SqliOobDetector, sqli_payloads, sqli_verdict, run_sqli_probe,
    _TIME_DELAY_SIGNAL_MS,
)
from backend.app.services.verdict_tiers import Tier, classify
from backend.app.cli.sqli_command import run_sqli_from_config


def _stub_session(server="oast.test"):
    tr = StubTransport()
    sess = OOBSession(server=server, correlation_id=new_correlation_id(),
                      secret=new_secret(), transport=tr)
    sess.register()
    return sess, tr


def _vulnerable_sender(sess, tr, *, protocol="dns"):
    """A fake target that IS vulnerable: the DBMS parses the injected payload, i.e. the minted payload
    domain receives a token-correlated OOB interaction (delivered into the stub)."""
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
    """A fake target that is SECURE (parameterized): it runs but never reaches out, so NO callback."""
    return {"status_code": 200, "body": "", "elapsed_ms": 3.0}


def _noise_sender(sess, tr):
    """A fake target that triggers a callback for a token we NEVER minted (a confused-deputy / replay
    against an unrelated id). The session's correlation must DROP it -> never confirm."""
    def _send(*, target_url, method, headers, body):
        bogus_uid = sess.correlation_id + ("z" * 13)
        tr.deliver_raw(sess.correlation_id,
                       OOBInteraction(protocol="dns", unique_id=bogus_uid, q_type="A"))
        return {"status_code": 200, "body": "", "elapsed_ms": 5.0}
    return _send


# -----------------------------------------------------------------------------
# Payload generation.
# -----------------------------------------------------------------------------
def test_sqli_payloads_embed_the_domain_and_cover_dbms_primitives_and_contexts():
    ps = sqli_payloads("abc.oast.test")
    assert ps and all("abc.oast.test" in p for p in ps)          # every payload targets OUR domain
    joined = "\n".join(ps)
    for prim in ("LOAD_FILE", "xp_dirtree", "UTL_INADDR", "UTL_HTTP", "dblink_connect"):
        assert prim in joined                                    # MySQL / MSSQL / Oracle / PostgreSQL
    for ctx in ("UNION SELECT", "' OR ", " OR ", "; EXEC", "||"):
        assert ctx in joined                                     # injection contexts


# -----------------------------------------------------------------------------
# Detector verdict mapping (synthetic results) — the core reservation.
# -----------------------------------------------------------------------------
def _result(interactions=None, probe_error=None, error=False, ms=None,
            injected=None, matched=None, matched_domain="abc.oast.test"):
    inj = injected if injected is not None else (["tok"] if interactions else [])
    mtok = matched if matched is not None else ("tok" if interactions else None)
    return SqliProbeResult(
        target="http://t", method="GET", param="id", param_location="query",
        oob_server="oast.test", correlation_id="corr", injected_tokens=inj,
        matched_token=mtok, matched_domain=matched_domain,
        interactions=interactions or [], probe_error=probe_error,
        error_marker=error, max_response_ms=ms, polls=3)


def test_token_matched_oob_hit_is_confirmed_with_the_interaction_as_proof():
    it = OOBInteraction(protocol="dns", unique_id="abc", q_type="A", remote_address="203.0.113.9")
    v = sqli_verdict(_result(interactions=[it]))
    assert v.tier is Tier.CONFIRMED
    assert v.proof is not None and v.proof.channel == "sqli_oob_callback"
    assert "sql execution" in v.proof.basis.lower()


def test_no_callback_is_refuted_never_confirmed():
    v = sqli_verdict(_result())
    assert v.tier is Tier.REFUTED and v.proof is None


def test_probe_error_is_not_data():
    v = sqli_verdict(_result(probe_error="OOB session unavailable: OOBError: boom"))
    assert v.tier is Tier.NOT_DATA and v.proof is None


def test_error_based_is_signal_not_confirmed():
    v = sqli_verdict(_result(error=True))
    assert v.tier is Tier.SIGNAL and v.proof is None


def test_time_based_blind_only_is_signal_not_confirmed():
    v = sqli_verdict(_result(ms=_TIME_DELAY_SIGNAL_MS + 500))
    assert v.tier is Tier.SIGNAL and v.proof is None


def test_small_time_delay_is_refuted_not_signal():
    v = sqli_verdict(_result(ms=50.0))
    assert v.tier is Tier.REFUTED


def test_detector_never_mints_confirmed_without_a_token_matched_interaction():
    for res in (_result(), _result(probe_error="x"), _result(error=True),
                _result(ms=_TIME_DELAY_SIGNAL_MS + 9000)):
        assert classify(SqliOobDetector(), res).tier is not Tier.CONFIRMED


# -----------------------------------------------------------------------------
# run_sqli_probe end-to-end (offline): vulnerable -> CONFIRMED; safe/none -> REFUTED.
# -----------------------------------------------------------------------------
def test_run_probe_confirms_on_real_token_matched_oob_hit():
    sess, tr = _stub_session()
    res = run_sqli_probe(
        base_url="http://target", path="/report", param="id",
        session_factory=lambda: sess, http_send=_vulnerable_sender(sess, tr),
        poll_seconds=4, poll_interval=1, sleep=lambda _s: None)
    assert res.confirmed and res.interactions
    assert sqli_verdict(res).tier is Tier.CONFIRMED
    assert res.payloads_tried > 0 and res.matched_token in res.injected_tokens


def test_run_probe_body_location_injects_into_json_body():
    sess, tr = _stub_session()
    res = run_sqli_probe(
        base_url="http://target", path="/report", param="id", param_location="body",
        method="POST", session_factory=lambda: sess, http_send=_vulnerable_sender(sess, tr),
        poll_seconds=4, poll_interval=1, sleep=lambda _s: None)
    assert res.confirmed and sqli_verdict(res).tier is Tier.CONFIRMED


# -----------------------------------------------------------------------------
# NON-VACUITY: a callback whose token does NOT match an injected one must NEVER confirm.
# (The RED-then-GREEN scratch break of the causal gate is in the report.)
# -----------------------------------------------------------------------------
def test_nonmatching_token_callback_is_dropped_and_never_confirms():
    sess, tr = _stub_session()
    res = run_sqli_probe(
        base_url="http://target", path="/report", param="id",
        session_factory=lambda: sess, http_send=_noise_sender(sess, tr),
        poll_seconds=4, poll_interval=1, sleep=lambda _s: None)
    assert res.interactions == []
    assert sqli_verdict(res).tier is Tier.REFUTED


# -----------------------------------------------------------------------------
# CAUSAL NEGATIVE-CONTROL: a legitimate session token whose payload was NEVER injected must NOT confirm.
# -----------------------------------------------------------------------------
def test_causal_negative_control_callback_for_a_non_injected_token_never_confirms():
    it = OOBInteraction(protocol="dns", unique_id="corr-noninjected", q_type="A")
    res = _result(interactions=[it], matched="NONINJECTED", injected=[])   # matched token NOT injected
    assert res.confirmed is False
    assert sqli_verdict(res).tier is not Tier.CONFIRMED
    assert sqli_verdict(res).tier is Tier.REFUTED


def test_causal_positive_a_token_we_actually_injected_confirms():
    it = OOBInteraction(protocol="dns", unique_id="corr-injected", q_type="A", remote_address="203.0.113.9")
    res = _result(interactions=[it], matched="TOKX", injected=["TOKA", "TOKX"])
    assert res.confirmed is True and sqli_verdict(res).tier is Tier.CONFIRMED


def test_probe_confirms_only_a_dispatched_token_not_a_send_that_errored():
    sess, tr = _stub_session()
    def _raising_sender(*, target_url, method, headers, body):
        raise ConnectionError("target unreachable")
    res = run_sqli_probe(
        base_url="http://target", path="/report", param="id",
        session_factory=lambda: sess, http_send=_raising_sender,
        poll_seconds=2, poll_interval=1, sleep=lambda _s: None)
    assert res.injected_tokens == []
    assert sqli_verdict(res).tier is not Tier.CONFIRMED


# -----------------------------------------------------------------------------
# ZERO-FP NAIL: the SAFE control (parameterized, no reach-out) is never CONFIRMED.
# -----------------------------------------------------------------------------
def test_safe_control_endpoint_is_never_confirmed():
    sess, _tr = _stub_session()
    res = run_sqli_probe(
        base_url="http://target", path="/report-safe", param="id",
        session_factory=lambda: sess, http_send=_safe_sender,
        poll_seconds=3, poll_interval=1, sleep=lambda _s: None)
    assert not res.confirmed and res.interactions == []
    assert sqli_verdict(res).tier is Tier.REFUTED


def test_run_probe_not_data_when_no_oob_server():
    def _boom():
        raise OOBError("no public interactsh server reachable")
    res = run_sqli_probe(base_url="http://target", path="/report", param="id",
                         session_factory=_boom, sleep=lambda _s: None)
    assert res.probe_error and sqli_verdict(res).tier is Tier.NOT_DATA


# -----------------------------------------------------------------------------
# CLI (run_sqli_from_config) — exit codes + JSON, offline via injected seams.
# -----------------------------------------------------------------------------
def _write_cfg(tmp_path, **over):
    cfg = {"mode": "sqli", "base_url": "http://target", "path": "/report", "param": "id"}
    cfg.update(over)
    p = tmp_path / "sqli.json"
    p.write_text(json.dumps(cfg), encoding="utf-8")
    return str(p)


def test_cli_confirmed_exit_1_and_json(tmp_path):
    sess, tr = _stub_session()
    out_lines = []
    code = run_sqli_from_config(
        _write_cfg(tmp_path), environ={}, out=out_lines.append, err=lambda *a: None,
        session_factory=lambda: sess, http_send=_vulnerable_sender(sess, tr), sleep=lambda _s: None)
    assert code == 1
    payload = json.loads(out_lines[-1])
    assert payload["mode"] == "sqli"
    assert payload["result"]["tier"] == "confirmed" and payload["result"]["confirmed"] is True
    assert payload["result"]["interactions"]
    assert payload["result"]["payloads_injected"] > 0
    assert "payloads" not in payload["result"]              # weaponized SQL strings are never logged


def test_cli_refuted_exit_0(tmp_path):
    sess, _tr = _stub_session()
    out_lines = []
    code = run_sqli_from_config(
        _write_cfg(tmp_path, poll_seconds=2, poll_interval=1), environ={},
        out=out_lines.append, err=lambda *a: None,
        session_factory=lambda: sess, http_send=_safe_sender, sleep=lambda _s: None)
    assert code == 0
    assert json.loads(out_lines[-1])["result"]["tier"] == "refuted"


def test_cli_notdata_exit_2_when_oob_unavailable(tmp_path):
    def _boom():
        raise OOBError("unreachable")
    out_lines = []
    code = run_sqli_from_config(
        _write_cfg(tmp_path), environ={}, out=out_lines.append, err=lambda *a: None,
        session_factory=_boom, sleep=lambda _s: None)
    assert code == 2
    assert json.loads(out_lines[-1])["result"]["tier"] == "not_data"


def test_cli_missing_fields_exit_2(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text(json.dumps({"mode": "sqli", "base_url": "http://t"}), encoding="utf-8")
    out_lines = []
    code = run_sqli_from_config(str(p), environ={}, out=out_lines.append, err=lambda *a: None)
    assert code == 2 and json.loads(out_lines[-1])["error"] == "missing_fields"


def test_cli_requires_exactly_one_of_config_or_target_file():
    out_lines = []
    code = run_sqli_from_config(config_path=None, target_file_path=None,
                                environ={}, out=out_lines.append, err=lambda *a: None)
    assert code == 2 and json.loads(out_lines[-1])["error"] == "bad_input"


def test_cli_target_file_maps_a_query_target(tmp_path):
    tf = tmp_path / "t.toml"
    tf.write_text(
        'name = "sqli-report"\n'
        'base_url = "http://target"\n'
        'spec_path = ""\n'
        'method = "GET"\n'
        'path_template = "/report"\n'
        'id_location = "query"\n'
        'id_param = "id"\n'
        'attacker_id = "a"\n'
        'victim_id = "b"\n'
        'auth_spec_path = ""\n', encoding="utf-8")
    sess, tr = _stub_session()
    out_lines = []
    code = run_sqli_from_config(
        target_file_path=str(tf), environ={}, out=out_lines.append, err=lambda *a: None,
        session_factory=lambda: sess, http_send=_vulnerable_sender(sess, tr), sleep=lambda _s: None)
    assert code == 1
    payload = json.loads(out_lines[-1])
    assert payload["result"]["param"] == "id" and payload["result"]["confirmed"] is True
