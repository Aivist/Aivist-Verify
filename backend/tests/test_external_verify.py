# ==============================================================================
# Offline tests for the external real-target verify path (backend/app/cli/external_verify.py).
# Zero API cost, no network: the engine is injected as a fake that captures the assembled
# kwargs and returns a crafted result. Proves the THREE RED LINES structurally, plus the
# NOT-DATA degradation honesty and the input assembly.
# ==============================================================================
import os
import sys
import json
import types
import asyncio

import pytest
import yaml
from pydantic import SecretStr

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, _REPO_ROOT)

from backend.app.cli import external_verify as ev
from backend.app.cli.external_verify import (
    run_external_verify, classify_degradation, _resolve_tokens,
    _approved_host, _build_parsed_request, _attack_path_from_op, _auth_header, _load_spec_file,
    _split_path_query,
)
from backend.app.services.endpoint_catalog import catalog_from_openapi
from backend.app.services import deep_verifier as dv
from backend.app.services.deep_verifier import OwnerCredential, fetch_owner_view
from backend.app.services.fuzzer import _reconstruct_url, mutate_request
from backend.app.services.scope import ScopePolicy
from backend.app.core.config import settings


# ------------------------------------------------------------------ helpers
class _FakeEngine:
    """Async stand-in for execute_deep_verification: records the kwargs it was called with
    and returns a preset result. Lets tests assert the ASSEMBLY without any network/LLM."""

    def __init__(self, result):
        self.result = result
        self.captured = None

    async def __call__(self, **kwargs):
        self.captured = kwargs
        return self.result


def _result(**over):
    base = dict(
        status="completed", ai_verdict="failed", ai_verdict_raw="failed",
        guard_override=None, degraded_reason=None,
        caller_identity_anchor=None, payload_causality_anchor=None, state_jump_anchor=None,
        negative_assertion_anchor=None, anchoring_result=None, pre_flight_status=None,
        owner_view_corroborated=None, follow_up_response=None,
        baseline={"response": {"status_code": 200}},
        attack={"response": {"status_code": 200}},
    )
    base.update(over)
    return types.SimpleNamespace(**base)


def _prompts(*vals):
    it = iter(vals)
    return lambda *_a: next(it)


def _write(tmp_path, name, obj):
    p = tmp_path / name
    p.write_text(json.dumps(obj), encoding="utf-8")
    return str(p)


_SPEC = {"openapi": "3.0.0", "paths": {"/api/users/{id}/gizmo": {"post": {"operationId": "g"}}}}
_OP = {"method": "POST", "baseline_path": "/api/users/1/gizmo", "body": {"code": "$UNIQUE"},
       "payload": {"location": "path_segment", "target_param": "1", "payload_string": "2", "type": "BOLA"},
       "shape": "silent_write"}


def _run(tmp_path, monkeypatch, engine, *, prompt, target="http://localhost:8888",
         op=_OP, cfg_path=None, echo_sink=None):
    """Drive run_external_verify with an injected engine + scripted secret prompt."""
    monkeypatch.setattr(settings, "LLM_API_KEY", SecretStr("test-key"))   # key gate passes
    monkeypatch.setattr(settings, "AI_DEEP_VERIFY_ENABLED", False)        # auto-restore after test
    spec_path = _write(tmp_path, "spec.json", _SPEC)
    op_path = _write(tmp_path, "op.json", op)
    lines = echo_sink if echo_sink is not None else []
    code = run_external_verify(
        target=target, spec_path=spec_path, op_path=op_path,
        prompt_secret=prompt, config_path=cfg_path or str(tmp_path / "no-config.toml"),
        engine=engine, echo=lambda *a: lines.append(" ".join(str(x) for x in a)),
        err=lambda *a: lines.append(" ".join(str(x) for x in a)),
    )
    return code, "\n".join(lines)


# ------------------------------------------------------------------ RED LINE 1: scope
def test_red_line_1_scope_declared_from_target_and_fail_closed(tmp_path, monkeypatch):
    eng = _FakeEngine(_result())
    _run(tmp_path, monkeypatch, eng, prompt=_prompts("atk", ""))
    # the scope declaration handed to the engine is the target's host:port (no exemption)
    assert eng.captured["approved_host"] == "localhost:8888"
    assert eng.captured["base_url"] == "http://localhost:8888"
    # that declared policy is fail-closed: in-scope allowed, out-of-scope refused
    pol = ScopePolicy.from_declaration([eng.captured["approved_host"]])
    assert pol.check("http://localhost:8888/api/users/2/gizmo").allowed is True
    assert pol.check("http://evil.example.com/api/users/2/gizmo").allowed is False
    assert pol.check("http://localhost:9999/x").allowed is False        # wrong port -> refused


def test_approved_host_derivation():
    assert _approved_host("http://localhost:8888") == "localhost:8888"
    assert _approved_host("http://127.0.0.1:8080/base") == "127.0.0.1:8080"
    assert _approved_host("crapi.local") == "crapi.local"               # no scheme, no port


# ------------------------------------------------------------------ RED LINE 2: identity isolation
def test_red_line_2_owner_token_never_in_attack_headers(tmp_path, monkeypatch):
    eng = _FakeEngine(_result())
    _run(tmp_path, monkeypatch, eng, prompt=_prompts("ATTACKER-CANARY-111", "OWNER-CANARY-222"))
    auth = eng.captured["auth_context"]
    owner = eng.captured["owner_credential"]
    # attacker token is in the attack header; owner token is NOT
    assert "ATTACKER-CANARY-111" in str(auth)
    assert "OWNER-CANARY-222" not in str(auth)
    # owner token flows ONLY through the OwnerCredential channel (and it is one, not a dict)
    assert isinstance(owner, OwnerCredential)
    assert "OWNER-CANARY-222" in owner.header_value
    assert "ATTACKER-CANARY-111" not in owner.header_value


def test_attacker_header_is_never_an_owner_credential():
    # structural: the attacker header helper returns a plain dict, never an OwnerCredential
    hdr = _auth_header("Bearer abc")
    assert isinstance(hdr, dict) and not isinstance(hdr, OwnerCredential)
    assert hdr == {"Authorization": "Bearer abc"}
    assert _auth_header("X-Token: t") == {"X-Token": "t"}
    assert _auth_header("bare") == {"Authorization": "Bearer bare"}


# ------------------------------------------------------------------ RED LINE 3: SecretStr / redaction
def test_red_line_3_tokens_are_secretstr(tmp_path):
    cfg = tmp_path / "none.toml"
    atk, own = _resolve_tokens(str(cfg), _prompts("ATTACKER-SECRET", "OWNER-SECRET"))
    assert isinstance(atk, SecretStr) and isinstance(own, SecretStr)
    assert "ATTACKER-SECRET" not in repr(atk)          # SecretStr masks in repr
    assert "OWNER-SECRET" not in str(own)


def test_red_line_3_canary_tokens_never_in_output(tmp_path, monkeypatch):
    eng = _FakeEngine(_result(ai_verdict="failed"))
    code, out = _run(tmp_path, monkeypatch, eng, prompt=_prompts("ATK-CANARY-XYZ", "OWN-CANARY-QRS"))
    assert "ATK-CANARY-XYZ" not in out
    assert "OWN-CANARY-QRS" not in out


def test_tokens_read_from_config_file_are_secretstr(tmp_path):
    cfg = tmp_path / "config.toml"
    cfg.write_text('TARGET_ATTACKER_TOKEN = "cfg-atk"\nTARGET_OWNER_TOKEN = "cfg-own"\n', encoding="utf-8")

    def _boom(*_a):
        raise AssertionError("must NOT prompt when tokens are in the config file")

    atk, own = _resolve_tokens(str(cfg), _boom)
    assert isinstance(atk, SecretStr) and atk.get_secret_value() == "cfg-atk"
    assert own.get_secret_value() == "cfg-own"


# ------------------------------------------------------------------ degradation honesty
def test_classify_degradation():
    assert classify_degradation(_result(status="degraded", ai_verdict=None))          # engine degraded
    assert classify_degradation(_result(ai_verdict=None))                             # no verdict
    assert "429" in classify_degradation(_result(attack={"response": {"status_code": 429}}))
    assert "403" in classify_degradation(_result(attack={"response": {"status_code": 403}}))
    assert "401" in classify_degradation(_result(baseline={"response": {"status_code": 401}}))
    assert classify_degradation(_result(follow_up_response={"status_code": 429}))
    assert classify_degradation(_result()) is None                                    # clean 200/200 verdict


def test_challenge_response_renders_notdata_not_a_security_signal(tmp_path, monkeypatch):
    # The engine "judged" the 403 attack as 'failed', but a 403 is a challenge/auth signal,
    # NOT security evidence -> the run must render NOT DATA, never 'safe'/'refuted'.
    eng = _FakeEngine(_result(ai_verdict="failed", attack={"response": {"status_code": 403}}))
    code, out = _run(tmp_path, monkeypatch, eng, prompt=_prompts("atk", ""))
    assert code == 2
    assert "[NOT DATA]" in out
    assert "[REFUTED]" not in out and "[CONFIRMED]" not in out
    assert "403" in out


def test_timeout_degraded_result_is_notdata(tmp_path, monkeypatch):
    eng = _FakeEngine(_result(status="degraded", ai_verdict=None, degraded_reason="TimeoutError"))
    code, out = _run(tmp_path, monkeypatch, eng, prompt=_prompts("atk", ""))
    assert code == 2
    assert "[NOT DATA]" in out


# ------------------------------------------------------------------ assembly + no zero-FP claim
def test_assembly_fills_unique_and_attack_path():
    parsed = _build_parsed_request(_OP, "u-123")
    assert parsed["body"] == {"code": "u-123"}                    # $UNIQUE filled
    assert parsed["headers"] == {"Content-Type": "application/json"}
    assert parsed["method"] == "POST" and parsed["path"] == "/api/users/1/gizmo"
    assert _attack_path_from_op(_OP) == "/api/users/2/gizmo"      # id swapped 1 -> 2


def test_real_target_makes_no_zero_fp_claim(tmp_path, monkeypatch):
    eng = _FakeEngine(_result(ai_verdict="failed"))
    code, out = _run(tmp_path, monkeypatch, eng, prompt=_prompts("atk", ""))
    assert "not a zero-fp claim" in out.lower()                   # output disclaims zero-FP
    assert "no ground_truth" in out                               # lab-oracle line: nothing to compare
    assert "zero false positive" not in out.lower()               # never asserts the lab claim


# ------------------------------------------------------------------ YAML --spec support
_SPEC_DICT = {
    "openapi": "3.0.0",
    "paths": {
        "/api/users/{id}/gizmo": {"post": {"operationId": "g", "tags": ["writes"]}},
        "/api/gizmos/{gizmo_id}": {"get": {"operationId": "getGizmo"}},
    },
}


def test_spec_yaml_and_json_produce_same_catalog(tmp_path):
    # The reader is a swap, not a semantic change: a YAML spec and the equivalent JSON spec
    # must yield the SAME catalog. JSON stays byte-identical to the source dict.
    json_path = tmp_path / "spec.json"
    yaml_path = tmp_path / "spec.yaml"
    json_path.write_text(json.dumps(_SPEC_DICT), encoding="utf-8")
    yaml_path.write_text(yaml.safe_dump(_SPEC_DICT), encoding="utf-8")

    from_json = _load_spec_file(str(json_path))
    from_yaml = _load_spec_file(str(yaml_path))
    assert from_json == _SPEC_DICT                       # .json path byte-identical
    assert from_yaml == _SPEC_DICT                       # .yaml parses to the same dict
    assert catalog_from_openapi(from_yaml) == catalog_from_openapi(from_json)
    assert catalog_from_openapi(from_yaml) != []         # sanity: it actually produced a catalog


def test_yaml_spec_uses_safe_load_not_the_unsafe_loader(tmp_path):
    # A hostile spec carrying a python-object tag: safe_load REFUSES it (raises); the unsafe
    # loader would try to construct/execute it. If _load_spec_file raises, it did NOT execute.
    malicious = tmp_path / "evil.yaml"
    malicious.write_text('!!python/object/apply:os.system ["echo pwned"]\n', encoding="utf-8")
    with pytest.raises(yaml.YAMLError):
        _load_spec_file(str(malicious))
    # regression guard: the module must use safe_load and must never call the unsafe loader
    src = open(ev.__file__, encoding="utf-8").read()
    assert "safe_load" in src
    assert "yaml.load(" not in src


def test_malformed_yaml_spec_degrades_to_notdata(tmp_path, monkeypatch):
    # A malformed spec must hit the graceful NOT-DATA path, never a traceback.
    monkeypatch.setattr(settings, "LLM_API_KEY", SecretStr("test-key"))
    monkeypatch.setattr(settings, "AI_DEEP_VERIFY_ENABLED", False)
    bad_spec = tmp_path / "spec.yaml"
    bad_spec.write_text("openapi: '3.0.0'\npaths: [1, 2, 3\n", encoding="utf-8")  # unclosed flow seq
    op_path = _write(tmp_path, "op.json", _OP)
    lines = []
    code = run_external_verify(
        target="http://localhost:8888", spec_path=str(bad_spec), op_path=op_path,
        prompt_secret=_prompts("atk", ""), config_path=str(tmp_path / "no-config.toml"),
        engine=_FakeEngine(_result()),
        echo=lambda *a: lines.append(" ".join(str(x) for x in a)),
        err=lambda *a: lines.append(" ".join(str(x) for x in a)),
    )
    out = "\n".join(lines)
    assert code == 2
    assert "[NOT DATA]" in out and "could not read --spec" in out


# ============================================================================
# D29 — query-string / non-path IDOR is now expressible and confirmable.
# The id lives in the query string: carry it on the BASELINE, swap it for the
# attack, compose a single-'?' URL, and re-read it in the owner view. Path-based
# cases stay byte-identical (regression). Observed-real trigger: crAPI
# GET /workshop/api/mechanic/mechanic_report?report_id= (hand-verified IDOR).
# ============================================================================
_OP_QS = {
    "method": "GET",
    "baseline_path": "/workshop/api/mechanic/mechanic_report?report_id=7",  # attacker's OWN id
    "body": None,
    "payload": {"location": "query_param", "target_param": "report_id",
                "payload_string": "6", "type": "BOLA"},                     # swap -> victim id 6
    "shape": "query_string_idor",
}


def test_split_path_query_parses_baseline_query_and_is_empty_for_path_cases():
    path, q = _split_path_query("/workshop/api/mechanic/mechanic_report?report_id=7")
    assert path == "/workshop/api/mechanic/mechanic_report" and q == {"report_id": "7"}
    assert _split_path_query("/api/users/1/gizmo") == ("/api/users/1/gizmo", {})  # path case: no query


def test_query_string_baseline_carries_id_and_attack_swaps_it():
    parsed = _build_parsed_request(_OP_QS, "u-1")
    # BASELINE now carries the attacker's OWN query id (was {} before -> baseline had no id -> 500)
    assert parsed["path"] == "/workshop/api/mechanic/mechanic_report"
    assert parsed["query_params"] == {"report_id": "7"}
    # the engine's REAL mutation swaps ONLY that id for the attack (baseline vs attack differ by the id)
    attack = asyncio.run(mutate_request(parsed, _OP_QS["payload"]))
    assert attack["query_params"] == {"report_id": "6"} and attack["path"] == parsed["path"]
    # rendered Reproduce line is correct for a query id (single '?')
    assert _attack_path_from_op(_OP_QS) == "/workshop/api/mechanic/mechanic_report?report_id=6"


def test_reconstruct_url_never_double_question_mark():
    base = "http://localhost:8888"
    u = _reconstruct_url({"path": "/x?a=1", "query_params": {"b": "2"}}, base)
    assert u.count("?") == 1 and "a=1" in u and "b=2" in u
    # explicit query_params WIN on a key clash (the attack id replacing the baseline id)
    u2 = _reconstruct_url({"path": "/m?report_id=7", "query_params": {"report_id": "6"}}, base)
    assert u2.count("?") == 1 and "report_id=6" in u2 and "report_id=7" not in u2


def test_reconstruct_url_path_based_is_byte_identical():
    base = "http://localhost:8888"
    assert _reconstruct_url({"path": "/api/users/2/gizmo", "query_params": {}}, base) \
        == "http://localhost:8888/api/users/2/gizmo"
    assert _reconstruct_url({"path": "/a", "query_params": {"k": "v"}}, base) \
        == "http://localhost:8888/a?k=v"


def test_owner_view_carries_query_string_and_stays_get_owner_only(monkeypatch):
    """The owner re-read hits the SAME resource id when the id is in the query (D29), while
    remaining a custody-free GET AS THE OWNER (identity isolation)."""
    captured = {}

    async def fake_send(client, req, base_url, **kw):
        captured["req"] = req
        return {"status_code": 200, "response_body": '{"id":6}'}

    monkeypatch.setattr(dv, "_send_request", fake_send)
    owner = OwnerCredential.from_config("OWNER-TOKEN-CANARY")
    res = asyncio.run(fetch_owner_view(
        object(), "/workshop/api/mechanic/mechanic_report", "http://localhost:8888",
        owner, query_params={"report_id": "6"}))
    assert res.available is True
    req = captured["req"]
    assert req["query_params"] == {"report_id": "6"}          # the query id reached the owner read
    assert req["method"] == "GET" and req["body"] is None      # still GET-only, no body (structural)
    assert "OWNER-TOKEN-CANARY" in str(req["headers"])         # reads AS THE OWNER (identity isolation)


def test_owner_view_with_query_is_still_fail_safe_block_on_non_2xx(monkeypatch):
    """Downgrade-only preserved: a non-2xx owner view (a query-string case that is NOT a real
    leak) blocks -> available=False -> the gate can never manufacture a confirmation."""
    async def fake_send(client, req, base_url, **kw):
        return {"status_code": 403, "response_body": "denied"}
    monkeypatch.setattr(dv, "_send_request", fake_send)
    owner = OwnerCredential.from_config("owner-token")
    res = asyncio.run(fetch_owner_view(
        object(), "/m", "http://localhost:8888", owner, query_params={"report_id": "6"}))
    assert res.available is False


def test_path_segment_assembly_byte_identical_regression():
    """Path-based shape unchanged: query_params stays {} and the attack path is the same swap."""
    parsed = _build_parsed_request(_OP, "u-9")
    assert parsed["path"] == "/api/users/1/gizmo" and parsed["query_params"] == {}
    assert _attack_path_from_op(_OP) == "/api/users/2/gizmo"
