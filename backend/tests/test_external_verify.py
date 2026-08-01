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

from pydantic import SecretStr

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, _REPO_ROOT)

from backend.app.cli import external_verify as ev
from backend.app.cli.external_verify import (
    run_external_verify, classify_degradation, _resolve_tokens,
    _approved_host, _build_parsed_request, _attack_path_from_op, _auth_header,
)
from backend.app.services.deep_verifier import OwnerCredential
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
