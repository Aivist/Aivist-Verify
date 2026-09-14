# ==============================================================================
# Offline tests for the `verify --target-file` GOLDEN PATH (P1).
#
# `run_verify_from_target_file` must confirm ONE finding from a saved Target with NO hand-authored
# --op and NO --spec, by REUSING the shipped functions (Target.to_op == build_op for the op;
# spec_from_endpoints for a synthesized catalog) and then deferring to the UNCHANGED
# run_external_verify core. These tests inject a fake engine (zero network / zero LLM) and assert:
#   * happy path: the op is BUILT from the target's fields and reaches the engine (-> CONFIRMED, exit 1);
#   * spec is SYNTHESIZED when the target is spec-less (the endpoint appears in available_endpoints);
#   * both --target-file and --op -> a fail-loud error, never a silent pick (via run.main dispatch);
#   * tokens stay ENV-ONLY (attacker->auth_context, owner->owner_credential) and a token in the target
#     file is REJECTED (off-disk discipline);
#   * attacker == owner is STILL fail-closed through this path (engine never runs, exit 2).
# The feature is input-layer only: the zero-FP judge is untouched and is exercised by the fake engine.
# ==============================================================================
import os
import sys
import types

import pytest
from pydantic import SecretStr

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, _REPO_ROOT)

from backend.app.cli.external_verify import run_verify_from_target_file
from backend.app.core.config import settings


# ------------------------------------------------------------------ helpers
class _FakeEngine:
    """Async stand-in for execute_deep_verification: records the kwargs it was called with and
    returns a preset result. Lets tests assert the ASSEMBLY without any network / LLM."""

    def __init__(self, result):
        self.result = result
        self.captured = None
        self.calls = 0

    async def __call__(self, **kwargs):
        self.calls += 1
        self.captured = kwargs
        return self.result


def _result(**over):
    base = dict(
        status="completed", ai_verdict="verified", ai_verdict_raw="verified",
        guard_override=None, degraded_reason=None,
        caller_identity_anchor=None, payload_causality_anchor=None, state_jump_anchor=None,
        negative_assertion_anchor=None, anchoring_result=None, pre_flight_status=None,
        owner_view_corroborated=True, follow_up_response=None,
        baseline={"response": {"status_code": 200}},
        attack={"response": {"status_code": 200}},
    )
    base.update(over)
    return types.SimpleNamespace(**base)


_TARGET_TOML = (
    'name = "stmt"\n'
    'base_url = "http://localhost:8888"\n'
    'spec_path = ""\n'                       # spec-less -> synthesized catalog
    'method = "GET"\n'
    'path_template = "/api/statements/{id}"\n'
    'id_location = "path"\n'
    'id_param = "id"\n'
    'attacker_id = "1"\n'
    'victim_id = "2"\n'
    'auth_spec_path = ""\n'
)


def _seed_target(tmp_path, toml_text=_TARGET_TOML, name="stmt.toml"):
    p = tmp_path / name
    p.write_text(toml_text, encoding="utf-8")
    return str(p)


def _run(tmp_path, monkeypatch, engine, *, atk="ATK-CANARY", own="OWN-CANARY",
         toml_text=_TARGET_TOML):
    """Drive run_verify_from_target_file with env tokens + an injected engine. prompt_secret RAISES
    (proving the env path is taken and no getpass ever happens)."""
    monkeypatch.setattr(settings, "LLM_API_KEY", SecretStr("test-key"))   # key gate passes
    monkeypatch.setattr(settings, "AI_DEEP_VERIFY_ENABLED", False)        # auto-restored after test
    monkeypatch.setenv("TARGET_ATTACKER_TOKEN", atk)
    monkeypatch.setenv("TARGET_OWNER_TOKEN", own)
    monkeypatch.delenv("TARGET_BYSTANDER_TOKEN", raising=False)
    tf = _seed_target(tmp_path, toml_text)

    def _boom(*_a):
        raise AssertionError("must NOT prompt — tokens come from the environment")

    lines = []
    code = run_verify_from_target_file(
        tf, prompt_secret=_boom, config_path=str(tmp_path / "no-config.toml"),
        engine=engine, echo=lambda *a: lines.append(" ".join(str(x) for x in a)),
        err=lambda *a: lines.append(" ".join(str(x) for x in a)))
    return code, "\n".join(lines)


# ------------------------------------------------------------------ happy path: op built + reaches engine
def test_target_file_builds_op_and_confirms(tmp_path, monkeypatch):
    eng = _FakeEngine(_result(ai_verdict="verified"))
    code, out = _run(tmp_path, monkeypatch, eng)
    assert eng.calls == 1                                            # the engine ran
    cap = eng.captured
    # the op was BUILT from the target's fields (attacker id filled into the {id} template)
    assert cap["parsed_request"]["path"] == "/api/statements/1"
    assert cap["parsed_request"]["method"] == "GET"
    assert cap["parsed_request"]["body"] is None                    # no body via the target file
    # the payload swaps the id to the victim (build_op path-segment shape)
    assert cap["payload"]["location"] == "path_segment"
    assert cap["payload"]["payload_string"] == "2"
    # scope declared from the target's base_url
    assert cap["base_url"] == "http://localhost:8888"
    assert cap["approved_host"] == "localhost:8888"
    # a 'verified' engine verdict renders CONFIRMED -> exit 1
    assert code == 1
    assert "[CONFIRMED]" in out


# ------------------------------------------------------------------ spec synthesized when absent
def test_spec_synthesized_when_target_is_spec_less(tmp_path, monkeypatch):
    eng = _FakeEngine(_result())
    _run(tmp_path, monkeypatch, eng)
    catalog = eng.captured["available_endpoints"]
    assert isinstance(catalog, list) and catalog                    # a catalog was synthesized
    # the target's single endpoint is present in the synthesized catalog (no --spec authored)
    assert any("/api/statements/{id}" in e and e.upper().startswith("GET") for e in catalog)


# ------------------------------------------------------------------ both --target-file and --op -> fail loud
def test_both_target_file_and_op_is_fail_loud(monkeypatch, capsys):
    import run as runmod
    monkeypatch.setattr(sys, "argv",
                        ["run.py", "verify", "--target-file", "t.toml", "--op", "op.json"])
    with pytest.raises(SystemExit) as e:
        runmod.main()
    assert e.value.code == 2                                         # NOT DATA / refused
    err = capsys.readouterr().err
    assert "standalone golden path" in err and "--op" in err        # names the clashing flag


# ------------------------------------------------------------------ tokens stay ENV-ONLY
def test_tokens_are_env_only_and_route_per_account(tmp_path, monkeypatch):
    eng = _FakeEngine(_result())
    _run(tmp_path, monkeypatch, eng, atk="ATTACKER-CANARY-111", own="OWNER-CANARY-222")
    auth = str(eng.captured["auth_context"])
    owner = eng.captured["owner_credential"]
    assert "ATTACKER-CANARY-111" in auth and "OWNER-CANARY-222" not in auth   # attacker only in header
    assert "OWNER-CANARY-222" in owner.header_value                            # owner only in its channel
    assert "ATTACKER-CANARY-111" not in owner.header_value


def test_token_key_in_target_file_is_rejected(tmp_path, monkeypatch):
    # A token in the target file is REFUSED (tokens never come from the file — off-disk discipline).
    toml_with_token = _TARGET_TOML + 'TARGET_ATTACKER_TOKEN = "leaked-in-file"\n'
    eng = _FakeEngine(_result())
    code, out = _run(tmp_path, monkeypatch, eng, toml_text=toml_with_token)
    assert code == 2
    assert eng.calls == 0                                           # never reached the engine
    assert "target file" in out and "NEVER contain a token" in out


# ------------------------------------------------------------------ attacker == owner still fail-closed
def test_attacker_equals_owner_refused_via_target_file(tmp_path, monkeypatch):
    # THE FP NAIL through this path: identical attacker/owner tokens -> refused BEFORE any verdict.
    # The engine would return 'verified' (would CONFIRM if the guard were gone) — prove it NEVER runs.
    eng = _FakeEngine(_result(ai_verdict="verified"))
    code, out = _run(tmp_path, monkeypatch, eng, atk="IDENTICAL-TOK", own="IDENTICAL-TOK")
    assert code == 2                                                # fail-closed
    assert eng.calls == 0                                           # engine NEVER ran -> no CONFIRMED path
    assert "SAME identity" in out
    assert "[CONFIRMED]" not in out
