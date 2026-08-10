# ==============================================================================
# `aivist run --config<file.json>` — the non-interactive, programmatic entry point. Fully coverable
# (unlike the interactive path): a JSON config + env tokens -> the SAME engine -> structured JSON out.
# Proves: verify + scan modes produce correct JSON; tokens are ENV-ONLY (missing -> JSON error, never a
# prompt; attacker==owner refused; never read from the config file; never appear in the JSON output);
# exit codes (verdict -> 0, NOT DATA/error -> non-zero). No verdict/engine change — this only adapts
# input and serializes output. Offline: engine faked, provider stubbed, no network.
# ==============================================================================
import os
import sys
import json

import pytest
from pydantic import SecretStr

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, _REPO_ROOT)

from backend.app.core.config import settings
from backend.app.cli.run_command import run_from_config
from backend.tests.test_scan_run import _result, _stub_provider, _CANDS, _ID_MAP, _ScriptedEngine

_ENV = {"TARGET_ATTACKER_TOKEN": "ATK-SECRET", "TARGET_OWNER_TOKEN": "OWN-SECRET",
        "TARGET_BYSTANDER_TOKEN": "BYST-SECRET"}

_VERIFY_CFG = {
    "mode": "verify", "base_url": "http://t", "method": "GET",
    "path_template": "/books/v1/{book_title}", "id_location": "path", "id_param": "book_title",
    "attacker_id": "alicebook", "victim_id": "bobbook",
}


def _write(tmp_path, obj, name="config.json"):
    p = tmp_path / name
    p.write_text(json.dumps(obj), encoding="utf-8")
    return str(p)


def _capture():
    out = []
    return out, (lambda *a: out.append(" ".join(str(x) for x in a)))


def _async_engine(**over):
    async def eng(**kw):
        eng.calls.append(kw)
        return _result(**over)
    eng.calls = []
    return eng


@pytest.fixture(autouse=True)
def _api_key(monkeypatch):
    monkeypatch.setattr(settings, "LLM_API_KEY", SecretStr("test-key"))
    monkeypatch.setattr(settings, "AI_DEEP_VERIFY_ENABLED", False)
    monkeypatch.setattr(settings, "LLM_MODEL", "test-model")


# ------------------------------------------------------------------ verify mode
def test_verify_mode_emits_json_verdict(tmp_path):
    cfg = _write(tmp_path, _VERIFY_CFG)
    out, put = _capture()
    eng = _async_engine(ai_verdict="failed")
    code = run_from_config(cfg, environ=_ENV, out=put, engine=eng)
    payload = json.loads("".join(out))
    assert code == 0 and payload["exit_code"] == 0
    assert payload["mode"] == "verify" and payload["target"] == "http://t"
    assert payload["result"]["tier"] == "refuted" and payload["result"]["verdict"] == "failed"
    assert payload["result"]["baseline_path"] == "/books/v1/alicebook"   # op built from the config fields
    assert len(eng.calls) == 1                                           # the real engine call ran


def test_verify_notdata_exits_nonzero(tmp_path):
    cfg = _write(tmp_path, _VERIFY_CFG)
    out, put = _capture()
    code = run_from_config(cfg, environ=_ENV, out=put,
                           engine=_async_engine(status="degraded", ai_verdict=None))
    payload = json.loads("".join(out))
    assert code == 2 and payload["exit_code"] == 2 and payload["result"]["tier"] == "notdata"


# ------------------------------------------------------------------ scan mode
def test_scan_mode_emits_tiered_json_report(tmp_path):
    cfg = _write(tmp_path, {
        "mode": "scan", "base_url": "http://t",
        "endpoints": ["GET /api/reports/{report_id}", "GET /api/users/{user_id}/profile",
                      "GET /api/orders/{order_id}"],
        "id_source": {"ids": _ID_MAP},
    })
    out, put = _capture()
    code = run_from_config(cfg, environ=_ENV, out=put, engine=_ScriptedEngine(),
                           scan_provider_factory=_stub_provider(_CANDS))
    payload = json.loads("".join(out))
    assert code == 0 and payload["mode"] == "scan" and payload["catalog_source"] == "endpoints"
    s = payload["summary"]
    assert s["confirmed"] == 1 and s["refuted"] == 1 and s["skipped"] == 1 and s["dropped"] == 1
    assert s["total"] == 3 and len(payload["records"]) == 3


# ------------------------------------------------------------------ tokens: env-only, guard, redaction
def test_missing_owner_token_is_a_clear_json_error(tmp_path):
    cfg = _write(tmp_path, _VERIFY_CFG)
    out, put = _capture()
    code = run_from_config(cfg, environ={"TARGET_ATTACKER_TOKEN": "only-attacker"}, out=put)
    payload = json.loads("".join(out))
    assert code == 2 and payload["error"] == "missing_token" and payload["exit_code"] == 2
    assert "TARGET_OWNER_TOKEN" in payload["message"]                    # names the missing token, no prompt


def test_attacker_equals_owner_is_refused(tmp_path):
    cfg = _write(tmp_path, _VERIFY_CFG)
    out, put = _capture()
    code = run_from_config(cfg, out=put,
                           environ={"TARGET_ATTACKER_TOKEN": "same", "TARGET_OWNER_TOKEN": "same"})
    payload = json.loads("".join(out))
    assert code == 2 and payload["error"] == "identity_collision"       # collision guard fires


def test_tokens_are_never_read_from_the_config_file(tmp_path):
    # the config file CONTAINS a token field -> it MUST be ignored (env-only). Env has no owner ->
    # a missing-token error proves the file's token was not used.
    cfg = _write(tmp_path, {**_VERIFY_CFG, "TARGET_OWNER_TOKEN": "FROM-FILE-SHOULD-BE-IGNORED"})
    out, put = _capture()
    code = run_from_config(cfg, environ={"TARGET_ATTACKER_TOKEN": "a"}, out=put)
    payload = json.loads("".join(out))
    assert code == 2 and payload["error"] == "missing_token"
    assert "FROM-FILE-SHOULD-BE-IGNORED" not in "".join(out)            # the file token never used/echoed


def test_no_token_value_ever_appears_in_the_json(tmp_path):
    cfg = _write(tmp_path, _VERIFY_CFG)
    out, put = _capture()
    run_from_config(cfg, environ=_ENV, out=put, engine=_async_engine(ai_verdict="failed"))
    blob = "".join(out)
    for tok in _ENV.values():
        assert tok not in blob                                          # ATK/OWN/BYST secrets redacted-out


# ------------------------------------------------------------------ config / mode errors -> non-zero JSON
def test_bad_mode_is_a_json_error(tmp_path):
    cfg = _write(tmp_path, {"mode": "nope", "base_url": "http://t"})
    out, put = _capture()
    code = run_from_config(cfg, environ=_ENV, out=put)
    assert code == 2 and json.loads("".join(out))["error"] == "bad_mode"


def test_scan_without_a_catalog_source_is_a_json_error(tmp_path):
    cfg = _write(tmp_path, {"mode": "scan", "base_url": "http://t"})
    out, put = _capture()
    code = run_from_config(cfg, environ=_ENV, out=put)
    assert code == 2 and json.loads("".join(out))["error"] == "no_catalog_source"
