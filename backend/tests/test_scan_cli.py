# ==============================================================================
# Feature 2 — non-interactive `scan` from a target FILE + tokens. Proves:
#   * run_scan_from_file runs the SAME onramp with NO prompts and the SAME result as the interactive
#     scan (2 engine calls; [CONFIRMED] + [SKIPPED] report),
#   * TOKENS OFF DISK: tokens come from env / a --tokens-file, are masked (never echoed), and are NEVER
#     written into the target file,
#   * per-account routing is REUSED (attacker->auth_context, owner->owner_credential,
#     bystander->bystander_credential),
#   * the attacker!=owner fail-closed collision guard fires on env/file tokens and the engine NEVER runs.
# Zero network / no API: the provider is stubbed and the engine is the same fake the interactive test uses.
# ==============================================================================
import os
import sys
import json

import pytest
from pydantic import SecretStr

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, _REPO_ROOT)

from backend.app.core.config import settings
from backend.app.cli.scan_cli import run_scan_from_file, resolve_scan_tokens
# reuse the interactive scan test's fixtures so "same result" is a true apples-to-apples comparison
from backend.tests.test_scan_run import _SPEC, _CANDS, _ID_MAP, _ScriptedEngine, _stub_provider


def _target_file(tmp_path, spec_path, **over):
    fields = dict(name="scan-t", base_url="http://localhost:8888", method="GET",
                  path_template="/api/reports/{report_id}", id_location="path", id_param="report_id",
                  attacker_id="1", victim_id="2", auth_spec_path="")
    fields.update(over)
    lines = [f'{k} = "{v}"' for k, v in fields.items()]
    lines.insert(2, f"spec_path = '{spec_path}'")
    p = tmp_path / "target.toml"
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return p


def _spec_and_ids(tmp_path):
    sp = tmp_path / "spec.json"
    sp.write_text(json.dumps(_SPEC), encoding="utf-8")
    ids = tmp_path / "ids.json"
    ids.write_text(json.dumps({"ids": _ID_MAP}), encoding="utf-8")
    return sp, ids


def _run(tf, ids, environ, eng, tmp_path, **over):
    lines = []
    sink = lambda *a: lines.append(" ".join(str(x) for x in a))
    code = run_scan_from_file(
        str(tf), id_source_file=str(ids) if ids else None, environ=environ,
        echo=sink, err=sink, engine=eng, scan_provider_factory=_stub_provider(_CANDS), **over)
    return code, "\n".join(lines)


# ------------------------------------------------------------------ resolve_scan_tokens (unit)
def test_resolve_tokens_from_env_and_file_override_and_missing():
    a, o, b = resolve_scan_tokens(environ={"TARGET_ATTACKER_TOKEN": "A", "TARGET_OWNER_TOKEN": "O"})
    assert a.get_secret_value() == "A" and o.get_secret_value() == "O" and b is None

    # a --tokens-file overrides env per key, and can add the optional bystander
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False, encoding="utf-8") as fh:
        fh.write('TARGET_OWNER_TOKEN = "O2"\nTARGET_BYSTANDER_TOKEN = "B"\n')
        tf = fh.name
    try:
        a, o, b = resolve_scan_tokens(
            tokens_file=tf, environ={"TARGET_ATTACKER_TOKEN": "A", "TARGET_OWNER_TOKEN": "O"})
        assert a.get_secret_value() == "A" and o.get_secret_value() == "O2" and b.get_secret_value() == "B"
    finally:
        os.unlink(tf)

    with pytest.raises(ValueError):                       # attacker + owner are required
        resolve_scan_tokens(environ={"TARGET_ATTACKER_TOKEN": "only-attacker"})


# ------------------------------------------------------------------ same result as interactive, tokens off disk
def test_non_interactive_scan_same_result_and_tokens_off_disk(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "LLM_API_KEY", SecretStr("test-key"))
    monkeypatch.setattr(settings, "AI_DEEP_VERIFY_ENABLED", False)
    monkeypatch.setattr(settings, "LLM_MODEL", "test-model")
    sp, ids = _spec_and_ids(tmp_path)
    tf = _target_file(tmp_path, sp)
    eng = _ScriptedEngine()
    code, out = _run(tf, ids, {"TARGET_ATTACKER_TOKEN": "attacker-token",
                               "TARGET_OWNER_TOKEN": "owner-token"}, eng, tmp_path)
    assert code == 0
    assert "scan report:" in out and "[CONFIRMED]" in out and "[SKIPPED - needs manual id]" in out
    assert len(eng.calls) == 2                            # reports + users ran; orders skipped (== interactive)
    assert "attacker-token" not in out and "owner-token" not in out    # masked, never echoed
    # THE WELD: tokens are NEVER written into the target file
    saved = tf.read_text(encoding="utf-8")
    assert "attacker-token" not in saved and "owner-token" not in saved
    assert "TARGET_ATTACKER_TOKEN" not in saved and "token" not in saved.lower()


def test_non_interactive_scan_tokens_route_per_account(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "LLM_API_KEY", SecretStr("test-key"))
    monkeypatch.setattr(settings, "AI_DEEP_VERIFY_ENABLED", False)
    monkeypatch.setattr(settings, "LLM_MODEL", "test-model")
    from backend.app.services.deep_verifier import OwnerCredential
    sp, ids = _spec_and_ids(tmp_path)
    tf = _target_file(tmp_path, sp)
    eng = _ScriptedEngine()
    code, out = _run(tf, ids, {"TARGET_ATTACKER_TOKEN": "atk-tok", "TARGET_OWNER_TOKEN": "own-tok",
                               "TARGET_BYSTANDER_TOKEN": "byst-tok"}, eng, tmp_path)
    assert code == 0 and eng.calls
    for kw in eng.calls:
        assert "atk-tok" in str(kw["auth_context"])                 # attacker -> auth_context ONLY
        assert "own-tok" not in str(kw["auth_context"])             # owner never in the attack path
        assert "byst-tok" not in str(kw["auth_context"])            # bystander never in the attack path
        bys = kw["bystander_credential"]
        assert isinstance(bys, OwnerCredential) and "byst-tok" in bys.header_value   # -> bystander_credential
        own = kw["owner_credential"]
        assert isinstance(own, OwnerCredential) and "own-tok" in own.header_value    # -> owner_credential
    assert "atk-tok" not in out and "byst-tok" not in out           # all masked, never echoed


# ------------------------------------------------------------------ collision fail-closed (from env)
def test_non_interactive_attacker_equals_owner_is_refused_engine_never_runs(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "LLM_API_KEY", SecretStr("test-key"))
    sp, ids = _spec_and_ids(tmp_path)
    tf = _target_file(tmp_path, sp)
    eng = _ScriptedEngine()
    code, out = _run(tf, ids, {"TARGET_ATTACKER_TOKEN": "same-tok",
                               "TARGET_OWNER_TOKEN": "same-tok"}, eng, tmp_path)
    assert code == 2                                     # refused, before any verdict
    assert eng.calls == []                               # the engine NEVER ran (no manufactured verdict)
    assert "SAME identity" in out and "NOT DATA" in out  # the fail-closed guard fired on env tokens


def test_non_interactive_missing_token_is_not_data(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "LLM_API_KEY", SecretStr("test-key"))
    sp, ids = _spec_and_ids(tmp_path)
    tf = _target_file(tmp_path, sp)
    eng = _ScriptedEngine()
    code, out = _run(tf, ids, {"TARGET_ATTACKER_TOKEN": "only-attacker"}, eng, tmp_path)
    assert code == 2 and eng.calls == []
    assert "TARGET_OWNER_TOKEN" in out and "NOT DATA" in out
