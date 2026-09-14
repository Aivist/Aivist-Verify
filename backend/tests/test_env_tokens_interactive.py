# ==============================================================================
# Bug B (real-path) — the INTERACTIVE do_verify / do_scan token collection must read owner AND
# bystander from the environment (like attacker), not force a manual paste. The earlier test exercised
# _resolve_tokens in ISOLATION and missed the interactive path; these drive the real do_verify / do_scan
# token collection with all three env vars set and assert ZERO paste prompts.
# RED LINE unchanged: masked (never printed), per-account routed, attacker!=owner guard intact.
# ==============================================================================
import os
import sys
import json

from pydantic import SecretStr

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, _REPO_ROOT)

from backend.app.core.config import settings
from backend.app.cli.console.controller import ConsoleController
from backend.app.cli.console import targets as tmod
from backend.tests.test_scan_run import _result


def _async_engine():
    async def eng(**kw):
        eng.calls.append(kw)
        return _result(ai_verdict="failed")
    eng.calls = []
    return eng


def _record_pastes():
    pastes = []
    return pastes, (lambda label: (pastes.append(str(label)), "PASTED")[1])


def _set_all_env(monkeypatch):
    monkeypatch.setattr(settings, "LLM_API_KEY", SecretStr("test-key"))
    monkeypatch.setattr(settings, "AI_DEEP_VERIFY_ENABLED", False)
    monkeypatch.setattr(settings, "LLM_MODEL", "test-model")
    monkeypatch.setenv("TARGET_ATTACKER_TOKEN", "ATK-ENV")
    monkeypatch.setenv("TARGET_OWNER_TOKEN", "OWN-ENV")
    monkeypatch.setenv("TARGET_BYSTANDER_TOKEN", "BYST-ENV")


_ROLE_KEYS = (("attacker", "TARGET_ATTACKER_TOKEN"), ("owner", "TARGET_OWNER_TOKEN"),
              ("bystander", "TARGET_BYSTANDER_TOKEN"))


def test_interactive_verify_reads_all_three_tokens_from_env(tmp_path, monkeypatch):
    _set_all_env(monkeypatch)
    pastes, secret = _record_pastes()
    lines = []
    it = iter(["", ""])   # assert-owner? blank, account-labels? blank
    c = ConsoleController(prompt=lambda *a: next(it, ""), secret_prompt=secret,
                          echo=lambda *a: lines.append(" ".join(str(x) for x in a)),
                          config_path=str(tmp_path / "c.toml"), engine=_async_engine())
    # spec-less target: exercises the real interactive verify (incl. the Bug-C spec synth)
    c.selected = tmod.Target(name="vampi", base_url="http://localhost:5000", spec_path="", method="GET",
                             path_template="/books/v1/{book_title}", id_location="path",
                             id_param="book_title", attacker_id="alicebook", victim_id="bobbook")
    c.do_verify()
    out = "\n".join(lines)
    for role, key in _ROLE_KEYS:
        assert f"Using {role} token from environment ({key}, masked)." in out
    assert pastes == []                                          # no manual paste for ANY of the three
    assert "ATK-ENV" not in out and "OWN-ENV" not in out and "BYST-ENV" not in out   # masked


def test_interactive_scan_reads_all_three_tokens_from_env(tmp_path, monkeypatch):
    _set_all_env(monkeypatch)
    spec = {"openapi": "3.0.0", "paths": {"/books/v1/{book_title}": {"get": {"operationId": "b"}}}}
    spec_path = tmp_path / "spec.json"
    spec_path.write_text(json.dumps(spec), encoding="utf-8")
    sel = tmod.Target(name="vampi", base_url="http://localhost:5000", spec_path=str(spec_path),
                      method="GET", path_template="/books/v1/{book_title}", id_location="path",
                      id_param="book_title", attacker_id="alicebook", victim_id="bobbook")

    class _NoProv:
        default_model = "m"
        def is_configured(self): return True
        async def generate(self, **kw): return '{"candidates": []}'

    pastes, secret = _record_pastes()
    lines = []
    it = iter(["", "", "", ""])   # id-hints, login, assert, review->run
    c = ConsoleController(prompt=lambda *a: next(it, ""), secret_prompt=secret,
                          echo=lambda *a: lines.append(" ".join(str(x) for x in a)),
                          config_path=str(tmp_path / "c.toml"),
                          engine=_async_engine(), scan_provider_factory=lambda: _NoProv())
    c.selected = sel
    c.do_scan()
    out = "\n".join(lines)
    for role, key in _ROLE_KEYS:
        assert f"Using {role} token from environment ({key}, masked)." in out
    assert pastes == []                                          # scan too: no paste for any of the three
