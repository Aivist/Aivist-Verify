# ==============================================================================
# scan v1, commit 3 — the loop + aggregated report + the CLI command. The scan loops the EXISTING
# confirm on each vetted op and groups results by tier ([CONFIRMED]/[SIGNAL]/[broken-for-all]/
# [REFUTED]/[NOT DATA]/[SKIPPED]). Zero network/API: the provider is stubbed, the engine is a fake,
# and tier-a ids avoid any harvest. Proves: a valid op runs the engine; a skip/failed-fence op does
# NOT; the report groups correctly; and the CLI `scan` command drives it end-to-end.
# ==============================================================================
import os
import sys
import json
import types
import asyncio

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, _REPO_ROOT)

from pydantic import SecretStr

from backend.tests._llmstub import as_provider
from backend.app.cli.scan_run import run_scan
from backend.app.cli.scan_report import render_scan_report
from backend.app.cli.console.controller import ConsoleController
from backend.app.core.config import settings

_SPEC = {"openapi": "3.0.0", "paths": {
    "/api/reports/{report_id}": {"get": {"operationId": "getReport"}},
    "/api/users/{user_id}/profile": {"get": {"operationId": "getProfile"}},
    "/api/orders/{order_id}": {"get": {"operationId": "getOrder"}},
}}

_CANDS = [
    {"method": "GET", "path_template": "/api/reports/{report_id}", "id_location": "path", "id_param": "report_id"},
    {"method": "GET", "path_template": "/api/users/{user_id}/profile", "id_location": "path", "id_param": "user_id"},
    {"method": "GET", "path_template": "/api/orders/{order_id}", "id_location": "path", "id_param": "order_id"},
    {"method": "GET", "path_template": "/api/not-in-catalog/{id}", "id_location": "path", "id_param": "id"},
]

# tier-a ids for two of the three catalog candidates; the third has NO id -> SKIP.
_ID_MAP = {
    "/api/reports/{report_id}": {"attacker_id": "1", "victim_id": "2"},
    "/api/users/{user_id}/profile": {"attacker_id": "5", "victim_id": "6"},
}


def _stub_provider(candidates):
    async def gen():
        class _R:
            text = json.dumps({"candidates": candidates})
        return _R()
    return as_provider(gen)


def _result(**over):
    base = dict(status="completed", ai_verdict="failed", ai_verdict_raw="failed",
                guard_override=None, degraded_reason=None, caller_identity_anchor=None,
                payload_causality_anchor=None, state_jump_anchor=None, negative_assertion_anchor=None,
                anchoring_result=None, pre_flight_status=None, owner_view_corroborated=None,
                owner_view_status=None, owner_view_body=None, follow_up_response=None,
                follow_up_request=None, baseline={"response": {"status_code": 200}},
                attack={"response": {"status_code": 200}})
    base.update(over)
    return types.SimpleNamespace(**base)


class _ScriptedEngine:
    """A fake engine: verdict chosen per attack path so the report exercises multiple tiers."""
    def __init__(self):
        self.calls = []

    async def __call__(self, **kw):
        self.calls.append(kw)
        path = kw["parsed_request"]["path"]
        if "reports" in path:
            return _result(ai_verdict="verified", owner_view_corroborated=True)   # CONFIRMED
        return _result(ai_verdict="failed")                                       # REFUTED


# ------------------------------------------------------------------ loop + report
def test_run_scan_loops_confirm_and_groups_by_tier():
    eng = _ScriptedEngine()

    async def run_op(op):
        return await eng(parsed_request={"method": op["method"], "path": op["baseline_path"].split("?")[0],
                                         "query_params": {}, "headers": {}, "body": None},
                         payload=op.get("payload"), base_url="http://t", approved_host="t",
                         auth_context={}, available_endpoints=[], owner_credential=None)

    res = asyncio.run(run_scan("http://t", _SPEC, run_op=run_op, id_map=_ID_MAP,
                               raw_candidates=_CANDS))
    # 4 raw -> 3 accepted (the not-in-catalog one dropped by the candidate fence)
    assert len(res["accepted"]) == 3 and len(res["dropped"]) == 1
    # 2 had ids (reports, users) -> ran the engine; orders had no id -> SKIPPED (engine NOT called)
    assert len(eng.calls) == 2
    assert len(res["skipped"]) == 1 and res["skipped"][0]["path_template"] == "/api/orders/{order_id}"

    report = render_scan_report(res, "http://t", color=False)
    assert "[CONFIRMED]" in report                       # reports -> verified + owner-view
    assert "[REFUTED]" in report                         # users -> failed
    assert "[SKIPPED - needs manual id]" in report
    assert "/api/orders/{order_id}" in report            # the skipped candidate is named
    assert "1 confirmed (code-gated)" in report
    assert "1 skipped" in report and "1 invalid candidate(s) dropped" in report


def test_run_scan_never_calls_engine_on_skip_or_failed_fence():
    eng = _ScriptedEngine()

    async def run_op(op):
        return await eng(parsed_request={"method": op["method"], "path": op["baseline_path"], "query_params": {},
                                         "headers": {}, "body": None}, payload=None, base_url="http://t",
                         approved_host="t", auth_context={}, available_endpoints=[], owner_credential=None)

    # NO id map, NO collections -> every accepted candidate is SKIPPED -> engine NEVER called.
    res = asyncio.run(run_scan("http://t", _SPEC, run_op=run_op, raw_candidates=_CANDS))
    assert eng.calls == []                               # not one fabricated-id run
    assert len(res["skipped"]) == 3


def test_run_scan_assert_owner_only_applies_to_generated_ops():
    seen = []

    async def run_op(op):
        seen.append(dict(op))
        return _result(ai_verdict="failed")

    # default OFF -> no op carries the flag (byte-identical)
    asyncio.run(run_scan("http://t", _SPEC, run_op=run_op, id_map=_ID_MAP, raw_candidates=_CANDS))
    assert seen and all("assert_owner_only" not in op for op in seen)

    seen.clear()
    asyncio.run(run_scan("http://t", _SPEC, run_op=run_op, id_map=_ID_MAP, raw_candidates=_CANDS,
                         assert_owner_only=True))
    assert seen and all(op.get("assert_owner_only") is True for op in seen)   # every generated op carries it


# ------------------------------------------------------------------ CLI command (end-to-end, offline)
def _prompts(*vals):
    it = iter(vals)
    return lambda *_a: next(it, "")


def test_do_scan_cli_end_to_end(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "LLM_API_KEY", SecretStr("test-key"))
    monkeypatch.setattr(settings, "AI_DEEP_VERIFY_ENABLED", False)
    monkeypatch.setattr(settings, "LLM_MODEL", "test-model")

    spec_path = tmp_path / "spec.json"
    spec_path.write_text(json.dumps(_SPEC), encoding="utf-8")
    ids_path = tmp_path / "ids.json"
    ids_path.write_text(json.dumps({"ids": _ID_MAP}), encoding="utf-8")

    from backend.app.cli.console import targets as targets_mod
    sel = targets_mod.Target(name="scan-t", base_url="http://localhost:8888", spec_path=str(spec_path),
                             method="GET", path_template="/api/reports/{report_id}", id_location="path",
                             id_param="report_id", attacker_id="1", victim_id="2")

    eng = _ScriptedEngine()
    lines = []
    ctl = ConsoleController(
        prompt=_prompts(str(ids_path)),                 # the id-source file prompt
        secret_prompt=_prompts("attacker-token", "owner-token"),
        echo=lambda *a: lines.append(" ".join(str(x) for x in a)),
        config_path=str(tmp_path / "no-config.toml"),
        engine=eng, scan_provider_factory=_stub_provider(_CANDS))
    ctl.selected = sel
    ctl.do_scan()
    out = "\n".join(lines)
    assert "scan report:" in out
    assert "[CONFIRMED]" in out and "[SKIPPED - needs manual id]" in out
    assert "attacker-token" not in out and "owner-token" not in out   # tokens never printed
    assert len(eng.calls) == 2                           # reports + users ran; orders skipped


def test_do_scan_bystander_and_assert_route(tmp_path, monkeypatch):
    # 2a: the scan CLI wires a masked bystander token (-> bystander_credential ONLY) and a run-level
    # assert_owner_only (-> every generated op).
    monkeypatch.setattr(settings, "LLM_API_KEY", SecretStr("test-key"))
    monkeypatch.setattr(settings, "AI_DEEP_VERIFY_ENABLED", False)
    monkeypatch.setattr(settings, "LLM_MODEL", "test-model")
    from backend.app.cli.console import targets as targets_mod
    from backend.app.services.deep_verifier import OwnerCredential

    spec_path = tmp_path / "spec.json"
    spec_path.write_text(json.dumps(_SPEC), encoding="utf-8")
    ids_path = tmp_path / "ids.json"
    ids_path.write_text(json.dumps({"ids": _ID_MAP}), encoding="utf-8")
    sel = targets_mod.Target(name="scan-t", base_url="http://localhost:8888", spec_path=str(spec_path),
                             method="GET", path_template="/api/reports/{report_id}", id_location="path",
                             id_param="report_id", attacker_id="1", victim_id="2")

    eng = _ScriptedEngine()
    lines = []
    ctl = ConsoleController(
        prompt=_prompts(str(ids_path), "", "y"),              # id-source file, login-file (blank), assert=yes
        secret_prompt=_prompts("atk-tok", "own-tok", "byst-tok"),   # attacker, owner, bystander
        echo=lambda *a: lines.append(" ".join(str(x) for x in a)),
        config_path=str(tmp_path / "no-config.toml"),
        engine=eng, scan_provider_factory=_stub_provider(_CANDS))
    ctl.selected = sel
    ctl.do_scan()
    assert len(eng.calls) == 2
    for kw in eng.calls:
        assert kw["assert_owner_only"] is True                          # run-level broken-for-all opt-in
        bys = kw["bystander_credential"]
        assert isinstance(bys, OwnerCredential) and "byst-tok" in bys.header_value
        assert "byst-tok" not in str(kw["auth_context"])                # bystander NEVER in the attack path
    out = "\n".join(lines)
    assert "byst-tok" not in out and "atk-tok" not in out               # tokens masked, never echoed
