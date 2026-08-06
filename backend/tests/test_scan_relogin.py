# ==============================================================================
# scan v1, 2b — wire --auth (multi-step / OAuth re-login) into the scan LOOP. The loop reuses the
# EXISTING single-op relogin path (_verify_external_relogin) per candidate, with the per-account
# TokenProviders built ONCE and REUSED across candidates (option a). LOAD-BEARING: identity isolation
# across the whole scan — each account keeps its OWN provider/session; the owner token flows ONLY into
# owner_credential, never auth_context; a per-account refresh touches only that account. Zero network:
# the login HTTP and the engine are stubbed.
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
from backend.app.cli.relogin import LoginSpec, Credential, LoginError
from backend.app.cli.external_verify import _build_relogin_providers, _verify_external_relogin
from backend.app.cli.scan_run import run_scan
from backend.app.cli.console.controller import ConsoleController
from backend.app.cli.console.targets import Target
from backend.app.core.config import settings

_TARGET = "http://127.0.0.1:5000"
_LOGIN_SPEC = LoginSpec(method="POST", path="/users/v1/login", username_field="username",
                        password_field="password", token_field="auth_token")
_SPEC = {"openapi": "3.0.0", "paths": {
    "/api/reports/{report_id}": {"get": {}},
    "/api/users/{user_id}/profile": {"get": {}},
    "/api/orders/{order_id}": {"get": {}},
}}
_CANDS = [
    {"method": "GET", "path_template": "/api/reports/{report_id}", "id_location": "path", "id_param": "report_id"},
    {"method": "GET", "path_template": "/api/users/{user_id}/profile", "id_location": "path", "id_param": "user_id"},
    {"method": "GET", "path_template": "/api/orders/{order_id}", "id_location": "path", "id_param": "order_id"},
]
_ID_MAP = {"/api/reports/{report_id}": {"attacker_id": "1", "victim_id": "2"},
           "/api/users/{user_id}/profile": {"attacker_id": "5", "victim_id": "6"}}   # orders -> no id -> SKIP
_ATK = Credential("attackeruser", SecretStr("apw"))
_OWN = Credential("victimowner", SecretStr("opw"))


def _fake_login(status=200, token_field="auth_token"):
    """A single-request login http_post that records calls and mints TOK.<user>.<n> (non-JWT -> cached
    by TokenProvider, so a reuse across candidates does NOT re-login)."""
    calls = []

    async def fake(method, url, body):
        calls.append({"method": method, "url": url, "body": dict(body)})
        if not (200 <= status < 300):
            return status, {"message": "denied"}
        return 200, {token_field: f"TOK.{body.get('username', '?')}.{len(calls)}"}

    fake.calls = calls
    return fake


def _result(**over):
    base = dict(status="completed", ai_verdict="failed", ai_verdict_raw="failed", guard_override=None,
                degraded_reason=None, caller_identity_anchor=None, payload_causality_anchor=None,
                state_jump_anchor=None, negative_assertion_anchor=None, anchoring_result=None,
                pre_flight_status=None, owner_view_corroborated=None, owner_view_status=None,
                owner_view_body=None, follow_up_response=None, follow_up_request=None,
                baseline={"response": {"status_code": 200}}, attack={"response": {"status_code": 200}})
    base.update(over)
    return types.SimpleNamespace(**base)


class _CapEngine:
    """Records every call's kwargs; returns a scripted sequence of results (default: failed)."""
    def __init__(self, script=None):
        self.calls = []
        self._script = list(script or [])

    async def __call__(self, **kw):
        self.calls.append(kw)
        if self._script:
            return self._script[min(len(self.calls) - 1, len(self._script) - 1)]
        return _result(ai_verdict="failed")


def _relogin_run_op(providers, eng, bystander_cred=None):
    async def run_op(op):
        return await _verify_external_relogin(
            _TARGET, _SPEC, op, _LOGIN_SPEC, _ATK, _OWN, None, eng,
            bystander_cred=bystander_cred, providers=providers)
    return run_op


def _stub_provider(candidates):
    async def gen():
        class _R:
            text = json.dumps({"candidates": candidates})
        return _R()
    return as_provider(gen)


def _prompts(*vals):
    it = iter(vals)
    return lambda *_a: next(it, "")


# ------------------------------------------------------------------ isolation + provider reuse (LOAD-BEARING)
def test_relogin_scan_reuses_providers_once_and_isolates_accounts():
    fake = _fake_login()
    eng = _CapEngine()
    providers = _build_relogin_providers(_TARGET, _LOGIN_SPEC, _ATK, _OWN, None, http_post=fake)
    res = asyncio.run(run_scan(_TARGET, _SPEC, run_op=_relogin_run_op(providers, eng),
                               id_map=_ID_MAP, raw_candidates=_CANDS))
    ran = [r for r in res["records"] if not r.get("scan_skipped")]
    assert len(ran) == 2 and len(res["skipped"]) == 1                    # reports+users ran; orders skipped
    # OPTION (a): each account logged in ONCE and was REUSED across BOTH candidates (no re-login).
    atk_logins = [c for c in fake.calls if c["body"].get("username") == "attackeruser"]
    own_logins = [c for c in fake.calls if c["body"].get("username") == "victimowner"]
    assert len(atk_logins) == 1 and len(own_logins) == 1
    assert len(eng.calls) == 2                                           # both candidates reached the engine
    # ISOLATION: per candidate, the owner token is in owner_credential ONLY — never the attack path.
    for kw in eng.calls:
        auth = str(kw["auth_context"])
        oc = kw["owner_credential"]
        assert "attackeruser" in auth and "victimowner" not in auth
        assert "victimowner" in oc.header_value and "attackeruser" not in oc.header_value
    # separate providers -> distinct tokens (a shared provider would collide attacker==owner -> refused)
    assert eng.calls[0]["auth_context"] != {"Authorization": eng.calls[0]["owner_credential"].header_value}


def test_relogin_scan_isolation_sensitive_to_a_shared_provider():
    # NEGATIVE CONTROL: if the SAME provider served attacker AND owner (a bleed), the two would obtain
    # the SAME token -> the identity-collision guard fires -> ValueError, the engine NEVER runs.
    fake = _fake_login()
    scope_atk, _, _ = _build_relogin_providers(_TARGET, _LOGIN_SPEC, _ATK, _OWN, None, http_post=fake)
    shared = (scope_atk, scope_atk, None)               # attacker and owner FORCED to share one provider
    eng = _CapEngine()
    res = asyncio.run(run_scan(_TARGET, _SPEC, run_op=_relogin_run_op(shared, eng),
                               id_map=_ID_MAP, raw_candidates=_CANDS))
    assert eng.calls == []                              # collision -> every candidate failed pre-verdict
    # each candidate became NOT DATA (the run_op raised the collision ValueError), scan continued
    notdata = [r for r in res["records"] if r.get("degraded") and not r.get("scan_skipped")]
    assert len(notdata) == 2


# ------------------------------------------------------------------ per-account refresh on 401
def test_relogin_scan_attacker_401_refreshes_attacker_and_completes():
    fake = _fake_login()
    eng = _CapEngine(script=[
        _result(ai_verdict=None, attack={"response": {"status_code": 401}}),  # candidate: attacker token expired
        _result(ai_verdict="verified"),                                        # after refresh -> completes
    ])
    providers = _build_relogin_providers(_TARGET, _LOGIN_SPEC, _ATK, _OWN, None, http_post=fake)
    # ONE candidate (only reports has an id here) so we isolate the refresh accounting.
    res = asyncio.run(run_scan(_TARGET, _SPEC, run_op=_relogin_run_op(providers, eng),
                               id_map={"/api/reports/{report_id}": {"attacker_id": "1", "victim_id": "2"}},
                               raw_candidates=_CANDS[:1]))
    ran = [r for r in res["records"] if not r.get("scan_skipped")]
    assert len(ran) == 1 and ran[0]["final_verdict"] == "verified"        # candidate COMPLETED, not NOT DATA
    # attacker-side 401 -> BOTH attacker and owner refreshed (existing behavior): 2 logins each
    assert len([c for c in fake.calls if c["body"].get("username") == "attackeruser"]) == 2
    assert len([c for c in fake.calls if c["body"].get("username") == "victimowner"]) == 2


def test_relogin_scan_owner_view_401_refreshes_owner_only():
    fake = _fake_login()
    eng = _CapEngine(script=[
        _result(ai_verdict="verified", owner_view_corroborated=False, owner_view_status=401),  # owner tok expired
        _result(ai_verdict="verified", owner_view_corroborated=True, owner_view_status=200),    # after owner refresh
    ])
    providers = _build_relogin_providers(_TARGET, _LOGIN_SPEC, _ATK, _OWN, None, http_post=fake)
    asyncio.run(run_scan(_TARGET, _SPEC, run_op=_relogin_run_op(providers, eng),
                         id_map={"/api/reports/{report_id}": {"attacker_id": "1", "victim_id": "2"}},
                         raw_candidates=_CANDS[:1]))
    # D28: ONLY the owner refreshed (owner logs in twice); the attacker provider is UNTOUCHED (once).
    assert len([c for c in fake.calls if c["body"].get("username") == "victimowner"]) == 2
    assert len([c for c in fake.calls if c["body"].get("username") == "attackeruser"]) == 1


# ------------------------------------------------------------------ direction-safety: per-candidate failure
def test_relogin_scan_candidate_failure_is_notdata_and_scan_continues():
    calls = {"n": 0}

    async def run_op(op):
        calls["n"] += 1
        if calls["n"] == 1:
            raise LoginError("re-login failed for this candidate")   # e.g. a mid-scan refresh failure
        return _result(ai_verdict="failed")

    res = asyncio.run(run_scan(_TARGET, _SPEC, run_op=run_op, id_map=_ID_MAP, raw_candidates=_CANDS))
    # candidate 1 -> NOT DATA (safe miss), candidate 2 -> ran (refuted); orders skipped
    notdata = [r for r in res["records"] if r.get("degraded") and not r.get("scan_skipped")]
    ran_ok = [r for r in res["records"] if not r.get("degraded") and not r.get("scan_skipped")]
    assert len(notdata) == 1 and len(ran_ok) == 1                    # one failed candidate, scan CONTINUED


# ------------------------------------------------------------------ do_scan --auth end-to-end (offline)
class _ScriptedEngine:
    def __init__(self):
        self.calls = []

    async def __call__(self, **kw):
        self.calls.append(kw)
        path = kw["parsed_request"]["path"]
        if "reports" in path:
            return _result(ai_verdict="verified", owner_view_corroborated=True)
        return _result(ai_verdict="failed")


def test_do_scan_auth_end_to_end_uses_relogin_and_reuses_providers(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "LLM_API_KEY", SecretStr("test-key"))
    monkeypatch.setattr(settings, "AI_DEEP_VERIFY_ENABLED", False)
    monkeypatch.setattr(settings, "LLM_MODEL", "test-model")
    from backend.app.cli import relogin
    fake = _fake_login()
    monkeypatch.setattr(relogin, "_default_http_post", fake)          # do_scan's providers use the fake login

    cfg = tmp_path / "config.toml"
    cfg.write_text('TARGET_ATTACKER_USERNAME = "atkuser"\nTARGET_ATTACKER_PASSWORD = "apw"\n'
                   'TARGET_OWNER_USERNAME = "ownuser"\nTARGET_OWNER_PASSWORD = "opw"\n', encoding="utf-8")
    spec_path = tmp_path / "spec.json"
    spec_path.write_text(json.dumps(_SPEC), encoding="utf-8")
    ids_path = tmp_path / "ids.json"
    ids_path.write_text(json.dumps({"ids": _ID_MAP}), encoding="utf-8")
    login_path = tmp_path / "login.json"
    login_path.write_text(json.dumps({"method": "POST", "path": "/users/v1/login",
                                      "username_field": "username", "password_field": "password",
                                      "token_field": "auth_token"}), encoding="utf-8")
    sel = Target(name="scan-t", base_url=_TARGET, spec_path=str(spec_path), method="GET",
                 path_template="/api/reports/{report_id}", id_location="path", id_param="report_id",
                 attacker_id="1", victim_id="2")

    eng = _ScriptedEngine()
    lines = []
    ctl = ConsoleController(
        prompt=_prompts(str(ids_path), str(login_path), "n"),          # id-source, login file, assert=n
        secret_prompt=_prompts(),                                      # creds from config -> no prompt
        echo=lambda *a: lines.append(" ".join(str(x) for x in a)),
        config_path=str(cfg), engine=eng, scan_provider_factory=_stub_provider(_CANDS))
    ctl.selected = sel
    ctl.do_scan()
    out = "\n".join(lines)
    assert "auto-relogin" in out and "scan report:" in out and "[CONFIRMED]" in out
    assert len(eng.calls) == 2                                         # reports + users ran; orders skipped
    # relogin drove it, per-account, and providers were REUSED (login ONCE per account across candidates)
    assert len([c for c in fake.calls if c["body"].get("username") == "atkuser"]) == 1
    assert len([c for c in fake.calls if c["body"].get("username") == "ownuser"]) == 1
    assert "TOK.atkuser" not in out and "TOK.ownuser" not in out      # obtained tokens never printed
