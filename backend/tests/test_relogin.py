# ==============================================================================
# Offline tests for auto re-login / token refresh (backend/app/cli/relogin.py + the
# --auth path in external_verify.py). Zero API, no network: login HTTP is an injected
# fake; the engine is an injected fake. Proves the THREE RED LINES (identity isolation,
# credential+token secrecy, scope fail-closed on login), the login-failure -> NOT DATA
# degradation, and the relogin-on-401 mechanic.
# ==============================================================================
import os
import sys
import json
import time
import types
import base64

import pytest
from pydantic import SecretStr

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, _REPO_ROOT)

from backend.app.cli.external_verify import (
    run_external_verify, _verify_external_relogin, _auth_degraded,
)
from backend.app.cli.relogin import (
    LoginSpec, Credential, TokenProvider, resolve_login_credentials, LoginError, _jwt_exp,
)
from backend.app.services.deep_verifier import OwnerCredential
from backend.app.services.scope import ScopePolicy
from backend.app.core.config import settings


# ------------------------------------------------------------------ helpers
def _jwt(exp=None, tag="x"):
    """A minimal unsigned JWT-shaped token (header.payload.sig); payload carries exp + a tag."""
    def b64(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    payload = {"tag": tag}
    if exp is not None:
        payload["exp"] = exp
    return f"{b64({'alg': 'none'})}.{b64(payload)}.sig"


_LOGIN_SPEC = LoginSpec(method="POST", path="/users/v1/login",
                        username_field="username", password_field="password", token_field="auth_token")
_TARGET = "http://127.0.0.1:5000"
_SCOPE = ScopePolicy.from_declaration(["127.0.0.1:5000"])
_SPEC = {"openapi": "3.0.0", "paths": {"/books/v1/{t}": {"get": {"operationId": "g"}}}}
_OP = {"method": "GET", "baseline_path": "/books/v1/alicebook", "body": None,
       "payload": {"location": "path_segment", "target_param": "alicebook",
                   "payload_string": "bobbook", "type": "BOLA"}, "shape": "read_semantic"}


def _fake_post_factory(*, status=200, token_field="auth_token", make_token=None):
    """An async http_post that records calls and returns a token identifying the account.
    Default token `TOK.<username>.<call#>` is identifiable AND distinct per login."""
    calls = []

    async def fake(method, url, body):
        calls.append({"method": method, "url": url, "body": dict(body)})
        if not (200 <= status < 300):
            return status, {"message": "denied"}
        user = body.get("username", "?")
        n = len(calls)
        tok = make_token(user, n) if make_token else f"TOK.{user}.{n}"
        return 200, {token_field: tok}

    fake.calls = calls
    return fake


class _FakeEngine:
    def __init__(self, results):
        self._results = results
        self.calls = []

    async def __call__(self, **kw):
        self.calls.append(kw)
        return self._results[min(len(self.calls) - 1, len(self._results) - 1)]


def _result(**over):
    base = dict(status="completed", ai_verdict="failed", ai_verdict_raw="failed",
                guard_override=None, degraded_reason=None,
                caller_identity_anchor=None, payload_causality_anchor=None, state_jump_anchor=None,
                negative_assertion_anchor=None, anchoring_result=None, pre_flight_status=None,
                owner_view_corroborated=None, follow_up_response=None,
                baseline={"response": {"status_code": 200}}, attack={"response": {"status_code": 200}})
    base.update(over)
    return types.SimpleNamespace(**base)


def _write_cfg(tmp_path, pw="pw"):
    cfg = tmp_path / "config.toml"
    cfg.write_text(
        f'TARGET_ATTACKER_USERNAME = "atkuser"\nTARGET_ATTACKER_PASSWORD = "{pw}"\n'
        f'TARGET_OWNER_USERNAME = "ownuser"\nTARGET_OWNER_PASSWORD = "{pw}"\n', encoding="utf-8")
    return str(cfg)


def _write_files(tmp_path):
    login = tmp_path / "login.json"
    login.write_text(json.dumps({"method": "POST", "path": "/users/v1/login",
                                 "username_field": "username", "password_field": "password",
                                 "token_field": "auth_token"}), encoding="utf-8")
    spec = tmp_path / "spec.json"
    spec.write_text(json.dumps(_SPEC), encoding="utf-8")
    op = tmp_path / "op.json"
    op.write_text(json.dumps(_OP), encoding="utf-8")
    return str(login), str(spec), str(op)


# ------------------------------------------------------------------ LoginSpec / JWT
def test_login_spec_from_file(tmp_path):
    p = tmp_path / "login.json"
    p.write_text(json.dumps({"path": "/users/v1/login", "username_field": "username",
                             "password_field": "password", "token_field": "auth_token"}), encoding="utf-8")
    spec = LoginSpec.from_file(str(p))
    assert spec.method == "POST" and spec.token_field == "auth_token"
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"path": "/x"}), encoding="utf-8")
    with pytest.raises(ValueError):
        LoginSpec.from_file(str(bad))


def test_jwt_exp_reads_exp_without_verifying():
    assert _jwt_exp(_jwt(exp=12345)) == 12345.0
    assert _jwt_exp("not-a-jwt") is None
    assert _jwt_exp(_jwt(exp=None)) is None


# ------------------------------------------------------------------ RED LINE 3: scope fail-closed on login
def test_login_endpoint_out_of_scope_is_refused():
    fake = _fake_post_factory()
    spec = LoginSpec("POST", "http://evil.example.com/login", "username", "password", "auth_token")
    prov = TokenProvider(Credential("u", SecretStr("p")), spec, _TARGET, _SCOPE, http_post=fake)
    with pytest.raises(LoginError):
        __import__("asyncio").run(prov.token())
    assert fake.calls == []                       # scope refused BEFORE any request left


def test_login_to_in_scope_target_is_allowed():
    fake = _fake_post_factory()
    prov = TokenProvider(Credential("u", SecretStr("p")), _LOGIN_SPEC, _TARGET, _SCOPE, http_post=fake)
    tok = __import__("asyncio").run(prov.token())
    assert tok.startswith("TOK.u.")
    assert fake.calls[0]["url"] == "http://127.0.0.1:5000/users/v1/login"


# ------------------------------------------------------------------ login failure / refresh mechanics
def test_login_failure_bad_creds_raises_login_error():
    fake = _fake_post_factory(status=401)
    prov = TokenProvider(Credential("u", SecretStr("p")), _LOGIN_SPEC, _TARGET, _SCOPE, http_post=fake)
    with pytest.raises(LoginError):
        __import__("asyncio").run(prov.token())


def test_login_no_token_field_raises():
    async def fake(m, u, b):
        return 200, {"message": "ok but no token"}
    prov = TokenProvider(Credential("u", SecretStr("p")), _LOGIN_SPEC, _TARGET, _SCOPE, http_post=fake)
    with pytest.raises(LoginError):
        __import__("asyncio").run(prov.token())


def test_token_provider_reuses_fresh_token():
    fake = _fake_post_factory(make_token=lambda u, n: _jwt(exp=time.time() + 3600, tag=f"{u}{n}"))
    prov = TokenProvider(Credential("u", SecretStr("p")), _LOGIN_SPEC, _TARGET, _SCOPE, http_post=fake)
    import asyncio
    t1 = asyncio.run(prov.token())
    t2 = asyncio.run(prov.token())
    assert t1 == t2 and len(fake.calls) == 1      # fresh JWT reused; only one login


def test_token_provider_refreshes_when_near_expiry():
    fake = _fake_post_factory(make_token=lambda u, n: _jwt(exp=time.time() - 5, tag=f"{u}{n}"))
    prov = TokenProvider(Credential("u", SecretStr("p")), _LOGIN_SPEC, _TARGET, _SCOPE,
                         http_post=fake, refresh_margin=10)
    import asyncio
    t1 = asyncio.run(prov.token())
    t2 = asyncio.run(prov.token())
    assert len(fake.calls) == 2 and t1 != t2      # expired -> proactively re-logged in


# ------------------------------------------------------------------ RED LINE 1: identity isolation
def test_owner_token_never_in_attack_headers_incl_after_refresh():
    import asyncio
    fake = _fake_post_factory()                   # token = TOK.<username>.<n>, carries the username
    eng = _FakeEngine([
        _result(ai_verdict=None, attack={"response": {"status_code": 401}}),  # 1st: forces relogin
        _result(ai_verdict="verified"),                                       # 2nd: success
    ])
    atk = Credential("attackeruser", SecretStr("apw"))
    own = Credential("victimowner", SecretStr("opw"))
    result = asyncio.run(_verify_external_relogin(
        _TARGET, _SPEC, _OP, _LOGIN_SPEC, atk, own, None, eng, http_post=fake))
    assert len(eng.calls) == 2                     # retried once after the 401
    for kw in eng.calls:                           # holds on BOTH the initial and the refreshed tokens
        auth = str(kw["auth_context"])
        assert "attackeruser" in auth              # attacker token IS in the attack headers
        assert "victimowner" not in auth           # owner token is NEVER in the attack headers
        oc = kw["owner_credential"]
        assert isinstance(oc, OwnerCredential)
        assert "victimowner" in oc.header_value    # owner token flows ONLY through owner_credential
        assert "attackeruser" not in oc.header_value


def test_relogin_retries_engine_on_401_then_succeeds():
    import asyncio
    fake = _fake_post_factory()
    eng = _FakeEngine([
        _result(ai_verdict=None, attack={"response": {"status_code": 401}}),  # expired -> 401
        _result(ai_verdict="verified"),                                       # fresh token -> success
    ])
    result = asyncio.run(_verify_external_relogin(
        _TARGET, _SPEC, _OP, _LOGIN_SPEC,
        Credential("atk", SecretStr("p")), Credential("own", SecretStr("p")), None, eng, http_post=fake))
    assert len(eng.calls) == 2                     # retried exactly once
    assert result.ai_verdict == "verified"         # succeeded after re-login
    assert str(eng.calls[0]["auth_context"]) != str(eng.calls[1]["auth_context"])  # token refreshed
    assert len(fake.calls) == 4                     # 2 initial logins + 2 refresh logins


# ------------------------------------------------------------------ RED LINE 2: credentials + tokens secret
def test_credentials_are_secretstr(tmp_path):
    cfg = _write_cfg(tmp_path, pw="apw-secret-canary")
    atk, own = resolve_login_credentials(cfg)
    assert isinstance(atk.password, SecretStr) and isinstance(own.password, SecretStr)
    assert "apw-secret-canary" not in repr(atk)    # dataclass repr shows SecretStr(**), not the value
    assert "apw-secret-canary" not in str(own)


def test_password_and_token_never_in_output(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "LLM_API_KEY", SecretStr("test-key"))
    monkeypatch.setattr(settings, "AI_DEEP_VERIFY_ENABLED", False)
    PW = "CANARY-PASSWORD-DO-NOT-LEAK"
    cfg = _write_cfg(tmp_path, pw=PW)
    login, spec, op = _write_files(tmp_path)
    fake = _fake_post_factory()                    # tokens: TOK.atkuser.1 / TOK.ownuser.2
    eng = _FakeEngine([_result(ai_verdict="failed")])
    lines = []
    code = run_external_verify(
        target=_TARGET, spec_path=spec, op_path=op, config_path=cfg, auth_spec_path=login,
        http_post=fake, engine=eng,
        echo=lambda *a: lines.append(" ".join(str(x) for x in a)),
        err=lambda *a: lines.append(" ".join(str(x) for x in a)))
    out = "\n".join(lines)
    assert PW not in out                           # the password never appears in output
    assert "TOK.atkuser" not in out                # nor does the obtained attacker token
    assert "TOK.ownuser" not in out                # nor the owner token
    # and the password DID reach the login body (so login worked), just never the screen
    assert any(c["body"].get("password") == PW for c in fake.calls)


# ------------------------------------------------------------------ degradation: login failure -> NOT DATA
def test_login_failure_degrades_to_notdata(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "LLM_API_KEY", SecretStr("test-key"))
    monkeypatch.setattr(settings, "AI_DEEP_VERIFY_ENABLED", False)
    cfg = _write_cfg(tmp_path)
    login, spec, op = _write_files(tmp_path)
    bad_login = _fake_post_factory(status=401)     # login itself 401s (bad creds / changed endpoint)

    async def _no_engine(**kw):
        raise AssertionError("engine must not run when login fails")

    lines = []
    code = run_external_verify(
        target=_TARGET, spec_path=spec, op_path=op, config_path=cfg, auth_spec_path=login,
        http_post=bad_login, engine=_no_engine,
        echo=lambda *a: lines.append(" ".join(str(x) for x in a)),
        err=lambda *a: lines.append(" ".join(str(x) for x in a)))
    out = "\n".join(lines)
    assert code == 2 and "[NOT DATA]" in out       # graceful, never "target safe"
    assert "HTTP 401" in out                        # the honest reason surfaces (no password)
