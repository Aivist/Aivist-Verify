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
    LoginResponse, _extract_token, _as_login_response, OAuthConfig,
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
_LOGIN_SPEC_HEADER = LoginSpec(method="POST", path="/users/v1/login",
                               username_field="username", password_field="password",
                               token_field="Authorization", token_location="header")
_LOGIN_SPEC_COOKIE = LoginSpec(method="POST", path="/users/v1/login",
                               username_field="username", password_field="password",
                               token_field="session", token_location="cookie")
_TARGET = "http://127.0.0.1:5000"
_SCOPE = ScopePolicy.from_declaration(["127.0.0.1:5000"])
_SPEC = {"openapi": "3.0.0", "paths": {"/books/v1/{t}": {"get": {"operationId": "g"}}}}
_OP = {"method": "GET", "baseline_path": "/books/v1/alicebook", "body": None,
       "payload": {"location": "path_segment", "target_param": "alicebook",
                   "payload_string": "bobbook", "type": "BOLA"}, "shape": "read_semantic"}


def _fake_post_factory(*, status=200, token_field="auth_token", make_token=None,
                       location="body", name=None):
    """An async http_post that records calls and returns a token identifying the account.
    Default token `TOK.<username>.<call#>` is identifiable AND distinct per login.

    `location` places that token where the extractor must read it from: "body" (default; a
    legacy (status, json) 2-tuple — proving the byte-identical back-compat path), "header"
    (a LoginResponse header named `name`/Authorization) or "cookie" (a LoginResponse cookie
    named `name`/session — WITH a Set-Cookie header carrying it too, to prove even that
    echo never leaks)."""
    calls = []

    async def fake(method, url, body):
        calls.append({"method": method, "url": url, "body": dict(body)})
        if not (200 <= status < 300):
            return status, {"message": "denied"}
        user = body.get("username", "?")
        n = len(calls)
        tok = make_token(user, n) if make_token else f"TOK.{user}.{n}"
        if location == "header":
            return LoginResponse(200, {}, {name or "Authorization": tok}, {})
        if location == "cookie":
            cname = name or "session"
            return LoginResponse(200, {}, {"set-cookie": f"{cname}={tok}; Path=/"}, {cname: tok})
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


# ==============================================================================
# Slice 2b — token extraction by LOCATION (header / cookie), beyond the body field.
# The four invariants (isolation, secrecy, scope fail-closed, degradation honesty) must
# hold for the NEW modes too; the body-field path must stay byte-identical (regression).
# ==============================================================================
def _write_login(tmp_path, extra):
    """Write a login.json declaring `extra` (e.g. a token_location/token_field), plus the
    reusable spec/op, and return (login, spec, op) paths. Mirrors _write_files."""
    login = tmp_path / "login.json"
    d = {"method": "POST", "path": "/users/v1/login",
         "username_field": "username", "password_field": "password"}
    d.update(extra)
    login.write_text(json.dumps(d), encoding="utf-8")
    spec = tmp_path / "spec.json"
    spec.write_text(json.dumps(_SPEC), encoding="utf-8")
    op = tmp_path / "op.json"
    op.write_text(json.dumps(_OP), encoding="utf-8")
    return str(login), str(spec), str(op)


# --------------------------------------------- declaration surface + pure extraction
def test_login_spec_token_location_parsing(tmp_path):
    base = {"path": "/login", "username_field": "u", "password_field": "p", "token_field": "t"}

    def _w(d):
        p = tmp_path / "l.json"
        p.write_text(json.dumps(d), encoding="utf-8")
        return str(p)

    assert LoginSpec.from_file(_w(base)).token_location == "body"               # default
    assert LoginSpec.from_file(_w({**base, "token_location": "header"})).token_location == "header"
    assert LoginSpec.from_file(_w({**base, "token_location": "COOKIE"})).token_location == "cookie"  # case-folded
    with pytest.raises(ValueError):                                             # unknown location rejected
        LoginSpec.from_file(_w({**base, "token_location": "querystring"}))


def test_extract_token_from_header():
    # header value taken as-is (Bearer prefix preserved for the downstream builders)
    assert _extract_token(_LOGIN_SPEC_HEADER,
                          LoginResponse(200, {}, {"Authorization": "Bearer HDR"}, {})) == "Bearer HDR"
    # header NAME lookup is case-insensitive
    assert _extract_token(_LOGIN_SPEC_HEADER,
                          LoginResponse(200, {}, {"authorization": "Bearer HDR"}, {})) == "Bearer HDR"


def test_extract_token_from_cookie():
    resp = LoginResponse(200, {}, {"set-cookie": "session=CKTOK; Path=/"}, {"session": "CKTOK"})
    assert _extract_token(_LOGIN_SPEC_COOKIE, resp) == "CKTOK"


def test_body_extraction_regression_byte_identical():
    # a body-field spec, whether fed a LoginResponse or the legacy 2-tuple, yields the exact
    # JSON field value unchanged from slice 1 (the same downstream feed).
    assert _extract_token(_LOGIN_SPEC, LoginResponse(200, {"auth_token": "BODYTOK"}, {}, {})) == "BODYTOK"
    assert _extract_token(_LOGIN_SPEC, _as_login_response((200, {"auth_token": "BODYTOK"}))) == "BODYTOK"


# --------------------------------------------- INVARIANT 1: identity isolation (new modes)
def _assert_isolation(login_spec, fake):
    """Run the relogin flow (which forces one 401 -> refresh) and assert the owner token —
    however extracted — never appears in an attack header, only in owner_credential."""
    import asyncio
    eng = _FakeEngine([
        _result(ai_verdict=None, attack={"response": {"status_code": 401}}),   # forces a relogin
        _result(ai_verdict="verified"),
    ])
    atk = Credential("attackeruser", SecretStr("apw"))
    own = Credential("victimowner", SecretStr("opw"))
    asyncio.run(_verify_external_relogin(
        _TARGET, _SPEC, _OP, login_spec, atk, own, None, eng, http_post=fake))
    assert len(eng.calls) == 2                      # retried once after the 401
    for kw in eng.calls:                            # holds on the initial AND the refreshed token
        auth = str(kw["auth_context"])
        assert "attackeruser" in auth               # attacker token IS in the attack headers
        assert "victimowner" not in auth            # owner token is NEVER in the attack headers
        oc = kw["owner_credential"]
        assert isinstance(oc, OwnerCredential)
        assert "victimowner" in oc.header_value     # owner token flows ONLY via owner_credential
        assert "attackeruser" not in oc.header_value


def test_owner_token_never_in_attack_headers_header_mode():
    _assert_isolation(_LOGIN_SPEC_HEADER, _fake_post_factory(location="header"))


def test_owner_token_never_in_attack_headers_cookie_mode():
    _assert_isolation(_LOGIN_SPEC_COOKIE, _fake_post_factory(location="cookie"))


# --------------------------------------------- INVARIANT 2: secrecy (canaries, new modes)
def test_header_token_never_in_output(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "LLM_API_KEY", SecretStr("test-key"))
    monkeypatch.setattr(settings, "AI_DEEP_VERIFY_ENABLED", False)
    cfg = _write_cfg(tmp_path)
    login, spec, op = _write_login(tmp_path, {"token_field": "Authorization", "token_location": "header"})
    fake = _fake_post_factory(location="header", name="Authorization")   # tokens TOK.<user>.<n>
    eng = _FakeEngine([_result(ai_verdict="failed")])
    lines = []
    run_external_verify(
        target=_TARGET, spec_path=spec, op_path=op, config_path=cfg, auth_spec_path=login,
        http_post=fake, engine=eng,
        echo=lambda *a: lines.append(" ".join(str(x) for x in a)),
        err=lambda *a: lines.append(" ".join(str(x) for x in a)))
    out = "\n".join(lines)
    assert "TOK.atkuser" not in out and "TOK.ownuser" not in out   # header-sourced tokens never printed


def test_cookie_token_never_in_output_incl_setcookie(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "LLM_API_KEY", SecretStr("test-key"))
    monkeypatch.setattr(settings, "AI_DEEP_VERIFY_ENABLED", False)
    cfg = _write_cfg(tmp_path)
    login, spec, op = _write_login(tmp_path, {"token_field": "session", "token_location": "cookie"})
    fake = _fake_post_factory(location="cookie", name="session")     # Set-Cookie carries TOK.<user>.<n>
    eng = _FakeEngine([_result(ai_verdict="failed")])
    lines = []
    run_external_verify(
        target=_TARGET, spec_path=spec, op_path=op, config_path=cfg, auth_spec_path=login,
        http_post=fake, engine=eng,
        echo=lambda *a: lines.append(" ".join(str(x) for x in a)),
        err=lambda *a: lines.append(" ".join(str(x) for x in a)))
    out = "\n".join(lines)
    assert "TOK.atkuser" not in out and "TOK.ownuser" not in out   # cookie-sourced tokens never printed
    assert "set-cookie" not in out.lower()                          # nor is the raw Set-Cookie echoed


# --------------------------------------------- INVARIANT 4: degradation honesty (new modes)
def test_login_header_missing_degrades_to_notdata(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "LLM_API_KEY", SecretStr("test-key"))
    monkeypatch.setattr(settings, "AI_DEEP_VERIFY_ENABLED", False)
    cfg = _write_cfg(tmp_path)
    login, spec, op = _write_login(tmp_path, {"token_field": "Authorization", "token_location": "header"})

    async def no_header(m, u, b):
        return LoginResponse(200, {}, {}, {})       # 200, but the declared header is absent

    async def _no_engine(**kw):
        raise AssertionError("engine must not run when the token is missing")

    lines = []
    code = run_external_verify(
        target=_TARGET, spec_path=spec, op_path=op, config_path=cfg, auth_spec_path=login,
        http_post=no_header, engine=_no_engine,
        echo=lambda *a: lines.append(" ".join(str(x) for x in a)),
        err=lambda *a: lines.append(" ".join(str(x) for x in a)))
    out = "\n".join(lines)
    assert code == 2 and "[NOT DATA]" in out        # graceful, never "target safe"
    assert "Authorization" in out                   # honest reason names the missing header (no secret)


def test_login_cookie_missing_degrades_to_notdata(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "LLM_API_KEY", SecretStr("test-key"))
    monkeypatch.setattr(settings, "AI_DEEP_VERIFY_ENABLED", False)
    cfg = _write_cfg(tmp_path)
    login, spec, op = _write_login(tmp_path, {"token_field": "session", "token_location": "cookie"})

    async def no_cookie(m, u, b):
        return LoginResponse(200, {}, {}, {})       # 200, but the declared cookie is absent

    async def _no_engine(**kw):
        raise AssertionError("engine must not run when the token is missing")

    lines = []
    code = run_external_verify(
        target=_TARGET, spec_path=spec, op_path=op, config_path=cfg, auth_spec_path=login,
        http_post=no_cookie, engine=_no_engine,
        echo=lambda *a: lines.append(" ".join(str(x) for x in a)),
        err=lambda *a: lines.append(" ".join(str(x) for x in a)))
    out = "\n".join(lines)
    assert code == 2 and "[NOT DATA]" in out        # graceful, never "target safe"
    assert "session" in out                         # honest reason names the missing cookie (no secret)


# ==============================================================================
# Slice 2c — multi-step / CSRF login: an ordered pre-login sequence run within ONE per-account
# session (one client; a cookie set in a step carries to the login). The four invariants hold for
# the sequence too; IDENTITY ISOLATION is the load-bearing check (a shared client -> false positive).
# ==============================================================================
import asyncio as _asyncio
import httpx as _httpx
from backend.app.cli.relogin import (
    LoginStep, Extract, Inject, _HttpxLoginSession,
)


class _MSSession:
    """Fake per-account login session. Mimics an httpx cookie jar (Set-Cookie carries WITHIN this
    session only) and records every request. A GET step yields a CSRF (in body/header/cookie/HTML)
    and sets a per-session SESSIONID; a POST login REQUIRES the injected CSRF to match AND the
    session cookie to have carried, then returns a username-identifying token."""
    _seq = 0

    def __init__(self):
        type(self)._seq += 1
        self.sid = type(self)._seq
        self.jar = {}                 # THIS session's own cookie jar — never shared across accounts
        self.requests = []
        self.closed = False

    async def request(self, method, url, *, json_body=None, headers=None):
        sent = dict(self.jar)
        rec = {"method": method, "url": url, "headers": dict(headers or {}),
               "sent_cookies": sent, "body": dict(json_body or {})}
        self.requests.append(rec)
        csrf, sess = f"CSRF{self.sid}", f"SESS{self.sid}"
        if method == "GET":                                   # a pre-login step
            self.jar["SESSIONID"] = sess                      # mimic Set-Cookie -> this session's jar
            return LoginResponse(200, {"csrf_token": csrf}, {"X-Csrf": csrf},
                                 {"SESSIONID": sess, "csrftoken": csrf},
                                 text='<form><input name="csrf" value="' + csrf + '"></form>')
        injected = rec["headers"].get("X-CSRF-Token") or rec["body"].get("csrf")
        if injected != csrf:
            return LoginResponse(403, {"error": "bad or missing csrf"}, {}, {})
        if sent.get("SESSIONID") != sess:
            return LoginResponse(403, {"error": "session cookie did not carry"}, {}, {})
        user = rec["body"].get("username", "?")
        return LoginResponse(200, {"auth_token": "TOK." + user + "." + str(self.sid)}, {}, {})

    async def aclose(self):
        self.closed = True


def _ms_factory():
    created = []

    def factory(scope):
        s = _MSSession()
        created.append(s)
        return s

    factory.created = created
    return factory


def _ms_spec(extract_location="body", extract_field="csrf_token", inject_in="header"):
    """GET /login (extract csrf) then POST /login (inject csrf)."""
    inject = (Inject(headers={"X-CSRF-Token": "csrf"}) if inject_in == "header"
              else Inject(body={"csrf": "csrf"}))
    return LoginSpec(method="POST", path="/users/v1/login",
                     username_field="username", password_field="password", token_field="auth_token",
                     steps=(LoginStep(method="GET", path="/users/v1/login",
                                      extract=Extract("csrf", extract_location, extract_field)),),
                     inject=inject)


def test_multistep_body_extract_header_inject_obtains_token():
    factory = _ms_factory()
    prov = TokenProvider(Credential("alice", SecretStr("pw")), _ms_spec(), _TARGET, _SCOPE,
                         session_factory=factory)
    tok = _asyncio.run(prov.token())
    s = factory.created[0]
    assert tok == "TOK.alice." + str(s.sid)
    assert [r["method"] for r in s.requests] == ["GET", "POST"]          # pre-GET then login POST
    assert s.requests[1]["headers"]["X-CSRF-Token"] == "CSRF" + str(s.sid)      # captured csrf injected
    assert s.requests[1]["sent_cookies"]["SESSIONID"] == "SESS" + str(s.sid)    # cookie carried GET->login
    assert s.closed                                                     # session cleaned up


@pytest.mark.parametrize("loc,field", [("body", "csrf_token"), ("header", "X-Csrf"),
                                       ("cookie", "csrftoken"), ("regex", r'value="(CSRF\d+)"')])
def test_multistep_extract_from_each_location(loc, field):
    factory = _ms_factory()
    prov = TokenProvider(Credential("bob", SecretStr("pw")),
                         _ms_spec(extract_location=loc, extract_field=field), _TARGET, _SCOPE,
                         session_factory=factory)
    tok = _asyncio.run(prov.token())
    assert tok == "TOK.bob." + str(factory.created[0].sid)              # every location yields the CSRF


def test_multistep_body_inject_puts_captured_value_in_login_body():
    factory = _ms_factory()
    prov = TokenProvider(Credential("carol", SecretStr("pw")),
                         _ms_spec(inject_in="body"), _TARGET, _SCOPE, session_factory=factory)
    tok = _asyncio.run(prov.token())
    s = factory.created[0]
    assert tok == "TOK.carol." + str(s.sid)
    assert s.requests[1]["body"]["csrf"] == "CSRF" + str(s.sid)         # captured csrf injected into body


# --------------------------------------------- LOAD-BEARING: identity isolation (multi-step)
def test_isolation_multistep_owner_token_reads_as_owner_not_attacker():
    factory = _ms_factory()
    eng = _FakeEngine([
        _result(ai_verdict=None, attack={"response": {"status_code": 401}}),   # forces a relogin
        _result(ai_verdict="verified"),
    ])
    atk = Credential("attackeruser", SecretStr("apw"))
    own = Credential("victimowner", SecretStr("opw"))
    _asyncio.run(_verify_external_relogin(
        _TARGET, _SPEC, _OP, _ms_spec(), atk, own, None, eng, session_factory=factory))
    assert len(eng.calls) == 2
    # a MULTI-STEP owner token flows ONLY through owner_credential; never into the attack headers
    for kw in eng.calls:
        auth = str(kw["auth_context"])
        assert "attackeruser" in auth and "victimowner" not in auth
        oc = kw["owner_credential"]
        assert isinstance(oc, OwnerCredential)
        assert "victimowner" in oc.header_value and "attackeruser" not in oc.header_value
    # STRUCTURAL: every session object served EXACTLY ONE account (a shared client would serve both)
    for s in factory.created:
        users = {r["body"].get("username") for r in s.requests if r["method"] == "POST"}
        assert len(users) == 1
    # owner sessions carry NONE of the attacker sessions' cookies (zero cross-account state bleed)
    atk_sess = [s for s in factory.created
                if any(r["body"].get("username") == "attackeruser" for r in s.requests)]
    own_sess = [s for s in factory.created
                if any(r["body"].get("username") == "victimowner" for r in s.requests)]
    atk_cookie_vals = {c for s in atk_sess for r in s.requests for c in r["sent_cookies"].values()}
    for s in own_sess:
        for r in s.requests:
            assert not (set(r["sent_cookies"].values()) & atk_cookie_vals)


def test_isolation_assertion_is_sensitive_to_a_shared_client():
    # NEGATIVE CONTROL: a factory handing out ONE shared session across accounts -> that session
    # serves BOTH usernames, which the isolation assertion above forbids. Proves the test would FAIL
    # if a single client were shared across accounts (the poison-the-verdict red line).
    shared = _MSSession()

    def shared_factory(scope):
        return shared

    atk = TokenProvider(Credential("attackeruser", SecretStr("p")), _ms_spec(), _TARGET, _SCOPE,
                        session_factory=shared_factory)
    own = TokenProvider(Credential("victimowner", SecretStr("p")), _ms_spec(), _TARGET, _SCOPE,
                        session_factory=shared_factory)
    _asyncio.run(atk.token())
    _asyncio.run(own.token())
    users = {r["body"].get("username") for r in shared.requests if r["method"] == "POST"}
    assert users == {"attackeruser", "victimowner"}                     # one session, two accounts -> detectable


# --------------------------------------------- back-compat: no steps == slice 1 (byte-identical)
def test_no_steps_spec_uses_http_post_not_the_session():
    def _boom_factory(scope):
        raise AssertionError("the multi-step session must NOT be used for a no-steps spec")

    fake = _fake_post_factory()
    prov = TokenProvider(Credential("u", SecretStr("p")), _LOGIN_SPEC, _TARGET, _SCOPE,
                         http_post=fake, session_factory=_boom_factory)
    tok = _asyncio.run(prov.token())
    assert tok.startswith("TOK.u.") and len(fake.calls) == 1           # single POST via http_post; no session


# --------------------------------------------- direction-safe: broken sequence -> LoginError -> NOT DATA
def test_multistep_missing_extract_field_is_login_error():
    factory = _ms_factory()
    spec = _ms_spec(extract_location="body", extract_field="nonexistent_field")
    prov = TokenProvider(Credential("u", SecretStr("p")), spec, _TARGET, _SCOPE, session_factory=factory)
    with pytest.raises(LoginError):
        _asyncio.run(prov.token())


def test_multistep_inject_undefined_capture_is_login_error():
    factory = _ms_factory()
    spec = LoginSpec(method="POST", path="/users/v1/login", username_field="username",
                     password_field="password", token_field="auth_token",
                     steps=(LoginStep("GET", "/users/v1/login",
                                      extract=Extract("csrf", "body", "csrf_token")),),
                     inject=Inject(headers={"X-CSRF-Token": "does_not_exist"}))
    prov = TokenProvider(Credential("u", SecretStr("p")), spec, _TARGET, _SCOPE, session_factory=factory)
    with pytest.raises(LoginError):
        _asyncio.run(prov.token())


def test_multistep_login_error_degrades_to_notdata_via_cli(tmp_path, monkeypatch):
    # end-to-end: a multi-step login.json whose step extract cannot resolve -> LoginError -> NOT DATA
    # (code 2), never a verdict. Uses the default-session seam with a stub that omits the csrf field.
    monkeypatch.setattr(settings, "LLM_API_KEY", SecretStr("test-key"))
    monkeypatch.setattr(settings, "AI_DEEP_VERIFY_ENABLED", False)
    cfg = _write_cfg(tmp_path)
    login = tmp_path / "login.json"
    login.write_text(json.dumps({"method": "POST", "path": "/users/v1/login",
                                 "username_field": "username", "password_field": "password",
                                 "token_field": "auth_token",
                                 "steps": [{"method": "GET", "path": "/users/v1/login",
                                            "extract": {"name": "csrf", "location": "body",
                                                        "field": "nope"}}],
                                 "inject": {"headers": {"X-CSRF-Token": "csrf"}}}), encoding="utf-8")
    spec = tmp_path / "spec.json"
    spec.write_text(json.dumps(_SPEC), encoding="utf-8")
    op = tmp_path / "op.json"
    op.write_text(json.dumps(_OP), encoding="utf-8")

    async def _no_engine(**kw):
        raise AssertionError("engine must not run when the login sequence fails")

    from backend.app.cli import relogin as _relogin

    class _StubSession:
        async def request(self, method, url, *, json_body=None, headers=None):
            return LoginResponse(200, {"something_else": 1}, {}, {})   # 200 but no 'nope' field

        async def aclose(self):
            pass

    monkeypatch.setattr(_relogin, "_default_session_factory", lambda scope: _StubSession())
    lines = []
    code = run_external_verify(
        target=_TARGET, spec_path=str(spec), op_path=str(op), config_path=cfg, auth_spec_path=str(login),
        engine=_no_engine,
        echo=lambda *a: lines.append(" ".join(str(x) for x in a)),
        err=lambda *a: lines.append(" ".join(str(x) for x in a)))
    out = "\n".join(lines)
    assert code == 2 and "[NOT DATA]" in out                          # graceful, never "target safe"


# --------------------------------------------- SCOPE red line: login/step client is NOT exempt
def test_multistep_absolute_out_of_scope_step_refused_before_any_request():
    factory = _ms_factory()
    spec = LoginSpec(method="POST", path="/users/v1/login", username_field="username",
                     password_field="password", token_field="auth_token",
                     steps=(LoginStep("GET", "http://evil.example.com/csrf",
                                      extract=Extract("csrf", "body", "csrf_token")),))
    prov = TokenProvider(Credential("u", SecretStr("p")), spec, _TARGET, _SCOPE, session_factory=factory)
    with pytest.raises(LoginError):
        _asyncio.run(prov.token())
    assert factory.created[0].requests == []                          # refused BEFORE any bytes left


def test_multistep_step_redirect_out_of_scope_is_refused():
    # a pre-login step that 302s to an out-of-scope host -> refused per-hop by the REAL
    # _HttpxLoginSession reusing the engine's _follow_redirects_scoped; fail-closed to LoginError.
    def handler(request):
        return _httpx.Response(302, headers={"location": "http://evil.example.com/next"})

    def redirecting_factory(scope):
        client = _httpx.AsyncClient(transport=_httpx.MockTransport(handler), follow_redirects=False)
        return _HttpxLoginSession(scope, client=client)

    spec = LoginSpec(method="POST", path="/users/v1/login", username_field="username",
                     password_field="password", token_field="auth_token",
                     steps=(LoginStep("GET", "/csrf", extract=Extract("csrf", "body", "csrf_token")),))
    prov = TokenProvider(Credential("u", SecretStr("p")), spec, _TARGET, _SCOPE,
                         session_factory=redirecting_factory)
    with pytest.raises(LoginError):
        _asyncio.run(prov.token())


def test_multistep_login_redirect_out_of_scope_is_refused():
    # the FINAL login request (not just a step) is equally non-exempt: a 302 out of origin -> refused.
    def handler(request):
        return _httpx.Response(302, headers={"location": "https://evil.example.com/landing"})

    def redirecting_factory(scope):
        client = _httpx.AsyncClient(transport=_httpx.MockTransport(handler), follow_redirects=False)
        return _HttpxLoginSession(scope, client=client)

    spec = LoginSpec(method="POST", path="/users/v1/login", username_field="username",
                     password_field="password", token_field="auth_token", inject=Inject())
    prov = TokenProvider(Credential("u", SecretStr("p")), spec, _TARGET, _SCOPE,
                         session_factory=redirecting_factory)
    with pytest.raises(LoginError):
        _asyncio.run(prov.token())


# ==============================================================================
# #7 FP NAIL (re-login mode): attacker and owner must be DISTINCT accounts. Same username = same
# account -> the D24 owner-view corroborates self-vs-self -> a false [CONFIRMED]. Refuse fail-closed:
#   * pre-login, on identical USERNAMES (before any login leaves), and
#   * post-login, on identical obtained TOKENS (two usernames aliasing to one identity).
# In every case the engine must NEVER run — a test that would FAIL if a verdict were produced.
# ==============================================================================
def test_7_fp_nail_same_username_refused_before_any_login(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "LLM_API_KEY", SecretStr("test-key"))
    monkeypatch.setattr(settings, "AI_DEEP_VERIFY_ENABLED", False)
    cfg = tmp_path / "config.toml"
    cfg.write_text('TARGET_ATTACKER_USERNAME = "same"\nTARGET_ATTACKER_PASSWORD = "p1"\n'
                   'TARGET_OWNER_USERNAME = "same"\nTARGET_OWNER_PASSWORD = "p2"\n', encoding="utf-8")
    login, spec, op = _write_files(tmp_path)
    fake = _fake_post_factory()

    class _CountingVerifiedEngine:
        def __init__(self):
            self.calls = 0

        async def __call__(self, **kw):
            self.calls += 1
            return _result(ai_verdict="verified")     # would CONFIRM if the guard were removed

    eng = _CountingVerifiedEngine()
    lines = []
    code = run_external_verify(
        target=_TARGET, spec_path=spec, op_path=op, config_path=str(cfg), auth_spec_path=login,
        http_post=fake, engine=eng,
        echo=lambda *a: lines.append(" ".join(str(x) for x in a)),
        err=lambda *a: lines.append(" ".join(str(x) for x in a)))
    out = "\n".join(lines)
    assert code == 2 and eng.calls == 0               # refused; engine NEVER ran (no verdict)
    assert "SAME identity" in out
    assert len(fake.calls) == 0                        # refused BEFORE any login left (pre-login check)


def test_7_fp_nail_identical_tokens_refused_post_login():
    # Two DIFFERENT usernames whose logins return the SAME token -> caught on the OBTAINED tokens ->
    # refused, engine NEVER called (the pre-login username check can't see this; the token check does).
    async def fake(m, u, b):
        return 200, {"auth_token": "SAME-TOKEN-FOR-BOTH"}

    eng = _FakeEngine([_result(ai_verdict="verified")])
    atk = Credential("attackeruser", SecretStr("apw"))
    own = Credential("victimowner", SecretStr("opw"))
    with pytest.raises(ValueError):
        _asyncio.run(_verify_external_relogin(
            _TARGET, _SPEC, _OP, _LOGIN_SPEC, atk, own, None, eng, http_post=fake))
    assert eng.calls == []                             # engine NEVER ran on a token collision


# ==============================================================================
# D28 — mid-run OWNER-token refresh. An owner-view 401 (owner token expired mid-run) triggers a
# refresh of ONLY the owner provider + one engine retry. Attacker/bystander providers are UNTOUCHED,
# and the fresh owner token flows ONLY into owner_credential (never auth_context/the attack path).
# ==============================================================================
def _d28_results():
    return [
        _result(ai_verdict="verified", owner_view_corroborated=False, owner_view_status=401),  # owner tok expired mid-run
        _result(ai_verdict="verified", owner_view_corroborated=True, owner_view_status=200),    # after owner refresh
    ]


def test_d28_owner_view_401_refreshes_only_owner_and_retries_once():
    fake = _fake_post_factory()                        # tokens TOK.<user>.<n> (non-JWT -> no proactive refresh)
    eng = _FakeEngine(_d28_results())
    atk = Credential("attackeruser", SecretStr("apw"))
    own = Credential("victimowner", SecretStr("opw"))
    result = _asyncio.run(_verify_external_relogin(
        _TARGET, _SPEC, _OP, _LOGIN_SPEC, atk, own, None, eng, http_post=fake))
    assert len(eng.calls) == 2                          # engine re-run EXACTLY once (owner-view 401)
    atk_logins = [c for c in fake.calls if c["body"].get("username") == "attackeruser"]
    own_logins = [c for c in fake.calls if c["body"].get("username") == "victimowner"]
    assert len(own_logins) == 2                         # ONLY the owner provider refreshed
    assert len(atk_logins) == 1                         # attacker provider UNTOUCHED
    assert result.owner_view_corroborated is True       # retry completed with the fresh owner token


def test_d28_isolation_fresh_owner_token_only_in_owner_credential_never_auth_context():
    # LOAD-BEARING: after a mid-run owner refresh, the fresh owner token is present in owner_credential
    # and ABSENT from auth_context; the attacker's session/token is untouched. A test that would FAIL
    # if a refresh mixed the attacker's session into the owner path (or the owner token into the attack).
    fake = _fake_post_factory()
    eng = _FakeEngine(_d28_results())
    atk = Credential("attackeruser", SecretStr("apw"))
    own = Credential("victimowner", SecretStr("opw"))
    _asyncio.run(_verify_external_relogin(
        _TARGET, _SPEC, _OP, _LOGIN_SPEC, atk, own, None, eng, http_post=fake))
    call0, call1 = eng.calls[0], eng.calls[1]
    # attacker auth_context UNCHANGED across the retry (attacker provider never refreshed)
    assert str(call0["auth_context"]) == str(call1["auth_context"])
    assert "attackeruser" in str(call1["auth_context"])
    # owner credential WAS refreshed (a different token on the retry)
    fresh_owner_val = call1["owner_credential"].header_value
    assert fresh_owner_val != call0["owner_credential"].header_value
    # the fresh owner token lives ONLY in owner_credential — never in the attack headers (no bleed)
    assert "victimowner" in fresh_owner_val
    assert fresh_owner_val not in str(call1["auth_context"])
    assert "victimowner" not in str(call1["auth_context"])


def test_d28_owner_view_401_does_not_touch_bystander_or_attacker_providers():
    fake = _fake_post_factory()
    eng = _FakeEngine(_d28_results())
    atk = Credential("attackeruser", SecretStr("apw"))
    own = Credential("victimowner", SecretStr("opw"))
    bys = Credential("bystanderuser", SecretStr("bpw"))
    _asyncio.run(_verify_external_relogin(
        _TARGET, _SPEC, _OP, _LOGIN_SPEC, atk, own, None, eng, http_post=fake, bystander_cred=bys))
    own_logins = [c for c in fake.calls if c["body"].get("username") == "victimowner"]
    atk_logins = [c for c in fake.calls if c["body"].get("username") == "attackeruser"]
    bys_logins = [c for c in fake.calls if c["body"].get("username") == "bystanderuser"]
    assert len(own_logins) == 2                         # ONLY the owner refreshed
    assert len(atk_logins) == 1 and len(bys_logins) == 1   # attacker + bystander providers UNTOUCHED


def test_d28_owner_refresh_login_failure_is_login_error_never_a_second_verdict():
    # If the owner's REFRESH login itself fails -> LoginError propagates (the CLI turns this into
    # NOT DATA). It can only turn a safe-miss into a completion OR stay NOT DATA — never a verdict.
    calls = []

    async def fake(method, url, body):
        calls.append(dict(body))
        user = body.get("username")
        n_user = sum(1 for c in calls if c.get("username") == user)
        if user == "victimowner" and n_user >= 2:      # the owner's REFRESH login fails
            return 401, {"message": "owner re-login denied"}
        return 200, {"auth_token": f"TOK.{user}.{len(calls)}"}

    eng = _FakeEngine([_result(ai_verdict="verified", owner_view_corroborated=False, owner_view_status=401)])
    atk = Credential("attackeruser", SecretStr("apw"))
    own = Credential("victimowner", SecretStr("opw"))
    with pytest.raises(LoginError):
        _asyncio.run(_verify_external_relogin(
            _TARGET, _SPEC, _OP, _LOGIN_SPEC, atk, own, None, eng, http_post=fake))
    assert len(eng.calls) == 1                          # engine ran once; refresh failed -> NO 2nd verdict


def test_d28_owner_refresh_failure_renders_notdata_via_cli(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "LLM_API_KEY", SecretStr("test-key"))
    monkeypatch.setattr(settings, "AI_DEEP_VERIFY_ENABLED", False)
    cfg = _write_cfg(tmp_path)                          # atkuser / ownuser (distinct)
    login, spec, op = _write_files(tmp_path)
    calls = []

    async def fake(method, url, body):
        calls.append(dict(body))
        user = body.get("username")
        n_user = sum(1 for c in calls if c.get("username") == user)
        if user == "ownuser" and n_user >= 2:          # owner refresh login fails
            return 401, {"message": "denied"}
        return 200, {"auth_token": f"TOK.{user}.{len(calls)}"}

    eng = _FakeEngine([_result(ai_verdict="verified", owner_view_corroborated=False, owner_view_status=401)])
    lines = []
    code = run_external_verify(
        target=_TARGET, spec_path=spec, op_path=op, config_path=cfg, auth_spec_path=login,
        http_post=fake, engine=eng,
        echo=lambda *a: lines.append(" ".join(str(x) for x in a)),
        err=lambda *a: lines.append(" ".join(str(x) for x in a)))
    out = "\n".join(lines)
    assert code == 2 and "[NOT DATA]" in out           # graceful; never "target safe", never a verdict


def test_d28_no_owner_view_status_is_not_degraded_byte_identical():
    # A result that never ran the owner-view gate (owner_view_status absent) must NOT trigger a refresh:
    # exactly one engine call, no owner refresh. Proves D28 detection is inert on the common path.
    fake = _fake_post_factory()
    eng = _FakeEngine([_result(ai_verdict="failed")])   # base _result has no owner_view_status
    atk = Credential("attackeruser", SecretStr("apw"))
    own = Credential("victimowner", SecretStr("opw"))
    _asyncio.run(_verify_external_relogin(
        _TARGET, _SPEC, _OP, _LOGIN_SPEC, atk, own, None, eng, http_post=fake))
    assert len(eng.calls) == 1                          # no retry
    own_logins = [c for c in fake.calls if c["body"].get("username") == "victimowner"]
    assert len(own_logins) == 1                          # owner NOT refreshed


# ==============================================================================
# Slice 3 — OAuth 2.0 login (authorization_code + PKCE, and resource-owner-password). The obtained
# access token flows into the SAME three-variable routing as every other login; the verdict core is
# untouched. The four invariants hold: SCOPE fail-closed per hop, IDENTITY ISOLATION (own session per
# account, zero shared client/PKCE/code/token), secrecy, and direction-safety (broken -> NOT DATA).
# ==============================================================================
class _FakeOAuthSession:
    """Fake per-account OAuth session. Mimics an IdP: `request` = the account login (records the
    username), `oauth_get_no_follow` = the authorize endpoint (302 -> redirect_uri?code=CODE.<user>.<sid>),
    `oauth_post_form` = the token endpoint (records code_verifier/code, returns TOK.<user>.<sid>). Its
    own state (sid/username/verifier) is LOCAL — never shared across accounts."""
    _seq = 0

    def __init__(self, expires_in=3600):
        type(self)._seq += 1
        self.sid = type(self)._seq
        self.expires_in = expires_in
        self.requests = []
        self.username = None
        self.verifier = None
        self.closed = False

    async def request(self, method, url, *, json_body=None, headers=None):
        self.username = (json_body or {}).get("username", self.username)
        self.requests.append({"kind": "login", "url": url, "body": dict(json_body or {})})
        return LoginResponse(200, {"ok": True}, {}, {})       # login established the session

    async def oauth_get_no_follow(self, url, headers=None):
        self.requests.append({"kind": "authorize", "url": url})
        code = f"CODE.{self.username}.{self.sid}"              # a code identifying THIS session
        return LoginResponse(302, {}, {"location": f"http://app.local/callback?code={code}&state=s"}, {})

    async def oauth_post_form(self, url, data, headers=None):
        self.verifier = data.get("code_verifier")
        self.requests.append({"kind": "token", "url": url, "data": dict(data)})
        user = data.get("username") or self.username          # password grant carries username in the body
        return LoginResponse(200, {"access_token": f"TOK.{user}.{self.sid}",
                                   "expires_in": self.expires_in}, {}, {})

    async def aclose(self):
        self.closed = True


def _oauth_factory(expires_in=3600):
    created = []

    def factory(scope):
        s = _FakeOAuthSession(expires_in=expires_in)
        created.append(s)
        return s

    factory.created = created
    return factory


def _oauth_authcode_spec():
    return LoginSpec(
        method="POST", path="/account/login", username_field="username", password_field="password",
        token_field="access_token", grant="authorization_code",
        oauth=OAuthConfig(grant="authorization_code", token_url="/oauth/token", client_id="cid",
                          authorize_url="/oauth/authorize", redirect_uri="http://app.local/callback",
                          pkce=True))


def _oauth_password_spec():
    return LoginSpec(
        method="POST", path="", username_field="username", password_field="password",
        token_field="access_token", grant="password",
        oauth=OAuthConfig(grant="password", token_url="/oauth/token", client_id="cid",
                          client_secret=SecretStr("csecret"), scope="read"))


# --------------------------------------------- happy paths (fake IdP session)
def test_oauth_authcode_pkce_obtains_code_then_token():
    factory = _oauth_factory()
    prov = TokenProvider(Credential("alice", SecretStr("pw")), _oauth_authcode_spec(), _TARGET, _SCOPE,
                         session_factory=factory)
    tok = _asyncio.run(prov.token())
    s = factory.created[0]
    assert tok == f"TOK.alice.{s.sid}"
    assert [r["kind"] for r in s.requests] == ["login", "authorize", "token"]   # login -> authorize -> token
    authorize_url = [r["url"] for r in s.requests if r["kind"] == "authorize"][0]
    assert "code_challenge=" in authorize_url and "code_challenge_method=S256" in authorize_url  # PKCE S256
    token_data = [r["data"] for r in s.requests if r["kind"] == "token"][0]
    assert token_data["grant_type"] == "authorization_code"
    assert token_data["code"] == f"CODE.alice.{s.sid}"                          # the captured code
    assert token_data["code_verifier"] and len(token_data["code_verifier"]) >= 40  # PKCE verifier sent
    assert s.closed                                                             # session cleaned up


def test_oauth_password_grant_sets_token_and_sends_client_secret():
    factory = _oauth_factory()
    prov = TokenProvider(Credential("bob", SecretStr("pw")), _oauth_password_spec(), _TARGET, _SCOPE,
                         session_factory=factory)
    tok = _asyncio.run(prov.token())
    s = factory.created[0]
    assert tok == f"TOK.bob.{s.sid}"
    assert [r["kind"] for r in s.requests] == ["token"]                         # single form POST, no authorize
    data = s.requests[0]["data"]
    assert data["grant_type"] == "password" and data["username"] == "bob"
    assert data["client_secret"] == "csecret" and "code_verifier" not in data   # secret sent; no PKCE


def test_oauth_expires_in_drives_proactive_refresh():
    factory = _oauth_factory(expires_in=5)                    # token TTL 5s
    now = {"t": 1000.0}
    prov = TokenProvider(Credential("alice", SecretStr("pw")), _oauth_authcode_spec(), _TARGET, _SCOPE,
                         session_factory=factory, refresh_margin=10, clock=lambda: now["t"])
    tok1 = _asyncio.run(prov.token())                         # grant #1: exp = 1000 + 5 = 1005
    tok2 = _asyncio.run(prov.token())                         # exp-now (5) <= margin (10) -> re-grant
    assert len(factory.created) == 2 and tok1 != tok2         # expires_in drove a proactive refresh


# --------------------------------------------- SCOPE (load-bearing): off-scope redirect refused per-hop
def test_oauth_offscope_authorize_redirect_is_refused_per_hop_never_followed():
    seen = []

    def handler(request):
        seen.append(str(request.url))
        if request.method == "POST" and request.url.path == "/account/login":
            return _httpx.Response(200, json={"ok": True})
        if request.url.path == "/oauth/authorize":                              # 302 to an OUT-OF-SCOPE IdP
            return _httpx.Response(302, headers={"location": "http://evil.example.com/steal?code=X"})
        return _httpx.Response(404)

    def factory(scope):
        client = _httpx.AsyncClient(transport=_httpx.MockTransport(handler), follow_redirects=False)
        return _HttpxLoginSession(scope, client=client)

    prov = TokenProvider(Credential("u", SecretStr("p")), _oauth_authcode_spec(), _TARGET, _SCOPE,
                         session_factory=factory)
    with pytest.raises(LoginError):
        _asyncio.run(prov.token())
    # the off-scope host was NEVER contacted (refused BEFORE the bytes left, not auto-followed)
    assert not any("evil.example.com" in u for u in seen)


def test_oauth_offscope_token_url_is_refused_before_any_request():
    # the token endpoint itself is not exempt: a token_url that leaves the target origin is refused.
    spec = LoginSpec(method="POST", path="", username_field="username", password_field="password",
                     token_field="access_token", grant="password",
                     oauth=OAuthConfig(grant="password", token_url="http://evil.example.com/oauth/token",
                                       client_id="cid"))
    calls = []

    def factory(scope):
        class _NoNet:
            async def oauth_post_form(self, url, data, headers=None):
                calls.append(url)                                              # must NOT be reached
                return LoginResponse(200, {"access_token": "X"}, {}, {})
            async def aclose(self):
                pass
        return _NoNet()

    prov = TokenProvider(Credential("u", SecretStr("p")), spec, _TARGET, _SCOPE, session_factory=factory)
    with pytest.raises(LoginError):
        _asyncio.run(prov.token())
    assert calls == []                                                        # refused before any bytes left


# --------------------------------------------- ISOLATION (load-bearing): zero cross-account OAuth state
def test_oauth_isolation_owner_token_reads_as_owner_not_attacker():
    factory = _oauth_factory()
    eng = _FakeEngine([
        _result(ai_verdict=None, attack={"response": {"status_code": 401}}),   # force a relogin
        _result(ai_verdict="verified"),
    ])
    atk = Credential("attackeruser", SecretStr("apw"))
    own = Credential("victimowner", SecretStr("opw"))
    _asyncio.run(_verify_external_relogin(
        _TARGET, _SPEC, _OP, _oauth_authcode_spec(), atk, own, None, eng, session_factory=factory))
    assert len(eng.calls) == 2
    # the OAuth owner token flows ONLY through owner_credential; never into the attack headers
    for kw in eng.calls:
        auth = str(kw["auth_context"])
        assert "attackeruser" in auth and "victimowner" not in auth
        oc = kw["owner_credential"]
        assert isinstance(oc, OwnerCredential)
        assert "victimowner" in oc.header_value and "attackeruser" not in oc.header_value
    # STRUCTURAL: every session served EXACTLY ONE account (a shared client would serve both)
    for s in factory.created:
        users = {r["body"].get("username") for r in s.requests if r["kind"] == "login"}
        assert len(users) == 1
    # owner sessions carry NONE of the attacker sessions' PKCE verifiers / codes (zero cross-account bleed)
    atk_sess = [s for s in factory.created if s.username == "attackeruser"]
    own_sess = [s for s in factory.created if s.username == "victimowner"]
    atk_secrets = {s.verifier for s in atk_sess} | {
        r["data"].get("code") for s in atk_sess for r in s.requests if r["kind"] == "token"}
    for s in own_sess:
        own_secrets = {s.verifier} | {
            r["data"].get("code") for r in s.requests if r["kind"] == "token"}
        assert not (own_secrets & atk_secrets)


def test_oauth_isolation_assertion_is_sensitive_to_a_shared_session():
    # NEGATIVE CONTROL: one shared session across accounts -> it serves BOTH usernames, which the
    # isolation assertion above forbids. Proves that assertion would FAIL if a client were shared.
    shared = _FakeOAuthSession()

    def shared_factory(scope):
        return shared

    atk = TokenProvider(Credential("attackeruser", SecretStr("p")), _oauth_authcode_spec(), _TARGET,
                        _SCOPE, session_factory=shared_factory)
    own = TokenProvider(Credential("victimowner", SecretStr("p")), _oauth_authcode_spec(), _TARGET,
                        _SCOPE, session_factory=shared_factory)
    _asyncio.run(atk.token())
    _asyncio.run(own.token())
    users = {r["body"].get("username") for r in shared.requests if r["kind"] == "login"}
    assert users == {"attackeruser", "victimowner"}            # one session, two accounts -> detectable


# --------------------------------------------- from_file parsing / back-compat / direction-safety
def test_oauth_from_file_parsing_and_validation(tmp_path):
    def _w(d):
        p = tmp_path / "l.json"
        p.write_text(json.dumps(d), encoding="utf-8")
        return str(p)

    s = LoginSpec.from_file(_w({"grant": "password",
                                "oauth": {"token_url": "/oauth/token", "client_id": "cid", "scope": "read"}}))
    assert s.grant == "password" and s.oauth.token_url == "/oauth/token" and s.oauth.client_id == "cid"

    s2 = LoginSpec.from_file(_w({"grant": "authorization_code", "path": "/login",
                                 "username_field": "u", "password_field": "p",
                                 "oauth": {"token_url": "/t", "client_id": "c",
                                           "authorize_url": "/oauth/authorize",
                                           "redirect_uri": "http://app/cb"}}))
    assert s2.grant == "authorization_code" and s2.oauth.authorize_url == "/oauth/authorize"

    with pytest.raises(ValueError):                            # missing token_url
        LoginSpec.from_file(_w({"grant": "password", "oauth": {"client_id": "cid"}}))
    with pytest.raises(ValueError):                            # auth-code missing redirect_uri
        LoginSpec.from_file(_w({"grant": "authorization_code",
                                "oauth": {"token_url": "/t", "client_id": "c", "authorize_url": "/a"}}))
    with pytest.raises(ValueError):                            # unknown grant
        LoginSpec.from_file(_w({"grant": "implicit", "oauth": {"token_url": "/t", "client_id": "c"}}))


def test_oauth_client_secret_is_secretstr_never_plaintext(tmp_path):
    p = tmp_path / "l.json"
    p.write_text(json.dumps({"grant": "password",
                             "oauth": {"token_url": "/t", "client_id": "c", "client_secret": "SEKRET"}}),
                 encoding="utf-8")
    s = LoginSpec.from_file(str(p))
    assert isinstance(s.oauth.client_secret, SecretStr)
    assert "SEKRET" not in repr(s.oauth) and "SEKRET" not in str(s.oauth)   # masked in repr


def test_oauth_back_compat_form_spec_is_byte_identical(tmp_path):
    # a form login.json (no grant/oauth) -> grant="form", oauth=None, and logs in via the unchanged
    # single-request http_post path.
    p = tmp_path / "login.json"
    p.write_text(json.dumps({"path": "/users/v1/login", "username_field": "username",
                             "password_field": "password", "token_field": "auth_token"}), encoding="utf-8")
    spec = LoginSpec.from_file(str(p))
    assert spec.grant == "form" and spec.oauth is None and spec.token_field == "auth_token"

    def _boom_factory(scope):
        raise AssertionError("a form spec must NOT use the OAuth/session path")

    fake = _fake_post_factory()
    prov = TokenProvider(Credential("u", SecretStr("p")), spec, _TARGET, _SCOPE,
                         http_post=fake, session_factory=_boom_factory)
    tok = _asyncio.run(prov.token())
    assert tok.startswith("TOK.u.") and len(fake.calls) == 1   # single POST via http_post; no session used


def test_oauth_broken_grant_is_login_error_not_a_verdict():
    class _BadTokenSession:
        async def request(self, method, url, *, json_body=None, headers=None):
            return LoginResponse(200, {"ok": True}, {}, {})
        async def oauth_post_form(self, url, data, headers=None):
            return LoginResponse(400, {"error": "invalid_client"}, {}, {})      # token endpoint rejects
        async def aclose(self):
            pass

    prov = TokenProvider(Credential("u", SecretStr("p")), _oauth_password_spec(), _TARGET, _SCOPE,
                         session_factory=lambda scope: _BadTokenSession())
    with pytest.raises(LoginError):
        _asyncio.run(prov.token())


def test_oauth_authorize_error_redirect_is_login_error():
    # an authorize redirect carrying ?error=access_denied (not a code) -> LoginError -> NOT DATA.
    class _DeniedSession:
        async def request(self, method, url, *, json_body=None, headers=None):
            return LoginResponse(200, {"ok": True}, {}, {})
        async def oauth_get_no_follow(self, url, headers=None):
            return LoginResponse(302, {}, {"location": "http://app.local/callback?error=access_denied"}, {})
        async def aclose(self):
            pass

    prov = TokenProvider(Credential("u", SecretStr("p")), _oauth_authcode_spec(), _TARGET, _SCOPE,
                         session_factory=lambda scope: _DeniedSession())
    with pytest.raises(LoginError):
        _asyncio.run(prov.token())


def test_oauth_token_and_secret_never_printed_via_cli(tmp_path, monkeypatch):
    # end-to-end secrecy: an OAuth --auth run never prints the obtained token or the client_secret.
    monkeypatch.setattr(settings, "LLM_API_KEY", SecretStr("test-key"))
    monkeypatch.setattr(settings, "AI_DEEP_VERIFY_ENABLED", False)
    cfg = _write_cfg(tmp_path)                                 # atkuser / ownuser (distinct)
    login = tmp_path / "login.json"
    login.write_text(json.dumps({"grant": "password",
                                 "oauth": {"token_url": "/oauth/token", "client_id": "cid",
                                           "client_secret": "SECRET-CANARY-DO-NOT-LEAK"}}), encoding="utf-8")
    spec = tmp_path / "spec.json"
    spec.write_text(json.dumps(_SPEC), encoding="utf-8")
    op = tmp_path / "op.json"
    op.write_text(json.dumps(_OP), encoding="utf-8")

    from backend.app.cli import relogin as _relogin
    monkeypatch.setattr(_relogin, "_default_session_factory", lambda scope: _FakeOAuthSession())
    eng = _FakeEngine([_result(ai_verdict="failed")])
    lines = []
    code = run_external_verify(
        target=_TARGET, spec_path=str(spec), op_path=str(op), config_path=cfg, auth_spec_path=str(login),
        engine=eng,
        echo=lambda *a: lines.append(" ".join(str(x) for x in a)),
        err=lambda *a: lines.append(" ".join(str(x) for x in a)))
    out = "\n".join(lines)
    assert "SECRET-CANARY-DO-NOT-LEAK" not in out              # client_secret never printed
    assert "TOK.atkuser" not in out and "TOK.ownuser" not in out   # obtained tokens never printed
