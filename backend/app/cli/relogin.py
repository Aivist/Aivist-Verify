# ==============================================================================
# Auto re-login / token refresh for `<brand> verify --target` (multi-step auth, slice 1).
#
# ORCHESTRATION / CREDENTIAL-SOURCE layer only. It changes ONLY where the two bearer
# tokens come from: instead of static tokens, each account logs in to obtain its own JWT
# and re-logs-in to refresh near/at expiry. The obtained tokens flow into the SAME
# `execute_deep_verification(...)` call the external path already builds — attacker token
# -> auth_context, owner token -> owner_credential — byte-identical to the static path.
# The engine, the four channels, the cross-resource guard, D24/D19, and scope.py's rules
# are NOT touched.
#
# THREE RED LINES (proven in tests):
#   1. IDENTITY ISOLATION. Attacker and owner log in INDEPENDENTLY: separate TokenProvider
#      instances, separate credentials, a FRESH httpx client per login (no shared cookie
#      jar / auth state). Each holds its OWN token. The owner's token can never carry the
#      attacker's session, so it can never appear in an attack request.
#   2. CREDENTIALS + TOKENS ARE SECRET. Passwords are SecretStr, revealed only at the moment
#      the login body is built; obtained tokens are handed back as plain strings the caller
#      immediately wraps in SecretStr. Neither the password nor the token is ever printed or
#      put in an error message (LoginError messages carry status codes / field names only).
#   3. SCOPE FAIL-CLOSED. The login request is a request to the target: its URL is
#      ScopePolicy.check()-ed BEFORE any bytes go out. An out-of-scope login endpoint is
#      refused (LoginError), never silently reached.
#
# SCOPE (slice 2b): token extraction from the login response by LOCATION — a JSON body
# field (default; covers VAmPI and most JWT logins), a response HEADER (e.g. Authorization
# or a custom header), or a Set-Cookie COOKIE. This is READ-ONLY: wherever the token is read
# from, it flows downstream IDENTICALLY (attacker -> auth_context, owner -> OwnerCredential),
# and refresh / scope-check / identity-isolation wrap the extractor unchanged. Still OUT
# (later slices — report, do not build): OAuth redirect flows, multi-step / MFA challenges,
# CSRF-token round-trips and captcha.
# ==============================================================================
from __future__ import annotations

import base64
import getpass
import hashlib
import json
import os
import re
import time
import tomllib
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, Optional, Tuple
from urllib.parse import urljoin, urlsplit, urlencode, parse_qsl

import httpx
from pydantic import SecretStr

from backend.app.core.config import reveal_secret
from backend.app.services.scope import ScopePolicy
# Reuse the engine's ONE audited per-hop redirect-scope discipline (do NOT build a parallel,
# weaker one): the login/step client is NOT exempt from scope-lock. `_follow_redirects_scoped`
# re-validates every redirect Location against the SAME ScopePolicy before following it and
# refuses the first out-of-scope hop; `_build_request_kwargs` is the shared httpx-kwargs builder.
from backend.app.services.fuzzer import (
    _follow_redirects_scoped, _build_request_kwargs, ScopeViolationError,
)

# Injectable HTTP for tests: (method, url, json_body) -> LoginResponse. A bare
# (status_code, json_body_dict) 2-tuple is ALSO accepted (back-compat, body-only) and
# normalized by _as_login_response — so a body-field login stays byte-identical to slice 1.
HttpPost = Callable[[str, str, Dict[str, Any]], Awaitable["LoginResponse"]]


@dataclass(frozen=True)
class LoginResponse:
    """The parts of a login response a token / captured value may be read from. `headers` are
    looked up case-insensitively by the extractor; `cookies` is name -> value parsed from
    Set-Cookie; `text` is the RAW body (used only by a `regex` step extractor for HTML/form CSRF
    tokens). `text` defaults to "" so every existing 4-field construction stays byte-identical."""
    status: int
    body: Dict[str, Any]
    headers: Dict[str, str]
    cookies: Dict[str, str]
    text: str = ""


def _as_login_response(raw: Any) -> "LoginResponse":
    """Normalize an http_post return into a LoginResponse. Accepts a LoginResponse as-is, or a
    legacy (status, json_body) 2-tuple (body-only; headers/cookies empty) — the latter keeps
    every body-field caller/test byte-identical to slice 1."""
    if isinstance(raw, LoginResponse):
        return raw
    status, body = raw
    return LoginResponse(status=status, body=(body if isinstance(body, dict) else {}),
                         headers={}, cookies={})

# Per-user config keys for the two accounts' login credentials (sensitive; same privacy
# discipline as the static tokens — file/prompt only, never the command line).
_CFG_ATTACKER_USER = "TARGET_ATTACKER_USERNAME"
_CFG_ATTACKER_PASS = "TARGET_ATTACKER_PASSWORD"
_CFG_OWNER_USER = "TARGET_OWNER_USERNAME"
_CFG_OWNER_PASS = "TARGET_OWNER_PASSWORD"
# D30 (optional): the THIRD/bystander account's login credential. Read from the config file ONLY
# (never prompted, so the attacker/owner prompt flow is unchanged); absent => None => no bystander.
_CFG_BYSTANDER_USER = "TARGET_BYSTANDER_USERNAME"
_CFG_BYSTANDER_PASS = "TARGET_BYSTANDER_PASSWORD"


class LoginError(Exception):
    """A login / token-refresh failure. Message carries only non-secret detail (status code,
    field name) so it is safe to surface. The caller turns it into the NOT-DATA path."""


# Where in the login response the token lives. "body" (default) reads a JSON field;
# "header" reads a response header value as-is (e.g. "Bearer <jwt>"); "cookie" reads a
# Set-Cookie cookie value. In EVERY mode `token_field` names the source in that location.
_TOKEN_LOCATIONS = frozenset({"body", "header", "cookie"})


# Slice 2c — an OPTIONAL ordered pre-login sequence (CSRF / nonce / session-cookie round-trip).
# Where a STEP may read a captured value from. Superset of _TOKEN_LOCATIONS by `regex` (a capture
# group from the raw HTML/text body, for form CSRF tokens — read-only).
_EXTRACT_LOCATIONS = frozenset({"body", "header", "cookie", "regex"})

# Slice 3 — login GRANT kind. "form" is today's username/password login (single-request or
# multi-step); the two OAuth grants produce a token via the operator's OWN authorized flow.
_GRANTS = frozenset({"form", "password", "authorization_code"})
_OAUTH_GRANTS = frozenset({"password", "authorization_code"})


@dataclass(frozen=True)
class Extract:
    """Capture ONE named value from a step response for later reference. `location`: "body" (a JSON
    field), "header" (a response header, case-insensitive), "cookie" (a Set-Cookie cookie), or
    "regex" (the FIRST capture group of the `field` pattern applied to the RAW body — an HTML/form
    CSRF token; read-only). The captured value is held as SecretStr and is NEVER printed."""
    name: str
    location: str
    field: str


@dataclass(frozen=True)
class Inject:
    """Reference previously-captured values INTO a request. `headers` maps a header NAME -> a
    captured value NAME (e.g. {"X-CSRF-Token": "csrf"}); `body` maps a JSON field -> a captured
    value NAME. All DECLARED in the spec — no guessing. An unknown captured name -> LoginError."""
    headers: Dict[str, str] = field(default_factory=dict)
    body: Dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class LoginStep:
    """One ordered pre-login step: a request whose response MAY `extract` a value and which MAY
    `inject` earlier-captured values. Scope-checked fail-closed and secret-carrying exactly like
    the login request itself."""
    method: str
    path: str
    extract: Optional[Extract] = None
    inject: Optional[Inject] = None


def _inject_from(raw: Any) -> Optional["Inject"]:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ValueError("--auth 'inject' must be a JSON object with optional 'headers'/'body' maps")
    hdrs, body = raw.get("headers") or {}, raw.get("body") or {}
    if not isinstance(hdrs, dict) or not isinstance(body, dict):
        raise ValueError("--auth inject.headers and inject.body must each be a JSON object")
    return Inject(headers={str(k): str(v) for k, v in hdrs.items()},
                  body={str(k): str(v) for k, v in body.items()})


def _extract_from(raw: Any) -> Optional["Extract"]:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ValueError("--auth step 'extract' must be a JSON object")
    loc = str(raw.get("location", "body")).lower()
    if loc not in _EXTRACT_LOCATIONS:
        raise ValueError(f"--auth step extract.location must be one of "
                         f"{sorted(_EXTRACT_LOCATIONS)}, got {loc!r}")
    try:
        return Extract(name=str(raw["name"]), location=loc, field=str(raw["field"]))
    except KeyError as e:
        raise ValueError(f"--auth step extract missing required field: {e}") from e


def _step_from(raw: Any) -> "LoginStep":
    if not isinstance(raw, dict):
        raise ValueError("--auth each step must be a JSON object")
    try:
        return LoginStep(method=str(raw.get("method", "GET")).upper(), path=str(raw["path"]),
                         extract=_extract_from(raw.get("extract")),
                         inject=_inject_from(raw.get("inject")))
    except KeyError as e:
        raise ValueError(f"--auth step missing required field: {e}") from e


# ==============================================================================
# OAuth 2.0 authorization (slice 3): the operator AUTOMATES a login THEY are authorized to perform —
# supplying their OWN client credentials + the resource-owner (account) credentials for a target they
# may test. It only produces a token string, which flows into the SAME three-variable routing as every
# other login (attacker->auth_context, owner->owner_credential, bystander->bystander_credential); it
# changes NOTHING in the verdict core.
#
# EXPLICIT NON-GOAL — a DIFFERENT tool category, NOT built here: anything that DEFEATS an auth
# challenge — captcha solving, MFA/2FA bypass, third-party consent-screen scraping, or credential
# brute-force. OAuth here means walking the operator's OWN authorized flow, never breaking someone's
# auth. A failed / misconfigured flow -> LoginError -> no token -> NOT DATA, never a verdict.
# ==============================================================================
@dataclass(frozen=True)
class OAuthConfig:
    """OAuth grant parameters. `grant`: "password" (resource-owner-password) or "authorization_code"
    (+ PKCE). Secrets (`client_secret`) are SecretStr, revealed only at request-build time, never
    logged. `token_field` names the access-token field in the token response (default "access_token").
    The auth-code-only fields (`authorize_url`, `redirect_uri`, `pkce`, `code_param`) are unused by the
    password grant."""
    grant: str
    token_url: str
    client_id: str
    client_secret: Optional[SecretStr] = None
    scope: str = ""
    token_field: str = "access_token"
    authorize_url: str = ""
    redirect_uri: str = ""
    pkce: bool = True
    code_param: str = "code"

    @staticmethod
    def from_dict(grant: str, raw: Any) -> "OAuthConfig":
        if not isinstance(raw, dict):
            raise ValueError("--auth 'oauth' must be a JSON object")
        try:
            token_url = str(raw["token_url"])
            client_id = str(raw["client_id"])
        except KeyError as e:
            raise ValueError(f"--auth oauth missing required field: {e}") from e
        secret = raw.get("client_secret")
        cfg = OAuthConfig(
            grant=grant, token_url=token_url, client_id=client_id,
            client_secret=(SecretStr(str(secret)) if secret else None),
            scope=str(raw.get("scope", "")),
            token_field=str(raw.get("token_field", "access_token")),
            authorize_url=str(raw.get("authorize_url", "")),
            redirect_uri=str(raw.get("redirect_uri", "")),
            pkce=bool(raw.get("pkce", True)),
            code_param=str(raw.get("code_param", "code")),
        )
        if grant == "authorization_code" and not (cfg.authorize_url and cfg.redirect_uri):
            raise ValueError(
                "--auth oauth authorization_code requires 'authorize_url' and 'redirect_uri'")
        return cfg


@dataclass(frozen=True)
class LoginSpec:
    """The `--auth login.json` declaration: how to log in and where the token is.

    `token_location` selects WHERE the token is read from — "body" (default; a JSON field),
    "header" (a response header) or "cookie" (a Set-Cookie cookie) — and `token_field` names
    the source in that location (the JSON field / header name / cookie name).

    `steps` (OPTIONAL) is an ordered pre-login sequence run BEFORE the login request within the
    SAME per-account session (one httpx client, so a session cookie set in a step carries to the
    login); each step may `extract` a captured value and `inject` earlier ones. `inject` (OPTIONAL)
    references captured values into the FINAL login request. Empty `steps` => byte-identical to
    the single-request login (guarded by a test)."""
    method: str
    path: str
    username_field: str
    password_field: str
    token_field: str
    token_location: str = "body"
    steps: Tuple[LoginStep, ...] = ()
    inject: Optional[Inject] = None
    # Slice 3 — OAuth. `grant` selects the login mode: "form" (default; today's byte-identical form
    # login) or an OAuth grant, whose parameters live in `oauth`. When `grant != "form"`, `oauth` is
    # present; the form fields above default (auth-code reuses them for the operator's account login,
    # the password grant ignores them).
    grant: str = "form"
    oauth: Optional[OAuthConfig] = None

    @staticmethod
    def from_file(path: str) -> "LoginSpec":
        with open(path, encoding="utf-8") as fh:
            d = json.load(fh)
        if not isinstance(d, dict):
            raise ValueError("--auth login spec must be a JSON object")
        try:
            location = str(d.get("token_location", "body")).lower()
            if location not in _TOKEN_LOCATIONS:
                raise ValueError(
                    f"--auth token_location must be one of {sorted(_TOKEN_LOCATIONS)}, "
                    f"got {location!r}")
            steps_raw = d.get("steps") or []
            if not isinstance(steps_raw, list):
                raise ValueError("--auth 'steps' must be a JSON array")
            grant = str(d.get("grant", "form")).lower()
            if grant not in _GRANTS:
                raise ValueError(f"--auth grant must be one of {sorted(_GRANTS)}, got {grant!r}")
            steps = tuple(_step_from(s) for s in steps_raw)
            inject = _inject_from(d.get("inject"))
            if grant == "form":
                # Byte-identical to today: the form fields are REQUIRED.
                return LoginSpec(
                    method=str(d.get("method", "POST")).upper(),
                    path=str(d["path"]),
                    username_field=str(d["username_field"]),
                    password_field=str(d["password_field"]),
                    token_field=str(d["token_field"]),
                    token_location=location,
                    steps=steps,
                    inject=inject,
                )
            # OAuth grant: OAuth params in `oauth`; the form fields are OPTIONAL (auth-code reuses
            # them for the operator's account login via the SAME form-login sequence; the password
            # grant ignores them and uses the standard OAuth "username"/"password" body fields).
            oauth = OAuthConfig.from_dict(grant, d.get("oauth") or {})
            return LoginSpec(
                method=str(d.get("method", "POST")).upper(),
                path=str(d.get("path", "")),
                username_field=str(d.get("username_field", "username")),
                password_field=str(d.get("password_field", "password")),
                token_field=str(d.get("token_field", "access_token")),
                token_location=location,
                steps=steps,
                inject=inject,
                grant=grant,
                oauth=oauth,
            )
        except KeyError as e:
            raise ValueError(f"--auth login spec missing required field: {e}") from e


@dataclass(frozen=True)
class Credential:
    """One account's login credential. Password is a SecretStr (never a plaintext repr)."""
    username: str
    password: SecretStr


def _read_config(config_path: Optional[str]) -> Dict[str, Any]:
    try:
        if config_path and os.path.isfile(config_path):
            with open(config_path, "rb") as fh:
                loaded = tomllib.load(fh)
            if isinstance(loaded, dict):
                return loaded
    except Exception:
        pass
    return {}


def resolve_login_credentials(
    config_path: Optional[str],
    prompt: Callable[[str], str] = input,
    secret_prompt: Callable[[str], str] = getpass.getpass,
    *,
    attacker_user_key: str = _CFG_ATTACKER_USER, attacker_pass_key: str = _CFG_ATTACKER_PASS,
    owner_user_key: str = _CFG_OWNER_USER, owner_pass_key: str = _CFG_OWNER_PASS,
) -> Tuple[Credential, Credential]:
    """(attacker, owner) login credentials. Read from the per-user config file if present,
    else prompted (username plain, password masked). Passwords become SecretStr immediately.

    The config-key names are parameters (default: today's TARGET_ATTACKER_* / TARGET_OWNER_* keys, so
    every existing caller is byte-identical). #7 per-finding: the caller may point a role at a DIFFERENT
    account's keys so different findings/ops can attack different owners across separate runs. Key
    SELECTION is the caller's; this function still resolves exactly two INDEPENDENT credentials, and
    each still feeds its OWN TokenProvider downstream (no provider/client sharing across accounts)."""
    cfg = _read_config(config_path)

    def _cred(user_key: str, pass_key: str, role: str) -> Credential:
        user = str(cfg.get(user_key) or "").strip()
        if not user:
            user = (prompt(f"{role} username: ") or "").strip()
        pw = str(cfg.get(pass_key) or "")
        if not pw:
            pw = secret_prompt(f"{role} password (input hidden): ") or ""
        if not user or not pw:
            raise ValueError(f"{role} username and password are required for --auth login")
        return Credential(username=user, password=SecretStr(pw))

    return (_cred(attacker_user_key, attacker_pass_key, "attacker"),
            _cred(owner_user_key, owner_pass_key, "owner"))


def resolve_bystander_login_credential(
    config_path: Optional[str],
    *,
    user_key: str = _CFG_BYSTANDER_USER, pass_key: str = _CFG_BYSTANDER_PASS,
) -> Optional[Credential]:
    """The OPTIONAL D30 third/bystander login credential (a principal with no ownership of the
    attacked object). Read from the config file ONLY (default keys TARGET_BYSTANDER_USERNAME /
    TARGET_BYSTANDER_PASSWORD) — deliberately NOT prompted, so the attacker/owner login flow is
    unchanged. Returns None unless BOTH a username and password are present (partial config => no
    bystander, byte-identical). Password becomes SecretStr immediately.

    `user_key`/`pass_key` are parameters (default: today's keys) so #7 per-finding can point the
    bystander at a different account's keys across separate runs."""
    cfg = _read_config(config_path)
    user = str(cfg.get(user_key) or "").strip()
    pw = str(cfg.get(pass_key) or "")
    if not user or not pw:
        return None
    return Credential(username=user, password=SecretStr(pw))


def _jwt_exp(token: str) -> Optional[float]:
    """The `exp` (epoch seconds) from a JWT payload, WITHOUT verifying the signature — we only
    read the timing to decide when to refresh, never trusting it for auth. None if the token is
    not a JWT / has no exp (then refresh is reactive-only)."""
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload.encode()))
        exp = data.get("exp")
        return float(exp) if exp is not None else None
    except Exception:
        return None


def _reconstruct_login_url(base_url: str, path: str) -> str:
    """Build the login URL. An absolute path is used verbatim (scope.check will refuse it if
    it leaves the target's origin); a relative path is joined onto the target base."""
    p = path.strip()
    if p.lower().startswith(("http://", "https://")):
        return p
    return base_url.rstrip("/") + ("" if p.startswith("/") else "/") + p


def _httpx_to_login_response(resp: "httpx.Response") -> "LoginResponse":
    """Convert an httpx.Response to a LoginResponse — body (JSON dict, else {}), headers,
    Set-Cookie cookies, and the RAW text (for a regex extractor). Shared by the single-request
    default post and the multi-step session so both surface identical fields."""
    try:
        data = resp.json()
    except Exception:
        data = {}
    return LoginResponse(
        status=resp.status_code,
        body=(data if isinstance(data, dict) else {}),
        headers={k: v for k, v in resp.headers.items()},
        cookies={k: v for k, v in resp.cookies.items()},
        text=resp.text,
    )


async def _default_http_post(method: str, url: str, json_body: Dict[str, Any]) -> "LoginResponse":
    """Real SINGLE-request login (the no-`steps` path): a FRESH client per call (no shared
    cookie/auth state — red line 1). verify=False matches the engine's self-signed-target posture
    (TECH_DEBT D13). Surfaces body, headers, and Set-Cookie cookies so the token can be read from
    any of them. UNCHANGED behaviorally from slice 1 (the multi-step path uses a session instead)."""
    async with httpx.AsyncClient(timeout=20.0, verify=False) as client:
        resp = await client.request(method, url, json=json_body)
    return _httpx_to_login_response(resp)


def _header_lookup(headers: Dict[str, str], name: str) -> Optional[str]:
    """Case-insensitive header value lookup (HTTP header names are case-insensitive)."""
    want = name.lower()
    for k, v in headers.items():
        if k.lower() == want:
            return v
    return None


def _extract_token(spec: "LoginSpec", resp: "LoginResponse") -> str:
    """Read the token out of the login response at the declared location. Returns the token
    string, or raises LoginError (the NOT-DATA path) when it is absent/empty — the SAME failure
    shape as slice 1's missing body field, for every mode. The value itself is NEVER placed in
    the error message (secrecy): only the location + source NAME are named.

    body:   unchanged from slice 1 — the JSON field value, returned as-is (byte-identical).
    header: the value as-is (e.g. "Bearer <jwt>", which the downstream auth builders accept),
            whitespace-stripped.
    cookie: the Set-Cookie cookie value, whitespace-stripped."""
    loc = spec.token_location
    if loc == "body":
        val = resp.body.get(spec.token_field)
        if not val or not isinstance(val, str):
            raise LoginError(f"login response had no token in field {spec.token_field!r}")
        return val
    if loc == "header":
        val = _header_lookup(resp.headers, spec.token_field)
        where = f"header {spec.token_field!r}"
    elif loc == "cookie":
        val = resp.cookies.get(spec.token_field)
        where = f"cookie {spec.token_field!r}"
    else:  # defensive: from_file validates token_location; direct construction could bypass it
        raise LoginError(f"unknown token_location {loc!r}")
    if not val or not isinstance(val, str):
        raise LoginError(f"login response had no token in {where}")
    return val.strip()


# ==============================================================================
# Multi-step login sequence (slice 2c): an ordered pre-login sequence + the login, run within ONE
# per-account session (one httpx client — a cookie set in a step carries to the login WITHIN the
# account), with the SAME fail-closed scope-lock + secrecy discipline as the single-request login.
#
# IDENTITY-ISOLATION RED LINE (welded structurally, not by convention): the session (its client +
# cookie jar) and the captured-value store are LOCAL to one `_run_login_sequence` call for one
# account. Attacker, owner, and bystander each run their OWN sequence -> their own session object ->
# their own client + cookies + captured values. Nothing is shared across accounts, so cross-account
# state bleed is IMPOSSIBLE (a bleed would make the owner token carry the attacker's identity -> D24
# would corroborate trivially -> the custody / SEV-1 false-positive class).
# ==============================================================================
class LoginSession:
    """A per-account login session: ONE client for the whole sequence. `request` sends one request
    (redirects followed MANUALLY, every hop scope-checked fail-closed) -> LoginResponse."""

    async def request(self, method: str, url: str, *, json_body: Optional[Dict[str, Any]] = None,
                      headers: Optional[Dict[str, str]] = None) -> "LoginResponse":
        raise NotImplementedError

    async def oauth_get_no_follow(self, url: str,
                                  headers: Optional[Dict[str, str]] = None) -> "LoginResponse":
        """OAuth: a SINGLE GET with redirects NOT auto-followed — the caller inspects the Location to
        capture the authorization code or to scope-check the next hop manually."""
        raise NotImplementedError

    async def oauth_post_form(self, url: str, data: Dict[str, str],
                              headers: Optional[Dict[str, str]] = None) -> "LoginResponse":
        """OAuth: a form-urlencoded POST — the token endpoint requires form encoding (RFC 6749)."""
        raise NotImplementedError

    async def aclose(self) -> None:
        pass


class _HttpxLoginSession(LoginSession):
    """Default real session: ONE httpx client (verify=False, auto-follow DISABLED) for the whole
    account sequence, so a session cookie set in step 1 carries to the login POST via this client's
    jar. Redirects are followed MANUALLY via the engine's `_follow_redirects_scoped` (reused, not
    re-implemented): each hop is scope-checked and the first out-of-scope hop raises
    ScopeViolationError (-> LoginError -> NOT DATA). `client` is injectable for offline tests."""

    def __init__(self, scope: Optional[ScopePolicy], *, client: Optional[httpx.AsyncClient] = None) -> None:
        self._scope = scope
        self._client = client or httpx.AsyncClient(timeout=20.0, verify=False, follow_redirects=False)
        self._own_client = client is None

    async def request(self, method, url, *, json_body=None, headers=None) -> "LoginResponse":
        hdrs = dict(headers or {})
        resp = await self._client.request(
            **_build_request_kwargs(method, url, hdrs, json_body, follow_redirects=False))
        if self._scope is not None and getattr(self._scope, "locked", False):
            resp = await _follow_redirects_scoped(self._client, resp, method, hdrs, json_body, self._scope)
        return _httpx_to_login_response(resp)

    async def oauth_get_no_follow(self, url, headers=None) -> "LoginResponse":
        # Redirects NOT auto-followed (the client is constructed follow_redirects=False): the OAuth
        # code capture inspects the Location and scope-checks each hop MANUALLY (see _oauth_capture_code).
        resp = await self._client.request("GET", url, headers=dict(headers or {}))
        return _httpx_to_login_response(resp)

    async def oauth_post_form(self, url, data, headers=None) -> "LoginResponse":
        # Form-urlencoded (httpx sets Content-Type from `data=`), no auto-follow (token endpoints
        # return a JSON body, not a redirect).
        resp = await self._client.request("POST", url, data=dict(data), headers=dict(headers or {}))
        return _httpx_to_login_response(resp)

    async def aclose(self) -> None:
        if self._own_client:
            await self._client.aclose()


# session_factory: given the account's ScopePolicy, return a FRESH session. Default -> real httpx
# session. Tests inject a factory that hands EACH account its own fake session (proving isolation).
SessionFactory = Callable[[Optional[ScopePolicy]], LoginSession]


def _default_session_factory(scope: Optional[ScopePolicy]) -> LoginSession:
    return _HttpxLoginSession(scope)


def _join_login_url(base_url: str, path: str) -> str:
    """Normalize a step/login path against base_url with urljoin (consistent relative/absolute
    handling). NORMALIZATION IS NOT THE SECURITY BOUNDARY: an absolute URL replaces the base, so the
    RESULT is always ScopePolicy.check()-ed by the caller before bytes go out (an absolute path that
    leaves the target origin is refused there — preserving the single-request login's property)."""
    return urljoin(base_url if base_url.endswith("/") else base_url + "/", path.strip())


def _scope_check_login_url(scope: Optional[ScopePolicy], url: str) -> None:
    """Fail-closed pre-send scope gate — identical standard to the single-request login and the main
    engine send path. Refused -> LoginError (NOT-DATA path), before any bytes leave."""
    if scope is not None and not scope.check(url).allowed:
        raise LoginError("login step endpoint is out of scope (refused before any request was sent)")


def _extract_captured(extract: "Extract", resp: "LoginResponse") -> str:
    """Read one captured value from a step response at the declared location. Raises LoginError
    (NOT-DATA) when absent — a mis-declared sequence can only FAIL to obtain a value, never a verdict.
    The value itself is NEVER placed in the error (only the location + source name)."""
    loc = extract.location
    if loc == "body":
        val = resp.body.get(extract.field)
    elif loc == "header":
        val = _header_lookup(resp.headers, extract.field)
    elif loc == "cookie":
        val = resp.cookies.get(extract.field)
    elif loc == "regex":
        try:
            m = re.search(extract.field, resp.text or "")
        except re.error as e:
            raise LoginError(f"step extract {extract.name!r}: invalid regex pattern ({e})") from e
        if m is None:
            raise LoginError(f"step extract {extract.name!r}: regex matched nothing in the body")
        val = m.group(1) if m.groups() else m.group(0)   # first capture group, else whole match
    else:  # defensive: _extract_from validates location
        raise LoginError(f"step extract {extract.name!r}: unknown location {loc!r}")
    if not val or not isinstance(val, str):
        raise LoginError(f"step extract {extract.name!r}: no value at {loc} {extract.field!r}")
    return val.strip()


def _apply_injection(
    inject: Optional["Inject"], captured: Dict[str, SecretStr], base_body: Optional[Dict[str, Any]],
) -> Tuple[Dict[str, str], Optional[Dict[str, Any]]]:
    """Build (headers, body) with declared captured values injected. Captured values are revealed
    only here, at request-build time (like the password), never logged. An injection referencing an
    unknown captured name -> LoginError (mis-declared sequence -> NOT DATA, never a verdict)."""
    headers: Dict[str, str] = {}
    body = dict(base_body) if base_body is not None else None
    if inject is None:
        return headers, body

    def _val(cap_name: str, where: str) -> str:
        sec = captured.get(cap_name)
        if sec is None:
            raise LoginError(f"{where} references undefined captured value {cap_name!r}")
        return reveal_secret(sec)

    for header_name, cap_name in inject.headers.items():
        headers[header_name] = _val(cap_name, f"inject.headers[{header_name!r}]")
    for field_name, cap_name in inject.body.items():
        if body is None:
            body = {}
        body[field_name] = _val(cap_name, f"inject.body[{field_name!r}]")
    return headers, body


async def _run_login_sequence(
    cred: "Credential", spec: "LoginSpec", base_url: str,
    scope: Optional[ScopePolicy], session: "LoginSession",
) -> "LoginResponse":
    """Run the ordered pre-login steps then the login, ALL on ONE per-account `session`. The
    captured-value store is LOCAL to this call (per account). Every request is scope-checked
    fail-closed BEFORE bytes go out and follows redirects per-hop-scoped inside the session. Returns
    the final login response for token extraction. Any failure -> LoginError (NOT DATA)."""
    captured: Dict[str, SecretStr] = {}   # per-account, per-call — NEVER shared across accounts
    for step in spec.steps:
        url = _join_login_url(base_url, step.path)
        _scope_check_login_url(scope, url)                        # fail-closed BEFORE bytes go out
        headers, body = _apply_injection(step.inject, captured, base_body=None)
        try:
            resp = await session.request(step.method, url, json_body=body, headers=headers)
        except ScopeViolationError as e:                          # out-of-scope redirect hop refused
            raise LoginError(f"login step {step.path!r}: {e}") from e
        if not (200 <= resp.status < 300):
            raise LoginError(f"login step {step.path!r} failed: HTTP {resp.status}")
        if step.extract is not None:
            captured[step.extract.name] = SecretStr(_extract_captured(step.extract, resp))

    url = _join_login_url(base_url, spec.path)
    _scope_check_login_url(scope, url)
    login_body: Dict[str, Any] = {
        spec.username_field: cred.username,
        spec.password_field: reveal_secret(cred.password),       # revealed only here
    }
    headers, login_body = _apply_injection(spec.inject, captured, base_body=login_body)
    try:
        resp = await session.request(spec.method, url, json_body=login_body, headers=headers)
    except ScopeViolationError as e:
        raise LoginError(f"login request: {e}") from e
    if not (200 <= resp.status < 300):
        raise LoginError(f"login failed: HTTP {resp.status}")
    return resp


# ==============================================================================
# OAuth 2.0 grant execution (slice 3). Reuses the per-account isolation weld (ONE LoginSession per
# account via session_factory -> own client + cookie jar + PKCE verifier + captured code/token) and
# the SAME fail-closed scope gate (`_scope_check_login_url` -> ScopePolicy.check) the step machinery
# uses. The authorize-chain redirects are handled MANUALLY, per hop, each scope-checked BEFORE bytes
# leave; an out-of-scope hop (e.g. a redirect to an external IdP NOT in the declared scope) is REFUSED
# (LoginError), never followed. The ONLY declared exception is the operator's OWN redirect_uri: the
# flow STOPS there and READS the code from the Location — it never sends bytes to redirect_uri, so it
# cannot leave scope. This is NOT a weaker parallel scope check; it is the same policy, per hop.
# ==============================================================================
_OAUTH_MAX_REDIRECTS = 10


def _pkce_pair() -> Tuple[str, str]:
    """A fresh PKCE (verifier, S256 challenge). Generated PER ACCOUNT, per grant — a local pair,
    never shared across accounts. The verifier is high-entropy and is NEVER logged."""
    verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode("ascii")
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def _rand_state() -> str:
    """A fresh anti-CSRF `state` value (per authorize request)."""
    return base64.urlsafe_b64encode(os.urandom(16)).rstrip(b"=").decode("ascii")


def _matches_redirect_uri(target: str, redirect_uri: str) -> bool:
    """True iff `target` is the operator's declared redirect_uri (scheme + host + port + path; the
    query is ignored because the authorization code lives IN the query)."""
    t, r = urlsplit(target), urlsplit(redirect_uri)
    return (t.scheme.lower(), (t.hostname or "").lower(), t.port, t.path) == \
           (r.scheme.lower(), (r.hostname or "").lower(), r.port, r.path)


def _build_authorize_url(base_url: str, oauth: "OAuthConfig", challenge: str) -> str:
    """The authorization-endpoint URL with the standard query params (+ PKCE S256 challenge when
    enabled). urljoin-normalized against base_url; the RESULT is ScopePolicy.check()-ed by the caller
    before any bytes leave."""
    url = _join_login_url(base_url, oauth.authorize_url)
    params = {"response_type": "code", "client_id": oauth.client_id,
              "redirect_uri": oauth.redirect_uri, "state": _rand_state()}
    if oauth.scope:
        params["scope"] = oauth.scope
    if oauth.pkce:
        params["code_challenge"] = challenge
        params["code_challenge_method"] = "S256"
    sep = "&" if urlsplit(url).query else "?"
    return url + sep + urlencode(params)


async def _oauth_capture_code(session: "LoginSession", authorize_url: str, oauth: "OAuthConfig",
                              scope: Optional[ScopePolicy]) -> str:
    """Drive the authorize request and capture the authorization `code` from the redirect to the
    declared redirect_uri. Each hop is scope-checked fail-closed BEFORE bytes leave (the SAME gate as
    the step machinery); an out-of-scope hop is REFUSED, never followed. The code is READ from the
    redirect_uri Location — redirect_uri itself is never REQUESTED (so the flow cannot leave scope)."""
    url = authorize_url
    for _ in range(_OAUTH_MAX_REDIRECTS):
        _scope_check_login_url(scope, url)                        # fail-closed BEFORE any bytes leave
        resp = await session.oauth_get_no_follow(url)
        if 300 <= resp.status < 400:
            loc = _header_lookup(resp.headers, "location")
            if not loc:
                raise LoginError("OAuth authorize: redirect had no Location header")
            target = urljoin(url, loc)
            if _matches_redirect_uri(target, oauth.redirect_uri):
                q = dict(parse_qsl(urlsplit(target).query))
                if q.get("error"):                                # e.g. access_denied — a real signal, not a code
                    raise LoginError(f"OAuth authorize returned error {q.get('error')!r} (no code)")
                code = q.get(oauth.code_param)
                if not code:
                    raise LoginError(f"OAuth authorize redirect carried no {oauth.code_param!r}")
                return code                                       # READ the code; never REQUEST redirect_uri
            url = target                                          # in-scope intermediate hop -> loop (scope-checked next)
            continue
        raise LoginError(f"OAuth authorize did not redirect to redirect_uri (HTTP {resp.status})")
    raise LoginError("OAuth authorize exceeded the redirect budget")


def _extract_oauth_token(oauth: "OAuthConfig", resp: "LoginResponse") -> Tuple[str, Optional[float]]:
    """Read (access_token, ttl_seconds) from the token response. `ttl` is `expires_in` (relative
    seconds) when present, else None (the caller falls back to the JWT `exp`). The token is NEVER
    logged; a non-2xx / missing token -> LoginError (NOT DATA)."""
    if not (200 <= resp.status < 300):
        raise LoginError(f"OAuth token endpoint failed: HTTP {resp.status}")
    tok = resp.body.get(oauth.token_field)
    if not tok or not isinstance(tok, str):
        raise LoginError(f"OAuth token response had no token in field {oauth.token_field!r}")
    ei = resp.body.get("expires_in")
    ttl = float(ei) if isinstance(ei, (int, float)) and not isinstance(ei, bool) and ei > 0 else None
    return tok.strip(), ttl


async def _oauth_password_grant(
    cred: "Credential", oauth: "OAuthConfig", base_url: str,
    scope: Optional[ScopePolicy], session: "LoginSession",
) -> Tuple[str, Optional[float]]:
    """Resource-owner-password grant: ONE form POST to token_url. Secrets revealed only here."""
    data = {"grant_type": "password", "client_id": oauth.client_id,
            "username": cred.username, "password": reveal_secret(cred.password)}   # revealed only here
    if oauth.scope:
        data["scope"] = oauth.scope
    if oauth.client_secret is not None:
        data["client_secret"] = reveal_secret(oauth.client_secret)                 # revealed only here
    url = _join_login_url(base_url, oauth.token_url)
    _scope_check_login_url(scope, url)
    resp = await session.oauth_post_form(url, data)
    return _extract_oauth_token(oauth, resp)


async def _oauth_authcode_grant(
    cred: "Credential", spec: "LoginSpec", oauth: "OAuthConfig", base_url: str,
    scope: Optional[ScopePolicy], session: "LoginSession",
) -> Tuple[str, Optional[float]]:
    """Authorization-code grant (+ PKCE), all on ONE per-account session:
      1. authenticate the operator's OWN account (reuse the form-login sequence: steps + login POST),
      2. GET authorize_url and capture the `code` from the redirect_uri (per-hop scope-checked),
      3. exchange code (+ PKCE verifier) at token_url (form POST).
    The PKCE verifier is generated per account and is never shared or logged."""
    verifier, challenge = _pkce_pair() if oauth.pkce else ("", "")
    # 1. Establish the authenticated account session (its response is NOT the token here).
    await _run_login_sequence(cred, spec, base_url, scope, session)
    # 2. Authorize -> capture the code (stop+read at the declared redirect_uri).
    authorize_url = _build_authorize_url(base_url, oauth, challenge)
    code = await _oauth_capture_code(session, authorize_url, oauth, scope)
    # 3. Token exchange.
    data = {"grant_type": "authorization_code", "code": code,
            "client_id": oauth.client_id, "redirect_uri": oauth.redirect_uri}
    if oauth.pkce:
        data["code_verifier"] = verifier
    if oauth.client_secret is not None:
        data["client_secret"] = reveal_secret(oauth.client_secret)                 # revealed only here
    token_url = _join_login_url(base_url, oauth.token_url)
    _scope_check_login_url(scope, token_url)
    resp = await session.oauth_post_form(token_url, data)
    return _extract_oauth_token(oauth, resp)


async def _run_oauth_grant(
    cred: "Credential", spec: "LoginSpec", base_url: str,
    scope: Optional[ScopePolicy], session: "LoginSession",
) -> Tuple[str, Optional[float]]:
    """Dispatch the OAuth grant on ONE per-account session. Returns (access_token, ttl_seconds)."""
    oauth = spec.oauth
    if oauth is None:   # defensive: refresh() only routes here when grant is an OAuth grant
        raise LoginError("OAuth grant selected but no 'oauth' config present")
    if oauth.grant == "password":
        return await _oauth_password_grant(cred, oauth, base_url, scope, session)
    return await _oauth_authcode_grant(cred, spec, oauth, base_url, scope, session)


class TokenProvider:
    """Obtains and refreshes ONE account's token via login. Holds no other account's state.

    `token()` returns a valid token, re-logging-in when there is none cached or the cached JWT
    is within `refresh_margin` of expiry (proactive). `refresh()` forces a new login (reactive,
    e.g. after a 401). Every login is scope-checked and uses its own fresh HTTP client (a fresh
    per-call client for a single-request login, or a fresh per-account session for a multi-step one)."""

    def __init__(
        self, credential: Credential, spec: LoginSpec, base_url: str,
        scope: Optional[ScopePolicy], *, refresh_margin: float = 10.0,
        http_post: Optional[HttpPost] = None, clock: Callable[[], float] = time.time,
        session_factory: Optional[SessionFactory] = None,
    ) -> None:
        self._cred = credential
        self._spec = spec
        self._base_url = base_url
        self._scope = scope
        self._refresh_margin = refresh_margin
        self._http_post = http_post or _default_http_post          # single-request (no-steps) path
        self._session_factory = session_factory or _default_session_factory  # multi-step path
        self._clock = clock
        self._cached: Optional[Tuple[str, Optional[float]]] = None   # (token, exp)

    async def token(self) -> str:
        if self._cached is not None:
            tok, exp = self._cached
            if exp is None or (exp - self._clock()) > self._refresh_margin:
                return tok
        return await self.refresh()

    async def refresh(self) -> str:
        if self._spec.grant in _OAUTH_GRANTS:
            # OAuth grant: the token's expiry comes from `expires_in` (absolute-ized via THIS
            # provider's clock, for consistency with proactive refresh) or, absent that, the JWT exp.
            tok, ttl = await self._login_oauth()
            self._cached = (tok, (self._clock() + ttl) if ttl is not None else _jwt_exp(tok))
        else:
            tok = await self._login()                                # form path — unchanged
            self._cached = (tok, _jwt_exp(tok))
        return tok

    async def _login(self) -> str:
        # Multi-step (has `steps` or `inject`) -> run the ordered sequence on ONE per-account
        # session. No steps/inject -> the single-request path below, BYTE-IDENTICAL to slice 1.
        if self._spec.steps or self._spec.inject is not None:
            return await self._login_sequence()
        url = _reconstruct_login_url(self._base_url, self._spec.path)
        if self._scope is not None and not self._scope.check(url).allowed:
            raise LoginError("login endpoint is out of scope (refused before any request was sent)")
        body = {
            self._spec.username_field: self._cred.username,
            self._spec.password_field: reveal_secret(self._cred.password),   # revealed only here
        }
        resp = _as_login_response(await self._http_post(self._spec.method, url, body))
        if not (200 <= resp.status < 300):
            raise LoginError(f"login failed: HTTP {resp.status}")
        return _extract_token(self._spec, resp)   # body / header / cookie — value never logged

    async def _login_sequence(self) -> str:
        """Multi-step login: a FRESH per-account session (its own client + cookie jar + captured
        store) runs the ordered steps then the login. Nothing is shared with any other account's
        provider, so the obtained token can only be THIS account's identity."""
        session = self._session_factory(self._scope)
        try:
            resp = await _run_login_sequence(self._cred, self._spec, self._base_url, self._scope, session)
        finally:
            await session.aclose()
        return _extract_token(self._spec, resp)   # body / header / cookie — value never logged

    async def _login_oauth(self) -> Tuple[str, Optional[float]]:
        """OAuth grant on a FRESH per-account session (its OWN client + cookie jar + PKCE verifier +
        captured code/token). Nothing is shared with any other account's provider — identical to the
        multi-step isolation weld — so the obtained token can only be THIS account's identity."""
        session = self._session_factory(self._scope)
        try:
            return await _run_oauth_grant(self._cred, self._spec, self._base_url, self._scope, session)
        finally:
            await session.aclose()
