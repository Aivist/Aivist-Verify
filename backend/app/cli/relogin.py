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
# SCOPE OF THIS SLICE (do not widen): single-JSON-field token extraction from the login
# response (covers VAmPI and most JWT logins). Tokens in headers/cookies, OAuth redirects,
# multi-step challenges, CSRF and captcha are LATER slices — report, do not build.
# ==============================================================================
from __future__ import annotations

import base64
import getpass
import json
import os
import time
import tomllib
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, Optional, Tuple

import httpx
from pydantic import SecretStr

from backend.app.core.config import reveal_secret
from backend.app.services.scope import ScopePolicy

# Injectable HTTP for tests: (method, url, json_body) -> (status_code, parsed_json_dict).
HttpPost = Callable[[str, str, Dict[str, Any]], Awaitable[Tuple[int, Dict[str, Any]]]]

# Per-user config keys for the two accounts' login credentials (sensitive; same privacy
# discipline as the static tokens — file/prompt only, never the command line).
_CFG_ATTACKER_USER = "TARGET_ATTACKER_USERNAME"
_CFG_ATTACKER_PASS = "TARGET_ATTACKER_PASSWORD"
_CFG_OWNER_USER = "TARGET_OWNER_USERNAME"
_CFG_OWNER_PASS = "TARGET_OWNER_PASSWORD"


class LoginError(Exception):
    """A login / token-refresh failure. Message carries only non-secret detail (status code,
    field name) so it is safe to surface. The caller turns it into the NOT-DATA path."""


@dataclass(frozen=True)
class LoginSpec:
    """The `--auth login.json` declaration: how to log in and where the token is."""
    method: str
    path: str
    username_field: str
    password_field: str
    token_field: str

    @staticmethod
    def from_file(path: str) -> "LoginSpec":
        with open(path, encoding="utf-8") as fh:
            d = json.load(fh)
        if not isinstance(d, dict):
            raise ValueError("--auth login spec must be a JSON object")
        try:
            return LoginSpec(
                method=str(d.get("method", "POST")).upper(),
                path=str(d["path"]),
                username_field=str(d["username_field"]),
                password_field=str(d["password_field"]),
                token_field=str(d["token_field"]),
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
) -> Tuple[Credential, Credential]:
    """(attacker, owner) login credentials. Read from the per-user config file if present,
    else prompted (username plain, password masked). Passwords become SecretStr immediately."""
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

    return (_cred(_CFG_ATTACKER_USER, _CFG_ATTACKER_PASS, "attacker"),
            _cred(_CFG_OWNER_USER, _CFG_OWNER_PASS, "owner"))


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


async def _default_http_post(method: str, url: str, json_body: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    """Real login request: a FRESH client per call (no shared cookie/auth state — red line 1).
    verify=False matches the engine's self-signed-target posture (TECH_DEBT D13)."""
    async with httpx.AsyncClient(timeout=20.0, verify=False) as client:
        resp = await client.request(method, url, json=json_body)
    try:
        data = resp.json()
    except Exception:
        data = {}
    return resp.status_code, (data if isinstance(data, dict) else {})


class TokenProvider:
    """Obtains and refreshes ONE account's token via login. Holds no other account's state.

    `token()` returns a valid token, re-logging-in when there is none cached or the cached JWT
    is within `refresh_margin` of expiry (proactive). `refresh()` forces a new login (reactive,
    e.g. after a 401). Every login is scope-checked and uses its own fresh HTTP client."""

    def __init__(
        self, credential: Credential, spec: LoginSpec, base_url: str,
        scope: Optional[ScopePolicy], *, refresh_margin: float = 10.0,
        http_post: Optional[HttpPost] = None, clock: Callable[[], float] = time.time,
    ) -> None:
        self._cred = credential
        self._spec = spec
        self._base_url = base_url
        self._scope = scope
        self._refresh_margin = refresh_margin
        self._http_post = http_post or _default_http_post
        self._clock = clock
        self._cached: Optional[Tuple[str, Optional[float]]] = None   # (token, exp)

    async def token(self) -> str:
        if self._cached is not None:
            tok, exp = self._cached
            if exp is None or (exp - self._clock()) > self._refresh_margin:
                return tok
        return await self.refresh()

    async def refresh(self) -> str:
        tok = await self._login()
        self._cached = (tok, _jwt_exp(tok))
        return tok

    async def _login(self) -> str:
        url = _reconstruct_login_url(self._base_url, self._spec.path)
        if self._scope is not None and not self._scope.check(url).allowed:
            raise LoginError("login endpoint is out of scope (refused before any request was sent)")
        body = {
            self._spec.username_field: self._cred.username,
            self._spec.password_field: reveal_secret(self._cred.password),   # revealed only here
        }
        status, data = await self._http_post(self._spec.method, url, body)
        if not (200 <= status < 300):
            raise LoginError(f"login failed: HTTP {status}")
        tok = data.get(self._spec.token_field)
        if not tok or not isinstance(tok, str):
            raise LoginError(f"login response had no token in field {self._spec.token_field!r}")
        return tok
