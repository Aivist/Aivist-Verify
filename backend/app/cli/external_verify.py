# ==============================================================================
# `<brand> verify --target ...` — run the confirmer against an EXTERNAL, locally-run
# REAL target (e.g. OWASP crAPI), in addition to the built-in caseset lab.
#
# This is ORCHESTRATION / INPUT-LAYER only. It assembles a user-supplied target
# (base URL + OpenAPI spec + one operation + two bearer tokens) into the SAME
# `execute_deep_verification(...)` call the lab harness builds. It does NOT change how
# the engine judges: deep_verifier (four channels / cross-resource guard / D24 / D19),
# fuzzer._differential_verdict, and scope.py's enforcement are reused verbatim.
#
# THREE RED LINES, held structurally (see tests):
#   1. Scope fail-closed. `approved_host` is derived from --target and passed to the
#      engine, which declares it to ScopePolicy and .check()s EVERY request (existing
#      code). No exemption for "the user gave it"; an out-of-scope request -> refused.
#   2. Attacker/owner identity isolation. The attacker token becomes the attack
#      `auth_context` ONLY; the owner token becomes an `OwnerCredential` consumed ONLY by
#      the GET-only, custody-free `fetch_owner_view`. They are separate variables, never
#      merged — the owner token can never appear in an attack request.
#   3. Credentials are SecretStr, redacted, never logged. Both tokens are held as
#      SecretStr and unwrapped only at the point of use (building the attack header /
#      the OwnerCredential); the rendered record carries no token, and all output passes
#      the existing credential redactor.
#
# ACCEPTANCE REFRAME (honored): a real target has NO ground truth, so there is NO
# zero-false-positive claim anywhere. On timeout / 429 / 401 / 403 / transport error the
# run is NOT DATA — never silently rendered "safe" or "vulnerable" (a challenge / rate
# limit is not a security signal).
# ==============================================================================
from __future__ import annotations

import asyncio
import getpass
import json
import os
import re
import sys
import tomllib
import uuid
from typing import Any, Callable, Dict, Optional, Tuple
from urllib.parse import urlsplit, parse_qsl, urlencode

from pydantic import SecretStr

from backend.app.core.config import settings, reveal_secret
from backend.app.cli import branding
from backend.app.cli import relogin
from backend.app.cli.confirm_render import render_tree, exit_code_for
from backend.app.services.endpoint_catalog import catalog_from_openapi
from backend.app.services.scope import ScopePolicy
from backend.app.services.deep_verifier import OwnerCredential, execute_deep_verification

# A challenged / auth-failed / rate-limited response is NOT a security signal -> NOT DATA.
_CHALLENGE_STATUSES = frozenset({401, 403, 429})
_HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9-]+$")

# Per-user config keys the two target tokens may be stored under (read directly here as
# SecretStr; see _resolve_tokens). The config flow does not write these yet — a user adds
# them, or supplies them at the masked prompt.
_CFG_ATTACKER_KEY = "TARGET_ATTACKER_TOKEN"
_CFG_OWNER_KEY = "TARGET_OWNER_TOKEN"
# D30: the THIRD/bystander token (a principal with no ownership of the attacked object). Optional;
# read from the per-user config file ONLY (never a CLI flag; no interactive prompt, so the existing
# attacker/owner prompt sequence is unchanged). Absent => None => no bystander probe (D30 unmitigated,
# byte-identical). It flows ONLY into `bystander_credential`, never into an attack request.
_CFG_BYSTANDER_KEY = "TARGET_BYSTANDER_TOKEN"


# ------------------------------------------------------------------------------
# Pure input helpers (offline-testable).
# ------------------------------------------------------------------------------
def _load_json(path: str) -> Dict[str, Any]:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _load_spec_file(path: str) -> Dict[str, Any]:
    """Read an OpenAPI/Swagger spec file into a dict for `--spec`. A `.json` spec is parsed
    exactly as before (byte-identical); a `.yml`/`.yaml` spec (e.g. VAmPI's openapi3.yml) is
    parsed with yaml.safe_load. The parsed dict feeds the SAME `catalog_from_openapi` — only the
    read changes, nothing downstream.

    SECURITY: YAML is parsed with yaml.safe_load ONLY, never the unsafe loader — safe_load cannot
    deserialize arbitrary Python objects, so a hostile spec file cannot execute code. A malformed
    file raises (json.JSONDecodeError / yaml.YAMLError), which the caller turns into the graceful
    '[NOT DATA] could not read --spec' path — never a crash."""
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    if path.lower().endswith((".yml", ".yaml")):
        import yaml  # lazy: pure-JSON specs never need PyYAML imported
        return yaml.safe_load(text)
    try:
        return json.loads(text)               # .json / no-ext: JSON first (byte-identical)
    except json.JSONDecodeError:
        import yaml                            # courtesy: a YAML spec under a non-yaml name still loads
        return yaml.safe_load(text)


def _approved_host(base_url: str) -> str:
    """host[:port] of the external target — the scope DECLARATION handed to the engine.
    Mirrors the lab's `approved = '127.0.0.1:<port>'`. Including the port locks scope to
    that exact host+port (ScopePolicy: explicit port => strict host+port lock)."""
    parts = urlsplit(base_url if "://" in base_url else "http://" + base_url)
    host = (parts.hostname or "").strip()
    try:
        port = parts.port
    except ValueError:
        port = None
    return f"{host}:{port}" if port else host


def _fill_unique(body: Optional[Dict[str, Any]], unique: str) -> Optional[Dict[str, Any]]:
    """Replace a '$UNIQUE' sentinel with a fresh high-entropy value (mirrors the lab
    harness), so write-shape payload-causality has a unique value to trace on a real target."""
    if body is None:
        return None
    return {k: (unique if v == "$UNIQUE" else v) for k, v in body.items()}


def _split_path_query(raw_path: str) -> Tuple[str, Dict[str, str]]:
    """Split a baseline_path into (path, query_params). A path with no '?' yields an empty
    dict — byte-identical to the pre-existing path-based behavior. This lets a query-string id
    be expressed in the op (`/…/mechanic_report?report_id=7`) and carried on the BASELINE
    request, exactly as a path id is carried in the path (D29 — query-string IDOR)."""
    parts = urlsplit(raw_path)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    return (parts.path or raw_path), query


def _build_parsed_request(op: Dict[str, Any], unique: str) -> Dict[str, Any]:
    """The BASELINE request dict the engine consumes — same shape verdict_measure builds.

    A query string in `baseline_path` is parsed into `query_params` so the BASELINE carries
    the attacker's OWN query id; the engine's `query_param` mutation then swaps only that id
    for the attack (D29). For a path-based op (no '?') `query_params` is `{}`, unchanged."""
    body = _fill_unique(op.get("body"), unique)
    path, query_params = _split_path_query(op["baseline_path"])
    return {
        "method": op["method"],
        "path": path,
        "query_params": query_params,
        "headers": {"Content-Type": "application/json"} if body else {},
        "body": body,
    }


def _attack_path_from_op(op: Dict[str, Any]) -> str:
    """The concrete path the attack hits (baseline path with the id swapped in), for the
    rendered header / Reproduce line only. Mirrors verdict_measure._attack_path.

    For a `query_param` payload the swap is on the target query param's VALUE (keeping a
    single '?'), matching the actual attack the engine sends (D29); path-based cases are a
    literal substring replace, unchanged."""
    p = op.get("payload")
    if not p:
        return op.get("baseline_path", "")
    if str(p.get("location", "")).lower() == "query_param":
        path, query = _split_path_query(op["baseline_path"])
        query[str(p.get("target_param"))] = str(p.get("payload_string"))
        qs = urlencode(query)
        return f"{path}?{qs}" if qs else path
    return op["baseline_path"].replace(str(p.get("target_param")), str(p.get("payload_string")))


def _auth_header(raw: str) -> Dict[str, str]:
    """Parse the ATTACKER credential into ONE request header.

    Deliberately a SEPARATE function from OwnerCredential.from_config (which parses the
    OWNER credential): the attacker header is a plain dict and NEVER an OwnerCredential, so
    the two identities cannot be conflated (red line 2). Grammar mirrors from_config:
    'Header-Name: value' | 'Bearer <token>' | a bare token (=> 'Authorization: Bearer ...')."""
    text = (raw or "").strip()
    name, sep, value = text.partition(":")
    if sep and _HEADER_NAME_RE.match(name.strip()) and value.strip():
        return {name.strip(): value.strip()}
    if text.lower().startswith("bearer "):
        return {"Authorization": text}
    return {"Authorization": f"Bearer {text}"}


def _resolve_tokens(
    config_path: str, prompt_secret: Callable[[str], str],
) -> Tuple[SecretStr, Optional[SecretStr]]:
    """Attacker (required) + owner (optional) tokens, as SecretStr. Read from the per-user
    config file if present, else a masked prompt. No raw-token CLI flag exists (avoids
    shell-history / process-list leakage). Values become SecretStr immediately."""
    cfg: Dict[str, Any] = {}
    try:
        if config_path and os.path.isfile(config_path):
            with open(config_path, "rb") as fh:
                loaded = tomllib.load(fh)
            if isinstance(loaded, dict):
                cfg = loaded
    except Exception:
        cfg = {}

    attacker = str(cfg.get(_CFG_ATTACKER_KEY) or "").strip()
    if not attacker:
        attacker = (prompt_secret("Attacker bearer token (input hidden): ") or "").strip()
    if not attacker:
        raise ValueError("an attacker token is required")

    owner = str(cfg.get(_CFG_OWNER_KEY) or "").strip()
    if not owner:
        owner = (prompt_secret("Owner/victim bearer token (hidden; blank to skip owner-view): ") or "").strip()

    return SecretStr(attacker), (SecretStr(owner) if owner else None)


def _resolve_bystander_token(config_path: str) -> Optional[SecretStr]:
    """The D30 THIRD/bystander token as a SecretStr, or None. Read from the per-user config file
    ONLY (key TARGET_BYSTANDER_TOKEN) — deliberately NOT prompted, so the attacker/owner masked-
    prompt sequence stays exactly as it was. Absent / unreadable => None => no bystander probe
    (byte-identical behavior). Never raises."""
    try:
        if config_path and os.path.isfile(config_path):
            with open(config_path, "rb") as fh:
                loaded = tomllib.load(fh)
            if isinstance(loaded, dict):
                val = str(loaded.get(_CFG_BYSTANDER_KEY) or "").strip()
                if val:
                    return SecretStr(val)
    except Exception:
        pass
    return None


def classify_degradation(result: Any) -> Optional[str]:
    """CLI-layer honesty gate (DOWNGRADE-ONLY): the reason this real-target run is NOT DATA,
    or None if the engine's verdict may stand. It NEVER manufactures a verdict — it only
    decides whether the run is trustworthy. A timeout / transport failure already surfaces
    as status!='completed' or ai_verdict=None; a 401/403/429 RESPONSE on the baseline,
    attack, or follow-up is a challenge / auth-failure / rate-limit and is NOT a security
    signal, so it is NOT DATA too (never 'safe', never 'vulnerable')."""
    if getattr(result, "status", None) != "completed" or getattr(result, "ai_verdict", None) is None:
        return getattr(result, "degraded_reason", None) or "engine degraded / no usable verdict"
    for name in ("baseline", "attack"):
        trail = getattr(result, name, None) or {}
        code = (trail.get("response") or {}).get("status_code")
        if code in _CHALLENGE_STATUSES:
            return (f"{name} request returned HTTP {code} "
                    f"(auth / challenge / rate-limit — not a security signal)")
    fu = getattr(result, "follow_up_response", None) or {}
    if fu.get("status_code") in _CHALLENGE_STATUSES:
        return (f"follow-up read returned HTTP {fu.get('status_code')} "
                f"(auth / challenge / rate-limit — not a security signal)")
    return None


def _record_from_result(result: Any, op: Dict[str, Any], deg_reason: Optional[str]) -> Dict[str, Any]:
    """Build the flat record the renderer consumes from the engine result. When degraded,
    the verdict is forced to NONE + NOT DATA (never 'safe'/'vulnerable'). ground_truth is
    None on a real target (no zero-FP claim). Carries NO credential."""
    degraded = bool(deg_reason)
    return {
        "shape": op.get("shape", "external"),
        "ground_truth": None,                        # real target: nothing to compare against
        "final_verdict": None if degraded else getattr(result, "ai_verdict", None),
        "ai_verdict_raw": getattr(result, "ai_verdict_raw", None),
        "guard_override": getattr(result, "guard_override", None),
        "status": "degraded" if degraded else getattr(result, "status", None),
        "degraded": degraded,
        "degraded_reason": deg_reason,
        "caller_identity": getattr(result, "caller_identity_anchor", None),
        "payload_causality": getattr(result, "payload_causality_anchor", None),
        "state_jump": getattr(result, "state_jump_anchor", None),
        "negative_assertion": getattr(result, "negative_assertion_anchor", None),
        "anchoring_result": getattr(result, "anchoring_result", None),
        "pre_flight_status": getattr(result, "pre_flight_status", None),
        "owner_view_corroborated": getattr(result, "owner_view_corroborated", None),
        "broken_for_all_suspected": getattr(result, "broken_for_all_suspected", None),
        "owner_view_similarity": None,
        # header + Reproduce line (no credentials):
        "method": op.get("method"),
        "baseline_path": op.get("baseline_path"),
        "attack_path": _attack_path_from_op(op),
        "body": op.get("body"),
    }


# ------------------------------------------------------------------------------
# Assembly + run.
# ------------------------------------------------------------------------------
async def _verify_external(
    target: str, spec: Dict[str, Any], op: Dict[str, Any],
    attacker_tok: SecretStr, owner_tok: Optional[SecretStr], model: Optional[str], engine: Callable,
    bystander_tok: Optional[SecretStr] = None,
) -> Any:
    """Assemble external inputs into the ONE existing engine call. The attacker token flows
    ONLY into auth_context; the owner token ONLY into owner_credential; the bystander token ONLY
    into bystander_credential (red line 2 — three separate variables, never merged). The bystander
    credential is consumed solely by the D30 public-resource discrimination check (downgrade-only,
    fail-safe) and is NEVER used for an attack request."""
    approved = _approved_host(target)
    catalog = catalog_from_openapi(spec)
    unique = f"ext-{uuid.uuid4().hex[:12]}"
    parsed = _build_parsed_request(op, unique)

    auth_context = _auth_header(reveal_secret(attacker_tok))                 # attacker ONLY
    owner_cred = (OwnerCredential.from_config(reveal_secret(owner_tok))       # owner ONLY
                  if owner_tok is not None else None)
    bystander_cred = (OwnerCredential.from_config(reveal_secret(bystander_tok))   # bystander ONLY
                      if bystander_tok is not None else None)

    return await engine(
        parsed_request=parsed,
        payload=op.get("payload"),
        base_url=target,
        approved_host=approved,             # scope declaration -> fail-closed .check() (red line 1)
        auth_context=auth_context,
        available_endpoints=catalog,
        owner_credential=owner_cred,
        bystander_credential=bystander_cred,
        challenge_break=True,               # real target -> run-level WAF/rate-limit circuit breaker
        assert_owner_only=bool(op.get("assert_owner_only")),   # opt-in broken-for-all disclosure
        model_name=model,
    )


def _auth_degraded(result: Any) -> bool:
    """True iff the engine result shows a 401 on the baseline or attack request — the
    token-expiry / auth-failure signal a re-login may fix. (403/429 are challenge/rate-limit,
    NOT token expiry, so they are not retried here; they stay NOT DATA via classify_degradation.)"""
    for name in ("baseline", "attack"):
        trail = getattr(result, name, None) or {}
        if (trail.get("response") or {}).get("status_code") == 401:
            return True
    return False


async def _verify_external_relogin(
    target: str, spec: Dict[str, Any], op: Dict[str, Any],
    login_spec: relogin.LoginSpec, attacker_cred: relogin.Credential,
    owner_cred: relogin.Credential, model: Optional[str], engine: Callable,
    *, http_post=None, bystander_cred: Optional[relogin.Credential] = None,
) -> Any:
    """Obtain the tokens by INDEPENDENT logins (separate providers / clients / credentials —
    red line 1), feed them into the SAME `_verify_external` engine call the static path uses, and
    — if a request 401s (token expired) — re-log-in the accounts and retry the engine ONCE. The
    owner token only ever becomes an `OwnerCredential`; it can never enter an attack request.

    D30: an OPTIONAL third/bystander account (default None => no bystander login, byte-identical —
    the existing attacker+owner login flow and its login-call count are unchanged). When supplied it
    logs in INDEPENDENTLY (its own TokenProvider / client / credential), and its token flows ONLY
    into `bystander_credential` for the downgrade-only public-resource check — never an attack."""
    scope = ScopePolicy.from_declaration([_approved_host(target)])
    attacker = relogin.TokenProvider(attacker_cred, login_spec, target, scope, http_post=http_post)
    owner = relogin.TokenProvider(owner_cred, login_spec, target, scope, http_post=http_post)
    bystander = (relogin.TokenProvider(bystander_cred, login_spec, target, scope, http_post=http_post)
                 if bystander_cred is not None else None)

    attacker_tok = SecretStr(await attacker.token())      # fresh login (proactive, near-expiry aware)
    owner_tok = SecretStr(await owner.token())
    bystander_tok = SecretStr(await bystander.token()) if bystander is not None else None
    result = await _verify_external(target, spec, op, attacker_tok, owner_tok, model, engine,
                                    bystander_tok=bystander_tok)

    if _auth_degraded(result):                            # 401 -> re-login + retry ONCE
        attacker_tok = SecretStr(await attacker.refresh())
        owner_tok = SecretStr(await owner.refresh())
        if bystander is not None:
            bystander_tok = SecretStr(await bystander.refresh())
        result = await _verify_external(target, spec, op, attacker_tok, owner_tok, model, engine,
                                        bystander_tok=bystander_tok)
    return result


def run_external_verify(
    *,
    target: str,
    spec_path: str,
    op_path: str,
    model: Optional[str] = None,
    prompt_secret: Callable[[str], str] = getpass.getpass,
    prompt: Callable[[str], str] = input,
    config_path: Optional[str] = None,
    engine: Callable = execute_deep_verification,
    echo: Callable[..., None] = print,
    err: Optional[Callable[..., None]] = None,
    auth_spec_path: Optional[str] = None,
    http_post=None,
) -> int:
    """Run `verify` against a locally-run external real target. Returns a process exit code
    (0 nothing confirmed · 1 confirmed · 2 NOT DATA / input error). I/O is injectable for
    offline tests (prompt / prompt_secret / engine / echo / err / config_path / http_post).

    Tokens come EITHER from static tokens (default) OR, when `auth_spec_path` (`--auth`) is
    given, from an auto re-login flow (see relogin.py) — either/or; the static path is unchanged.
    Whichever the source, the same `_verify_external` engine call is built (byte-identical)."""
    if err is None:
        def err(*a):  # default: stderr
            print(*a, file=sys.stderr)

    if not (reveal_secret(settings.LLM_API_KEY) or reveal_secret(settings.GEMINI_API_KEY)):
        err(f"No API key configured. Run  {branding.command_name()} config  to set one up "
            f"(provider, key, model) - or set GEMINI_API_KEY / LLM_API_KEY. Nothing was sent.")
        return 2

    try:
        spec = _load_spec_file(spec_path)     # JSON or YAML (--spec); op stays JSON below
        op = _load_json(op_path)
    except Exception as e:
        err(f"[NOT DATA] could not read --spec / --op: {type(e).__name__}: {e}")
        return 2
    if not op.get("method") or not op.get("baseline_path"):
        err("[NOT DATA] the --op JSON must include 'method' and 'baseline_path'.")
        return 2

    cfg = config_path or branding.config_file_path()

    if auth_spec_path:
        # RE-LOGIN mode (--auth): obtain both tokens by INDEPENDENT logins (either/or vs static).
        try:
            login_spec = relogin.LoginSpec.from_file(auth_spec_path)
            attacker_cred, owner_cred = relogin.resolve_login_credentials(cfg, prompt, prompt_secret)
            # D30: optional third/bystander login credential (config-file only; None => no bystander).
            bystander_cred = relogin.resolve_bystander_login_credential(cfg)
        except Exception as e:
            err(f"[NOT DATA] could not set up --auth re-login: {type(e).__name__}: {e}")
            return 2
        # Runtime-only enablement (committed config defaults stay False), mirroring the lab path.
        settings.AI_DEEP_VERIFY_ENABLED = True
        try:
            result = asyncio.run(_verify_external_relogin(
                target, spec, op, login_spec, attacker_cred, owner_cred, model, engine,
                http_post=http_post, bystander_cred=bystander_cred,
            ))
        except Exception as e:
            # login failure / token-refresh failure / scope violation -> NOT DATA, never "safe".
            err(f"[NOT DATA] run error against {target}: {type(e).__name__}: {e}")
            return 2
    else:
        # STATIC-token mode (unchanged attacker/owner; optional D30 bystander from config file).
        try:
            attacker_tok, owner_tok = _resolve_tokens(cfg, prompt_secret)
        except Exception as e:
            err(f"[NOT DATA] no usable attacker token: {e}")
            return 2
        bystander_tok = _resolve_bystander_token(cfg)   # config-file only; None => no bystander probe
        # Runtime-only enablement (committed config defaults stay False), mirroring the lab path.
        settings.AI_DEEP_VERIFY_ENABLED = True
        try:
            result = asyncio.run(
                _verify_external(target, spec, op, attacker_tok, owner_tok, model, engine,
                                 bystander_tok=bystander_tok)
            )
        except Exception as e:
            err(f"[NOT DATA] run error against {target}: {type(e).__name__}: {e}")
            return 2

    deg = classify_degradation(result)
    record = _record_from_result(result, op, deg)
    echo(f"[real target: {target}]  (no ground truth - an engineering signal, NOT a zero-FP claim)")
    echo(render_tree(record))
    return exit_code_for([record])
