# ==============================================================================
# Non-interactive `scan` - drive the auto-discovery onramp from a target FILE + tokens, with NO
# interactive prompts. This is the "automate the whole string of config" path: a filled target
# template (target_file.py) supplies the non-secret config; tokens come from ENV VARS or a runtime
# --tokens-file. It reuses the EXACT interactive assembly (run_scan + _verify_external + the report),
# so the engine and its verdict are untouched.
#
# TOKEN RED LINES (welded):
#   * Tokens are NEVER read from - nor written to - the target file. They come ONLY from env vars
#     (TARGET_ATTACKER_TOKEN / TARGET_OWNER_TOKEN / TARGET_BYSTANDER_TOKEN) or a --tokens-file that is
#     read AT USE-TIME and never persisted.
#   * Each token becomes a SecretStr immediately (masked, never echoed) and routes ONLY per account -
#     attacker -> auth_context, owner -> owner_credential, bystander -> bystander_credential - by
#     REUSING _verify_external's existing routing (not a fork).
#   * The attacker!=owner fail-closed collision guard (_identity_collision_reason) fires on the
#     env/file credentials EXACTLY as on interactive ones; on a collision the engine is NEVER called.
# ==============================================================================
from __future__ import annotations

import asyncio
import json
import os
import tomllib
from typing import Any, Callable, Dict, Mapping, Optional, Tuple

from pydantic import SecretStr

from backend.app.core.config import settings, reveal_secret
from backend.app.cli import branding, target_file
from backend.app.cli.external_verify import (
    _verify_external, _identity_collision_reason, _load_spec_file, _load_endpoints_file,
)
from backend.app.services.endpoint_catalog import spec_from_endpoints

# The env / tokens-file keys (the SAME names the config-file token source uses). Reading them from the
# process environment or a runtime file is deliberate - a target file must never carry a token.
_ATTACKER_KEY = "TARGET_ATTACKER_TOKEN"
_OWNER_KEY = "TARGET_OWNER_TOKEN"
_BYSTANDER_KEY = "TARGET_BYSTANDER_TOKEN"


def _parse_tokens_file(path: str) -> Dict[str, str]:
    """Parse a runtime tokens file into {KEY: value}. Accepts TOML (`KEY = "v"`) OR dotenv-style
    (`KEY=v`) lines; '#' comments and blanks ignored; surrounding quotes stripped. Read at use-time,
    NEVER persisted. Raises on a missing/unreadable file (the caller turns it into a clear error)."""
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    try:
        data = tomllib.loads(text)                       # a proper TOML tokens file
        if isinstance(data, dict) and data:
            return {str(k): str(v) for k, v in data.items()}
    except Exception:
        pass
    out: Dict[str, str] = {}
    for raw in text.splitlines():                        # dotenv-style fallback
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        v = v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            v = v[1:-1]
        out[k.strip()] = v
    return out


def resolve_scan_tokens(
    *, tokens_file: Optional[str] = None, environ: Optional[Mapping[str, str]] = None,
) -> Tuple[SecretStr, SecretStr, Optional[SecretStr]]:
    """Resolve (attacker, owner, bystander) tokens NON-INTERACTIVELY, as SecretStr. Sources, merged with
    a --tokens-file taking precedence over env vars per key:
        env  TARGET_ATTACKER_TOKEN / TARGET_OWNER_TOKEN / TARGET_BYSTANDER_TOKEN
        file the same keys (TOML or dotenv), read at use-time and never persisted.
    Attacker AND owner are REQUIRED (the confirm compares two identities); bystander is optional. The
    target FILE is never consulted for a token. Raises ValueError (=> the caller's NOT-DATA path),
    naming every missing token at once, so nothing half-runs."""
    env = environ if environ is not None else os.environ
    src: Dict[str, str] = {k: str(env.get(k) or "").strip() for k in (_ATTACKER_KEY, _OWNER_KEY, _BYSTANDER_KEY)}
    if tokens_file:
        for k, v in _parse_tokens_file(tokens_file).items():   # file overrides env, per key
            if k in src and str(v).strip():
                src[k] = str(v).strip()

    missing = [k for k in (_ATTACKER_KEY, _OWNER_KEY) if not src[k]]
    if missing:
        raise ValueError(
            "missing token(s): " + ", ".join(missing) + " - set them as env vars or in --tokens-file "
            "(never in the target file).")
    bystander = SecretStr(src[_BYSTANDER_KEY]) if src[_BYSTANDER_KEY] else None
    return SecretStr(src[_ATTACKER_KEY]), SecretStr(src[_OWNER_KEY]), bystander


def _load_id_source(path: Optional[str], err: Callable[..., None]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Optional id-source JSON {"ids": {...}, "collections": {...}} - the SAME shape the interactive
    scan accepts. A malformed file is a non-fatal warning (ignored), mirroring do_scan."""
    if not path:
        return {}, {}
    try:
        with open(path, encoding="utf-8") as fh:
            d = json.load(fh)
        return dict(d.get("ids") or {}), dict(d.get("collections") or {})
    except Exception as ex:
        err(f"  ! could not parse the id-source file ({type(ex).__name__}); ignoring it.")
        return {}, {}


def run_scan_from_file(
    target_file_path: str, *,
    tokens_file: Optional[str] = None,
    endpoints_file: Optional[str] = None,
    id_source_file: Optional[str] = None,
    assert_owner_only: bool = False,
    model: Optional[str] = None,
    environ: Optional[Mapping[str, str]] = None,
    echo: Callable[..., None] = print,
    err: Callable[..., None] = print,
    # test seams (offline; no network / no API):
    engine: Optional[Callable] = None,
    scan_provider_factory: Optional[Callable] = None,
    raw_candidates: Optional[list] = None,
    client_factory: Optional[Callable] = None,
) -> int:
    """Non-interactive scan from a target file + tokens. Returns a process exit code
    (0 = ran; 2 = a setup / NOT-DATA / collision refusal before any verdict). Prints the tier-grouped
    scan report. NO prompts. The engine + its verdict are untouched - this only assembles inputs and
    reuses run_scan / _verify_external / render_scan_report."""
    # lazy imports (keep the engine out of module import; mirror do_scan)
    from backend.app.cli.scan_run import run_scan
    from backend.app.cli.scan_report import render_scan_report
    from backend.app.services.deep_verifier import OwnerCredential, execute_deep_verification

    if not (reveal_secret(settings.LLM_API_KEY) or reveal_secret(settings.GEMINI_API_KEY)):
        err("  ! No API key configured - scan needs one for candidate discovery AND the confirm judge. "
            f"Run `{branding.command_name()} config` first. Nothing was sent.")
        return 2

    t, errors = target_file.load_target_file(target_file_path)
    if errors:
        err(f"  ! [NOT DATA] the target file has {len(errors)} problem(s) - fix them and re-run:")
        for e in errors:
            err(f"      - {e}")
        return 2

    # -- tokens: env / --tokens-file ONLY (never the target file); masked SecretStr ------------------
    try:
        attacker_tok, owner_tok, bystander_tok = resolve_scan_tokens(
            tokens_file=tokens_file, environ=environ)
    except Exception as ex:
        err(f"  ! [NOT DATA] {ex}")
        return 2

    # -- #7 FP NAIL (fail-closed): DISTINCT identities required. Fires here, BEFORE any verdict, exactly
    #    as the interactive/verify paths do. On a collision the engine is NEVER called. ---------------
    reason = _identity_collision_reason(
        reveal_secret(attacker_tok), reveal_secret(owner_tok),
        reveal_secret(bystander_tok) if bystander_tok is not None else None)
    if reason:
        err(f"  ! [NOT DATA] {reason}")
        return 2

    # -- catalog source: the target's spec, else a --endpoints-file for a spec-less target -----------
    spec = None
    endpoints = None
    confirm_spec = None
    if t.spec_path and os.path.isfile(t.spec_path):
        try:
            spec = confirm_spec = _load_spec_file(t.spec_path)
        except Exception as ex:
            err(f"  ! [NOT DATA] could not read the target's spec ({type(ex).__name__}): {ex}")
            return 2
    else:
        if not endpoints_file:
            err("  ! [NOT DATA] the target has no OpenAPI spec - pass --endpoints-file with a "
                "'METHOD /path' list, or give the target a spec.")
            return 2
        try:
            endpoints = _load_endpoints_file(endpoints_file)
            confirm_spec = spec_from_endpoints(endpoints)
        except Exception as ex:
            err(f"  ! [NOT DATA] could not read the endpoints file ({type(ex).__name__}): {ex}")
            return 2

    id_map, collections = _load_id_source(id_source_file, err)

    settings.AI_DEEP_VERIFY_ENABLED = True                # runtime-only, mirrors verify/do_scan
    engine = engine or execute_deep_verification
    model = model or settings.LLM_MODEL or None

    async def run_op(op):
        # REUSE the existing per-account routing - attacker->auth_context, owner->owner_credential,
        # bystander->bystander_credential - verbatim (not a fork).
        return await _verify_external(t.base_url, confirm_spec, op, attacker_tok, owner_tok,
                                      model, engine, bystander_tok=bystander_tok)

    kw: Dict[str, Any] = {}
    if scan_provider_factory is not None:
        kw["provider_factory"] = scan_provider_factory
    if client_factory is not None:
        kw["client_factory"] = client_factory
    if raw_candidates is not None:
        kw["raw_candidates"] = raw_candidates

    echo(f"Scanning {t.base_url} (non-interactive) - discovering + confirming each candidate...")
    try:
        result = asyncio.run(run_scan(
            t.base_url, spec, run_op=run_op, endpoints=endpoints, id_map=id_map, collections=collections,
            harvest_attacker_cred=OwnerCredential.from_config(reveal_secret(attacker_tok)),  # attacker ONLY
            harvest_owner_cred=OwnerCredential.from_config(reveal_secret(owner_tok)),        # owner ONLY
            model=model, assert_owner_only=assert_owner_only, **kw))
    except Exception as ex:
        err(f"  ! [NOT DATA] scan run error against {t.base_url}: {type(ex).__name__}: {ex}")
        return 2
    echo(render_scan_report(result, t.base_url))
    return 0
