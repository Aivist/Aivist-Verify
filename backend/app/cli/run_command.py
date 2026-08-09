# ==============================================================================
# `lanivist run --config <file.json>` — a NON-INTERACTIVE, programmatic entry point for CI / scripting.
#
# Zero interaction, zero color, zero getpass, zero per-field prompts: it reads ALL config from a JSON
# file, tokens from ENV ONLY, runs the SAME engine the interactive CLI runs, and emits a STRUCTURED JSON
# result to stdout. It is a thin INPUT-ADAPTER + OUTPUT-SERIALIZER around the existing engine functions —
# it touches NO verdict/engine logic:
#   * verify mode -> the SAME `_verify_external(...)` call `run_external_verify` makes (attacker->auth_context,
#     owner->owner_credential, bystander->bystander_credential), flattened by the SAME `_record_from_result`.
#   * scan mode   -> the SAME `run_scan(...)` loop, with the SAME per-account `run_op` and id sourcing.
#
# RED LINES (welded): tokens are ENV ONLY (never the config file), masked as SecretStr, per-account routed,
# and the attacker!=owner collision guard fires BEFORE any verdict. The engine judge is unchanged (zero-FP,
# downgrade-only). The JSON output passes through the SAME credential redactor the renderer uses, so no live
# token can appear in it. Scope-lock is unchanged (the engine's fail-closed ScopePolicy).
# ==============================================================================
from __future__ import annotations

import asyncio
import json
import os
from typing import Any, Callable, Dict, List, Mapping, Optional

from backend.app.core.config import settings, reveal_secret

_VERIFY_REQUIRED = ("base_url", "method", "path_template", "id_location", "id_param",
                    "attacker_id", "victim_id")


def _dump(payload: Dict[str, Any]) -> str:
    """Serialize to indented JSON, then run it through the SAME credential redactor the renderer uses
    (belt-and-suspenders — records already carry no live secret, but any token-looking substring is masked)."""
    from backend.app.cli.confirm_render import _redact
    # ensure_ascii=True -> pure-ASCII JSON (non-ASCII, e.g. an em-dash in a guard message, becomes \uXXXX),
    # so the machine contract is unambiguous regardless of the consumer's console encoding.
    return _redact(json.dumps(payload, indent=2, ensure_ascii=True, default=str))


def _error(code: str, message: str, **extra: Any) -> Dict[str, Any]:
    p: Dict[str, Any] = {"error": code, "message": message, "exit_code": 2}
    p.update(extra)
    return p


def _load_config(path: str) -> Dict[str, Any]:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError("config must be a JSON object")
    return data


def _tier(record: Dict[str, Any]) -> str:
    """The report tier for a record (mirrors scan_report grouping): skipped | broken_for_all |
    confirmed | signal | refuted | notdata. Reads ENGINE fields only (never ground_truth)."""
    from backend.app.cli.confirm_render import case_outcome, _BROKEN_FOR_ALL_REASON
    if record.get("scan_skipped"):
        return "skipped"
    if record.get("guard_override") == _BROKEN_FOR_ALL_REASON:
        return "broken_for_all"
    return case_outcome(record)             # confirmed | signal | refuted | notdata


def _record_view(record: Dict[str, Any]) -> Dict[str, Any]:
    """The machine-readable view of one engine record — the SAME fields the renderer reads, incl. the
    already-redacted flattened evidence chain / re-runnable PoC. Carries NO credential."""
    return {
        "verdict": record.get("final_verdict"),
        "tier": _tier(record),
        "guard_override": record.get("guard_override"),
        "method": record.get("method"),
        "baseline_path": record.get("baseline_path"),
        "attack_path": record.get("attack_path"),
        "body": record.get("body"),
        "degraded": bool(record.get("degraded")),
        "degraded_reason": record.get("degraded_reason"),
        "caller_identity": record.get("caller_identity"),
        "payload_causality": record.get("payload_causality"),
        "state_jump": record.get("state_jump"),
        "negative_assertion": record.get("negative_assertion"),
        "owner_view_corroborated": record.get("owner_view_corroborated"),
        "broken_for_all_suspected": record.get("broken_for_all_suspected"),
        "scan_skip_reason": record.get("scan_skip_reason"),
        "evidence": record.get("evidence"),      # already redacted at flatten time (no live secret)
    }


def run_from_config(
    config_path: str, *,
    environ: Optional[Mapping[str, str]] = None,
    out: Callable[..., None] = print,
    err: Callable[..., None] = print,
    pretty: bool = False,
    # test seams (offline; no network / no API):
    engine: Optional[Callable] = None,
    scan_provider_factory: Optional[Callable] = None,
    raw_candidates: Optional[list] = None,
    client_factory: Optional[Callable] = None,
) -> int:
    """Read the JSON config + env tokens, run the engine (verify OR scan), print a JSON result to `out`,
    and return a process exit code: 0 = a verdict/report was produced; non-zero = NOT DATA / setup error
    (so CI can branch). NO interaction, NO color, NO getpass — every input is the file or the environment."""
    environ = environ if environ is not None else os.environ

    if not (reveal_secret(settings.LLM_API_KEY) or reveal_secret(settings.GEMINI_API_KEY)):
        out(_dump(_error("no_api_key", "No API key configured. Set GEMINI_API_KEY / LLM_API_KEY "
                         "(the engine needs one to judge; scan also needs it for discovery).")))
        return 2
    try:
        cfg = _load_config(config_path)
    except Exception as ex:
        out(_dump(_error("bad_config", f"could not read the config file: {type(ex).__name__}: {ex}")))
        return 2
    mode = str(cfg.get("mode", "")).lower().strip()
    if mode not in ("verify", "scan"):
        out(_dump(_error("bad_mode", "config field 'mode' must be 'verify' or 'scan'.")))
        return 2
    if not cfg.get("base_url"):
        out(_dump(_error("missing_fields", "config requires 'base_url'.")))
        return 2

    # -- tokens: ENV ONLY, masked SecretStr, attacker+owner required (reuses resolve_scan_tokens) --------
    from backend.app.cli.scan_cli import resolve_scan_tokens
    try:
        attacker_tok, owner_tok, bystander_tok = resolve_scan_tokens(environ=environ)
    except Exception as ex:
        out(_dump(_error("missing_token", str(ex))))
        return 2

    # -- attacker != owner collision guard (fail-closed, BEFORE any verdict) -----------------------------
    from backend.app.cli.external_verify import _identity_collision_reason
    reason = _identity_collision_reason(
        reveal_secret(attacker_tok), reveal_secret(owner_tok),
        reveal_secret(bystander_tok) if bystander_tok is not None else None)
    if reason:
        out(_dump(_error("identity_collision", reason)))
        return 2

    settings.AI_DEEP_VERIFY_ENABLED = True                 # runtime-only, mirrors verify/scan
    model = cfg.get("model") or settings.LLM_MODEL or None

    if mode == "verify":
        return _run_verify(cfg, attacker_tok, owner_tok, bystander_tok, model, out, err, pretty, engine)
    return _run_scan(cfg, attacker_tok, owner_tok, bystander_tok, model, out, err, pretty,
                     engine, scan_provider_factory, raw_candidates, client_factory)


def _run_verify(cfg, attacker_tok, owner_tok, bystander_tok, model, out, err, pretty, engine) -> int:
    from backend.app.cli.console.targets import build_op
    from backend.app.cli.external_verify import (
        _verify_external, classify_degradation, _record_from_result, _load_spec_file)
    from backend.app.services.endpoint_catalog import spec_from_endpoints
    from backend.app.services.deep_verifier import execute_deep_verification

    missing = [f for f in _VERIFY_REQUIRED if not cfg.get(f)]
    if missing:
        out(_dump(_error("missing_fields", "verify mode requires: " + ", ".join(missing))))
        return 2

    op = build_op(cfg["method"], cfg["path_template"], cfg["id_location"], cfg["id_param"],
                  cfg["attacker_id"], cfg["victim_id"], shape=f"run:{cfg.get('name', 'verify')}")
    if cfg.get("assert_owner_only"):
        op["assert_owner_only"] = True

    if cfg.get("spec_path"):
        try:
            spec = _load_spec_file(cfg["spec_path"])
        except Exception as ex:
            out(_dump(_error("bad_spec", f"could not read spec_path: {type(ex).__name__}: {ex}")))
            return 2
    else:
        spec = spec_from_endpoints([f"{cfg['method']} {cfg['path_template']}"])   # spec-less: synth catalog

    try:
        result = asyncio.run(_verify_external(
            cfg["base_url"], spec, op, attacker_tok, owner_tok, model,
            engine or execute_deep_verification, bystander_tok=bystander_tok))
    except Exception as ex:
        out(_dump(_error("run_error", f"{type(ex).__name__}: {ex}", target=cfg["base_url"])))
        return 2

    record = _record_from_result(result, op, classify_degradation(result))
    view = _record_view(record)
    code = 2 if view["tier"] == "notdata" else 0            # NOT DATA -> non-zero; a verdict -> 0
    out(_dump({"mode": "verify", "target": cfg["base_url"], "result": view, "exit_code": code}))
    if pretty:
        err(f"[verify] {cfg['base_url']}  {view['method']} {view['baseline_path']}  "
            f"-> tier={view['tier']} verdict={view['verdict']} (exit {code})")
    return code


def _run_scan(cfg, attacker_tok, owner_tok, bystander_tok, model, out, err, pretty,
              engine, scan_provider_factory, raw_candidates, client_factory) -> int:
    from backend.app.cli.scan_run import run_scan
    from backend.app.cli.external_verify import _verify_external, _load_endpoints_file, _load_spec_file
    from backend.app.services.endpoint_catalog import spec_from_endpoints
    from backend.app.services.deep_verifier import OwnerCredential, execute_deep_verification

    base_url = cfg["base_url"]
    spec = None
    endpoints = None
    confirm_spec = None
    source = None
    if cfg.get("spec_path"):
        try:
            spec = confirm_spec = _load_spec_file(cfg["spec_path"])
        except Exception as ex:
            out(_dump(_error("bad_spec", f"could not read spec_path: {type(ex).__name__}: {ex}")))
            return 2
        source = "spec"
    elif cfg.get("endpoints"):
        endpoints = [str(e) for e in cfg["endpoints"]]
        confirm_spec = spec_from_endpoints(endpoints)
        source = "endpoints"
    elif cfg.get("endpoints_file"):
        try:
            endpoints = _load_endpoints_file(cfg["endpoints_file"])
        except Exception as ex:
            out(_dump(_error("bad_endpoints", f"could not read endpoints_file: {type(ex).__name__}: {ex}")))
            return 2
        confirm_spec = spec_from_endpoints(endpoints)
        source = "endpoints_file"
    elif cfg.get("traffic_file"):
        from backend.app.cli.scan_traffic import endpoints_from_traffic_file
        try:
            endpoints = endpoints_from_traffic_file(cfg["traffic_file"], base_url)
        except Exception as ex:
            out(_dump(_error("bad_traffic", f"could not read traffic_file: {type(ex).__name__}: {ex}")))
            return 2
        if not endpoints:
            out(_dump(_error("no_inscope_traffic",
                             f"no in-scope requests found in the traffic file (target origin {base_url}).")))
            return 2
        confirm_spec = spec_from_endpoints(endpoints)
        source = "traffic"
    else:
        out(_dump(_error("no_catalog_source",
                         "scan mode requires ONE catalog source: spec_path, endpoints, endpoints_file, "
                         "or traffic_file.")))
        return 2

    id_source = cfg.get("id_source") or {}
    id_map = dict(id_source.get("ids") or {})
    collections = dict(id_source.get("collections") or {})
    eng = engine or execute_deep_verification

    async def run_op(op):
        # SAME per-account routing as interactive scan (attacker->auth_context, owner->owner_credential,
        # bystander->bystander_credential) — not a fork.
        return await _verify_external(base_url, confirm_spec, op, attacker_tok, owner_tok,
                                      model, eng, bystander_tok=bystander_tok)

    kw: Dict[str, Any] = {}
    if scan_provider_factory is not None:
        kw["provider_factory"] = scan_provider_factory
    if client_factory is not None:
        kw["client_factory"] = client_factory
    if raw_candidates is not None:
        kw["raw_candidates"] = raw_candidates
    try:
        result = asyncio.run(run_scan(
            base_url, spec, run_op=run_op, endpoints=endpoints, id_map=id_map, collections=collections,
            harvest_attacker_cred=OwnerCredential.from_config(reveal_secret(attacker_tok)),   # attacker ONLY
            harvest_owner_cred=OwnerCredential.from_config(reveal_secret(owner_tok)),          # owner ONLY
            model=model, assert_owner_only=bool(cfg.get("assert_owner_only")), **kw))
    except Exception as ex:
        out(_dump(_error("run_error", f"{type(ex).__name__}: {ex}", target=base_url)))
        return 2

    records = result.get("records", [])
    views = [_record_view(r) for r in records]
    summary: Dict[str, int] = {"total": len(records), "confirmed": 0, "signal": 0,
                               "broken_for_all": 0, "refuted": 0, "notdata": 0, "skipped": 0,
                               "dropped": len(result.get("dropped", []))}
    for v in views:
        summary[v["tier"]] = summary.get(v["tier"], 0) + 1
    code = 0 if records else 2                              # a report was produced -> 0; nothing tested -> 2
    out(_dump({"mode": "scan", "target": base_url, "catalog_source": source,
               "summary": summary, "records": views, "exit_code": code}))
    if pretty:
        err(f"[scan] {base_url}  source={source}  " + "  ".join(
            f"{k}={summary[k]}" for k in ("confirmed", "signal", "broken_for_all", "refuted",
                                          "notdata", "skipped", "dropped")) + f"  (exit {code})")
    return code
