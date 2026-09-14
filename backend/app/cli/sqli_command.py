# ==============================================================================
# `aivist sqli --config <file.json>` (or `--target-file <target.toml>`) — NON-INTERACTIVE
# blind SQL-injection confirmation via OOB.
#
# The sqli entry point, kept SEPARATE and ADDITIVE (mirrors ssrf_command.py / cmdi_command.py): it
# does NOT reuse or alter the access-control `run --config` verify/scan dispatch. It reads a JSON
# config OR a saved Target file (`--target-file`, like `verify`) + an OPTIONAL attacker token from the
# env, runs the OOB sqli probe, and emits a structured JSON result.
#
# A CONFIRMED sqli requires a REAL token-correlated, injection-causal interactsh callback (the
# DeterministicProof); this entry only serializes what `services/sqli_detector` produced — it cannot
# manufacture a verdict. Error-based / time-based blind leads are SIGNAL at most. Needs OUTBOUND
# network + a reachable public interactsh server; if none is reachable the result is NOT DATA.
#
# Exit codes (CI-friendly): 0 = probed, NOT confirmed (refuted or signal); 1 = sqli CONFIRMED via a
# real OOB callback; 2 = NOT DATA / setup error.
# ==============================================================================
from __future__ import annotations

import json
import os
from typing import Any, Callable, Dict, Mapping, Optional

_SQLI_REQUIRED = ("base_url", "path", "param")
_ATTACKER_ENV = "TARGET_ATTACKER_TOKEN"


def _load_config(path: str) -> Dict[str, Any]:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError("config must be a JSON object")
    return data


def _config_from_target_file(target_file_path: str) -> Dict[str, Any]:
    """Map a saved Target (the `target --dump-template` / `--from-file` TOML) onto a sqli config, the
    SAME convenience `verify --target-file` gives: base_url + path_template (the endpoint path) +
    id_param (the parameter the payload is injected into) + method. sqli injects into a QUERY parameter,
    so the target's id_location must be 'query' (use --config for a body injection). Raises ValueError
    on an invalid target file or a non-query id_location."""
    from backend.app.cli import target_file as _tf
    t, errors = _tf.load_target_file(target_file_path)
    if errors:
        raise ValueError("the target file has problem(s): " + "; ".join(errors))
    if (t.id_location or "").lower() != "query":
        raise ValueError(
            f"sqli --target-file needs a query-param target (id_location='query'), got "
            f"{t.id_location!r}; use --config with param_location for a body injection.")
    return {"mode": "sqli", "base_url": t.base_url, "path": t.path_template,
            "param": t.id_param, "method": t.method or "GET", "param_location": "query"}


def run_sqli_from_config(
    config_path: Optional[str] = None, *,
    target_file_path: Optional[str] = None,
    environ: Optional[Mapping[str, str]] = None,
    out: Callable[..., None] = print,
    err: Callable[..., None] = print,
    pretty: bool = False,
    # test seams (offline; no network):
    session_factory: Optional[Callable] = None,
    http_send: Optional[Callable] = None,
    sleep: Optional[Callable[[float], None]] = None,
) -> int:
    """Read the JSON config (or a --target-file) + optional env attacker token, run the OOB sqli probe,
    print a JSON result, and return an exit code: 1 = CONFIRMED (real token-matched OOB callback),
    0 = refuted or signal, 2 = NOT DATA / setup error. No LLM key is needed — sqli is confirmed by a
    physical callback, not a model."""
    environ = environ if environ is not None else os.environ
    from backend.app.cli.run_command import _dump, _error
    from backend.app.services.sqli_detector import run_sqli_probe, sqli_verdict, result_view, Tier

    if bool(config_path) == bool(target_file_path):
        out(_dump(_error("bad_input", "provide EXACTLY ONE of --config or --target-file.")))
        return 2

    try:
        cfg = _config_from_target_file(target_file_path) if target_file_path else _load_config(config_path)
    except Exception as ex:
        out(_dump(_error("bad_config", f"could not read the config: {type(ex).__name__}: {ex}")))
        return 2

    if str(cfg.get("mode", "sqli")).lower().strip() != "sqli":
        out(_dump(_error("bad_mode", "this entry point handles mode 'sqli' only.")))
        return 2

    missing = [f for f in _SQLI_REQUIRED if not cfg.get(f)]
    if missing:
        out(_dump(_error("missing_fields", "sqli mode requires: " + ", ".join(missing))))
        return 2

    attacker_token = str(environ.get(_ATTACKER_ENV) or "").strip() or None
    oob_servers = None
    if cfg.get("oob_server"):
        oob_servers = (str(cfg["oob_server"]),)
    elif cfg.get("oob_servers"):
        oob_servers = tuple(str(s) for s in cfg["oob_servers"])

    kwargs: Dict[str, Any] = dict(
        base_url=cfg["base_url"],
        method=str(cfg.get("method", "GET")),
        path=str(cfg["path"]),
        param=str(cfg["param"]),
        param_location=str(cfg.get("param_location", "query")),
        attacker_token=attacker_token,
    )
    if oob_servers is not None:
        kwargs["oob_servers"] = oob_servers
    if cfg.get("poll_seconds") is not None:
        kwargs["poll_seconds"] = float(cfg["poll_seconds"])
    if cfg.get("poll_interval") is not None:
        kwargs["poll_interval"] = float(cfg["poll_interval"])
    if session_factory is not None:
        kwargs["session_factory"] = session_factory
    if http_send is not None:
        kwargs["http_send"] = http_send
    if sleep is not None:
        kwargs["sleep"] = sleep

    try:
        result = run_sqli_probe(**kwargs)
    except Exception as ex:
        out(_dump(_error("run_error", f"{type(ex).__name__}: {ex}", target=cfg["base_url"])))
        return 2

    verdict = sqli_verdict(result)
    view = result_view(result, verdict)
    if verdict.tier is Tier.CONFIRMED:
        code = 1
    elif verdict.tier is Tier.NOT_DATA:
        code = 2
    else:
        code = 0
    out(_dump({"mode": "sqli", "target": cfg["base_url"], "result": view, "exit_code": code}))
    if pretty:
        err(f"[sqli] {cfg['base_url']}  {view['method']} {cfg['path']} param={view['param']}  "
            f"-> {view['badge']} (exit {code})")
    return code
