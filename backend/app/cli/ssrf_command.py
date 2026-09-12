# ==============================================================================
# `aivist ssrf --config <file.json>` — NON-INTERACTIVE SSRF confirmation via OOB.
#
# The SSRF entry point, kept SEPARATE and ADDITIVE: it does NOT reuse or alter the
# access-control `run --config` verify/scan dispatch (`run_command.py`). It reads a JSON
# config + an OPTIONAL attacker token from the env, runs the OOB SSRF probe, and emits a
# structured JSON result to stdout.
#
# A CONFIRMED SSRF requires a REAL interactsh callback (the DeterministicProof); this entry
# only serializes what `services/ssrf_detector` produced — it cannot manufacture a verdict.
# Needs OUTBOUND network + a reachable public interactsh server; if none is reachable the
# result is NOT DATA (never a bluffed CONFIRMED).
#
# Exit codes (CI-friendly): 0 = probed, NOT confirmed (refuted); 1 = SSRF CONFIRMED via a
# real OOB callback; 2 = NOT DATA / setup error (could not probe).
# ==============================================================================
from __future__ import annotations

import json
import os
from typing import Any, Callable, Dict, Mapping, Optional

_SSRF_REQUIRED = ("base_url", "path")
_ATTACKER_ENV = "TARGET_ATTACKER_TOKEN"


def _load_config(path: str) -> Dict[str, Any]:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError("config must be a JSON object")
    return data


def run_ssrf_from_config(
    config_path: str, *,
    environ: Optional[Mapping[str, str]] = None,
    out: Callable[..., None] = print,
    err: Callable[..., None] = print,
    pretty: bool = False,
    # test seams (offline; no network):
    session_factory: Optional[Callable] = None,
    http_send: Optional[Callable] = None,
    sleep: Optional[Callable[[float], None]] = None,
) -> int:
    """Read the JSON config (+ optional env attacker token), run the OOB SSRF probe, print a
    JSON result, and return an exit code: 1 = CONFIRMED (real OOB callback), 0 = refuted,
    2 = NOT DATA / setup error. No LLM key is needed — SSRF is confirmed by a physical
    callback, not a model."""
    environ = environ if environ is not None else os.environ
    # Reuse the access-control entry's JSON dumper/redactor + error shape (import only; the
    # verify/scan code paths are never invoked here).
    from backend.app.cli.run_command import _dump, _error
    from backend.app.services.ssrf_detector import run_ssrf_probe, ssrf_verdict, result_view, Tier

    try:
        cfg = _load_config(config_path)
    except Exception as ex:
        out(_dump(_error("bad_config", f"could not read the config file: {type(ex).__name__}: {ex}")))
        return 2

    if str(cfg.get("mode", "ssrf")).lower().strip() != "ssrf":
        out(_dump(_error("bad_mode", "this entry point handles mode 'ssrf' only.")))
        return 2

    missing = [f for f in _SSRF_REQUIRED if not cfg.get(f)]
    if missing:
        out(_dump(_error("missing_fields", "ssrf mode requires: " + ", ".join(missing))))
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
        url_param=str(cfg.get("url_param", "url")),
        url_location=str(cfg.get("url_location", "query")),
        scheme=str(cfg.get("scheme", "http")),
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
        result = run_ssrf_probe(**kwargs)
    except Exception as ex:
        out(_dump(_error("run_error", f"{type(ex).__name__}: {ex}", target=cfg["base_url"])))
        return 2

    verdict = ssrf_verdict(result)
    view = result_view(result, verdict)
    if verdict.tier is Tier.CONFIRMED:
        code = 1
    elif verdict.tier is Tier.NOT_DATA:
        code = 2
    else:
        code = 0
    out(_dump({"mode": "ssrf", "target": cfg["base_url"], "result": view, "exit_code": code}))
    if pretty:
        err(f"[ssrf] {cfg['base_url']}  {view['method']} {cfg['path']}?{view['injected_url']}  "
            f"-> {view['badge']} (exit {code})")
    return code
