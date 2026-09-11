#!/usr/bin/env python
# ==============================================================================
# Aivist Verify confirmation-gate — Action entrypoint (THIN WRAPPER).
#
# It does NOT judge anything. For each already-known BOLA/IDOR candidate it:
#   1. assembles a `run` config (mode="verify") from the Action inputs,
#   2. invokes the REAL CLI unchanged:  python run.py run --config <file> --pretty,
#   3. reads the CLI's structured JSON result (verdict + tier), and
#   4. maps the aggregate onto a CI exit code:
#        exit 0  -> nothing CODE-CONFIRMED (build passes)
#        exit 1  -> >=1 candidate CODE-CONFIRMED and fail-on-confirm is true (build fails)
#        exit 2  -> the gate could not run (setup / execution error) — never a silent pass
#
# The verdict, the zero-false-positive gate, the labs and every committed artifact
# are untouched. This file only shuffles inputs in and the CLI's own JSON out.
# ==============================================================================
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from typing import Any, Dict, List, Optional, Tuple

# /action/.github/action/entrypoint.py -> repo root is three levels up.
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

# tier -> the bucket we count it in. Read straight off the CLI's own `result.tier`
# (backend/app/cli/confirm_render.case_outcome): confirmed = the deterministic
# code gate fired; signal = "verified" by model opinion only (a lead, not a
# confirmation); refuted = no cross-user effect; notdata = no usable verdict.
_TIERS = ("confirmed", "signal", "refuted", "notdata", "broken_for_all", "skipped")


# ------------------------------------------------------------------------------
# Inputs. GitHub exposes each `inputs.<name>` as an env var INPUT_<NAME>. The exact
# spelling of the env name across runner versions can keep the dash or swap it for
# an underscore, so we try both — and also accept a plain UPPER_SNAKE fallback so a
# local `docker run -e ATTACKER_TOKEN=...` works too.
# ------------------------------------------------------------------------------
def _input(name: str, default: str = "") -> str:
    up = name.upper()
    for key in (f"INPUT_{name}", f"INPUT_{up}", f"INPUT_{up.replace('-', '_')}",
                up.replace("-", "_")):
        val = os.environ.get(key)
        if val is not None and str(val).strip() != "":
            return str(val).strip()
    return default


def _bool(val: str, default: bool) -> bool:
    v = (val or "").strip().lower()
    if v in ("true", "1", "yes", "on"):
        return True
    if v in ("false", "0", "no", "off"):
        return False
    return default


def _log(msg: str) -> None:
    print(msg, flush=True)


def _err(msg: str) -> None:
    print(f"::error::{msg}", flush=True)


def _warn(msg: str) -> None:
    print(f"::warning::{msg}", flush=True)


# ------------------------------------------------------------------------------
# Candidate loading. Accepts a workspace-relative/absolute FILE path, or inline JSON.
# The payload is a JSON array of ops, or {"candidates": [...]}.
# ------------------------------------------------------------------------------
def _load_candidates(raw: str) -> List[Dict[str, Any]]:
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("input 'candidates' is empty")

    text: Optional[str] = None
    if raw[0] in "[{":
        text = raw                                   # inline JSON
    else:
        workspace = os.environ.get("GITHUB_WORKSPACE") or os.getcwd()
        for cand in (raw, os.path.join(workspace, raw)):
            if os.path.isfile(cand):
                with open(cand, encoding="utf-8") as fh:
                    text = fh.read()
                _log(f"  candidates read from file: {cand}")
                break
        if text is None:
            raise ValueError(f"'candidates' is neither inline JSON nor an existing file: {raw!r}")

    data = json.loads(text)
    if isinstance(data, dict):
        data = data.get("candidates")
    if not isinstance(data, list) or not data:
        raise ValueError("'candidates' must be a non-empty JSON array of operations "
                         "(or {\"candidates\": [...]})")
    return [dict(x) for x in data]


_REQUIRED_OP = ("method", "path_template", "id_param", "attacker_id", "victim_id")


def _op_to_run_config(op: Dict[str, Any], base_url: str, model: Optional[str],
                      index: int) -> Tuple[str, Dict[str, Any]]:
    missing = [k for k in _REQUIRED_OP if not op.get(k)]
    if missing:
        raise ValueError(f"candidate #{index} is missing field(s): {', '.join(missing)}")
    name = str(op.get("name") or f"candidate-{index}")
    cfg: Dict[str, Any] = {
        "mode": "verify",
        "name": name,
        "base_url": base_url,
        "method": str(op["method"]).upper(),
        "path_template": op["path_template"],
        "id_location": op.get("id_location") or "path",
        "id_param": op["id_param"],
        "attacker_id": str(op["attacker_id"]),
        "victim_id": str(op["victim_id"]),
    }
    if op.get("spec_path"):
        cfg["spec_path"] = op["spec_path"]
    if op.get("assert_owner_only"):
        cfg["assert_owner_only"] = True
    if model:
        cfg["model"] = model
    return name, cfg


# ------------------------------------------------------------------------------
# Run one candidate through the REAL CLI and classify its result.
# ------------------------------------------------------------------------------
def _run_candidate(cfg: Dict[str, Any], env: Dict[str, str]) -> Dict[str, Any]:
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as fh:
        json.dump(cfg, fh)
        cfg_path = fh.name
    try:
        proc = subprocess.run(
            [sys.executable, "run.py", "run", "--config", cfg_path, "--pretty"],
            cwd=REPO_ROOT, env=env, capture_output=True, text=True, timeout=600,
        )
    except subprocess.TimeoutExpired:
        return {"outcome": "error", "detail": "the CLI run timed out (600s)", "verdict": None}
    finally:
        try:
            os.unlink(cfg_path)
        except OSError:
            pass

    stdout, stderr = proc.stdout or "", proc.stderr or ""
    if stderr.strip():
        for line in stderr.strip().splitlines():
            _log(f"    [cli] {line}")

    try:
        obj = json.loads(stdout)
    except json.JSONDecodeError:
        snippet = stdout.strip()[:400] or "(empty stdout)"
        return {"outcome": "error",
                "detail": f"CLI produced non-JSON stdout (exit {proc.returncode}): {snippet}",
                "verdict": None}

    if "error" in obj:                                # setup / execution error from run_from_config
        return {"outcome": "error",
                "detail": f"{obj.get('error')}: {obj.get('message')}",
                "verdict": None, "raw": obj}

    result = obj.get("result") or {}
    tier = result.get("tier") or "notdata"
    outcome = tier if tier in _TIERS else "notdata"
    return {"outcome": outcome, "verdict": result.get("verdict"),
            "tier": tier, "guard_override": result.get("guard_override"),
            "method": result.get("method"), "baseline_path": result.get("baseline_path"),
            "attack_path": result.get("attack_path"),
            "degraded_reason": result.get("degraded_reason"), "raw": obj}


# ------------------------------------------------------------------------------
# Reporting: $GITHUB_STEP_SUMMARY (markdown) and $GITHUB_OUTPUT (key=value).
# ------------------------------------------------------------------------------
_BADGE = {
    "confirmed": "🔴 CONFIRMED",
    "signal": "🔵 signal (model opinion)",
    "refuted": "🟢 refuted",
    "notdata": "🟡 NOT DATA",
    "broken_for_all": "🟠 inconclusive (broken-for-all)",
    "skipped": "⚪ skipped",
    "error": "❌ gate error",
}


def _write_summary(results: List[Dict[str, Any]], counts: Dict[str, int],
                   target: str, fail_on_confirm: bool, exit_code: int) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    lines: List[str] = []
    lines.append("## Aivist Verify — access-control confirmation gate\n")
    lines.append(f"**Target:** `{target}`  ")
    verdict_line = ("**Gate: FAIL** — a real cross-user access bug was CONFIRMED."
                    if exit_code == 1 else
                    "**Gate: ERROR** — the confirmation gate could not run (see log)."
                    if exit_code == 2 else
                    "**Gate: PASS** — nothing was code-confirmed.")
    lines.append(verdict_line + "\n")
    lines.append(f"Confirmed **{counts['confirmed']}** · signal {counts['signal']} · "
                 f"refuted {counts['refuted']} · not-data {counts['notdata']} · "
                 f"errors {counts['error']}  "
                 f"(fail-on-confirm: `{str(fail_on_confirm).lower()}`)\n")
    lines.append("| Candidate | Method / attack path | Outcome | Engine verdict |")
    lines.append("|---|---|---|---|")
    for r in results:
        path_disp = f"`{r.get('method') or '?'} {r.get('attack_path') or r.get('baseline_path') or '-'}`"
        detail = r.get("degraded_reason") or r.get("detail") or ""
        badge = _BADGE.get(r["outcome"], r["outcome"])
        verdict = r.get("verdict") or (f"— ({detail})" if detail else "—")
        lines.append(f"| {r['name']} | {path_disp} | {badge} | {verdict} |")
    lines.append("")
    lines.append("> Scope note: this gate **confirms** already-known access-control candidates "
                 "and does **not** discover them. A CONFIRMED result means the deterministic code "
                 "gate proved a cross-user effect — not the model's opinion alone.")
    text = "\n".join(lines) + "\n"
    if path:
        try:
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(text)
        except OSError as ex:
            _warn(f"could not write step summary: {ex}")
    else:
        _log("\n----- step summary (GITHUB_STEP_SUMMARY unset; printing) -----")
        _log(text)


def _set_outputs(outputs: Dict[str, str]) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        _log("(GITHUB_OUTPUT unset; outputs: " + ", ".join(f"{k}={v}" for k, v in outputs.items()) + ")")
        return
    try:
        with open(path, "a", encoding="utf-8") as fh:
            for k, v in outputs.items():
                fh.write(f"{k}={v}\n")
    except OSError as ex:
        _warn(f"could not write outputs: {ex}")


# ------------------------------------------------------------------------------
def main() -> int:
    target = _input("target-url")
    candidates_raw = _input("candidates")
    attacker = _input("attacker-token")
    owner = _input("owner-token")
    bystander = _input("bystander-token")
    api_key = _input("provider-api-key")
    provider = _input("llm-provider", "gemini")
    base_url = _input("llm-base-url")
    model = _input("llm-model")
    fail_on_confirm = _bool(_input("fail-on-confirm", "true"), True)

    missing = [n for n, v in (("target-url", target), ("candidates", candidates_raw),
                              ("attacker-token", attacker), ("owner-token", owner)) if not v]
    if missing:
        _err(f"missing required input(s): {', '.join(missing)}")
        return 2

    try:
        candidates = _load_candidates(candidates_raw)
    except Exception as ex:
        _err(f"could not load candidates: {ex}")
        return 2

    # Child environment for the real CLI. Tokens are env-only (never a flag / the config file),
    # per-account routed by the CLI, and masked as SecretStr inside it.
    env = dict(os.environ)
    env["TARGET_ATTACKER_TOKEN"] = attacker
    env["TARGET_OWNER_TOKEN"] = owner
    if bystander:
        env["TARGET_BYSTANDER_TOKEN"] = bystander
    else:
        env.pop("TARGET_BYSTANDER_TOKEN", None)
    env["LLM_PROVIDER"] = provider or "gemini"
    if api_key:
        # The engine's key gate accepts either; set both so gemini and non-gemini both resolve.
        env["GEMINI_API_KEY"] = api_key
        env["LLM_API_KEY"] = api_key
    if base_url:
        env["LLM_BASE_URL"] = base_url
    if model:
        env["LLM_MODEL"] = model
    env.setdefault("NO_COLOR", "1")                    # deterministic, escape-free CLI output

    _log(f"Aivist Verify gate - target={target}  provider={env['LLM_PROVIDER']}  "
         f"candidates={len(candidates)}  fail-on-confirm={str(fail_on_confirm).lower()}")

    results: List[Dict[str, Any]] = []
    for i, op in enumerate(candidates, start=1):
        try:
            name, cfg = _op_to_run_config(op, target, model or None, i)
        except Exception as ex:
            _err(str(ex))
            results.append({"name": op.get("name") or f"candidate-{i}", "outcome": "error",
                            "detail": str(ex), "verdict": None})
            continue
        print(f"::group::Confirming {name}  ({cfg['method']} {cfg['path_template']})", flush=True)
        r = _run_candidate(cfg, env)
        r["name"] = name
        results.append(r)
        _log(f"  -> {r['outcome']}  verdict={r.get('verdict')!r}"
             + (f"  ({r.get('degraded_reason') or r.get('detail')})"
                if (r.get('degraded_reason') or r.get('detail')) else ""))
        print("::endgroup::", flush=True)

    counts = {k: 0 for k in list(_TIERS) + ["error"]}
    for r in results:
        counts[r["outcome"]] = counts.get(r["outcome"], 0) + 1

    # Persist the full per-candidate JSON (already credential-redacted by the CLI).
    workspace = os.environ.get("GITHUB_WORKSPACE") or REPO_ROOT
    verdicts_path = os.path.join(workspace, "aivist-verify-verdicts.json")
    try:
        with open(verdicts_path, "w", encoding="utf-8") as fh:
            json.dump({"target": target, "counts": counts,
                       "candidates": [{k: v for k, v in r.items() if k != "raw"} for r in results],
                       "results": [r.get("raw") for r in results]}, fh, indent=2)
    except OSError as ex:
        _warn(f"could not write verdicts file: {ex}")
        verdicts_path = ""

    # Exit-code policy.
    if counts["error"] > 0:
        exit_code = 2
    elif fail_on_confirm and counts["confirmed"] > 0:
        exit_code = 1
    else:
        exit_code = 0

    if counts["notdata"] > 0:
        _warn(f"{counts['notdata']} candidate(s) produced NO usable verdict (challenge / rate-limit / "
              f"transport failure) — they were neither confirmed nor cleared.")
    if counts["signal"] > 0:
        _warn(f"{counts['signal']} candidate(s) were 'verified' by model opinion only (a lead, NOT a "
              f"code-confirmation) — verify by hand; they do not fail the gate.")

    _set_outputs({
        "confirmed-count": str(counts["confirmed"]),
        "signal-count": str(counts["signal"]),
        "refuted-count": str(counts["refuted"]),
        "notdata-count": str(counts["notdata"]),
        "verdicts-path": verdicts_path,
    })
    _write_summary(results, counts, target, fail_on_confirm, exit_code)

    if exit_code == 1:
        _err(f"CONFIRMED {counts['confirmed']} real cross-user access bug(s) - failing the build.")
    elif exit_code == 2:
        _err("the confirmation gate could not run for one or more candidates (see errors above).")
    else:
        _log(f"Gate PASS — nothing code-confirmed "
             f"(refuted={counts['refuted']}, signal={counts['signal']}, notdata={counts['notdata']}).")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
