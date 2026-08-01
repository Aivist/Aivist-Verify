#!/usr/bin/env python
# ==============================================================================
# Anti-Gravity CLI — the human-walkable front door to the BOLA/IDOR confirmer.
#
#   python run.py confirm --caseset <path> --case <id>    # confirm ONE finding
#   python run.py confirm --caseset <path>                # confirm ALL cases + a one-line tally
#
# PURE ORCHESTRATION + PRESENTATION over the EXISTING confirmation path. It boots/connects
# the target and calls `execute_deep_verification` with the SAME arguments the measurement
# harness (`scripts/measure/verdict_measure.py`) already uses — via that harness's own
# helpers (`_run_one` / `_boot_target` / `_attack_path` / ...), reused, not duplicated. The
# verdict comes ONLY from the engine; the CLI renders `DeepVerificationResult`'s fields and
# structurally cannot manufacture `verified`. Credentials are never printed.
#
# Runtime-only: `AI_DEEP_VERIFY_ENABLED` is set True in-process (as verdict_measure does);
# the committed config defaults stay False.
# ==============================================================================
import os
import sys
import json
import asyncio
import argparse
import tempfile

_REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _REPO_ROOT)
sys.path.insert(0, os.path.join(_REPO_ROOT, "scripts", "measure"))

from backend.app.core.config import settings, reveal_secret  # noqa: E402
from backend.app.cli.confirm_render import render_tree, exit_code_for, render_tally  # noqa: E402
import verdict_measure as vm  # noqa: E402  (reuse: _run_one/_boot_target/_stop_target/_rm_db/_attack_path)

_EXIT_NOTDATA = 2


def _has_llm_key() -> bool:
    return bool(reveal_secret(settings.LLM_API_KEY) or reveal_secret(settings.GEMINI_API_KEY))


def _enrich(record: dict, case: dict) -> dict:
    """Add the case-derived fields the renderer needs for the header + Reproduce line
    (the engine's own row does not carry them). No credentials are added."""
    record = dict(record)
    record["method"] = case["method"]
    record["baseline_path"] = case["baseline_path"]
    record["attack_path"] = vm._attack_path(case)
    record["body"] = case.get("body")
    return record


def confirm(caseset_path: str, case_id, model) -> int:
    """Confirm one finding (--case) or ALL cases in the set. Returns the process exit code."""
    if not _has_llm_key():
        print("[NOT DATA] No LLM API key configured (GEMINI_API_KEY / LLM_API_KEY). The confirmer "
              "needs it to run the engine; nothing was sent.", file=sys.stderr)
        return _EXIT_NOTDATA

    with open(caseset_path, encoding="utf-8") as fh:
        cs = json.load(fh)
    selected = ([c for c in cs["cases"] if c["id"] == case_id]
                if case_id is not None else list(cs["cases"]))
    if not selected:
        print(f"[NOT DATA] no case matching --case {case_id!r} in {caseset_path}", file=sys.stderr)
        return _EXIT_NOTDATA

    # Runtime-only enablement (committed config defaults stay False), mirroring verdict_measure.
    settings.AI_DEEP_VERIFY_ENABLED = True
    settings.AI_DEEP_VERIFY_OWNER_AUTH = cs["owner_auth"]

    db_path = os.path.join(tempfile.gettempdir(), f"confirm_{cs['target']}.db")
    db_url = "sqlite+aiosqlite:///" + db_path.replace("\\", "/")
    os.environ[cs["db_env"]] = db_url

    records = []
    proc = None
    try:
        for case in selected:
            # Fresh-seed per case (the golden methodology) — reuse the harness helpers.
            vm._stop_target(proc)
            proc = None
            vm._rm_db(db_path)
            proc = vm._boot_target(cs["module"], cs["port"], cs["db_env"], db_url)
            row = asyncio.run(vm._run_one(case, cs, model, 1, 1, None))
            record = _enrich(row, case)
            print(render_tree(record))
            print()
            records.append(record)
    except Exception as e:
        vm._stop_target(proc)
        print(f"[NOT DATA] run error: {type(e).__name__}: {e}", file=sys.stderr)
        return _EXIT_NOTDATA
    finally:
        vm._stop_target(proc)

    code = exit_code_for(records)
    if len(records) > 1:
        print(render_tally(records))
    return code


def main():
    ap = argparse.ArgumentParser(prog="run.py", description="Anti-Gravity CLI.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("confirm", help="Confirm a BOLA/IDOR finding via the deep verifier.")
    c.add_argument("--caseset", required=True, help="path to a caseset JSON")
    c.add_argument("--case", default=None, help="a case id to confirm; omit to confirm ALL cases in the set")
    c.add_argument("--model", default=None, help="optional model override")
    args = ap.parse_args()
    if args.cmd == "confirm":
        sys.exit(confirm(args.caseset, args.case, args.model))


if __name__ == "__main__":
    main()
