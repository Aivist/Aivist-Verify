#!/usr/bin/env python
# ==============================================================================
# The CLI front door — installed as the `<brand> verify` command (see
# backend/app/cli/branding.py; the brand token is provisional, the `verify` suffix
# is locked). Also runnable directly as `python run.py ...` (unchanged).
#
#   <brand> verify --caseset <path> --case <id>    # confirm ONE finding
#   <brand> verify --caseset <path>                # confirm ALL cases + a one-line tally
#   <brand> config                                 # interactive first-run setup
#   python run.py verify ... | python run.py confirm ...   # both still work (confirm = alias)
#
# The `verify` path is PURE ORCHESTRATION + PRESENTATION over the EXISTING confirmation
# path. It boots/connects
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
from backend.app.cli.branding import command_name, product_name  # noqa: E402
from backend.app.cli.config_flow import run_config_flow  # noqa: E402
from backend.app.cli.external_verify import run_external_verify  # noqa: E402
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
        # First-run detection: guide, don't crash. No stack trace, one clear line.
        print(
            f"No API key configured. Run  {command_name()} config  to set one up interactively "
            f"(provider, key, model) - or set GEMINI_API_KEY / LLM_API_KEY. Nothing was sent.",
            file=sys.stderr,
        )
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


def build_parser() -> argparse.ArgumentParser:
    """The CLI parser. `prog` and the description derive from the brand constant so
    the finalized name flows here with no edit. `verify` is the primary subcommand;
    `confirm` is kept as a back-compat alias so the historical `python run.py confirm`
    path keeps working."""
    ap = argparse.ArgumentParser(
        prog=command_name(),
        description=f"{product_name()} - confirm BOLA/IDOR access-control findings with the deep verifier.",
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    v = sub.add_parser(
        "verify", aliases=["confirm"],
        help="Confirm a BOLA/IDOR finding via the deep verifier (lab caseset OR an external real target).",
    )
    # Lab mode (unchanged): a built-in caseset + optional case id.
    v.add_argument("--caseset", default=None, help="LAB mode: path to a caseset JSON")
    v.add_argument("--case", default=None, help="LAB mode: a case id to confirm; omit to confirm ALL cases in the set")
    # External mode: a locally-run REAL target (base URL + OpenAPI spec + one operation).
    v.add_argument("--target", default=None, help="EXTERNAL mode: base URL of a locally-run real target, e.g. http://localhost:8888")
    v.add_argument("--spec", default=None, help="EXTERNAL mode: path to the target's OpenAPI JSON")
    v.add_argument("--op", default=None, help="EXTERNAL mode: path to an operation JSON {method, baseline_path, body, payload, shape}")
    v.add_argument("--auth", default=None, help="EXTERNAL mode (optional): path to a login JSON {method, path, username_field, password_field, token_field, token_location?} for auto re-login instead of static tokens; token_location is body (default) | header | cookie and token_field names the source there (JSON field / header name / cookie name). Credentials come from per-user config / masked prompt.")
    v.add_argument("--model", default=None, help="optional model override")

    sub.add_parser(
        "config",
        help="Interactive setup: choose a provider, enter your API key (hidden), set a model.",
    )
    return ap


def main():
    args = build_parser().parse_args()
    if args.cmd in ("verify", "confirm"):
        if args.auth and not args.target:
            print("--auth is for EXTERNAL mode; it needs --target (and --spec / --op).", file=sys.stderr)
            sys.exit(_EXIT_NOTDATA)
        if args.target:
            # EXTERNAL mode: exactly one mode, and --target needs --spec + --op.
            if args.caseset:
                print("Give EITHER --caseset (lab) OR --target (external), not both.", file=sys.stderr)
                sys.exit(_EXIT_NOTDATA)
            missing = [flag for flag, val in (("--spec", args.spec), ("--op", args.op)) if not val]
            if missing:
                print(f"EXTERNAL mode (--target) also requires {' and '.join(missing)}.", file=sys.stderr)
                sys.exit(_EXIT_NOTDATA)
            sys.exit(run_external_verify(
                target=args.target, spec_path=args.spec, op_path=args.op, model=args.model,
                auth_spec_path=args.auth,
            ))
        if not args.caseset:
            print("Give --caseset <path> (lab mode) or --target <url> --spec <path> --op <path> "
                  "(external real-target mode).", file=sys.stderr)
            sys.exit(_EXIT_NOTDATA)
        sys.exit(confirm(args.caseset, args.case, args.model))
    if args.cmd == "config":
        sys.exit(run_config_flow())


if __name__ == "__main__":
    main()
