#!/usr/bin/env python
"""
verdict_measure — first-class measurement harness for the access-control verifier.

Drives the REAL `execute_deep_verification` at HEAD against a fresh-seeded target and
emits a STRUCTURED, committable evidence artifact (one JSON row per run) plus a
human-readable summary and a per-case regression check against a known-good baseline.

This is the tool the zero-false-positive claim is measured with. It is deliberately
parameterized (target / case set / N / model / seed policy) with NO hardcoded paths, so
the same harness measures either lab and any future case set.

It calls a real LLM: it needs the reader's own GEMINI_API_KEY in the environment (or a
backend/.env), and it makes roughly (sum of N over selected cases) model calls. Runtime
flags AI_DEEP_VERIFY_ENABLED / AI_DEEP_VERIFY_OWNER_AUTH are set in-process only; the
committed config defaults are unchanged.

Examples
--------
  # N=1 sweep across both labs, structured output to results.jsonl
  python scripts/measure/verdict_measure.py \
      --caseset scripts/measure/casesets/vulnerable_target.json \
      --caseset scripts/measure/casesets/depot.json \
      --n 1 --out run.jsonl

  # one case, curated committable transcript
  python scripts/measure/verdict_measure.py --caseset .../depot.json \
      --cases DP-READ-SAFE --curated-transcript curated.txt --curated-cases DP-READ-SAFE

Verbose per-run logs go to the gitignored scripts/audit/ path by default; a curated
transcript (committable) is written only for the cases named with --curated-cases.
"""

import os
import sys
import csv
import json
import time
import uuid
import argparse
import asyncio
import logging
import tempfile
import datetime
import subprocess
from collections import Counter, defaultdict

import httpx

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, _REPO_ROOT)

from backend.app.core.config import settings  # noqa: E402
from backend.app.services.endpoint_catalog import catalog_from_openapi  # noqa: E402
from backend.app.services.deep_verifier import (  # noqa: E402
    execute_deep_verification,
    OwnerCredential,
    fetch_owner_view,
    flatten_evidence,
)
from backend.app.services.fuzzer import (  # noqa: E402
    _compute_similarity,
    _code_authorized_channel,
)

# v3 adds the D19 promotion-layer observation columns (owner_view_corroborated,
# promotion_channel, would_promote) so the golden reproduction can prove, case-for-case,
# that the promotion decision reproduces the engine's 'verified' partition. Observation
# only — this harness never invokes the promotion writer or the PROMOTE flag; it records
# what the choke point _would_ authorize on the SAME DeepVerificationResult the engine
# produced.
SCHEMA_VERSION = 3
logger = logging.getLogger("verdict_measure")


# ---------------------------------------------------------------------------
# Target subprocess lifecycle
# ---------------------------------------------------------------------------
def _rm_db(path):
    for suffix in ("", "-wal", "-shm"):
        try:
            os.remove(path + suffix)
        except OSError:
            pass


def _boot_target(module, port, db_env, db_url):
    env = dict(os.environ)
    env[db_env] = db_url
    creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", module, "--host", "127.0.0.1",
         "--port", str(port), "--log-level", "warning"],
        cwd=_REPO_ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        creationflags=creationflags,
    )
    base = f"http://127.0.0.1:{port}"
    deadline = time.time() + 30
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"{module} exited early (code={proc.returncode})")
        try:
            if httpx.get(base + "/", timeout=2.0).status_code == 200:
                return proc
        except Exception:
            time.sleep(0.4)
    proc.terminate()
    raise RuntimeError(f"{module} not ready on :{port} within 30s")


def _stop_target(proc):
    if proc is None:
        return
    try:
        proc.terminate(); proc.wait(timeout=10)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Request construction
# ---------------------------------------------------------------------------
def _fill_unique(body, unique):
    if body is None:
        return None
    return {k: (unique if v == "$UNIQUE" else v) for k, v in body.items()}


def _parsed_request(case, unique):
    return {
        "method": case["method"],
        "path": case["baseline_path"],
        "query_params": {},
        "headers": {"Content-Type": "application/json"} if case.get("body") else {},
        "body": _fill_unique(case.get("body"), unique),
    }


def _attack_path(case):
    """The path the attack actually hits: baseline path with the attacked id swapped in.
    Only used for the independent owner-view similarity measurement on read cases."""
    p = case["payload"]
    return case["baseline_path"].replace(str(p["target_param"]), str(p["payload_string"]))


def _channel(guard_override):
    """A short label for the exemption channel that fired (or '-')."""
    return guard_override or "-"


# ---------------------------------------------------------------------------
# Regression check vs the known-good baseline stored in the caseset
# ---------------------------------------------------------------------------
def _regression(case, final, guard_override):
    gt = case["ground_truth"]
    if gt in ("SECURE", "CONTROL"):
        ok = final != "verified"
        return ok, ("SAFE/control never verified" if ok
                    else "*** SEV-1: SAFE/control reached 'verified' ***")
    # REAL
    if final != "verified":
        return False, "*** SEV-2: core VULN did not verify ***"
    expected = case.get("baseline_channel")
    if expected is not None and guard_override != expected:
        return False, (f"*** channel moved: expected {expected!r}, got {guard_override!r} ***")
    return True, "VULN verified via expected channel"


# ---------------------------------------------------------------------------
# One run
# ---------------------------------------------------------------------------
async def _run_one(case, caseset, model, run_index, n, curated_fh):
    unique = f"vm-{run_index}-{uuid.uuid4().hex[:10]}"
    base = f"http://127.0.0.1:{caseset['port']}"
    approved = f"127.0.0.1:{caseset['port']}"
    owner = OwnerCredential.from_config(caseset["owner_auth"])

    # Real endpoint catalog straight from the booted target (target-agnostic).
    spec = httpx.get(base + "/openapi.json", timeout=10.0).json()
    catalog = catalog_from_openapi(spec)

    row = {
        "schema_version": SCHEMA_VERSION,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "model": model or settings.GEMINI_PRO_MODEL,
        "target": caseset["target"],
        "case_id": case["id"],
        "ground_truth": case["ground_truth"],
        "shape": case["shape"],
        "run_index": run_index,
        "n": n,
    }
    try:
        res = await execute_deep_verification(
            parsed_request=_parsed_request(case, unique),
            payload=case["payload"],
            base_url=base,
            approved_host=approved,
            auth_context={"Authorization": caseset["attacker_auth"]},
            available_endpoints=catalog,
            owner_credential=owner,
            model_name=model,
        )
        degraded = res.status == "degraded" or res.ai_verdict is None
        # D19 promotion-layer observation on the SAME result the engine produced: what the
        # code choke point would authorize. would_promote must reproduce final_verdict=='verified'
        # case-for-case in the golden record (checked in _summary); any divergence is a finding.
        _promo_channel = _code_authorized_channel(res)
        row.update({
            "ai_verdict_raw": res.ai_verdict_raw,
            "final_verdict": res.ai_verdict,
            "guard_override": res.guard_override,
            "exemption_channel": _channel(res.guard_override),
            "status": res.status,
            "caller_identity": res.caller_identity_anchor,
            "payload_causality": res.payload_causality_anchor,
            "state_jump": res.state_jump_anchor,
            "negative_assertion": res.negative_assertion_anchor,
            "anchoring_result": res.anchoring_result,
            "pre_flight_status": res.pre_flight_status,
            "follow_up_performed": bool(res.follow_up_request),
            "follow_up_path": (res.follow_up_request or {}).get("path"),
            "owner_view_available": None,
            "owner_view_similarity": None,
            "owner_view_corroborated": res.owner_view_corroborated,
            "promotion_channel": _promo_channel,
            "would_promote": _promo_channel is not None,
            "degraded": degraded,
            "degraded_reason": res.degraded_reason,
            "error": None,
            # Cut B: flattened, ALREADY-redacted physical evidence bytes (baseline/attack/follow-up/
            # owner-view). New golden rows carry it; existing golden rows (no key) render via cut A.
            "evidence": flatten_evidence(res),
        })

        # Independent owner-view similarity for the record (read-semantic only; local
        # HTTP, no model cost). This is observation, not the gate — the gate ran inside
        # execute_deep_verification above and its outcome is in guard_override.
        if case["shape"] == "read_semantic":
            async with httpx.AsyncClient(timeout=20.0, verify=False) as c:
                atk = (await c.get(base + _attack_path(case),
                                   headers={"Authorization": caseset["attacker_auth"]})).text
                ov = await fetch_owner_view(c, _attack_path(case), base, owner,
                                            approved_host=approved)
            row["owner_view_available"] = ov.available
            row["owner_view_similarity"] = round(_compute_similarity(atk, ov.body or ""), 4)

        ok, note = _regression(case, res.ai_verdict, res.guard_override)
        if degraded:
            ok, note = None, "degraded/no-verdict (NOT DATA)"
    except Exception as e:
        row.update({
            "ai_verdict_raw": None, "final_verdict": None, "guard_override": None,
            "exemption_channel": None, "status": "error",
            "caller_identity": None, "payload_causality": None, "state_jump": None,
            "negative_assertion": None, "anchoring_result": None, "pre_flight_status": None,
            "follow_up_performed": None, "follow_up_path": None,
            "owner_view_available": None, "owner_view_similarity": None,
            "owner_view_corroborated": None, "promotion_channel": None,
            "would_promote": False,
            "degraded": True, "degraded_reason": None,
            "error": f"{type(e).__name__}: {e}",
            "evidence": None,                              # cut B: no exchange captured on an error row
        })
        ok, note = None, f"error: {row['error']}"

    row["regression_ok"] = ok
    row["regression_note"] = note

    if curated_fh is not None:
        curated_fh.write(json.dumps(row, indent=2, ensure_ascii=False) + "\n")
        curated_fh.flush()
    return row


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------
def _n_for(case, n_safe, n_vuln):
    """Per-case N: VULN (REAL) cases use n_vuln; SAFE/CONTROL use n_safe. The zero-FP
    methodology runs SAFE/control at higher N (they are what prove NO false positive) and
    VULN at lower N (a stability check)."""
    return n_vuln if case["ground_truth"] == "REAL" else n_safe


async def _run_caseset(caseset, selected, n_safe, n_vuln, model, seed_policy, out_fh, curated_fh):
    db_path = os.path.join(tempfile.gettempdir(),
                           f"verdict_measure_{caseset['target']}.db")
    db_url = "sqlite+aiosqlite:///" + db_path.replace("\\", "/")
    os.environ[caseset["db_env"]] = db_url
    settings.AI_DEEP_VERIFY_OWNER_AUTH = caseset["owner_auth"]

    rows = []
    proc = None
    try:
        if seed_policy == "per-case":
            _rm_db(db_path)
            proc = _boot_target(caseset["module"], caseset["port"], caseset["db_env"], db_url)
        for case in selected:
            n = _n_for(case, n_safe, n_vuln)
            print(f"\n### {caseset['target']} :: {case['id']}  "
                  f"[{case['ground_truth']} / {case['shape']}]  N={n}")
            for run_index in range(1, n + 1):
                if seed_policy == "per-run":
                    _stop_target(proc); proc = None
                    _rm_db(db_path)
                    proc = _boot_target(caseset["module"], caseset["port"],
                                        caseset["db_env"], db_url)
                row = await _run_one(case, caseset, model, run_index, n,
                                     curated_fh if case["id"] in curated_fh_ids else None)
                out_fh.write(json.dumps(row, ensure_ascii=False) + "\n")
                out_fh.flush()
                rows.append(row)
                sim = row.get("owner_view_similarity")
                print(f"  run {run_index}/{n}: raw={row['ai_verdict_raw']!r} -> "
                      f"FINAL={row['final_verdict']!r}  channel={row['exemption_channel']}"
                      + (f"  ov_sim={sim}" if sim is not None else "")
                      + (f"  [{row['regression_note']}]" if row['regression_ok'] is False else ""))
    finally:
        _stop_target(proc)
    return rows


# module-level set populated in main(), read by _run_caseset for curated routing
curated_fh_ids = set()


def _load_golden(path):
    """Load the committed golden record into a per-case partition — the INDEPENDENT acceptance
    bar. The new run is diffed case-for-case against THIS, so an engine or choke-point regression
    surfaces as a golden divergence rather than passing against the run's own output.

    Returns {(target, case_id): {"verified": bool, "final_verdicts": set, "channels": set,
    "n": int, "shape": str}}. `verified` is True iff EVERY golden run for that case was 'verified'.
    """
    by_case = defaultdict(list)
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            by_case[(r["target"], r["case_id"])].append(r)
    golden = {}
    for key, rs in by_case.items():
        finals = set(r["final_verdict"] for r in rs)
        golden[key] = {
            "verified": finals == {"verified"},
            "final_verdicts": finals,
            "channels": set(r.get("guard_override") for r in rs),
            "n": len(rs),
            "shape": rs[0].get("shape"),
        }
    return golden


def _summary(all_rows, golden=None):
    print("\n" + "=" * 108)
    print("STRUCTURED SUMMARY")
    print("=" * 108)
    hdr = f"{'CASE':<22}{'TARGET':<18}{'GT':<8}{'SHAPE':<15}{'RAW':<11}{'FINAL':<13}{'CHANNEL':<40}"
    print(hdr)
    print("-" * 108)
    # collapse to one line per case (mode of finals if N>1)
    by_case = defaultdict(list)
    for r in all_rows:
        by_case[(r["target"], r["case_id"])].append(r)
    for (target, cid), rs in by_case.items():
        r0 = rs[0]
        finals = Counter(r["final_verdict"] for r in rs)
        chans = Counter(r["exemption_channel"] for r in rs)
        fdisp = finals.most_common(1)[0][0] if len(finals) == 1 else dict(finals)
        cdisp = chans.most_common(1)[0][0] if len(chans) == 1 else dict(chans)
        print(f"{cid:<22}{target:<18}{r0['ground_truth']:<8}{r0['shape']:<15}"
              f"{str(r0['ai_verdict_raw']):<11}{str(fdisp):<13}{str(cdisp):<40}")

    print("\n" + "=" * 108)
    print("ACCEPTANCE")
    print("=" * 108)
    sev1 = [r for r in all_rows if r["ground_truth"] in ("SECURE", "CONTROL")
            and r["final_verdict"] == "verified"]
    sev2 = [r for r in all_rows if r["ground_truth"] == "REAL"
            and r["final_verdict"] != "verified" and not r["degraded"]]
    moved = [r for r in all_rows if r["regression_ok"] is False and r not in sev1 and r not in sev2]
    degraded = [r for r in all_rows if r["degraded"]]

    non_read_moved = [r for r in all_rows
                      if r["shape"] != "read_semantic" and r["regression_ok"] is False]

    # ---- §5.2 GOLDEN-ANCHORED acceptance: diff the new run case-for-case against the committed
    # sweep_highN.jsonl. The golden record is the INDEPENDENT bar — never the run's own output —
    # so an engine OR choke-point regression surfaces here as a golden divergence:
    #   * golden_final_div — new-run FINAL (engine verdict) disagrees with the golden case verdict
    #                        (the classic "reproduce the golden record" check).
    #   * promo_fp  — new-run would_promote on a case the GOLDEN says is NOT 'verified' (SEV-1:
    #                 the model would have been handed authority to fabricate a verdict).
    #   * promo_lost— a GOLDEN-'verified' case the new-run would NOT promote (SEV-2: promotion
    #                 would silently drop a true verdict — e.g. an unforeseen same-path verified).
    # NOTE: would_promote is compared to the GOLDEN partition, never to this run's own final.
    golden_final_div, promo_fp, promo_lost, unknown_case = [], [], [], []
    if golden is not None:
        for r in all_rows:
            key = (r["target"], r["case_id"])
            g = golden.get(key)
            if g is None:
                unknown_case.append(r)
                continue
            if not r["degraded"]:
                new_verified = (r["final_verdict"] == "verified")
                if new_verified != g["verified"]:
                    golden_final_div.append((r, g))
            if r.get("would_promote") and not g["verified"]:
                promo_fp.append((r, g))
            if g["verified"] and not r.get("would_promote") and not r["degraded"]:
                promo_lost.append((r, g))
        seen = {(r["target"], r["case_id"]) for r in all_rows}
        missing_golden = [k for k in golden if k not in seen]
    else:
        missing_golden = []

    for r in all_rows:
        if r["regression_ok"] is False:
            print(f"  FAIL  {r['target']}::{r['case_id']} run {r['run_index']}: {r['regression_note']}")
    for r, g in golden_final_div:
        print(f"  GOLDEN-DIV {r['target']}::{r['case_id']} run {r['run_index']}: FINAL={r['final_verdict']!r} "
              f"but golden case verified={g['verified']} (golden finals={g['final_verdicts']})")
    for r, g in promo_fp:
        print(f"  PROMO-FP  {r['target']}::{r['case_id']} run {r['run_index']}: would PROMOTE via "
              f"{r.get('promotion_channel')!r} but GOLDEN says this case is NOT verified — SEV-1")
    for r, g in promo_lost:
        print(f"  PROMO-LOST {r['target']}::{r['case_id']} run {r['run_index']}: GOLDEN-'verified' case "
              f"would NOT promote (guard_override={r.get('guard_override')!r} "
              f"owner_view_corroborated={r.get('owner_view_corroborated')!r}) — SEV-2")
    for r in unknown_case:
        print(f"  NO-GOLDEN {r['target']}::{r['case_id']}: case absent from the golden record")
    for k in missing_golden:
        print(f"  MISSING   {k[0]}::{k[1]}: golden case has NO run in this sweep (incomplete reproduction)")

    print(f"\n  SAFE/control reaching verified (SEV-1): {len(sev1)}")
    print(f"  core VULN not verifying   (SEV-2): {len(sev2)}")
    print(f"  four-non-read-shape movements    : {len(non_read_moved)}  "
          f"(ANY is a regression -> stop before high N)")
    print(f"  degraded/error runs (NOT DATA)   : {len(degraded)}")
    print(f"  golden FINAL divergences (case-for-case vs sweep_highN.jsonl): {len(golden_final_div)}")
    print(f"  D19 promo false positives  (SEV-1, golden-anchored): {len(promo_fp)}")
    print(f"  D19 promo lost verdicts    (SEV-2, golden-anchored): {len(promo_lost)}")
    print(f"  cases absent from golden / golden cases unrun: {len(unknown_case)} / {len(missing_golden)}")
    clean = (golden is not None
             and not sev1 and not sev2 and not non_read_moved and not degraded
             and not golden_final_div and not promo_fp and not promo_lost
             and not unknown_case and not missing_golden)
    if clean:
        print("\n  CLEAN — new-run FINAL reproduces the committed golden record case-for-case; the D19")
        print("  promotion decision (would_promote) reproduces the golden 'verified' partition exactly;")
        print("  zero SAFE promoted, zero golden-verified dropped, zero degraded. Acceptance met.")
    elif golden is None:
        print("\n  NO GOLDEN LOADED — cannot assert §5.2 acceptance. Pass --golden.")
    else:
        print("\n  NOT CLEAN — STOP and report. Do not touch the engine, labels, or threshold.")
    print("=" * 108)


def main():
    ap = argparse.ArgumentParser(description="Structured verdict measurement harness.")
    ap.add_argument("--caseset", action="append", required=True,
                    help="path to a caseset JSON (repeatable)")
    ap.add_argument("--n", type=int, default=1,
                    help="runs per case (default 1); the fallback for --n-safe/--n-vuln")
    ap.add_argument("--n-safe", type=int, default=None,
                    help="runs per SAFE/CONTROL case (defaults to --n). SAFE cases prove NO "
                         "false positive, so the zero-FP methodology runs them at higher N.")
    ap.add_argument("--n-vuln", type=int, default=None,
                    help="runs per REAL (VULN) case (defaults to --n); a stability check.")
    ap.add_argument("--model", default=None, help="override GEMINI_PRO_MODEL")
    ap.add_argument("--seed-policy", choices=["per-run", "per-case"], default="per-run",
                    help="per-run reboots+reseeds the target before EVERY run (default; "
                         "required for mutating cases at N>1)")
    ap.add_argument("--cases", default=None,
                    help="comma-separated case ids to include (default: all)")
    ap.add_argument("--out", default=None,
                    help="structured JSONL output path (the evidence artifact)")
    ap.add_argument("--golden", default=None,
                    help="path to the committed golden record (e.g. scripts/measure/results/"
                         "sweep_highN.jsonl). When set, acceptance is diffed case-for-case against "
                         "it: FINAL reproduction + golden-anchored promo_fp/promo_lost. The "
                         "independent bar — a regression surfaces as a golden divergence.")
    ap.add_argument("--curated-transcript", default=None,
                    help="committable transcript file for the --curated-cases only")
    ap.add_argument("--curated-cases", default=None,
                    help="comma-separated case ids to include in the curated transcript")
    args = ap.parse_args()

    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    for noisy in ("httpx", "httpcore", "google_genai", "google.genai", "uvicorn"):
        logging.getLogger(noisy).setLevel(logging.ERROR)

    # Runtime-only: enable the verifier. Committed defaults stay False.
    settings.AI_DEEP_VERIFY_ENABLED = True

    case_filter = set(args.cases.split(",")) if args.cases else None
    global curated_fh_ids
    curated_fh_ids = set(args.curated_cases.split(",")) if args.curated_cases else set()

    out_fh = open(args.out, "w", encoding="utf-8") if args.out else open(os.devnull, "w")
    curated_fh = (open(args.curated_transcript, "w", encoding="utf-8")
                  if args.curated_transcript else None)

    n_safe = args.n_safe if args.n_safe is not None else args.n
    n_vuln = args.n_vuln if args.n_vuln is not None else args.n

    planned = 0
    casesets = []
    for path in args.caseset:
        cs = json.load(open(path, encoding="utf-8"))
        selected = [c for c in cs["cases"] if not case_filter or c["id"] in case_filter]
        casesets.append((cs, selected))
        planned += sum(_n_for(c, n_safe, n_vuln) for c in selected)

    print("=" * 108)
    print("verdict_measure — structured measurement run")
    print("=" * 108)
    print(f"model={args.model or settings.GEMINI_PRO_MODEL}  N_safe={n_safe} N_vuln={n_vuln}  "
          f"seed_policy={args.seed_policy}  planned model calls={planned}")
    if args.out:
        print(f"structured artifact -> {args.out}")

    async def _go():
        all_rows = []
        for cs, selected in casesets:
            all_rows += await _run_caseset(cs, selected, n_safe, n_vuln, args.model,
                                           args.seed_policy, out_fh, curated_fh)
        return all_rows

    rows = asyncio.run(_go())
    out_fh.close()
    if curated_fh:
        curated_fh.close()
    golden = _load_golden(args.golden) if args.golden else None
    if args.golden:
        print(f"golden record -> {args.golden}  ({len(golden)} cases)")
    _summary(rows, golden)


if __name__ == "__main__":
    main()
