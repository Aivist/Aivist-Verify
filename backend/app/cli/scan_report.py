# ==============================================================================
# scan — v1 aggregated report. Groups the per-op records by OUTCOME TIER and renders each finding with
# the SAME confirm_render tree the single-op `verify` uses (so a scan finding reads identically to a
# verify finding), plus a summary tally. The code-confirmed tier is kept visually distinct from the
# human-review tier — the per-finding claim-tiering (cut A) already does this; the report only groups.
# It reads verdicts ONLY from the engine's record fields (via confirm_render); it manufactures none.
# ==============================================================================
from __future__ import annotations

from typing import Any, Dict, List, Optional

from backend.app.cli.confirm_render import render_tree, case_outcome, _redact, _BROKEN_FOR_ALL_REASON


def _group(records: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Bucket records into the report tiers, reading ONLY engine fields (never ground_truth)."""
    buckets: Dict[str, List[Dict[str, Any]]] = {
        "confirmed": [], "signal": [], "broken_for_all": [], "refuted": [], "notdata": [], "skipped": []}
    for r in records:
        if r.get("scan_skipped"):
            buckets["skipped"].append(r)
        elif r.get("guard_override") == _BROKEN_FOR_ALL_REASON:
            buckets["broken_for_all"].append(r)      # human-review conditional finding (never confirmed)
        else:
            oc = case_outcome(r)                      # confirmed | signal | refuted | notdata
            buckets[oc if oc in buckets else "notdata"].append(r)
    return buckets


# Findings are GROUPED in PRIORITY order so acting-worthy findings sit at the top, not buried:
# confirmed (act first) -> signal (verify these leads) -> broken-for-all (needs your review) ->
# skipped (needs an id from you) -> refuted (safe) -> not-data (blocked). Signal is placed right
# after confirmed because it is still a `verified` verdict (exit_code 1) and worth verifying early.
_PRIORITY_ORDER = [
    ("confirmed", "[CONFIRMED]  code-confirmed cross-user access (zero-FP tier) - ACT ON THESE FIRST"),
    ("signal", "[SIGNAL]  verified by the model but NOT code-confirmed (a lead to verify, not a confirmation)"),
    ("broken_for_all", "[INCONCLUSIVE - broken-for-all]  locked; needs YOUR review of the intended access policy"),
    ("skipped", "[SKIPPED - needs manual id]  no object id could be sourced automatically"),
    ("refuted", "[REFUTED]  checked - no cross-user effect here"),
    ("notdata", "[NOT DATA]  the target blocked/challenged the run - not a security signal"),
]

# The one-line "So what / Next step" for the SKIPPED tier (rendered once per group — the action is the
# same for every skipped endpoint). render_tree handles the next-step for the judged tiers.
_SKIPPED_NEXT_STEP = (
    "    So what / Next step: couldn't obtain an object id automatically for these endpoints. "
    "Next: provide an id (id_map) or declare its list endpoint (collections), then re-scan.")


def _plural(n: int, singular: str, plural: Optional[str] = None) -> str:
    return f"{n} {singular if n == 1 else (plural or singular + 's')}"


def _priority_summary(buckets: Dict[str, List[Dict[str, Any]]]) -> str:
    """The 'where do I start' line at the TOP. The `confirmed` count is CODE-CONFIRMED ONLY (buckets
    ['confirmed'] == case_outcome 'confirmed'; mirrors exit_code_for's tier discipline) — a
    broken-for-all / not-data is NEVER counted as a confirmed bug in this headline. A signal segment
    only appears when there is one (a lead to verify, not a confirmation)."""
    segs = [f"{_plural(len(buckets['confirmed']), 'confirmed cross-user bug')} (act on these first)"]
    if buckets["signal"]:
        segs.append(f"{_plural(len(buckets['signal']), 'lead')} to verify (signal)")
    segs += [
        f"{len(buckets['broken_for_all'])} need your review (broken-for-all)",
        f"{len(buckets['skipped'])} need an id from you (skipped)",
        f"{len(buckets['refuted'])} safe (refuted)",
        f"{len(buckets['notdata'])} blocked by the target (not data)",
    ]
    return "  Where to start: " + " | ".join(segs)


def _no_candidates_report(catalog, accepted, dropped) -> str:
    """Honest report when the scan discovered ZERO testable candidates. It did NOT test anything, so it
    must NOT print a '0 confirmed | 0 refuted | ...' tally — that reads like a clean/secure bill of health.
    Say plainly what happened, with the real numbers (endpoints seen; how many the AI proposed)."""
    seen = len(catalog or [])
    proposed = len(accepted or []) + len(dropped or [])        # AI proposals that reached the code fence
    out = ["  No testable BOLA/IDOR candidates were discovered from this spec."]
    if seen == 0:
        out.append("  0 endpoints were parsed from the catalog - the spec is likely NOT a valid "
                   "OpenAPI/Swagger document (no `paths`), so the AI candidate step was never even run.")
    elif proposed == 0:
        out.append(f"  {seen} endpoint(s) were seen, but 0 were proposed as BOLA/IDOR candidates "
                   "(none had an id-shaped object parameter, or the model proposed none).")
    else:
        out.append(f"  {seen} endpoint(s) were seen; {proposed} candidate(s) proposed but ALL were "
                   f"rejected by the code fence (0 survived, {len(dropped or [])} dropped) - none matched a "
                   "real {id}-templated path / query id in the catalog.")
    out.append("  This is NOT a 'secure' result - the scan did NOT test anything.")
    out.append("  Next: check the spec is a real OpenAPI doc with {id}-templated object endpoints "
               "(e.g. /books/v1/{book_title}), or provide an endpoints list / a candidate manually.")
    return "\n".join(out)


def render_scan_report(scan_result: Dict[str, Any], target: str, *, color: Optional[bool] = None) -> str:
    """Render the aggregated scan report. `scan_result` is the dict returned by scan_run.run_scan."""
    records = scan_result.get("records", [])
    dropped = scan_result.get("dropped", [])

    out: List[str] = []
    out.append(f"=== scan report: {target} ===")

    # HONEST EMPTY: the scan judged/skipped NOTHING (0 records => 0 candidates accepted). It did not test
    # anything, so do NOT print a tier tally (a row of zeros reads as 'secure'). Report the empty discovery.
    if not records:
        out.append(_no_candidates_report(
            scan_result.get("catalog", []), scan_result.get("accepted", []), dropped))
        return _redact("\n".join(out))

    buckets = _group(records)
    out.append(_priority_summary(buckets))                 # the prioritized "where do I start" line, at the top
    out.append(f"  candidates accepted: {len(scan_result.get('accepted', []))}  |  "
               f"dropped by code fence: {len(dropped)}  |  ops judged: "
               f"{sum(len(buckets[k]) for k in ('confirmed', 'signal', 'broken_for_all', 'refuted', 'notdata'))}")
    out.append("")

    for key, header in _PRIORITY_ORDER:                    # findings grouped in PRIORITY order (confirmed first)
        group = buckets[key]
        if not group:
            continue
        out.append(f"{header}  ({len(group)})")
        if key == "skipped":
            for r in group:
                out.append(f"  - {r.get('method')} {r.get('baseline_path')}  "
                           f"({r.get('scan_skip_reason', 'needs manual id')})")
            out.append(_SKIPPED_NEXT_STEP)
        else:
            for r in group:
                out.append(render_tree(r, color=color))
                out.append("")
        out.append("")

    # Summary tally — the code-confirmed count is the headline; a model-only signal is separate.
    out.append(
        "Summary:  "
        f"{len(buckets['confirmed'])} confirmed (code-gated)  |  "
        f"{len(buckets['signal'])} signal(s)  |  "
        f"{len(buckets['broken_for_all'])} broken-for-all (review)  |  "
        f"{len(buckets['refuted'])} refuted  |  "
        f"{len(buckets['notdata'])} not-data  |  "
        f"{len(buckets['skipped'])} skipped  |  "
        f"{len(dropped)} invalid candidate(s) dropped")
    return _redact("\n".join(out))
