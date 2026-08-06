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


_TIER_HEADER = [
    ("confirmed", "[CONFIRMED]  code-confirmed cross-user access (zero-FP tier)"),
    ("signal", "[SIGNAL]  verified by the model but NOT code-confirmed (a lead, not a confirmation)"),
    ("broken_for_all", "[INCONCLUSIVE - broken-for-all]  locked; requires human review"),
    ("refuted", "[REFUTED]  checked - no cross-user effect"),
    ("notdata", "[NOT DATA]  degraded / challenged - not a security signal"),
]


def render_scan_report(scan_result: Dict[str, Any], target: str, *, color: Optional[bool] = None) -> str:
    """Render the aggregated scan report. `scan_result` is the dict returned by scan_run.run_scan."""
    records = scan_result.get("records", [])
    dropped = scan_result.get("dropped", [])
    buckets = _group(records)

    out: List[str] = []
    out.append(f"=== scan report: {target} ===")
    out.append(f"  candidates accepted: {len(scan_result.get('accepted', []))}  |  "
               f"dropped by code fence: {len(dropped)}  |  ops judged: "
               f"{sum(len(buckets[k]) for k in ('confirmed', 'signal', 'broken_for_all', 'refuted', 'notdata'))}")
    out.append("")

    for key, header in _TIER_HEADER:
        group = buckets[key]
        if not group:
            continue
        out.append(f"{header}  ({len(group)})")
        for r in group:
            out.append(render_tree(r, color=color))
            out.append("")

    if buckets["skipped"]:
        out.append(f"[SKIPPED - needs manual id]  ({len(buckets['skipped'])})")
        for r in buckets["skipped"]:
            out.append(f"  - {r.get('method')} {r.get('baseline_path')}  "
                       f"({r.get('scan_skip_reason', 'needs manual id')})")
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
