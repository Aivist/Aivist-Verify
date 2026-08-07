# ==============================================================================
# scan — v1 orchestration: catalog -> AI candidates -> CODE FENCE -> id sourcing -> the EXISTING
# confirm run -> records. This is the ONRAMP loop. It reimplements NOTHING of the judge: each vetted
# op is handed to the caller-supplied `run_op`, which is the UNCHANGED `_verify_external` /
# `_verify_external_relogin` pre-bound with the run's creds. AI proposes; code vets (twice: the
# candidate descriptor AND the concrete op); the zero-FP engine judges. Direction-safe: a bad op is
# judged correctly (refuted / NOT-DATA), never a false positive.
# ==============================================================================
from __future__ import annotations

import logging
from typing import Any, Awaitable, Callable, Dict, List, Optional

from backend.app.services.endpoint_catalog import catalog_from_openapi, catalog_from_endpoints
from backend.app.cli.console.targets import build_op
from backend.app.cli.scan_discovery import (
    propose_candidates, discover_candidate_parts, validate_op, _default_provider_factory,
)
from backend.app.cli.scan_ids import source_ids
from backend.app.cli.external_verify import classify_degradation, _record_from_result, _approved_host
from backend.app.services.deep_verifier import fetch_control_view

logger = logging.getLogger("app.cli.scan_run")

# run_op: given a validated flat op, run the EXISTING confirm and return the engine result. Bound with
# the run's creds by the caller (static -> _verify_external; --auth -> _verify_external_relogin).
RunOp = Callable[[Dict[str, Any]], Awaitable[Any]]


def _skip_record(cand: Dict[str, str], reason: str) -> Dict[str, Any]:
    """A report row for a candidate that could not be sourced/vetted — grouped under [SKIPPED]. It is
    NOT a verdict: the engine was never called, so it can never be counted as confirmed/refuted."""
    return {
        "shape": cand.get("shape", "scan"),
        "final_verdict": None, "status": "skipped", "degraded": True, "degraded_reason": reason,
        "ground_truth": None,
        "method": cand.get("method"), "baseline_path": cand.get("path_template"),
        "attack_path": cand.get("path_template"), "body": None,
        "scan_skipped": True, "scan_skip_reason": reason,
    }


def _notdata_record(op: Dict[str, Any], reason: str) -> Dict[str, Any]:
    """A NOT-DATA report row for a candidate whose confirm RUN failed (e.g. a --auth login/refresh
    failure). The engine produced no verdict for it -> it groups under [NOT DATA], never a confirmed/
    refuted verdict. Direction-safe: a per-candidate auth failure is a safe miss, not a verdict."""
    return {
        "shape": op.get("shape", "scan"),
        "final_verdict": None, "status": "degraded", "degraded": True, "degraded_reason": reason,
        "ground_truth": None,
        "method": op.get("method"), "baseline_path": op.get("baseline_path"),
        "attack_path": op.get("baseline_path"), "body": op.get("body"),
    }


async def run_scan(
    target: str, spec: Optional[Dict[str, Any]] = None, *,
    run_op: RunOp,
    endpoints: Optional[List[str]] = None,
    id_map: Optional[Dict[str, Dict[str, str]]] = None,
    collections: Optional[Dict[str, str]] = None,
    harvest_attacker_cred: Any = None,
    harvest_owner_cred: Any = None,
    model: Optional[str] = None,
    provider_factory: Callable[[], Any] = _default_provider_factory,
    control_view: Callable[..., Awaitable[Any]] = fetch_control_view,
    client_factory: Optional[Callable[[], Any]] = None,
    raw_candidates: Optional[List[Any]] = None,
    assert_owner_only: bool = False,
) -> Dict[str, Any]:
    """Run the scan onramp and return a structured result:
      {records, dropped, skipped, accepted, catalog}.

    The endpoint catalog comes from EXACTLY ONE source: `spec` (an OpenAPI dict, today's path) OR
    `endpoints` (a user-provided "METHOD /path" list, for a target that publishes no spec). Both or
    neither -> ValueError (a clear error, not a crash). Only the catalog SOURCE differs; everything
    downstream (candidate proposal, code fence, id sourcing, confirm loop, report) is UNCHANGED.
    `raw_candidates` (optional) bypasses the AI proposal (offline tests); otherwise the model proposes.
    Every op that reaches `run_op` has passed BOTH code fences; a skip/drop never calls the engine."""
    if (spec is None) == (endpoints is None):
        raise ValueError("run_scan requires EXACTLY ONE of `spec` or `endpoints` "
                         f"(got spec={'set' if spec is not None else 'None'}, "
                         f"endpoints={'set' if endpoints is not None else 'None'})")
    catalog = catalog_from_openapi(spec) if spec is not None else catalog_from_endpoints(endpoints)
    approved = _approved_host(target)

    raw = raw_candidates if raw_candidates is not None else await propose_candidates(
        catalog, model=model, provider_factory=provider_factory)
    accepted, dropped_raw = discover_candidate_parts(catalog, raw)

    records: List[Dict[str, Any]] = []
    skipped: List[Dict[str, str]] = []
    dropped: List[Dict[str, Any]] = [{"reason": "failed_candidate_fence", "raw": r} for r in dropped_raw]

    kw = {}
    if client_factory is not None:
        kw["client_factory"] = client_factory

    for cand in accepted:
        ids = await source_ids(
            cand, base_url=target, approved_host=approved, id_map=id_map, collections=collections,
            attacker_cred=harvest_attacker_cred, owner_cred=harvest_owner_cred,
            control_view=control_view, catalog=catalog, model=model,   # tier-c: AI collection proposal
            provider_factory=provider_factory, **kw)
        if ids is None:
            skipped.append(cand)
            records.append(_skip_record(cand, "needs manual id (no id could be sourced)"))
            continue
        attacker_id, victim_id = ids
        op = build_op(cand["method"], cand["path_template"], cand["id_location"], cand["id_param"],
                      attacker_id, victim_id, shape=cand["shape"])
        if assert_owner_only:
            op["assert_owner_only"] = True   # run-level broken-for-all disclosure opt-in (D30)
        if not validate_op(op, catalog):
            # final CODE FENCE failed -> DROP, never run (defense in depth on the concrete op)
            dropped.append({"reason": "failed_op_fence", "op": op, "candidate": cand})
            logger.info("[SCAN] dropped op failing the final code fence: %r", op)
            continue
        try:
            result = await run_op(op)                              # the EXISTING confirm, unchanged
        except Exception as ex:
            # DIRECTION-SAFE: a per-candidate login/refresh/run failure -> NOT DATA for THIS candidate;
            # the scan CONTINUES to the next. Auth wiring can never manufacture a verdict.
            logger.info("[SCAN] candidate run failed (%s) -> NOT DATA, continuing", type(ex).__name__)
            records.append(_notdata_record(op, f"{type(ex).__name__}: {ex}"))
            continue
        records.append(_record_from_result(result, op, classify_degradation(result)))

    return {"records": records, "dropped": dropped, "skipped": skipped,
            "accepted": accepted, "catalog": catalog}
