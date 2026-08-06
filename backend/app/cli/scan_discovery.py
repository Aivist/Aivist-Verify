# ==============================================================================
# scan — v1 auto-discovery onramp: AI-driven candidate SELECTION + op generation, CODE-FENCED.
#
# This is the ONRAMP to the existing confirm engine. AI drives DISCOVERY only (which endpoints look
# like BOLA candidates + which param is the object id). CODE then VETS every proposal before it can
# run, and the unchanged zero-FP engine judges every op. AI can never widen what gets confirmed:
#   * AI proposes  -> a candidate DESCRIPTOR {method, templated path, id location, id param}
#   * CODE vets     -> the path must exist in the catalog VERBATIM; the id param must be a real
#                      template var (path) or a name (query); the shape/location are CODE-assigned
#                      from the known set (the AI's shape is never trusted).
#   * id-sourcing   -> fills the attacker/victim ids (scan_ids), producing the flat op.
#   * CODE vets AGAIN (validate_op) the CONCRETE op before it runs: path templated-matches the
#     catalog AND target_param actually appears in baseline_path. A failing op is DROPPED, never run.
#
# DIRECTION-SAFE: a wrongly-generated op is confirmed/refuted/NOT-DATA correctly by the existing
# judge. Auto-discovery CANNOT create a false positive. It touches NO verdict/engine logic.
# ==============================================================================
from __future__ import annotations

import json
import logging
from typing import Any, Callable, Dict, List, Optional, Tuple

from backend.app.services.endpoint_catalog import entry_method, entry_path

logger = logging.getLogger("app.cli.scan_discovery")

_METHODS = frozenset({"GET", "POST", "PUT", "DELETE", "PATCH"})
# CODE-assigned shapes (the AI's `shape` is never trusted — it is derived from the id location, so a
# vetted op's shape is ALWAYS one of these known values).
_SHAPE_BY_LOCATION = {"path": "path_segment_bola", "query": "query_string_idor"}
_KNOWN_SHAPES = frozenset(_SHAPE_BY_LOCATION.values())
_KNOWN_LOCATIONS = frozenset({"path_segment", "query_param"})


_DISCOVERY_SYSTEM_PROMPT = (
    "You are an API security analyst selecting BOLA / IDOR candidates from an endpoint catalog. "
    "A BOLA candidate is an endpoint that reads or writes ONE object identified by an id in the "
    "path or query string, where flipping that id to another user's object could expose a "
    "cross-user access-control flaw.\n\n"
    "You are given a catalog of real endpoints (one per line: 'METHOD /path  [metadata]'). Select "
    "the endpoints whose object id could be flipped between two users, and for EACH return an "
    "object with these fields ONLY:\n"
    "  method        - the HTTP method, exactly as in the catalog\n"
    "  path_template - the /path EXACTLY as in the catalog (verbatim; keep {templated} segments)\n"
    "  id_location   - \"path\" (the id is a {templated} path segment) or \"query\" (a ?name= param)\n"
    "  id_param      - for path: the template variable name (e.g. \"order_id\" for /orders/{order_id});\n"
    "                  for query: the query parameter name (e.g. \"report_id\")\n"
    "  reason        - one short phrase on why it is a candidate\n\n"
    "Rules: use ONLY endpoints present in the catalog; use the path VERBATIM; do NOT invent paths or "
    "ids. Return STRICT JSON of the form {\"candidates\": [ ... ]} and nothing else."
)


def _build_discovery_prompt(catalog: List[str]) -> str:
    listing = "\n".join(f"  {e}" for e in catalog)
    return ("Endpoint catalog:\n" + listing + "\n\n"
            "Return {\"candidates\": [...]} selecting the BOLA/IDOR candidates per the schema.")


def _catalog_pairs(catalog: List[str]) -> set:
    """The set of (METHOD, templated /path) the catalog advertises — for verbatim descriptor match."""
    return {(entry_method(e), entry_path(e)) for e in (catalog or [])}


def _seg_match(template_path: str, concrete_path: str) -> bool:
    """Segment-wise match where a '{templated}' catalog segment is a wildcard (mirrors
    endpoint_catalog._templates_match — kept local so this module has no private import)."""
    a = (template_path or "").split("/")
    b = (concrete_path or "").split("/")
    if len(a) != len(b):
        return False
    for s_a, s_b in zip(a, b):
        if s_a.startswith("{") and s_a.endswith("}"):
            continue
        if s_a != s_b:
            return False
    return True


def _concrete_path_in_catalog(method: str, concrete_path: str, catalog: List[str]) -> bool:
    """True iff `concrete_path` (ids filled in, query stripped) templated-matches a catalog endpoint
    of the same method."""
    p = (concrete_path or "").split("?", 1)[0]
    m = (method or "").upper()
    for e in (catalog or []):
        if entry_method(e) != m:
            continue
        if _seg_match(entry_path(e), p):
            return True
    return False


# ------------------------------------------------------------------------------
# AI proposal (discovery) — mirrors api/v1/hunter's provider pattern; graceful on every failure.
# ------------------------------------------------------------------------------
def _default_provider_factory() -> Any:
    # lazy import: the LLM service pulls provider SDKs; keep it out of module import for offline tests
    from backend.app.services.llm import get_provider
    return get_provider()


async def propose_candidates(
    catalog: List[str], *, model: Optional[str] = None,
    provider_factory: Callable[[], Any] = _default_provider_factory, timeout: float = 30.0,
) -> List[Dict[str, Any]]:
    """Ask the model to select BOLA candidates from the catalog. Returns the RAW candidate list (to
    be code-vetted by `validate_candidate`), or [] on any failure / no provider (graceful — a discovery
    miss yields no candidates, never a crash and never a fabricated one)."""
    if not catalog:
        return []
    try:
        provider = provider_factory()
    except Exception as e:
        logger.warning("[SCAN·DISCOVERY] provider unavailable (%s); no candidates.", type(e).__name__)
        return []
    if provider is None or not getattr(provider, "is_configured", lambda: False)():
        return []
    model_name = model or getattr(provider, "default_model", "") or ""
    if model_name.startswith("models/"):
        model_name = model_name[len("models/"):]
    try:
        raw_text = (await provider.generate(
            messages=[{"role": "user", "text": _build_discovery_prompt(catalog)}],
            system=_DISCOVERY_SYSTEM_PROMPT, json_mode=True, temperature=0.2,
            model=model_name, timeout=timeout, max_attempts=1,
        )).strip()
        data = json.loads(raw_text)
    except Exception as e:
        logger.warning("[SCAN·DISCOVERY] proposal failed (%s); no candidates.", type(e).__name__)
        return []
    cands = data.get("candidates") if isinstance(data, dict) else None
    return cands if isinstance(cands, list) else []


# ------------------------------------------------------------------------------
# CODE FENCE — validate every AI proposal before it can run.
# ------------------------------------------------------------------------------
def validate_candidate(raw: Any, catalog: List[str]) -> Optional[Dict[str, str]]:
    """Vet ONE AI-proposed candidate against the catalog. Returns a normalized DESCRIPTOR
    {method, path_template, id_location, id_param, shape} — with `shape` CODE-assigned from the id
    location (the AI's shape is never trusted) — or None to DROP it. A dropped candidate is never run."""
    if not isinstance(raw, dict):
        return None
    method = str(raw.get("method", "")).upper().strip()
    if method not in _METHODS:
        return None
    path_template = str(raw.get("path_template", "")).strip()
    if not path_template.startswith("/"):
        return None
    id_location = str(raw.get("id_location", "path")).lower().strip()
    if id_location not in ("path", "query"):
        return None
    id_param = str(raw.get("id_param", "")).strip()
    if not id_param:
        return None
    # the path must exist in the catalog VERBATIM (method + templated path) — no invented endpoints
    if (method, path_template) not in _catalog_pairs(catalog):
        return None
    if id_location == "path":
        if ("{" + id_param + "}") not in path_template:   # must be a real template var in the path
            return None
    else:  # query
        if "{" in id_param or "}" in id_param:            # a query id param is a NAME, not a template
            return None
    return {"method": method, "path_template": path_template, "id_location": id_location,
            "id_param": id_param, "shape": _SHAPE_BY_LOCATION[id_location]}


def validate_op(op: Any, catalog: List[str]) -> bool:
    """Final fence on the CONCRETE op (after id-sourcing built baseline_path), the last gate before
    the op is handed to the engine. Requires: a known method/location, target_param ACTUALLY present
    in baseline_path, and baseline_path templated-matching a catalog endpoint. A False op is DROPPED,
    never run — so a mis-sourced / malformed op can never reach the judge."""
    if not isinstance(op, dict):
        return False
    method = str(op.get("method", "")).upper()
    if method not in _METHODS:
        return False
    baseline_path = op.get("baseline_path")
    if not isinstance(baseline_path, str) or not baseline_path.startswith("/"):
        return False
    payload = op.get("payload") or {}
    if payload.get("location") not in _KNOWN_LOCATIONS:
        return False
    target_param = str(payload.get("target_param", ""))
    if not target_param or target_param not in baseline_path:
        return False
    return _concrete_path_in_catalog(method, baseline_path, catalog)


def discover_candidate_parts(
    catalog: List[str], raw_candidates: List[Any],
) -> Tuple[List[Dict[str, str]], List[Any]]:
    """Split raw AI candidates into (accepted descriptors, dropped raw). Pure — takes the already-
    proposed list so it is fully offline-testable; the AI call lives in `propose_candidates`."""
    accepted: List[Dict[str, str]] = []
    dropped: List[Any] = []
    for r in (raw_candidates or []):
        v = validate_candidate(r, catalog)
        if v is not None:
            accepted.append(v)
        else:
            dropped.append(r)
            logger.info("[SCAN·DISCOVERY] dropped invalid candidate (failed code fence): %r", r)
    return accepted, dropped
