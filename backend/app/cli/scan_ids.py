# ==============================================================================
# scan — v1 id sourcing (tiers a + b). A BOLA op needs two ids: the ATTACKER's own object id (the
# baseline) and the VICTIM's object id (the attack target, -> payload_string). This module sources
# them WITHOUT ever guessing.
#
# IDENTITY-ISOLATION RED LINE (welded, not convention):
#   * Tier a: the operator supplies an id map per resource (attacker's own id + owner/victim's id).
#   * Tier b: the operator declares a "list my objects" collection endpoint per resource; the tool
#     reads it AS THE ATTACKER (attacker creds ONLY) to harvest the attacker's ids, and AS THE OWNER
#     (owner creds ONLY) to harvest the owner's ids — EACH ACCOUNT READS ONLY ITS OWN LIST, on its
#     OWN fresh client. A harvested OWNER id is used ONLY as the victim target in payload_string; it
#     NEVER becomes an attacker credential. Every harvest is scope-checked fail-closed
#     (fetch_control_view enforces the same ScopePolicy as every engine request).
#   * If an id cannot be sourced for a candidate -> SKIP (return None, "needs manual id"). We NEVER
#     fabricate/guess an id and run it: a guessed id could hit a nonexistent object and mislead.
#
# This touches NO verdict/engine logic. It only picks ids and reuses the engine's GET-only,
# custody-free, scope-locked `fetch_control_view` to read a list AS one declared identity.
# ==============================================================================
from __future__ import annotations

import json
import logging
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

from backend.app.services.deep_verifier import OwnerCredential, OwnerViewResult, fetch_control_view
from backend.app.cli.scan_discovery import propose_collection, validate_collection

logger = logging.getLogger("app.cli.scan_ids")

# A control-view callable seam (default: the real engine helper). Tests inject a stub that records
# WHICH credential read WHICH path (proving per-account isolation) without any network.
ControlView = Callable[..., Awaitable[OwnerViewResult]]


def _default_client_factory():
    import httpx
    return httpx.AsyncClient(timeout=20.0, verify=False)


async def _aclose(client) -> None:
    try:
        await client.aclose()
    except Exception:
        pass


def _is_id_scalar(v: Any) -> bool:
    """An id-shaped scalar: a non-empty str/int (not bool), short enough to be an identifier."""
    if isinstance(v, bool):
        return False
    if isinstance(v, int):
        return True
    return isinstance(v, str) and 0 < len(v) <= 128


def _find_item_list(data: Any) -> List[Any]:
    """The list of objects in a collection response: a top-level JSON array, else the first list-of-
    dicts (or first list) value in a wrapping object (covers {"data":[...]}, {"results":[...]}, etc.)."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for v in data.values():
            if isinstance(v, list) and any(isinstance(x, dict) for x in v):
                return v
        for v in data.values():
            if isinstance(v, list):
                return v
    return []


def _extract_ids(body: Optional[str], id_param: str) -> List[str]:
    """Deterministically pull object ids out of a collection response body. For each item, prefer the
    candidate's `id_param`, then a generic "id"/"_id". Returns ids in response order (deduped). A body
    that cannot be parsed / has no id-shaped values yields [] (which -> SKIP, never a guess).

    (An AI parser could slot in here per the brief; the code extractor is the deterministic default
    so id sourcing never depends on the model hallucinating an id.)"""
    if not body:
        return []
    try:
        data = json.loads(body) if isinstance(body, str) else body
    except Exception:
        return []
    out: List[str] = []
    seen = set()
    for it in _find_item_list(data):
        val = None
        if isinstance(it, dict):
            for key in (id_param, "id", "_id"):
                if key in it and _is_id_scalar(it[key]):
                    val = str(it[key])
                    break
        elif _is_id_scalar(it):
            val = str(it)
        if val is not None and val not in seen:
            seen.add(val)
            out.append(val)
    return out


async def _harvest(
    coll_path: str, id_param: str, *, base_url: str, approved_host: Optional[str],
    cred: OwnerCredential, control_view: ControlView, client_factory: Callable[[], Any],
) -> List[str]:
    """Read the collection AS the single identity `cred` (its OWN fresh client) and extract ids.
    Scope-locked and custody-free via fetch_control_view. Non-2xx / transport failure -> []."""
    client = client_factory()
    try:
        res = await control_view(client, coll_path, base_url, cred, approved_host=approved_host)
    finally:
        await _aclose(client)
    body = res.body if getattr(res, "available", False) else None
    return _extract_ids(body, id_param)


async def _harvest_distinct_pair(
    coll_path: str, id_param: str, *, base_url: str, approved_host: Optional[str],
    attacker_cred: OwnerCredential, owner_cred: OwnerCredential,
    control_view: ControlView, client_factory: Callable[[], Any],
) -> Optional[Tuple[str, str]]:
    """Harvest attacker+owner ids from a collection (per-account, isolated) and pick
    (attacker_id, victim_id) where the victim is an OWNER id the attacker does NOT own. None when
    either side yields nothing distinct. THE ONE isolation weld shared by tier b (declared collection)
    and tier c (AI-proposed collection): the attacker's list is read with attacker_cred ONLY, the
    owner's with owner_cred ONLY, on separate clients; the harvested owner id becomes the victim target
    ONLY, never a credential."""
    atk_ids = await _harvest(coll_path, id_param, base_url=base_url, approved_host=approved_host,
                             cred=attacker_cred, control_view=control_view,
                             client_factory=client_factory)          # ATTACKER creds ONLY
    own_ids = await _harvest(coll_path, id_param, base_url=base_url, approved_host=approved_host,
                             cred=owner_cred, control_view=control_view,
                             client_factory=client_factory)          # OWNER creds ONLY
    attacker_id = atk_ids[0] if atk_ids else None
    atk_set = set(atk_ids)
    victim_id = next((i for i in own_ids if i not in atk_set), None)  # an object the attacker does NOT own
    if attacker_id and victim_id:
        return (attacker_id, victim_id)                              # owner id -> victim target ONLY
    return None


async def source_ids(
    candidate: Dict[str, str], *, base_url: str, approved_host: Optional[str] = None,
    id_map: Optional[Dict[str, Dict[str, str]]] = None,
    collections: Optional[Dict[str, str]] = None,
    attacker_cred: Optional[OwnerCredential] = None,
    owner_cred: Optional[OwnerCredential] = None,
    control_view: ControlView = fetch_control_view,
    client_factory: Callable[[], Any] = _default_client_factory,
    catalog: Optional[List[str]] = None,
    model: Optional[str] = None,
    provider_factory: Optional[Callable[[], Any]] = None,
) -> Optional[Tuple[str, str]]:
    """Return (attacker_id, victim_id) for a candidate, or None to SKIP (needs manual id).

    Tier a (id map) wins when present. Tier b harvests the operator-DECLARED collection. Tier c
    (2c) harvests an AI-PROPOSED, code-fenced collection from the catalog when neither a nor b applies.
    In tiers b and c the attacker reads its OWN list with attacker creds, the owner with owner creds
    (separate clients); the victim id is the owner's first id the attacker does NOT own. Never
    fabricates: no sourceable pair -> None."""
    key = candidate.get("path_template", "")

    # Tier a — operator-supplied id map.
    if id_map and key in id_map:
        m = id_map[key] or {}
        aid, vid = str(m.get("attacker_id", "")).strip(), str(m.get("victim_id", "")).strip()
        if aid and vid:
            return (aid, vid)

    # Tier b — operator-DECLARED collection endpoint, harvested per-account (identity-isolated).
    coll = (collections or {}).get(key)
    if coll and attacker_cred is not None and owner_cred is not None:
        pair = await _harvest_distinct_pair(
            coll, candidate.get("id_param", "id"), base_url=base_url, approved_host=approved_host,
            attacker_cred=attacker_cred, owner_cred=owner_cred,
            control_view=control_view, client_factory=client_factory)
        if pair is not None:
            return pair

    # Tier c (2c) — AI-PROPOSED collection from the CATALOG, code-fenced, then the SAME per-account
    # harvest. Runs ONLY when neither a nor b applies for this resource AND both creds are present AND a
    # catalog exists. AI proposes; code vets (must be a GET in the catalog, no id segment, this
    # resource's noun + lineage); a failed fence / non-2xx harvest / no id-shaped value -> None -> SKIP.
    # Catalog-based only — it does NOT depend on the target's response shape (that stays the deferred
    # AI-parser hook in _extract_ids).
    if (catalog and attacker_cred is not None and owner_cred is not None
            and not (id_map and key in id_map) and not (collections and key in collections)):
        proposed = await propose_collection(
            candidate, catalog, model=model,
            **({"provider_factory": provider_factory} if provider_factory is not None else {}))
        fenced = validate_collection(proposed, candidate, catalog) if proposed else None
        if fenced:
            logger.info("[SCAN·IDS] tier-c: AI-proposed collection %r vetted for %s %s", fenced,
                        candidate.get("method"), key)
            pair = await _harvest_distinct_pair(
                fenced, candidate.get("id_param", "id"), base_url=base_url, approved_host=approved_host,
                attacker_cred=attacker_cred, owner_cred=owner_cred,
                control_view=control_view, client_factory=client_factory)
            if pair is not None:
                return pair

    logger.info("[SCAN·IDS] no sourceable id for %s %s -> SKIP (needs manual id)",
                candidate.get("method"), key)
    return None
