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


# Common wrapper keys that hold the item list (checked in order, BEFORE falling back to any list-of-
# dicts). Covers {"data":[...]}, {"items":[...]}, {"results":[...]}, ... — the real-world envelopes.
_LIST_WRAPPER_KEYS = ("data", "items", "results", "records", "rows", "entries", "content", "list")

# Generic object-id field names, most-preferred first (checked AFTER the candidate's own id_param).
_GENERIC_ID_KEYS = ("id", "uuid", "guid", "_id", "pk", "objectId", "object_id")

# id-SHAPED keys that name a RELATIONSHIP / owner / parent, NOT the object's OWN id. The lab's real
# collection items carry `owner_id` next to the object id — this denylist stops the parser EVER picking
# the owner as the object id (which would harvest the WRONG id). Compared lower-cased.
_RELATION_ID_KEYS = frozenset({
    "owner_id", "ownerid", "owner", "user_id", "userid", "account_id", "accountid", "customer_id",
    "parent_id", "parentid", "created_by", "createdby", "author_id", "authorid", "tenant_id",
    "org_id", "organization_id", "group_id", "team_id", "role_id", "creator_id",
})


def _find_item_list(data: Any) -> List[Any]:
    """The list of objects in a collection response. Preference: a top-level array; a common wrapper key
    (data/items/results/...); the first list-of-dicts under any key (covers a plural resource key like
    {"users":[...]}, {"count":3,"users":[...]}); any list (scalar-id lists); else one level deeper
    (e.g. {"data":{"items":[...]}}). Returns [] when no list is present."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for k in _LIST_WRAPPER_KEYS:                          # 1) an explicit, common envelope key
            v = data.get(k)
            if isinstance(v, list):
                return v
        for v in data.values():                               # 2) the first list-of-dicts (plural resource key)
            if isinstance(v, list) and any(isinstance(x, dict) for x in v):
                return v
        for v in data.values():                               # 3) any list (scalar-id lists)
            if isinstance(v, list):
                return v
        for v in data.values():                               # 4) one level of nesting, best-effort
            if isinstance(v, dict):
                inner = _find_item_list(v)
                if inner:
                    return inner
    return []


def _looks_like_object_id_key(key: str) -> bool:
    """True for a key that NAMES an object id (id / uuid / guid / pk / <resource>_id / <resource>Id),
    but NOT a relationship/owner key (owner_id, user_id, ...) — those are id-shaped DECOYS, never the
    object's own id. Deliberately narrow (no bare '...id' like 'paid'/'valid') to avoid false hits."""
    kl = key.lower()
    if kl in _RELATION_ID_KEYS:
        return False
    if kl in ("id", "uuid", "guid", "pk"):
        return True
    if "uuid" in kl or "guid" in kl:
        return True
    return kl.endswith("_id") or key.endswith("Id") or key.endswith("ID")


def _resolve_id_field(items: List[Any], id_param: str) -> Optional[str]:
    """Choose ONE id field consistent across the collection's dict items, or None (=> SKIP). Preference:
    (1) the candidate's own `id_param` — ALWAYS first, so the object's own id beats any owner/relation
    field; (2) a generic id key (id/uuid/guid/_id/pk/objectId); (3) exactly ONE remaining object-id-shaped
    key present in every item (a resource-specific <name>_id, owner/relation keys already excluded).
    Two-or-more remaining candidates => AMBIGUOUS => None (the AI slot may disambiguate; else SKIP). A
    field qualifies only if it is present with an id-shaped value in EVERY dict item (consistency =
    confidence) — so a partial/decoy field is never chosen."""
    dict_items = [it for it in items if isinstance(it, dict)]
    if not dict_items:
        return None

    def consistent(key: str) -> bool:
        return all(key in it and _is_id_scalar(it[key]) for it in dict_items)

    if id_param and consistent(id_param):
        return id_param
    for k in _GENERIC_ID_KEYS:
        if consistent(k):
            return k
    id_like = sorted({k for it in dict_items for k in it
                      if _looks_like_object_id_key(k) and k not in _GENERIC_ID_KEYS and consistent(k)})
    if len(id_like) == 1:
        return id_like[0]
    return None                                               # 0 or >1 candidate -> ambiguous -> SKIP/AI


def _validated_ai_field(items: List[Any], id_param: str, proposer: Callable[..., Any]) -> Optional[str]:
    """The AI-parser slot: when deterministic resolution is AMBIGUOUS, an injected `proposer` MAY name the
    id field — but its proposal is CODE-VALIDATED before use: the field must exist with an id-shaped value
    in EVERY dict item AND must NOT be a relationship/owner key. An invalid/empty proposal => None => SKIP.
    So the model can NEVER introduce a fabricated id, nor point id-harvesting at the owner field. The
    proposer is a SYNC seam `(sorted_item_keys, id_param) -> Optional[field]` (a real LLM call can back it,
    cached); it is OFF by default (nothing calls it unless a proposer is injected)."""
    dict_items = [it for it in items if isinstance(it, dict)]
    if not dict_items:
        return None
    keys = sorted({k for it in dict_items for k in it})
    try:
        proposed = proposer(keys, id_param)
    except Exception:
        return None
    if not isinstance(proposed, str) or not proposed or proposed.lower() in _RELATION_ID_KEYS:
        return None                                           # empty / non-str / an owner-relation field
    if all(proposed in it and _is_id_scalar(it[proposed]) for it in dict_items):
        return proposed                                       # exists + id-shaped in EVERY item
    return None


def _extract_ids(body: Optional[str], id_param: str, *,
                 id_field_proposer: Optional[Callable[..., Any]] = None) -> List[str]:
    """Deterministically pull object ids from a collection response body. Finds the item list (top-level
    array OR a wrapped list), then resolves ONE id field for the list (`id_param` first, then a generic
    id key, then a single resource-specific <name>_id) and extracts that field from every item, in order,
    deduped. A scalar-id list ([1,2,3]) is taken directly. Genuinely ambiguous shapes (no confident id
    field) yield [] => SKIP; an owner/relation field is NEVER taken as the object id.

    `id_field_proposer` (optional) is the code-validated AI slot, consulted ONLY when deterministic
    resolution is ambiguous. NEVER fabricates: no confident id-shaped value => [] (the fail-safe weld)."""
    if not body:
        return []
    try:
        data = json.loads(body) if isinstance(body, str) else body
    except Exception:
        return []
    items = _find_item_list(data)
    if not items:
        return []
    out: List[str] = []
    seen = set()
    if all(not isinstance(it, dict) for it in items):         # scalar-id list: [1,2,3] / ["a","b"]
        for it in items:
            if _is_id_scalar(it):
                s = str(it)
                if s not in seen:
                    seen.add(s)
                    out.append(s)
        return out
    field = _resolve_id_field(items, id_param)
    if field is None and id_field_proposer is not None:
        field = _validated_ai_field(items, id_param, id_field_proposer)
    if field is None:
        return []                                             # ambiguous / no confident id -> SKIP
    for it in items:
        if isinstance(it, dict) and field in it and _is_id_scalar(it[field]):
            s = str(it[field])
            if s not in seen:
                seen.add(s)
                out.append(s)
    return out


async def _harvest(
    coll_path: str, id_param: str, *, base_url: str, approved_host: Optional[str],
    cred: OwnerCredential, control_view: ControlView, client_factory: Callable[[], Any],
    id_field_proposer: Optional[Callable[..., Any]] = None,
) -> List[str]:
    """Read the collection AS the single identity `cred` (its OWN fresh client) and extract ids.
    Scope-locked and custody-free via fetch_control_view. Non-2xx / transport failure -> []. Only the
    PARSER (`_extract_ids`) changed; WHO reads (this single `cred`, isolated) is untouched."""
    client = client_factory()
    try:
        res = await control_view(client, coll_path, base_url, cred, approved_host=approved_host)
    finally:
        await _aclose(client)
    body = res.body if getattr(res, "available", False) else None
    return _extract_ids(body, id_param, id_field_proposer=id_field_proposer)


async def _harvest_distinct_pair(
    coll_path: str, id_param: str, *, base_url: str, approved_host: Optional[str],
    attacker_cred: OwnerCredential, owner_cred: OwnerCredential,
    control_view: ControlView, client_factory: Callable[[], Any],
    id_field_proposer: Optional[Callable[..., Any]] = None,
) -> Optional[Tuple[str, str]]:
    """Harvest attacker+owner ids from a collection (per-account, isolated) and pick
    (attacker_id, victim_id) where the victim is an OWNER id the attacker does NOT own. None when
    either side yields nothing distinct. THE ONE isolation weld shared by tier b (declared collection)
    and tier c (AI-proposed collection): the attacker's list is read with attacker_cred ONLY, the
    owner's with owner_cred ONLY, on separate clients; the harvested owner id becomes the victim target
    ONLY, never a credential. `id_field_proposer` only affects PARSING, never which cred reads which list."""
    atk_ids = await _harvest(coll_path, id_param, base_url=base_url, approved_host=approved_host,
                             cred=attacker_cred, control_view=control_view,
                             client_factory=client_factory,
                             id_field_proposer=id_field_proposer)    # ATTACKER creds ONLY
    own_ids = await _harvest(coll_path, id_param, base_url=base_url, approved_host=approved_host,
                             cred=owner_cred, control_view=control_view,
                             client_factory=client_factory,
                             id_field_proposer=id_field_proposer)    # OWNER creds ONLY
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
    id_field_proposer: Optional[Callable[..., Any]] = None,
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
            control_view=control_view, client_factory=client_factory,
            id_field_proposer=id_field_proposer)
        if pair is not None:
            return pair

    # Tier c (2c) — AI-PROPOSED collection from the CATALOG, code-fenced, then the SAME per-account
    # harvest. Runs ONLY when neither a nor b applies for this resource AND both creds are present AND a
    # catalog exists. AI proposes the COLLECTION path (catalog-based — it never sees a response body);
    # code vets it (a GET in the catalog, no id segment, this resource's noun + lineage). The harvested
    # body is then parsed by `_extract_ids` (robust deterministic id extraction across real envelope /
    # id-field shapes, owner/relation fields excluded; a code-validated AI id-field slot for ambiguous
    # shapes). A failed fence / non-2xx harvest / no confident id-shaped value -> None -> SKIP.
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
                control_view=control_view, client_factory=client_factory,
                id_field_proposer=id_field_proposer)
            if pair is not None:
                return pair

    logger.info("[SCAN·IDS] no sourceable id for %s %s -> SKIP (needs manual id)",
                candidate.get("method"), key)
    return None
