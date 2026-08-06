# ==============================================================================
# scan v1, commit 2 — id sourcing (tiers a+b). LOAD-BEARING: per-account identity isolation. The
# attacker's list is read with ATTACKER creds only; the owner's with OWNER creds only; the harvested
# owner id becomes the VICTIM target (payload_string) and NEVER a credential. No sourceable id -> SKIP,
# never a fabricated/guessed id. Zero network — the control-view read is stubbed.
# ==============================================================================
import os
import sys
import json
import asyncio

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, _REPO_ROOT)

from backend.tests._llmstub import as_provider
from backend.app.cli.scan_ids import source_ids, _extract_ids
from backend.app.cli.scan_discovery import validate_collection
from backend.app.services.deep_verifier import OwnerCredential, OwnerViewResult

_CAND = {"method": "GET", "path_template": "/api/reports/{report_id}", "id_location": "path",
         "id_param": "report_id", "shape": "path_segment_bola"}
_ATK = OwnerCredential.from_config("Bearer attacker-tok-AAA")
_OWN = OwnerCredential.from_config("Bearer owner-tok-BBB")
# tier-c catalog: the single-object endpoint + its flat collection, plus another resource (orders).
_CATALOG = ["GET /api/reports/{report_id}", "GET /api/reports",
            "GET /api/orders/{order_id}", "GET /api/orders"]


def _stub_collection_provider(collection_path):
    """A get_provider() stand-in whose generate() returns the AI's proposed collection path."""
    async def gen():
        class _R:
            text = json.dumps({"collection_path": collection_path})
        return _R()
    return as_provider(gen)


def _cv_stub(atk_body, own_body):
    """A fetch_control_view stand-in that records WHICH credential read WHICH path, and returns the
    ATTACKER's list to attacker creds and the OWNER's list to owner creds."""
    calls = []

    async def cv(client, path, base_url, cred, **kw):
        calls.append({"cred": cred.header_value, "path": path})
        hv = (cred.header_value or "").lower()
        body = atk_body if "attacker" in hv else own_body
        return OwnerViewResult(available=True, status=200, body=body, reason="ok")

    cv.calls = calls
    return cv


def _no_client():
    return object()      # the stub ignores the client; _aclose swallows the missing .aclose()


# ------------------------------------------------------------------ tier a (id map)
def test_tier_a_id_map_wins_without_any_harvest():
    cv = _cv_stub("[]", "[]")
    res = asyncio.run(source_ids(
        _CAND, base_url="http://t", approved_host="t",
        id_map={"/api/reports/{report_id}": {"attacker_id": "3", "victim_id": "4"}},
        collections={"/api/reports/{report_id}": "/api/reports"},
        attacker_cred=_ATK, owner_cred=_OWN, control_view=cv, client_factory=_no_client))
    assert res == ("3", "4")
    assert cv.calls == []                         # tier a short-circuits — no harvest at all


# ------------------------------------------------------------------ tier b (LOAD-BEARING isolation)
def test_tier_b_harvest_is_per_account_isolated():
    cv = _cv_stub('[{"report_id":"1"},{"report_id":"2"}]', '[{"report_id":"9"},{"report_id":"2"}]')
    res = asyncio.run(source_ids(
        _CAND, base_url="http://t", approved_host="t",
        collections={"/api/reports/{report_id}": "/api/reports"},
        attacker_cred=_ATK, owner_cred=_OWN, control_view=cv, client_factory=_no_client))
    # attacker_id = attacker's own first id; victim_id = an OWNER id the attacker does NOT own
    assert res == ("1", "9")
    assert len(cv.calls) == 2
    # the attacker's list was read with ATTACKER creds; the owner's with OWNER creds — never crossed
    assert "attacker" in cv.calls[0]["cred"].lower()
    assert "owner" in cv.calls[1]["cred"].lower()
    assert cv.calls[0]["cred"] != cv.calls[1]["cred"]
    # the victim id is the OWNER's id, and it is NOT one the attacker owns (a genuine cross-user target)
    atk_ids = _extract_ids('[{"report_id":"1"},{"report_id":"2"}]', "report_id")
    assert res[1] not in atk_ids


def test_tier_b_isolation_would_fail_if_creds_swapped():
    # NEGATIVE CONTROL: if the code read the attacker's list with OWNER creds (a bleed), the recorded
    # first-call credential would be the owner's — which the isolation assertion above forbids.
    cv = _cv_stub('[{"report_id":"1"}]', '[{"report_id":"9"}]')
    asyncio.run(source_ids(
        _CAND, base_url="http://t", approved_host="t",
        collections={"/api/reports/{report_id}": "/api/reports"},
        attacker_cred=_ATK, owner_cred=_OWN, control_view=cv, client_factory=_no_client))
    # the very property the load-bearing test relies on: harvest #1 used the ATTACKER credential
    assert cv.calls[0]["cred"] == _ATK.header_value and cv.calls[0]["cred"] != _OWN.header_value


# ------------------------------------------------------------------ SKIP, never guess
def test_skip_when_no_id_source_at_all():
    assert asyncio.run(source_ids(_CAND, base_url="http://t")) is None


def test_skip_when_owner_has_no_distinct_object():
    # owner's ids are a subset of the attacker's -> no genuine victim target -> SKIP (never fabricate)
    cv = _cv_stub('[{"report_id":"1"},{"report_id":"2"}]', '[{"report_id":"1"}]')
    res = asyncio.run(source_ids(
        _CAND, base_url="http://t", approved_host="t",
        collections={"/api/reports/{report_id}": "/api/reports"},
        attacker_cred=_ATK, owner_cred=_OWN, control_view=cv, client_factory=_no_client))
    assert res is None


def test_skip_when_harvest_unavailable():
    async def cv_denied(client, path, base_url, cred, **kw):
        return OwnerViewResult(available=False, status=403, reason="non_2xx:403")
    res = asyncio.run(source_ids(
        _CAND, base_url="http://t", approved_host="t",
        collections={"/api/reports/{report_id}": "/api/reports"},
        attacker_cred=_ATK, owner_cred=_OWN, control_view=cv_denied, client_factory=_no_client))
    assert res is None                            # a non-2xx harvest yields no ids -> SKIP


# ------------------------------------------------------------------ id extraction shapes
def test_extract_ids_handles_common_shapes():
    assert _extract_ids('[{"id":"1"},{"id":"2"}]', "report_id") == ["1", "2"]           # generic id fallback
    assert _extract_ids('{"data":[{"report_id":7},{"report_id":8}]}', "report_id") == ["7", "8"]  # wrapped + int
    assert _extract_ids('["a","b","a"]', "id") == ["a", "b"]                            # scalar list, deduped
    assert _extract_ids("", "id") == [] and _extract_ids("not-json", "id") == []        # graceful


# ==============================================================================
# Tier c (2c) — AI proposes the collection endpoint from the CATALOG; code fences it; the SAME
# per-account _harvest sources ids. Only runs when neither tier a nor tier b applies. Zero network.
# ==============================================================================
def test_tier_c_ai_proposed_collection_harvested_per_account():
    cv = _cv_stub('[{"report_id":"1"},{"report_id":"2"}]', '[{"report_id":"9"},{"report_id":"2"}]')
    res = asyncio.run(source_ids(
        _CAND, base_url="http://t", approved_host="t",
        attacker_cred=_ATK, owner_cred=_OWN, control_view=cv, client_factory=_no_client,
        catalog=_CATALOG, provider_factory=_stub_collection_provider("/api/reports")))
    assert res == ("1", "9")                              # AI collection -> per-account harvest -> distinct
    assert len(cv.calls) == 2
    assert cv.calls[0]["path"] == "/api/reports" and cv.calls[1]["path"] == "/api/reports"


# ------------------------------------------------------------------ CODE FENCE (AI proposes, code vets)
def test_tier_c_out_of_catalog_proposal_is_skipped_no_harvest():
    cv = _cv_stub('[{"report_id":"1"}]', '[{"report_id":"9"}]')
    res = asyncio.run(source_ids(
        _CAND, base_url="http://t", approved_host="t",
        attacker_cred=_ATK, owner_cred=_OWN, control_view=cv, client_factory=_no_client,
        catalog=_CATALOG, provider_factory=_stub_collection_provider("/api/secret")))  # NOT in the catalog
    assert res is None                                   # fence rejects -> SKIP
    assert cv.calls == []                                # harvest NEVER called -> no fabricated id


def test_tier_c_implausible_wrong_resource_collection_rejected():
    cv = _cv_stub("[]", "[]")
    # /api/orders is a real GET in the catalog but a DIFFERENT resource than the candidate (reports).
    res = asyncio.run(source_ids(
        _CAND, base_url="http://t", approved_host="t",
        attacker_cred=_ATK, owner_cred=_OWN, control_view=cv, client_factory=_no_client,
        catalog=_CATALOG, provider_factory=_stub_collection_provider("/api/orders")))
    assert res is None and cv.calls == []


def test_validate_collection_fence_unit():
    assert validate_collection("/api/reports", _CAND, _CATALOG) == "/api/reports"        # id-stripped collection
    assert validate_collection("/api/reports/{report_id}", _CAND, _CATALOG) is None      # has id/template
    assert validate_collection("/api/secret", _CAND, _CATALOG) is None                   # not in catalog
    assert validate_collection("/api/orders", _CAND, _CATALOG) is None                   # wrong resource noun
    assert validate_collection(None, _CAND, _CATALOG) is None


# ------------------------------------------------------------------ ISOLATION (load-bearing)
def test_tier_c_isolation_per_account_and_owner_id_is_the_victim():
    cv = _cv_stub('[{"report_id":"1"},{"report_id":"2"}]', '[{"report_id":"9"},{"report_id":"2"}]')
    res = asyncio.run(source_ids(
        _CAND, base_url="http://t", approved_host="t",
        attacker_cred=_ATK, owner_cred=_OWN, control_view=cv, client_factory=_no_client,
        catalog=_CATALOG, provider_factory=_stub_collection_provider("/api/reports")))
    assert res == ("1", "9")
    # attacker list read with ATTACKER creds; owner with OWNER creds; never crossed (fails if swapped)
    assert cv.calls[0]["cred"] == _ATK.header_value and cv.calls[1]["cred"] == _OWN.header_value
    assert cv.calls[0]["cred"] != cv.calls[1]["cred"]
    # the victim id is the OWNER's id (used ONLY as the victim target) and NOT one the attacker owns
    atk_ids = _extract_ids('[{"report_id":"1"},{"report_id":"2"}]', "report_id")
    assert res[1] == "9" and res[1] not in atk_ids


# ------------------------------------------------------------------ fail-safe: never fabricate
def test_tier_c_harvest_non_2xx_is_skip():
    async def cv_denied(client, path, base_url, cred, **kw):
        return OwnerViewResult(available=False, status=403, reason="non_2xx:403")
    res = asyncio.run(source_ids(
        _CAND, base_url="http://t", approved_host="t",
        attacker_cred=_ATK, owner_cred=_OWN, control_view=cv_denied, client_factory=_no_client,
        catalog=_CATALOG, provider_factory=_stub_collection_provider("/api/reports")))
    assert res is None


def test_tier_c_no_id_shaped_values_is_skip():
    cv = _cv_stub('{"message":"you have no reports"}', '{"message":"you have no reports"}')
    res = asyncio.run(source_ids(
        _CAND, base_url="http://t", approved_host="t",
        attacker_cred=_ATK, owner_cred=_OWN, control_view=cv, client_factory=_no_client,
        catalog=_CATALOG, provider_factory=_stub_collection_provider("/api/reports")))
    assert res is None


# ------------------------------------------------------------------ back-compat: tier-c is a no-op / lowest priority
def test_tier_c_no_op_without_catalog():
    cv = _cv_stub("[]", "[]")
    res = asyncio.run(source_ids(
        _CAND, base_url="http://t", attacker_cred=_ATK, owner_cred=_OWN,
        control_view=cv, client_factory=_no_client,
        provider_factory=_stub_collection_provider("/api/reports")))   # no catalog -> tier-c never runs
    assert res is None and cv.calls == []


def test_tier_a_and_b_take_priority_over_tier_c():
    cv = _cv_stub('[{"report_id":"1"}]', '[{"report_id":"9"}]')
    # tier a wins: no harvest at all even though a catalog + provider are supplied
    res_a = asyncio.run(source_ids(
        _CAND, base_url="http://t",
        id_map={"/api/reports/{report_id}": {"attacker_id": "3", "victim_id": "4"}},
        attacker_cred=_ATK, owner_cred=_OWN, control_view=cv, client_factory=_no_client,
        catalog=_CATALOG, provider_factory=_stub_collection_provider("/api/reports")))
    assert res_a == ("3", "4") and cv.calls == []        # tier a short-circuits; tier c never harvests
    # tier b wins: the DECLARED collection is harvested, not the AI-proposed one
    res_b = asyncio.run(source_ids(
        _CAND, base_url="http://t", approved_host="t",
        collections={"/api/reports/{report_id}": "/declared/collection"},
        attacker_cred=_ATK, owner_cred=_OWN, control_view=cv, client_factory=_no_client,
        catalog=_CATALOG, provider_factory=_stub_collection_provider("/api/reports")))
    assert res_b == ("1", "9")
    assert all(c["path"] == "/declared/collection" for c in cv.calls)   # tier b's declared path, not tier c's
