# ==============================================================================
# scan v1, commit 2 — id sourcing (tiers a+b). LOAD-BEARING: per-account identity isolation. The
# attacker's list is read with ATTACKER creds only; the owner's with OWNER creds only; the harvested
# owner id becomes the VICTIM target (payload_string) and NEVER a credential. No sourceable id -> SKIP,
# never a fabricated/guessed id. Zero network — the control-view read is stubbed.
# ==============================================================================
import os
import sys
import asyncio

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, _REPO_ROOT)

from backend.app.cli.scan_ids import source_ids, _extract_ids
from backend.app.services.deep_verifier import OwnerCredential, OwnerViewResult

_CAND = {"method": "GET", "path_template": "/api/reports/{report_id}", "id_location": "path",
         "id_param": "report_id", "shape": "path_segment_bola"}
_ATK = OwnerCredential.from_config("Bearer attacker-tok-AAA")
_OWN = OwnerCredential.from_config("Bearer owner-tok-BBB")


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
