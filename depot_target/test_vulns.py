# ==============================================================================
# INDEPENDENT ground-truth suite for the Depot target (second vulnerable lab).
#
# THIS FILE IS THE ORACLE. It proves, against the live target's real bytes and with no
# involvement from our verification engine whatsoever, that:
#   * every case labelled REAL is genuinely exploitable cross-account, and
#   * every case labelled SECURE genuinely resists that same attack.
#
# It MUST be green BEFORE the deep verifier is ever pointed at Depot. The engine is
# then graded against THIS suite — never the other way round, and the labels asserted
# here are never adjusted to make the engine agree.
#
# Style mirrors vulnerable_target/test_vulns.py: fastapi TestClient over an ISOLATED,
# throwaway SQLite file (the app reads DEPOT_TARGET_DATABASE_URL, set before import),
# so the real on-disk DB is never touched and every test starts fresh-seeded.
#
# Run:  pytest depot_target/test_vulns.py -v
# ==============================================================================

import os
import sys
import importlib
import uuid

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

ALICE_TOKEN = "alice-depot-token-aaaa"
BOB_TOKEN = "bob-depot-token-bbbb"

ALICE = "a11ce000-0000-4000-8000-000000000001"
BOB = "b0b00000-0000-4000-8000-000000000002"
NEVER_SEEDED = "dead0000-0000-4000-8000-00000000dead"
ZERO_UUID = "00000000-0000-0000-0000-000000000000"


@pytest.fixture
def client(tmp_path):
    """Isolated TestClient backed by a fresh per-test SQLite file."""
    db_file = tmp_path / "depot_target_test.db"
    os.environ["DEPOT_TARGET_DATABASE_URL"] = "sqlite+aiosqlite:///" + str(db_file).replace("\\", "/")

    if "depot_target.main" in sys.modules:
        target = importlib.reload(sys.modules["depot_target.main"])
    else:
        target = importlib.import_module("depot_target.main")

    from fastapi.testclient import TestClient

    with TestClient(target.app) as c:      # lifespan -> create_all + seed alice & bob
        yield c


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def _unique(prefix):
    """A high-entropy value, so 'this value is present' can only mean THIS write."""
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


# =============================================================================
# Sanity / auth baseline
# =============================================================================

def test_login_returns_account_and_token(client):
    resp = client.post("/login", json={"name": "alice"})
    assert resp.status_code == 200
    assert resp.json() == {"account_id": ALICE, "name": "alice", "token": ALICE_TOKEN}


def test_missing_token_is_rejected(client):
    assert client.get(f"/depot/waybills/{BOB}").status_code == 401


def test_invalid_token_is_rejected(client):
    assert client.get(f"/depot/waybills/{BOB}", headers=_auth("nope")).status_code == 401


def test_alice_reads_own_waybill(client):
    resp = client.get(f"/depot/accounts/{ALICE}/waybill", headers=_auth(ALICE_TOKEN))
    assert resp.status_code == 200
    assert resp.json()["account_id"] == ALICE


# =============================================================================
# Shape 1 — write confirmed via a WRITE-RECORD
# =============================================================================

def test_DP_WRITE_VULN_alice_rewrites_bobs_recipient(client):
    """REAL. Alice's write lands on BOB's consignment and is recorded against BOB."""
    value = _unique("pwned-recipient")
    resp = client.patch(f"/depot/accounts/{BOB}/recipient",
                        json={"recipient": value}, headers=_auth(ALICE_TOKEN))
    assert resp.status_code == 202
    assert resp.json() == {"accepted": True}

    events = client.get("/depot/custody-events", headers=_auth(ALICE_TOKEN)).json()["events"]
    # The decisive proof: a record whose SUBJECT is Bob carries the value ALICE wrote.
    landed = [e for e in events if e["account_id"] == BOB and e["value"] == value]
    assert len(landed) == 1, f"cross-account write did not land on Bob: {events}"


def test_DP_WRITE_SAFE_alice_cannot_rewrite_bobs_memo(client):
    """SECURE. Identical opaque 202, but nothing lands and nothing is recorded.

    The record is a sound oracle here because a landed write ALWAYS appends a row —
    proven by the self-write control in the same test. No row for Bob therefore means
    no write landed."""
    value = _unique("pwned-memo")
    resp = client.patch(f"/depot/accounts/{BOB}/memo",
                        json={"memo": value}, headers=_auth(ALICE_TOKEN))
    assert resp.status_code == 202
    assert resp.json() == {"accepted": True}          # same opaque body as the REAL case

    events = client.get("/depot/custody-events", headers=_auth(ALICE_TOKEN)).json()["events"]
    assert [e for e in events if e["account_id"] == BOB and e["value"] == value] == []

    # Control: the SAME endpoint DOES record a legitimate self-write, so the absence
    # above is genuine enforcement, not a broken recording mechanism.
    own = _unique("alice-own-memo")
    client.patch(f"/depot/accounts/{ALICE}/memo", json={"memo": own}, headers=_auth(ALICE_TOKEN))
    events = client.get("/depot/custody-events", headers=_auth(ALICE_TOKEN)).json()["events"]
    assert len([e for e in events if e["account_id"] == ALICE and e["value"] == own]) == 1


def test_write_responses_are_byte_identical_vuln_vs_safe(client):
    """The two write endpoints are indistinguishable from the response alone — which is
    exactly why confirming either one requires gathering outside evidence."""
    r_vuln = client.patch(f"/depot/accounts/{BOB}/recipient",
                          json={"recipient": _unique("x")}, headers=_auth(ALICE_TOKEN))
    r_safe = client.patch(f"/depot/accounts/{BOB}/memo",
                          json={"memo": _unique("x")}, headers=_auth(ALICE_TOKEN))
    assert r_vuln.status_code == r_safe.status_code == 202
    assert r_vuln.content == r_safe.content


# =============================================================================
# Shape 2 — READ-TYPE semantic equivalence (equal-length bodies)
# =============================================================================

def test_DP_READ_VULN_alice_reads_bobs_waybill(client):
    """REAL. The flat path leaks Bob's object to Alice; the leak is semantic, and the
    two bodies are EQUAL LENGTH so a size/diff oracle cannot separate them."""
    own = client.get(f"/depot/waybills/{ALICE}", headers=_auth(ALICE_TOKEN))
    stolen = client.get(f"/depot/waybills/{BOB}", headers=_auth(ALICE_TOKEN))

    assert stolen.status_code == 200
    body = stolen.json()
    assert body["account_id"] == BOB          # someone else's object, returned to Alice
    assert body["route"] == "CDG-SFO"         # real victim data, not a masked stub
    assert len(own.content) == len(stolen.content)   # equal length -> oracle must stall


def test_DP_READ_SAFE_alice_cannot_read_bobs_docket(client):
    """SECURE. Same 200 status and the same body LENGTH as a real record, but it is a
    denial: no victim data, zeroed subject, SEALED status."""
    own = client.get(f"/depot/dockets/{ALICE}", headers=_auth(ALICE_TOKEN))
    denied = client.get(f"/depot/dockets/{BOB}", headers=_auth(ALICE_TOKEN))

    assert denied.status_code == 200          # soft-200 denial, never a 403
    body = denied.json()
    assert body["status"] == "SEALED"
    assert body["account_id"] == ZERO_UUID
    assert body["route"] != "CDG-SFO"         # Bob's real route is NOT disclosed
    assert len(own.content) == len(denied.content)   # equal length -> oracle must stall


# =============================================================================
# Shape 3 — SILENT write confirmed via the object's OWN STATE
# =============================================================================

def test_seal_write_path_has_no_same_path_get(client):
    """Structural precondition of this shape: the write path offers no read-back, so
    confirmation must come from the object's own state on a DIFFERENT path."""
    assert client.get(f"/depot/accounts/{BOB}/seal", headers=_auth(ALICE_TOKEN)).status_code == 405


def test_DP_SILENT_VULN_alice_writes_bobs_seal(client):
    """REAL. Opaque 202, no record anywhere — but Bob's object state actually moved."""
    before = client.get(f"/depot/seals/{BOB}", headers=_auth(BOB_TOKEN)).json()
    assert before["code"] == "seal_bob_v0"

    value = _unique("pwned-seal")
    resp = client.post(f"/depot/accounts/{BOB}/seal", json={"code": value}, headers=_auth(ALICE_TOKEN))
    assert resp.status_code == 202 and resp.json() == {"accepted": True}

    after = client.get(f"/depot/seals/{BOB}", headers=_auth(BOB_TOKEN)).json()
    assert after["code"] == value              # Alice's unique value landed on Bob's object
    assert after["account_id"] == BOB


def test_DP_SILENT_SAFE_alice_cannot_write_bobs_tag(client):
    """SECURE. Byte-identical opaque 202, but Bob's object state never moves."""
    before = client.get(f"/depot/tags/{BOB}", headers=_auth(BOB_TOKEN)).json()

    value = _unique("pwned-tag")
    resp = client.post(f"/depot/accounts/{BOB}/tag", json={"code": value}, headers=_auth(ALICE_TOKEN))
    assert resp.status_code == 202 and resp.json() == {"accepted": True}

    after = client.get(f"/depot/tags/{BOB}", headers=_auth(BOB_TOKEN)).json()
    assert after["code"] == before["code"] == "tag_bob_v0"   # unchanged
    assert after["code"] != value

    # Control: the owner's own write DOES land, so the endpoint works.
    own = _unique("bob-own-tag")
    client.post(f"/depot/accounts/{BOB}/tag", json={"code": own}, headers=_auth(BOB_TOKEN))
    assert client.get(f"/depot/tags/{BOB}", headers=_auth(BOB_TOKEN)).json()["code"] == own


# =============================================================================
# Shape 4 — DELETE confirmed by a NEGATIVE ASSERTION
# =============================================================================

def test_DP_DELETE_HARD_alice_physically_deletes_bobs_hold(client):
    """REAL, physical. Existed and active before; gone (404) after."""
    before = client.get(f"/depot/holds/{BOB}", headers=_auth(BOB_TOKEN))
    assert before.status_code == 200 and before.json()["is_active"] is True

    resp = client.delete(f"/depot/accounts/{BOB}/hold", headers=_auth(ALICE_TOKEN))
    assert resp.status_code == 204 and resp.content == b""

    assert client.get(f"/depot/holds/{BOB}", headers=_auth(BOB_TOKEN)).status_code == 404


def test_DP_DELETE_SOFT_alice_soft_deletes_bobs_escort(client):
    """REAL, logical. The row survives (still 200) — only the lifecycle flag flips, so
    404 is NOT the only possible proof of a delete."""
    before = client.get(f"/depot/escorts/{BOB}", headers=_auth(BOB_TOKEN))
    assert before.status_code == 200 and before.json()["is_active"] is True

    resp = client.delete(f"/depot/accounts/{BOB}/escort", headers=_auth(ALICE_TOKEN))
    assert resp.status_code == 204 and resp.content == b""

    after = client.get(f"/depot/escorts/{BOB}", headers=_auth(BOB_TOKEN))
    assert after.status_code == 200
    assert after.json()["is_active"] is False       # retired by Alice


def test_DP_DELETE_SAFE_alice_cannot_delete_bobs_label(client):
    """SECURE. Identical opaque 204, but the object is still present AND still active."""
    resp = client.delete(f"/depot/accounts/{BOB}/label", headers=_auth(ALICE_TOKEN))
    assert resp.status_code == 204 and resp.content == b""

    after = client.get(f"/depot/labels/{BOB}", headers=_auth(BOB_TOKEN))
    assert after.status_code == 200
    assert after.json()["is_active"] is True

    # Control: the owner CAN delete it, so the endpoint really does delete.
    assert client.delete(f"/depot/accounts/{BOB}/label", headers=_auth(BOB_TOKEN)).status_code == 204
    assert client.get(f"/depot/labels/{BOB}", headers=_auth(BOB_TOKEN)).status_code == 404


def test_DP_DELETE_CONTROL_nothing_ever_existed(client):
    """CONTROL — the coincidence gate. The object never existed, so the after-read is
    404 for a reason that has NOTHING to do with this attack. The delete response is
    byte-identical to the REAL case, so 'it is absent now' alone must never be read as
    proof of a deletion."""
    assert client.get(f"/depot/holds/{NEVER_SEEDED}", headers=_auth(ALICE_TOKEN)).status_code == 404

    resp = client.delete(f"/depot/accounts/{NEVER_SEEDED}/hold", headers=_auth(ALICE_TOKEN))
    assert resp.status_code == 204 and resp.content == b""

    assert client.get(f"/depot/holds/{NEVER_SEEDED}", headers=_auth(ALICE_TOKEN)).status_code == 404


def test_delete_responses_are_byte_identical_across_cases(client):
    """Physical delete, dropped delete, and delete-of-nothing are indistinguishable."""
    a = client.delete(f"/depot/accounts/{BOB}/hold", headers=_auth(ALICE_TOKEN))
    b = client.delete(f"/depot/accounts/{BOB}/label", headers=_auth(ALICE_TOKEN))
    c = client.delete(f"/depot/accounts/{NEVER_SEEDED}/hold", headers=_auth(ALICE_TOKEN))
    assert a.status_code == b.status_code == c.status_code == 204
    assert a.content == b.content == c.content == b""


# =============================================================================
# Shape 5 — MASS-ASSIGNMENT confirmed by a LOW-ENTROPY STATE JUMP
# =============================================================================

def test_DP_MASS_VULN_alice_escalates_bobs_tier(client):
    """REAL. The privileged, LOW-ENTROPY `tier` moves from a known prior value to the
    injected one — movement, not mere presence, is what makes this attributable."""
    before = client.get(f"/depot/profiles/{BOB}", headers=_auth(BOB_TOKEN)).json()
    assert before["tier"] == "standard"        # known prior state (never hidden in v1)

    resp = client.patch(f"/depot/accounts/{BOB}/profile",
                        json={"plan": "gold", "tier": "priority"}, headers=_auth(ALICE_TOKEN))
    assert resp.status_code == 202 and resp.json() == {"accepted": True}

    after = client.get(f"/depot/profiles/{BOB}", headers=_auth(BOB_TOKEN)).json()
    assert after["tier"] == "priority"         # privileged field bound -> escalation
    assert after["plan"] == "gold"
    assert after["account_id"] == BOB


def test_DP_MASS_SAFE_alice_cannot_touch_bobs_preference(client):
    """SECURE on both axes: ownership is enforced AND `tier` is allow-list stripped, so
    NOTHING moves — behind the same opaque 202."""
    before = client.get(f"/depot/preferences/{BOB}", headers=_auth(BOB_TOKEN)).json()
    assert before["tier"] == "standard" and before["plan"] == "basic"

    resp = client.patch(f"/depot/accounts/{BOB}/preference",
                        json={"plan": "gold", "tier": "priority"}, headers=_auth(ALICE_TOKEN))
    assert resp.status_code == 202 and resp.json() == {"accepted": True}

    after = client.get(f"/depot/preferences/{BOB}", headers=_auth(BOB_TOKEN)).json()
    assert after["tier"] == "standard"         # no escalation
    assert after["plan"] == "basic"            # and no cross-account write at all

    # Control: the owner's own allow-listed write lands, but even HE cannot set `tier`.
    client.patch(f"/depot/accounts/{BOB}/preference",
                 json={"plan": "silver", "tier": "priority"}, headers=_auth(BOB_TOKEN))
    owner_after = client.get(f"/depot/preferences/{BOB}", headers=_auth(BOB_TOKEN)).json()
    assert owner_after["plan"] == "silver"
    assert owner_after["tier"] == "standard"


def test_DP_MASS_CONTROL_injected_value_equals_current(client):
    """CONTROL — the low-entropy trap. The write genuinely lands, and afterwards the
    field really does read 'standard' — but it read 'standard' beforehand too, so the
    value's presence attributes nothing to this attack."""
    before = client.get(f"/depot/profiles/{BOB}", headers=_auth(BOB_TOKEN)).json()
    assert before["tier"] == "standard"

    resp = client.patch(f"/depot/accounts/{BOB}/profile",
                        json={"tier": "standard"}, headers=_auth(ALICE_TOKEN))
    assert resp.status_code == 202

    after = client.get(f"/depot/profiles/{BOB}", headers=_auth(BOB_TOKEN)).json()
    assert after["tier"] == "standard"         # identical before and after -> no movement
    assert after["tier"] == before["tier"]


def test_mass_write_responses_are_byte_identical_vuln_vs_safe(client):
    r_vuln = client.patch(f"/depot/accounts/{BOB}/profile",
                          json={"plan": "gold", "tier": "priority"}, headers=_auth(ALICE_TOKEN))
    r_safe = client.patch(f"/depot/accounts/{BOB}/preference",
                          json={"plan": "gold", "tier": "priority"}, headers=_auth(ALICE_TOKEN))
    assert r_vuln.status_code == r_safe.status_code == 202
    assert r_vuln.content == r_safe.content
