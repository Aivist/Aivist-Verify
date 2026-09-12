# ==============================================================================
# INDEPENDENT ground-truth suite for the Query Target (query-string IDOR lab, D29).
#
# THIS FILE IS THE ORACLE. With NO involvement from the verification engine, it proves
# against the live target's real bytes that:
#   * QS-READ-VULN (GET /reports?report_id=) is genuinely exploitable cross-account, and
#   * QS-READ-SAFE (GET /notes?note_id=) genuinely resists that same attack.
#
# It must be green BEFORE the deep verifier is pointed at this lab. The engine is graded
# against THIS suite — never the reverse — and these labels are never adjusted to make the
# engine agree. Style mirrors depot_target/test_vulns.py (fastapi TestClient); this app is
# in-memory and read-only, so no DB isolation is needed.
#
# Run:  pytest query_target/test_vulns.py -v
# ==============================================================================
import os
import sys

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from query_target.main import (  # noqa: E402
    ALICE_TOKEN, BOB_TOKEN,
    REPORT_ALICE_ID, REPORT_BOB_ID, NOTE_ALICE_ID, NOTE_BOB_ID,
    app,
)


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


# -----------------------------------------------------------------------------
# Auth baseline
# -----------------------------------------------------------------------------
def test_missing_token_is_401(client):
    assert client.get("/reports", params={"report_id": REPORT_ALICE_ID}).status_code == 401


def test_invalid_token_is_401(client):
    r = client.get("/reports", params={"report_id": REPORT_ALICE_ID}, headers=_auth("nope"))
    assert r.status_code == 401


def test_owner_reads_own_report(client):
    r = client.get("/reports", params={"report_id": REPORT_ALICE_ID}, headers=_auth(ALICE_TOKEN))
    assert r.status_code == 200 and r.json()["owner"] == "alice"


# -----------------------------------------------------------------------------
# QS-READ-VULN — REAL: alice reads bob's report via ?report_id=, and it LEAKS bob's data.
# -----------------------------------------------------------------------------
def test_QS_READ_VULN_attacker_reads_victims_report_cross_account(client):
    attacker = client.get("/reports", params={"report_id": REPORT_BOB_ID}, headers=_auth(ALICE_TOKEN))
    assert attacker.status_code == 200
    body = attacker.json()
    # The victim's owner-named data is disclosed to the attacker — the leak.
    assert body["owner"] == "bob"
    assert "engine knock" in body["problem_details"]


def test_QS_READ_VULN_attacker_view_equals_owner_view_bytewise(client):
    """The REAL endpoint is caller-independent, so the attacker's cross-account read and the
    owner's own read return IDENTICAL bytes. This is precisely what lets the engine's
    owner-view re-read corroborate and confirm the leak."""
    attacker = client.get("/reports", params={"report_id": REPORT_BOB_ID}, headers=_auth(ALICE_TOKEN))
    owner = client.get("/reports", params={"report_id": REPORT_BOB_ID}, headers=_auth(BOB_TOKEN))
    assert attacker.status_code == owner.status_code == 200
    assert attacker.json() == owner.json()          # identical -> corroborates


# -----------------------------------------------------------------------------
# QS-READ-SAFE — SECURE: alice reading bob's note via ?note_id= is refused (no victim data).
# -----------------------------------------------------------------------------
def test_QS_READ_SAFE_owner_reads_own_note(client):
    r = client.get("/notes", params={"note_id": NOTE_BOB_ID}, headers=_auth(BOB_TOKEN))
    assert r.status_code == 200 and r.json()["owner"] == "bob"
    assert "safe code" in r.json()["text"]


def test_QS_READ_SAFE_cross_account_read_leaks_nothing(client):
    attacker = client.get("/notes", params={"note_id": NOTE_BOB_ID}, headers=_auth(ALICE_TOKEN))
    owner = client.get("/notes", params={"note_id": NOTE_BOB_ID}, headers=_auth(BOB_TOKEN))
    assert attacker.status_code == 200                      # soft-200 denial, not a 403
    denial = attacker.json()
    # No victim data: owner masked, text a constant refusal, and NOTHING of the real note.
    assert denial["owner"] == "------"
    assert "SEALED" in denial["text"]
    assert denial != owner.json()                           # attacker view != owner's authentic view
    assert "safe code" not in denial["text"]
