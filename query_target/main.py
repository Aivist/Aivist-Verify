# ==============================================================================
# Query Target — a THIRD standalone vulnerable target  (LOCAL PRACTICE TARGET — NEVER DEPLOY)
# ==============================================================================
#
# A deliberately-insecure, fully self-contained FastAPI app whose access-control object id
# lives in the QUERY STRING, not the path. It exists to prove ONE thing end-to-end: the
# engine can now express, attack, and confirm a QUERY-STRING / non-path IDOR (TECH_DEBT
# D29), where the id is `?report_id=<n>` rather than `/reports/<n>`.
#
# WHY A NEW TARGET (not a change to depot_target / vulnerable_target)
# ------------------------------------------------------------------
# The two committed labs are frozen ground truth for the path-based shapes; their bytes and
# artifacts must not move. This lab is additive and isolated: a clean, self-contained
# fixture for the ONE new addressing mode, with its own human-signed-off ground truth
# (proven independently by query_target/test_vulns.py, which imports no engine code).
#
# THE ENGINE IS FROZEN while this target is used. If the engine false-positives on the SAFE
# case or fails to confirm the REAL one, THAT divergence is the finding — do not "fix" the
# engine and do not relabel these cases to make it pass.
#
# PLANTED TRUTH (read-semantic shape; the id is a QUERY parameter)
# ----------------------------------------------------------------
#   QS-READ-VULN   REAL    GET /reports?report_id=<id>
#       No ownership check: any authenticated account reads any report. The leak is the
#       victim-owned content in the response (owner name + private problem_details). This is
#       the crAPI `mechanic_report?report_id=` shape that D29 was found on, reproduced as a
#       controlled lab case.
#   QS-READ-SAFE   SECURE  GET /notes?note_id=<id>
#       Ownership IS enforced; a cross-account read returns an equal-shape soft-200 denial
#       carrying NO victim data (owner masked, text a constant refusal token). Only the
#       semantic content reveals it is a refusal — a 200 here must NOT be read as a leak.
#
# Two identities, opaque-token auth (no crypto — this is a target). Attacker = alice, owner
# / victim = bob. The attacker reads their OWN id on the baseline (?…=7) and swaps only the
# query id to the victim's (?…=6) for the attack — exactly what the engine's query_param
# mutation and the D24 owner-view re-read now carry through.
#
# Run:
#   python -m uvicorn query_target.main:app --reload --port 8003
# ==============================================================================
from __future__ import annotations

from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query

# ------------------------------------------------------------------------------
# Two accounts, opaque tokens. The map is token -> account name.
# ------------------------------------------------------------------------------
ALICE_TOKEN = "alice-query-token-aaaa"      # attacker (reads their own report_id=7)
BOB_TOKEN = "bob-query-token-bbbb"          # owner / victim (report_id=6, note_id=6)
_ACCOUNTS = {ALICE_TOKEN: "alice", BOB_TOKEN: "bob"}

# Query-string object ids (strings, as they arrive on the wire). Alice owns 7, Bob owns 6.
REPORT_ALICE_ID = "7"
REPORT_BOB_ID = "6"
NOTE_ALICE_ID = "7"
NOTE_BOB_ID = "6"

# Seeded content. Reports carry victim-owned data (owner + problem_details); a cross-account
# read of a report LEAKS it (the bug). Notes carry equally private data, but a cross-account
# read is refused with a constant, victim-data-free body (the secure control).
_REPORTS = {
    REPORT_ALICE_ID: {"report_id": REPORT_ALICE_ID, "owner": "alice",
                      "vehicle": "VIN-ALICE-0007",
                      "problem_details": "alice: brake fluid leak at the left front caliper"},
    REPORT_BOB_ID: {"report_id": REPORT_BOB_ID, "owner": "bob",
                    "vehicle": "VIN-BOB-0006",
                    "problem_details": "bob: intermittent engine knock under load, cylinder 3"},
}
_NOTES = {
    NOTE_ALICE_ID: {"note_id": NOTE_ALICE_ID, "owner": "alice",
                    "text": "alice private memo: storage locker combo 1187"},
    NOTE_BOB_ID: {"note_id": NOTE_BOB_ID, "owner": "bob",
                  "text": "bob private memo: office safe code 4417 downtown"},
}

# A cross-account note read returns THIS — same keys, no victim data, a constant refusal.
_NOTE_DENIAL = {"note_id": "", "owner": "------", "text": "SEALED-NO-CROSS-ACCOUNT-ACCESS"}

app = FastAPI(
    title="Query Target",
    description="Deliberately-insecure query-string IDOR practice target. Localhost only. Never deploy.",
    version="1.0.0",
)


async def get_current_account(
    authorization: Optional[str] = Header(default=None),
    x_token: Optional[str] = Header(default=None),
) -> str:
    """Trivial opaque-token auth. Proves WHO you are; the planted bug is that /reports never
    checks the requested resource is YOURS."""
    raw = None
    if authorization:
        raw = authorization[7:] if authorization.lower().startswith("bearer ") else authorization
    elif x_token:
        raw = x_token
    if not raw:
        raise HTTPException(status_code=401, detail="Missing token")
    account = _ACCOUNTS.get(raw)
    if account is None:
        raise HTTPException(status_code=401, detail="Invalid token")
    return account


@app.get("/reports", tags=["reports"])
async def get_report(
    report_id: str = Query(...),
    account: str = Depends(get_current_account),
):
    """QS-READ-VULN — REAL. The object id is in the QUERY STRING and there is NO ownership
    check: any authenticated account reads any report, so alice reading ?report_id=6 receives
    bob's owner-named, private problem_details. The response is caller-independent (both
    identities receive identical bytes), which is exactly why the owner-view re-read
    corroborates and the engine confirms."""
    report = _REPORTS.get(report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    return dict(report)


@app.get("/notes", tags=["notes"])
async def get_note(
    note_id: str = Query(...),
    account: str = Depends(get_current_account),
):
    """QS-READ-SAFE — SECURE. Same query-string addressing, but ownership IS enforced. A
    cross-account read returns a soft-200 denial with NO victim data (owner masked, text a
    constant refusal token), so the attacker's response does NOT match the owner's authentic
    view and the engine's owner-view gate refuses to confirm."""
    note = _NOTES.get(note_id)
    if note is None:
        raise HTTPException(status_code=404, detail="Note not found")
    if note["owner"] != account:
        return {**_NOTE_DENIAL, "note_id": note_id}
    return dict(note)


@app.get("/", tags=["meta"])
async def root():
    return {
        "service": "Query Target",
        "warning": "Deliberately insecure. Localhost query-string IDOR practice target only. Never deploy.",
        "shapes": {
            "query_string_read": [
                "GET /reports?report_id=<id> (REAL — no ownership check, leaks owner data)",
                "GET /notes?note_id=<id> (SECURE — ownership enforced, soft-200 denial)",
            ],
        },
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("query_target.main:app", host="127.0.0.1", port=8003, reload=False)
