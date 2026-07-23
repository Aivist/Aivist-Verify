# ==============================================================================
# Depot — SECOND standalone vulnerable target  (LOCAL PRACTICE TARGET — NEVER DEPLOY)
# ==============================================================================
#
# A deliberately-insecure, fully self-contained FastAPI application used as a
# STRUCTURALLY-DIFFERENT second ground-truth lab for our access-control verification
# engine. Runs on localhost only (default port 8002). Never deployed.
#
# WHY IT EXISTS
# -------------
# `vulnerable_target/` proved the engine on five vuln shapes with zero false positives,
# but on ONE target with ONE id scheme and ONE naming convention. Depot re-plants the
# SAME FIVE SHAPES with deliberately DIFFERENT structure, to test whether the engine's
# target-agnostic machinery really generalizes — or was quietly fitted to target #1.
#
# THE ENGINE IS FROZEN while this target is used. Depot tests the engine; it never
# modifies it. If the engine false-positives on a SAFE case or fails to confirm a REAL
# one, that divergence is the FINDING — do not "fix" the engine, and do not relabel
# these cases to make it pass. Ground truth here is human-signed-off and is proven
# independently by depot_target/test_vulns.py.
#
# STRUCTURAL DIFFERENCES vs vulnerable_target (v1 — all chosen to be *fair* tests)
# -------------------------------------------------------------------------------
#   S1  UUID string primary keys            (vs sequential integers)
#   S2  logistics resource nouns            (waybill/docket/seal/tag/hold/escort/label…)
#   S3  owner field named `account_id`      (vs `owner_id`/`user_id`)
#   S4  opaque success 202 {"accepted":true} for writes; 204 No Content for deletes
#                                           (vs a uniform 200 {"status":"ok"})
#   S5  soft-200 denial encoded {"status":"SEALED", account_id: <zero-uuid>}
#                                           (vs {"error":"forbidden"} / "DENY")
#
# DELIBERATELY NOT IN v1 (moved to the v2 boundary-probe set, so v1 stays a clean
# "does it generalize" signal — anything whose greenness is uncertain belongs in P):
#   * nested read-back bodies, out-of-vocabulary owner/lifecycle words, write-vs-state
#     noun mismatches, a privileged field nested inside the request body, and the
#     NULL-seeded "hidden field" mass-assignment variant.
#
# TOPOLOGY NOTE (why writes are account-scoped)
# ---------------------------------------------
# Attack paths are scoped by the OWNER id (`/depot/accounts/{account_id}/<noun>`) and
# each sub-object is seeded with `id == account_id`. This mirrors vulnerable_target's
# proven topology for a reason that is structural, not cosmetic: the engine binds the
# object-state read-back template to the ATTACKED PATH ID, and its caller-identity
# anchor compares the read-back's owner field against that same id. Scoping writes by a
# non-owner id would make both unresolvable and would test our own wiring mistake
# rather than the engine.
#
# PLANTED TRUTH (v1 — 11 labelled cases + 2 controls; full rationale in README/proposal)
# --------------------------------------------------------------------------------------
#   Shape 1 — write confirmed via a WRITE-RECORD (no same-path GET, no object state)
#     DP-WRITE-VULN   REAL    PATCH /depot/accounts/{account_id}/recipient
#     DP-WRITE-SAFE   SECURE  PATCH /depot/accounts/{account_id}/memo
#     (both observable only via GET /depot/custody-events)
#   Shape 2 — READ-TYPE semantic equivalence (equal-length bodies)
#     DP-READ-VULN    REAL    GET /depot/waybills/{waybill_id}
#     DP-READ-SAFE    SECURE  GET /depot/dockets/{docket_id}      (equal-length SEALED denial)
#     DP-READ-SAFE-ECHO SECURE GET /depot/bonds/{bond_id}         (ADVERSARIAL ANCHOR, added
#                             after the D24 finding: identical SEALED denial, but the
#                             owner-named `account_id` ECHOES the attacker-supplied id
#                             instead of being zeroed. Leaks nothing, yet makes
#                             `_anchor_caller_identity` report 'confirmed' — so it defeats
#                             the candidate caller_identity gate BY CONSTRUCTION. See
#                             get_bond() for the full milestone note.)
#   Shape 3 — SILENT write confirmed via the object's OWN STATE on another path
#     DP-SILENT-VULN  REAL    POST /depot/accounts/{account_id}/seal  -> GET /depot/seals/{seal_id}
#     DP-SILENT-SAFE  SECURE  POST /depot/accounts/{account_id}/tag   -> GET /depot/tags/{tag_id}
#   Shape 4 — DELETE confirmed by a NEGATIVE ASSERTION
#     DP-DELETE-HARD  REAL    DELETE /depot/accounts/{account_id}/hold   (physical -> 404)
#     DP-DELETE-SOFT  REAL    DELETE /depot/accounts/{account_id}/escort (logical -> is_active=false)
#     DP-DELETE-SAFE  SECURE  DELETE /depot/accounts/{account_id}/label  (dropped -> still active)
#     DP-DELETE-CONTROL       the same hold delete aimed at a NEVER-SEEDED account id
#                             (nothing ever existed -> must NEVER verify)
#   Shape 5 — MASS-ASSIGNMENT confirmed by a LOW-ENTROPY STATE JUMP
#     DP-MASS-VULN    REAL    PATCH /depot/accounts/{account_id}/profile    (binds privileged `tier`)
#     DP-MASS-SAFE    SECURE  PATCH /depot/accounts/{account_id}/preference (allow-list strips `tier`)
#     DP-MASS-CONTROL         inject tier == the CURRENT value (no movement -> must NEVER verify)
#
# Run:
#   python -m uvicorn depot_target.main:app --reload --port 8002
# ==============================================================================

import os
import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Optional

from fastapi import FastAPI, Depends, Header, HTTPException, Path
from pydantic import BaseModel, Field
from sqlalchemy import Column, String, Boolean, select
from sqlalchemy.orm import declarative_base
from sqlalchemy.pool import NullPool
from sqlalchemy.ext.asyncio import (
    create_async_engine,
    async_sessionmaker,
    AsyncSession,
)

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("depot_target")

# ------------------------------------------------------------------------------
# Database — local SQLite file next to this module; overridable so the test suite
# can point at a throwaway file (mirrors vulnerable_target).
# ------------------------------------------------------------------------------
_DEFAULT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "depot_target.db")
DATABASE_URL = os.environ.get(
    "DEPOT_TARGET_DATABASE_URL",
    "sqlite+aiosqlite:///" + _DEFAULT_DB_PATH.replace("\\", "/"),
)

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_async_engine(
    DATABASE_URL, connect_args=connect_args, echo=False, future=True, poolclass=NullPool
)
async_session_factory = async_sessionmaker(
    bind=engine, class_=AsyncSession, expire_on_commit=False, autoflush=False
)

Base = declarative_base()

# ------------------------------------------------------------------------------
# S1 — UUID string identifiers. Fixed, readable constants so the ground-truth suite
# and the measurement drivers address the same objects deterministically. These are
# ADDRESSING only; nothing about the planted truth depends on their values.
# ------------------------------------------------------------------------------
ACCOUNT_ALICE = "a11ce000-0000-4000-8000-000000000001"
ACCOUNT_BOB = "b0b00000-0000-4000-8000-000000000002"
# Used by DP-DELETE-CONTROL: a well-formed account id that was NEVER seeded.
ACCOUNT_NEVER_SEEDED = "dead0000-0000-4000-8000-00000000dead"
# S5 — the denial body carries no victim data; 36 chars so lengths still match.
ZERO_UUID = "00000000-0000-0000-0000-000000000000"

ALICE_TOKEN = "alice-depot-token-aaaa"
BOB_TOKEN = "bob-depot-token-bbbb"


# ------------------------------------------------------------------------------
# ORM models. Every sub-object is seeded with `id == account_id` (see TOPOLOGY NOTE).
# Owner column is `account_id` everywhere (S3).
# ------------------------------------------------------------------------------
class Account(Base):
    __tablename__ = "accounts"
    id = Column(String(36), primary_key=True)
    name = Column(String(64), nullable=False, unique=True)
    token = Column(String(128), nullable=False, unique=True)


class Consignment(Base):
    """Shape 1 subject. Deliberately has NO read endpoint of any kind — the only
    observation point for a write here is the custody-event record."""
    __tablename__ = "consignments"
    id = Column(String(36), primary_key=True)
    account_id = Column(String(36), nullable=False)
    recipient = Column(String(128), nullable=False)
    memo = Column(String(128), nullable=False)


class CustodyEvent(Base):
    """Shape 1 write-record. Rows are FLAT: the subject (`account_id`) and the written
    value (`value`) sit as top-level scalars in the SAME row, which is what the engine's
    structural content-match requires."""
    __tablename__ = "custody_events"
    event_id = Column(String(36), primary_key=True)
    account_id = Column(String(36), nullable=False)
    action = Column(String(64), nullable=False)
    value = Column(String(128), nullable=False)


class Waybill(Base):
    __tablename__ = "waybills"
    id = Column(String(36), primary_key=True)
    account_id = Column(String(36), nullable=False)
    route = Column(String(7), nullable=False)     # fixed width -> equal-length bodies
    status = Column(String(6), nullable=False)    # "ACTIVE" (6)


class Docket(Base):
    __tablename__ = "dockets"
    id = Column(String(36), primary_key=True)
    account_id = Column(String(36), nullable=False)
    route = Column(String(7), nullable=False)
    status = Column(String(6), nullable=False)


class Bond(Base):
    """DP-READ-SAFE-ECHO subject. Structurally identical to Docket; the ONLY difference
    is what its denial puts in the owner-named field (see get_bond)."""
    __tablename__ = "bonds"
    id = Column(String(36), primary_key=True)
    account_id = Column(String(36), nullable=False)
    route = Column(String(7), nullable=False)
    status = Column(String(6), nullable=False)


class Seal(Base):
    __tablename__ = "seals"
    id = Column(String(36), primary_key=True)
    account_id = Column(String(36), nullable=False)
    code = Column(String(128), nullable=False)


class Tag(Base):
    __tablename__ = "tags"
    id = Column(String(36), primary_key=True)
    account_id = Column(String(36), nullable=False)
    code = Column(String(128), nullable=False)


class Hold(Base):
    __tablename__ = "holds"
    id = Column(String(36), primary_key=True)
    account_id = Column(String(36), nullable=False)
    reason = Column(String(64), nullable=False)
    is_active = Column(Boolean, nullable=False, default=True)


class Escort(Base):
    __tablename__ = "escorts"
    id = Column(String(36), primary_key=True)
    account_id = Column(String(36), nullable=False)
    reason = Column(String(64), nullable=False)
    is_active = Column(Boolean, nullable=False, default=True)


class Label(Base):
    __tablename__ = "labels"
    id = Column(String(36), primary_key=True)
    account_id = Column(String(36), nullable=False)
    reason = Column(String(64), nullable=False)
    is_active = Column(Boolean, nullable=False, default=True)


class Profile(Base):
    __tablename__ = "profiles"
    id = Column(String(36), primary_key=True)
    account_id = Column(String(36), nullable=False)
    plan = Column(String(32), nullable=False)
    # Privileged field. Seeded with a KNOWN, non-null value and ALWAYS surfaced by the
    # state read, so v1 exercises a clean present->injected jump. (The NULL-seeded
    # "hidden field" variant is a v2 boundary probe, not core.)
    tier = Column(String(32), nullable=False)


class Preference(Base):
    __tablename__ = "preferences"
    id = Column(String(36), primary_key=True)
    account_id = Column(String(36), nullable=False)
    plan = Column(String(32), nullable=False)
    tier = Column(String(32), nullable=False)


# ------------------------------------------------------------------------------
# Seed data — two accounts, one of every object each, id == account_id.
# ------------------------------------------------------------------------------
SEED_ACCOUNTS = [
    {
        "id": ACCOUNT_ALICE, "name": "alice", "token": ALICE_TOKEN,
        "recipient": "Alice Original Recipient", "memo": "alice-memo-original",
        "route": "LHR-JFK",
        "seal_code": "seal_alice_v0", "tag_code": "tag_alice_v0",
        "plan": "basic", "tier": "standard",
    },
    {
        "id": ACCOUNT_BOB, "name": "bob", "token": BOB_TOKEN,
        "recipient": "Bob Original Recipient", "memo": "bob-memo-original",
        "route": "CDG-SFO",
        "seal_code": "seal_bob_v0", "tag_code": "tag_bob_v0",
        "plan": "basic", "tier": "standard",
    },
]


async def _seed(session: AsyncSession) -> None:
    existing = (await session.execute(select(Account))).scalars().first()
    if existing is not None:
        return  # already seeded
    for a in SEED_ACCOUNTS:
        aid = a["id"]
        session.add(Account(id=aid, name=a["name"], token=a["token"]))
        session.add(Consignment(id=aid, account_id=aid, recipient=a["recipient"], memo=a["memo"]))
        session.add(Waybill(id=aid, account_id=aid, route=a["route"], status="ACTIVE"))
        session.add(Docket(id=aid, account_id=aid, route=a["route"], status="ACTIVE"))
        session.add(Bond(id=aid, account_id=aid, route=a["route"], status="ACTIVE"))
        session.add(Seal(id=aid, account_id=aid, code=a["seal_code"]))
        session.add(Tag(id=aid, account_id=aid, code=a["tag_code"]))
        session.add(Hold(id=aid, account_id=aid, reason="customs-review", is_active=True))
        session.add(Escort(id=aid, account_id=aid, reason="high-value", is_active=True))
        session.add(Label(id=aid, account_id=aid, reason="fragile", is_active=True))
        session.add(Profile(id=aid, account_id=aid, plan=a["plan"], tier=a["tier"]))
        session.add(Preference(id=aid, account_id=aid, plan=a["plan"], tier=a["tier"]))
    await session.commit()
    logger.info("Seeded depot accounts: %s", ", ".join(a["name"] for a in SEED_ACCOUNTS))


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with async_session_factory() as session:
        await _seed(session)
    yield
    await engine.dispose()


app = FastAPI(
    title="Depot Target",
    description="Deliberately-insecure second local practice target. Localhost only. Never deploy.",
    version="1.0.0",
    lifespan=lifespan,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def get_current_account(
    db: AsyncSession = Depends(get_db),
    authorization: Optional[str] = Header(default=None),
    x_token: Optional[str] = Header(default=None),
) -> Account:
    """Trivial opaque-token auth (no crypto, no expiry — this is a target). It proves
    WHO you are; the planted bugs are that endpoints never check the resource is YOURS."""
    raw = None
    if authorization:
        raw = authorization[7:] if authorization.lower().startswith("bearer ") else authorization
    elif x_token:
        raw = x_token
    if not raw:
        raise HTTPException(status_code=401, detail="Missing token")
    acct = (await db.execute(select(Account).where(Account.token == raw))).scalars().first()
    if acct is None:
        raise HTTPException(status_code=401, detail="Invalid token")
    return acct


# ------------------------------------------------------------------------------
# Schemas + the two opaque success shapes (S4).
# ------------------------------------------------------------------------------
class LoginRequest(BaseModel):
    name: str = Field(..., examples=["alice"])


class RecipientUpdate(BaseModel):
    recipient: str


class MemoUpdate(BaseModel):
    memo: str


class SealUpdate(BaseModel):
    code: str


class TagUpdate(BaseModel):
    code: str


# Every write returns this, byte-identical, whether it landed or was silently dropped.
_ACCEPTED = {"accepted": True}


@app.post("/login", tags=["auth"])
async def login(payload: LoginRequest, db: AsyncSession = Depends(get_db)):
    acct = (await db.execute(select(Account).where(Account.name == payload.name))).scalars().first()
    if acct is None:
        raise HTTPException(status_code=404, detail="No such account")
    return {"account_id": acct.id, "name": acct.name, "token": acct.token}


# ==============================================================================
# Shape 1 — write confirmed via a WRITE-RECORD.
# Neither endpoint has a same-path GET and neither subject has an object-state read;
# the ONLY observation point is GET /depot/custody-events.
# ==============================================================================

@app.patch("/depot/accounts/{account_id}/recipient", status_code=202, tags=["consignments"])
async def update_recipient(
    payload: RecipientUpdate,
    account_id: str = Path(...),
    current: Account = Depends(get_current_account),
    db: AsyncSession = Depends(get_db),
):
    """DP-WRITE-VULN — REAL. No check that account_id == current.id: the write lands for
    whatever {account_id} was asked for, and a landed write appends a custody event."""
    cons = (
        await db.execute(select(Consignment).where(Consignment.account_id == account_id))
    ).scalars().first()
    if cons is not None:
        cons.recipient = payload.recipient
        db.add(CustodyEvent(
            event_id=f"{account_id}-recipient-{payload.recipient[:24]}",
            account_id=account_id, action="recipient.update", value=payload.recipient,
        ))
        await db.flush()
    return _ACCEPTED


@app.patch("/depot/accounts/{account_id}/memo", status_code=202, tags=["consignments"])
async def update_memo(
    payload: MemoUpdate,
    account_id: str = Path(...),
    current: Account = Depends(get_current_account),
    db: AsyncSession = Depends(get_db),
):
    """DP-WRITE-SAFE — SECURE. Ownership IS enforced: a cross-account write is silently
    dropped (no error, same opaque 202) and appends NOTHING to the record."""
    if account_id == current.id:
        cons = (
            await db.execute(select(Consignment).where(Consignment.account_id == account_id))
        ).scalars().first()
        if cons is not None:
            cons.memo = payload.memo
            db.add(CustodyEvent(
                event_id=f"{account_id}-memo-{payload.memo[:24]}",
                account_id=account_id, action="memo.update", value=payload.memo,
            ))
            await db.flush()
    return _ACCEPTED


@app.get("/depot/custody-events", tags=["custody"])
async def list_custody_events(
    current: Account = Depends(get_current_account),
    db: AsyncSession = Depends(get_db),
):
    """The append-only write record — a DIFFERENT path from the writes above, and the
    only place their effect is observable. Rows are flat (subject + value in one row)."""
    rows = (await db.execute(select(CustodyEvent).order_by(CustodyEvent.event_id))).scalars().all()
    return {"events": [
        {"event_id": e.event_id, "account_id": e.account_id, "action": e.action, "value": e.value}
        for e in rows
    ]}


# ==============================================================================
# Shape 2 — READ-TYPE semantic equivalence. Bodies are shaped EQUAL-LENGTH so a
# size/diff oracle cannot decide and the AI must judge on semantic content.
# ==============================================================================

@app.get("/depot/accounts/{account_id}/waybill", tags=["waybills"])
async def read_own_waybill(
    account_id: str = Path(...),
    current: Account = Depends(get_current_account),
    db: AsyncSession = Depends(get_db),
):
    """Owner-scoped canonical read (ownership enforced). The equivalent flat path below
    is the vulnerable one — same object, two routes to it."""
    if account_id != current.id:
        raise HTTPException(status_code=403, detail="Forbidden")
    wb = (await db.execute(select(Waybill).where(Waybill.account_id == account_id))).scalars().first()
    if wb is None:
        raise HTTPException(status_code=404, detail="Waybill not found")
    return {"waybill_id": wb.id, "account_id": wb.account_id, "route": wb.route, "status": wb.status}


@app.get("/depot/waybills/{waybill_id}", tags=["waybills"])
async def get_waybill(
    waybill_id: str = Path(...),
    current: Account = Depends(get_current_account),
    db: AsyncSession = Depends(get_db),
):
    """DP-READ-VULN — REAL. The flat path has NO ownership check, so any authenticated
    account reads any waybill. The leak is visible in the response itself (`account_id`)."""
    wb = (await db.execute(select(Waybill).where(Waybill.id == waybill_id))).scalars().first()
    if wb is None:
        raise HTTPException(status_code=404, detail="Waybill not found")
    return {"waybill_id": wb.id, "account_id": wb.account_id, "route": wb.route, "status": wb.status}


@app.get("/depot/accounts/{account_id}/docket", tags=["dockets"])
async def read_own_docket(
    account_id: str = Path(...),
    current: Account = Depends(get_current_account),
    db: AsyncSession = Depends(get_db),
):
    if account_id != current.id:
        raise HTTPException(status_code=403, detail="Forbidden")
    dk = (await db.execute(select(Docket).where(Docket.account_id == account_id))).scalars().first()
    if dk is None:
        raise HTTPException(status_code=404, detail="Docket not found")
    return {"docket_id": dk.id, "account_id": dk.account_id, "route": dk.route, "status": dk.status}


@app.get("/depot/dockets/{docket_id}", tags=["dockets"])
async def get_docket(
    docket_id: str = Path(...),
    current: Account = Depends(get_current_account),
    db: AsyncSession = Depends(get_db),
):
    """DP-READ-SAFE — SECURE. Ownership IS enforced, but a cross-account read is refused
    with an EQUAL-LENGTH soft-200 denial (S5) rather than a 403: same keys, same widths,
    no victim data (zeroed account_id, masked route, status SEALED). Only the semantic
    content reveals it is a refusal — a 200 here must NOT be read as a leak."""
    dk = (await db.execute(select(Docket).where(Docket.id == docket_id))).scalars().first()
    if dk is None:
        raise HTTPException(status_code=404, detail="Docket not found")
    if dk.account_id != current.id:
        return {"docket_id": docket_id, "account_id": ZERO_UUID, "route": "XXX-XXX", "status": "SEALED"}
    return {"docket_id": dk.id, "account_id": dk.account_id, "route": dk.route, "status": dk.status}


@app.get("/depot/accounts/{account_id}/bond", tags=["bonds"])
async def read_own_bond(
    account_id: str = Path(...),
    current: Account = Depends(get_current_account),
    db: AsyncSession = Depends(get_db),
):
    if account_id != current.id:
        raise HTTPException(status_code=403, detail="Forbidden")
    bd = (await db.execute(select(Bond).where(Bond.account_id == account_id))).scalars().first()
    if bd is None:
        raise HTTPException(status_code=404, detail="Bond not found")
    return {"bond_id": bd.id, "account_id": bd.account_id, "route": bd.route, "status": bd.status}


@app.get("/depot/bonds/{bond_id}", tags=["bonds"])
async def get_bond(
    bond_id: str = Path(...),
    current: Account = Depends(get_current_account),
    db: AsyncSession = Depends(get_db),
):
    """DP-READ-SAFE-ECHO — SECURE. An ADVERSARIAL anchor case, built deliberately.

    Ownership IS enforced and a cross-account read discloses NOTHING: the route is masked
    and the status is a constant refusal token, exactly like DP-READ-SAFE. The ONE
    difference from DP-READ-SAFE is the owner-named field:

        DP-READ-SAFE  (docket) -> "account_id": <zero uuid>        (owner field zeroed)
        DP-READ-SAFE-ECHO      -> "account_id": <the REQUESTED id> (owner field ECHOED)

    Echoing the requested id leaks nothing — the attacker supplied that value themselves
    and already knew it. The case is still genuinely SECURE, and its ground truth says so.

    WHY IT EXISTS (milestone note — recorded, not acted on):
    The candidate deterministic gate for the read-semantic shape (TECH_DEBT D24) is
    "the attack response must carry a victim-owned identity marker; caller_identity ==
    'owner_not_found' cannot be decisive". That gate discriminates 4/4 on the cases known
    so far. THIS CASE DEFEATS IT BY CONSTRUCTION: `_anchor_caller_identity` scans
    owner/subject-NAMED fields and asks whether the attacked id is among their values. Here
    it is — because the endpoint echoed it back — so the anchor reports 'confirmed' on an
    endpoint that leaked nothing, and a caller_identity-keyed gate would pass it.

    The lesson to carry into the fix milestone: a field-NAME filter is not enough. The
    eventual gate will likely need PROVENANCE — evidence must not be credited from a value
    the ATTACKER supplied (path id, request parameter), only from genuinely victim-owned
    data. This is the same class as the historical B-1/D23 resource-identity conflation.
    That design is NOT started and is not to be written until it is signed off.

    This endpoint is an allowed-to-fail regression anchor. Do NOT weaken it to make any
    gate pass, and do NOT relabel it: it is SECURE, proven independently in test_vulns.py.
    """
    bd = (await db.execute(select(Bond).where(Bond.id == bond_id))).scalars().first()
    if bd is None:
        raise HTTPException(status_code=404, detail="Bond not found")
    if bd.account_id != current.id:
        # Same keys and same widths as the real body (so the shape's equal-length property
        # holds), no victim data, and the owner-named field echoes the caller's own input.
        return {"bond_id": bond_id, "account_id": bond_id, "route": "XXX-XXX", "status": "SEALED"}
    return {"bond_id": bd.id, "account_id": bd.account_id, "route": bd.route, "status": bd.status}


# ==============================================================================
# Shape 3 — SILENT write confirmed via the object's OWN STATE on another path.
# The write paths have NO same-path GET (a GET yields 405) and append NO record.
# ==============================================================================

@app.post("/depot/accounts/{account_id}/seal", status_code=202, tags=["seals"])
async def apply_seal(
    payload: SealUpdate,
    account_id: str = Path(...),
    current: Account = Depends(get_current_account),
    db: AsyncSession = Depends(get_db),
):
    """DP-SILENT-VULN — REAL. No ownership check; the write lands silently. Nothing in
    the response reveals it, and there is no record — only GET /depot/seals/{id} shows it."""
    seal = (await db.execute(select(Seal).where(Seal.account_id == account_id))).scalars().first()
    if seal is not None:
        seal.code = payload.code
        await db.flush()
    return _ACCEPTED


@app.get("/depot/seals/{seal_id}", tags=["seals"])
async def get_seal(
    seal_id: str = Path(...),
    current: Account = Depends(get_current_account),
    db: AsyncSession = Depends(get_db),
):
    seal = (await db.execute(select(Seal).where(Seal.id == seal_id))).scalars().first()
    if seal is None:
        raise HTTPException(status_code=404, detail="Seal not found")
    return {"seal_id": seal.id, "account_id": seal.account_id, "code": seal.code}


@app.post("/depot/accounts/{account_id}/tag", status_code=202, tags=["tags"])
async def apply_tag(
    payload: TagUpdate,
    account_id: str = Path(...),
    current: Account = Depends(get_current_account),
    db: AsyncSession = Depends(get_db),
):
    """DP-SILENT-SAFE — SECURE. Identical shape and identical opaque 202, but a
    cross-account write is silently dropped; the object's state never moves."""
    if account_id == current.id:
        tag = (await db.execute(select(Tag).where(Tag.account_id == account_id))).scalars().first()
        if tag is not None:
            tag.code = payload.code
            await db.flush()
    return _ACCEPTED


@app.get("/depot/tags/{tag_id}", tags=["tags"])
async def get_tag(
    tag_id: str = Path(...),
    current: Account = Depends(get_current_account),
    db: AsyncSession = Depends(get_db),
):
    tag = (await db.execute(select(Tag).where(Tag.id == tag_id))).scalars().first()
    if tag is None:
        raise HTTPException(status_code=404, detail="Tag not found")
    return {"tag_id": tag.id, "account_id": tag.account_id, "code": tag.code}


# ==============================================================================
# Shape 4 — DELETE confirmed by a NEGATIVE ASSERTION (existence -> absence).
# Every delete returns the SAME opaque 204 No Content (S4), whether it deleted
# anything, was dropped, or targeted an id that never existed.
# ==============================================================================

@app.delete("/depot/accounts/{account_id}/hold", status_code=204, tags=["holds"])
async def delete_hold(
    account_id: str = Path(...),
    current: Account = Depends(get_current_account),
    db: AsyncSession = Depends(get_db),
):
    """DP-DELETE-HARD — REAL (physical removal). Also the DP-DELETE-CONTROL path when
    aimed at a never-seeded account id: the response is identical, so "it is gone now"
    proves nothing unless "it existed just before" was anchored first."""
    hold = (await db.execute(select(Hold).where(Hold.account_id == account_id))).scalars().first()
    if hold is not None:
        await db.delete(hold)
        await db.flush()
    return None


@app.get("/depot/holds/{hold_id}", tags=["holds"])
async def get_hold(
    hold_id: str = Path(...),
    current: Account = Depends(get_current_account),
    db: AsyncSession = Depends(get_db),
):
    hold = (await db.execute(select(Hold).where(Hold.id == hold_id))).scalars().first()
    if hold is None:
        raise HTTPException(status_code=404, detail="Hold not found")
    return {"hold_id": hold.id, "account_id": hold.account_id,
            "reason": hold.reason, "is_active": hold.is_active}


@app.delete("/depot/accounts/{account_id}/escort", status_code=204, tags=["escorts"])
async def delete_escort(
    account_id: str = Path(...),
    current: Account = Depends(get_current_account),
    db: AsyncSession = Depends(get_db),
):
    """DP-DELETE-SOFT — REAL (logical/soft delete). The row survives and the read-back is
    still 200; only the `is_active` lifecycle flag flips. A verifier that treats 404 as
    the only proof of deletion misses this entirely."""
    escort = (await db.execute(select(Escort).where(Escort.account_id == account_id))).scalars().first()
    if escort is not None:
        escort.is_active = False
        await db.flush()
    return None


@app.get("/depot/escorts/{escort_id}", tags=["escorts"])
async def get_escort(
    escort_id: str = Path(...),
    current: Account = Depends(get_current_account),
    db: AsyncSession = Depends(get_db),
):
    escort = (await db.execute(select(Escort).where(Escort.id == escort_id))).scalars().first()
    if escort is None:
        raise HTTPException(status_code=404, detail="Escort not found")
    return {"escort_id": escort.id, "account_id": escort.account_id,
            "reason": escort.reason, "is_active": escort.is_active}


@app.delete("/depot/accounts/{account_id}/label", status_code=204, tags=["labels"])
async def delete_label(
    account_id: str = Path(...),
    current: Account = Depends(get_current_account),
    db: AsyncSession = Depends(get_db),
):
    """DP-DELETE-SAFE — SECURE. Ownership IS enforced; a cross-account delete is silently
    dropped behind the same opaque 204. The object remains present and active."""
    if account_id == current.id:
        label = (await db.execute(select(Label).where(Label.account_id == account_id))).scalars().first()
        if label is not None:
            await db.delete(label)
            await db.flush()
    return None


@app.get("/depot/labels/{label_id}", tags=["labels"])
async def get_label(
    label_id: str = Path(...),
    current: Account = Depends(get_current_account),
    db: AsyncSession = Depends(get_db),
):
    label = (await db.execute(select(Label).where(Label.id == label_id))).scalars().first()
    if label is None:
        raise HTTPException(status_code=404, detail="Label not found")
    return {"label_id": label.id, "account_id": label.account_id,
            "reason": label.reason, "is_active": label.is_active}


# ==============================================================================
# Shape 5 — MASS-ASSIGNMENT confirmed by a LOW-ENTROPY STATE JUMP.
# `tier` is privileged and LOW-ENTROPY, so its mere presence proves nothing; only
# movement from a known prior value can attribute it to this attack.
# ==============================================================================

_PROFILE_COLUMNS = {"plan", "tier"}      # every writable column — NO allow-list (the bug)
_PREFERENCE_ALLOWED = {"plan"}           # explicit allow-list — `tier` is stripped (the fix)


@app.patch("/depot/accounts/{account_id}/profile", status_code=202, tags=["profiles"])
async def update_profile(
    payload: dict,
    account_id: str = Path(...),
    current: Account = Depends(get_current_account),
    db: AsyncSession = Depends(get_db),
):
    """DP-MASS-VULN — REAL. No ownership check AND every column named in the body is
    bound, including the privileged `tier`. Also the DP-MASS-CONTROL path when the
    injected tier equals the value already stored (no movement -> nothing attributable)."""
    profile = (
        await db.execute(select(Profile).where(Profile.account_id == account_id))
    ).scalars().first()
    if profile is not None:
        for k, v in (payload or {}).items():
            if k in _PROFILE_COLUMNS and isinstance(v, (str, int, float, bool)):
                setattr(profile, k, str(v))
        await db.flush()
    return _ACCEPTED


@app.get("/depot/profiles/{profile_id}", tags=["profiles"])
async def get_profile(
    profile_id: str = Path(...),
    current: Account = Depends(get_current_account),
    db: AsyncSession = Depends(get_db),
):
    """State read-back. `tier` is ALWAYS surfaced (seeded non-null), so v1 exercises a
    clean present->injected jump rather than the hidden-field variant."""
    profile = (await db.execute(select(Profile).where(Profile.id == profile_id))).scalars().first()
    if profile is None:
        raise HTTPException(status_code=404, detail="Profile not found")
    return {"profile_id": profile.id, "account_id": profile.account_id,
            "plan": profile.plan, "tier": profile.tier}


@app.patch("/depot/accounts/{account_id}/preference", status_code=202, tags=["preferences"])
async def update_preference(
    payload: dict,
    account_id: str = Path(...),
    current: Account = Depends(get_current_account),
    db: AsyncSession = Depends(get_db),
):
    """DP-MASS-SAFE — SECURE, on BOTH axes, behind the same opaque 202:
      (1) ownership IS enforced, so a cross-account write lands nothing at all; and
      (2) an explicit allow-list binds only `plan`, so even the owner's own write can
          never escalate the privileged `tier`.
    Being secure on both axes is deliberate: it makes the SECURE label unambiguous. The
    harder "allow-list only, no ownership check" variant — where the legitimate
    co-submitted field still lands cross-account — is NOT used here, because a landed
    cross-account write is itself a real access-control flaw and its label would be
    debatable. That trap belongs in the v2 boundary-probe set, not in a must-all-pass core."""
    if account_id != current.id:
        return _ACCEPTED
    pref = (
        await db.execute(select(Preference).where(Preference.account_id == account_id))
    ).scalars().first()
    if pref is not None:
        for k, v in (payload or {}).items():
            if k in _PREFERENCE_ALLOWED and isinstance(v, (str, int, float, bool)):
                setattr(pref, k, str(v))
        await db.flush()
    return _ACCEPTED


@app.get("/depot/preferences/{preference_id}", tags=["preferences"])
async def get_preference(
    preference_id: str = Path(...),
    current: Account = Depends(get_current_account),
    db: AsyncSession = Depends(get_db),
):
    pref = (
        await db.execute(select(Preference).where(Preference.id == preference_id))
    ).scalars().first()
    if pref is None:
        raise HTTPException(status_code=404, detail="Preference not found")
    return {"preference_id": pref.id, "account_id": pref.account_id,
            "plan": pref.plan, "tier": pref.tier}


@app.get("/", tags=["meta"])
async def root():
    return {
        "service": "Depot Target",
        "warning": "Deliberately insecure. Localhost practice target only. Never deploy.",
        "shapes": {
            "write_record": ["PATCH /depot/accounts/{account_id}/recipient (REAL)",
                             "PATCH /depot/accounts/{account_id}/memo (SECURE)",
                             "GET /depot/custody-events"],
            "read_semantic": ["GET /depot/waybills/{waybill_id} (REAL)",
                              "GET /depot/dockets/{docket_id} (SECURE, equal-length denial)",
                              "GET /depot/bonds/{bond_id} (SECURE, denial ECHOES the requested "
                              "id into the owner-named field — adversarial anchor)"],
            "silent_write": ["POST /depot/accounts/{account_id}/seal (REAL) -> GET /depot/seals/{seal_id}",
                             "POST /depot/accounts/{account_id}/tag (SECURE) -> GET /depot/tags/{tag_id}"],
            "delete": ["DELETE /depot/accounts/{account_id}/hold (REAL, physical)",
                       "DELETE /depot/accounts/{account_id}/escort (REAL, soft)",
                       "DELETE /depot/accounts/{account_id}/label (SECURE)"],
            "mass_assignment": ["PATCH /depot/accounts/{account_id}/profile (REAL)",
                                "PATCH /depot/accounts/{account_id}/preference (SECURE)"],
        },
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("depot_target.main:app", host="127.0.0.1", port=8002, reload=False)
