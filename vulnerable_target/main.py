# ==============================================================================
# Standalone Vulnerable Test Target  (LOCAL PRACTICE TARGET — NEVER DEPLOY)
# ==============================================================================
#
# This is a deliberately-insecure, fully self-contained FastAPI application used
# as a local ground-truth practice target for our own security tooling. It runs
# only on localhost (default port 8001) and is never deployed.
#
# It imports NOTHING from the main backend/app package — it has its own DB, its
# own engine, its own ORM Base, and its own uvicorn entrypoint. This mirrors the
# repo's conventions (SQLAlchemy 2.0 async + aiosqlite, classic Column ORM,
# async_sessionmaker(expire_on_commit=False), create_all inside a FastAPI
# lifespan) but stays entirely standalone.
#
# Planted truth (see README.md for the full answer key):
#   * Vuln A     — blatant BOLA           : GET  /api/orders/{order_id}
#   * Vuln B     — silent BOLA            : POST /api/users/{user_id}/profile
#   * Vuln C     — vertical priv-esc      : GET  /api/admin/users
#   * Vuln D     — silent BOLA (regress.) : POST /api/users/{user_id}/settings
#   * SAFE       — secured look-alike trap: POST /api/users/{user_id}/avatar  (NOT vulnerable)
#   * T-REAL     — strong-signal IDOR     : GET  /api/invoices/{invoice_id}   (REAL)
#   * T-TRAP     — soft-200 denial        : GET  /api/documents/{document_id} (SECURE; 200 + error body)
#   * T-WEAK     — weak-signal IDOR       : GET  /api/notes/{note_id}         (REAL, faint signal)
#   * T-SILENT2  — silent BOLA (theme)    : POST /api/users/{user_id}/theme   (REAL)
#
# Run:
#   python -m uvicorn vulnerable_target.main:app --reload --port 8001
#   (or, from inside vulnerable_target/:  uvicorn main:app --port 8001)
# ==============================================================================

import os
import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Optional

from fastapi import FastAPI, Depends, Header, HTTPException, Path
from pydantic import BaseModel, Field
from sqlalchemy import Column, Integer, String, Float, Text, ForeignKey, select
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy.pool import NullPool
from sqlalchemy.ext.asyncio import (
    create_async_engine,
    async_sessionmaker,
    AsyncSession,
)

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("vulnerable_target")

# ------------------------------------------------------------------------------
# Database — local SQLite file, sitting next to this module. The DATABASE_URL can
# be overridden via env var so the test suite can point at a throwaway file.
# ------------------------------------------------------------------------------
_DEFAULT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vulnerable_target.db")
DATABASE_URL = os.environ.get(
    "VULN_TARGET_DATABASE_URL",
    "sqlite+aiosqlite:///" + _DEFAULT_DB_PATH.replace("\\", "/"),
)

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
# NullPool: never reuse an aiosqlite connection across event loops (the FastAPI
# loop vs. a test/lifespan loop) — avoids "future attached to a different loop"
# stalls and keeps teardown fast. Same rationale the main repo's tests document.
engine = create_async_engine(
    DATABASE_URL, connect_args=connect_args, echo=False, future=True, poolclass=NullPool
)
async_session_factory = async_sessionmaker(
    bind=engine, class_=AsyncSession, expire_on_commit=False, autoflush=False
)

Base = declarative_base()


# ------------------------------------------------------------------------------
# ORM models (classic Column style, mirroring backend/app/models/scan.py)
# ------------------------------------------------------------------------------
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(64), nullable=False, unique=True)
    # The "token" is a trivial opaque identifier — NO real crypto. This is a target.
    # The token maps 1:1 to a user, and the user carries a role, so the token
    # transitively "encodes" which user (and thus their role) — see login().
    token = Column(String(128), nullable=False, unique=True)
    # "user" (normal) or "admin". Powers the Vuln C vertical-priv-esc test case.
    role = Column(String(16), nullable=False, default="user")

    order = relationship("Order", back_populates="owner", uselist=False)
    profile = relationship("Profile", back_populates="owner", uselist=False)
    setting = relationship("Setting", back_populates="owner", uselist=False)
    avatar = relationship("Avatar", back_populates="owner", uselist=False)
    invoice = relationship("Invoice", back_populates="owner", uselist=False)
    document = relationship("Document", back_populates="owner", uselist=False)
    note = relationship("Note", back_populates="owner", uselist=False)
    theme = relationship("Theme", back_populates="owner", uselist=False)


class Order(Base):
    __tablename__ = "orders"

    id = Column(Integer, primary_key=True, autoincrement=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    item = Column(String(128), nullable=False)
    amount = Column(Float, nullable=False)
    currency = Column(String(8), nullable=False, default="USD")

    owner = relationship("User", back_populates="order")


class Profile(Base):
    __tablename__ = "profiles"

    id = Column(Integer, primary_key=True, autoincrement=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    display_name = Column(String(128), nullable=False)

    owner = relationship("User", back_populates="profile")


class Setting(Base):
    """Notification setting — the object behind Vuln D (silent BOLA regression)."""
    __tablename__ = "settings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    notifications = Column(String(32), nullable=False, default="email")

    owner = relationship("User", back_populates="setting")


class Avatar(Base):
    """Avatar URL — the object behind the SAFE control (secured look-alike)."""
    __tablename__ = "avatars"

    id = Column(Integer, primary_key=True, autoincrement=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    avatar_url = Column(String(256), nullable=False, default="")

    owner = relationship("User", back_populates="avatar")


class Invoice(Base):
    """Invoice — object behind T-REAL (strong-signal IDOR). Bob's body is clearly
    larger/different from Alice's, so even a single-shot size/diff oracle catches it.
    The invoice id is seeded equal to the owner's user id for predictability."""
    __tablename__ = "invoices"

    id = Column(Integer, primary_key=True)  # explicit; == owner_id for clarity
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    number = Column(String(32), nullable=False)
    amount = Column(Float, nullable=False)
    details = Column(Text, nullable=False, default="")

    owner = relationship("User", back_populates="invoice")


class Document(Base):
    """Document — object behind T-TRAP (soft-200 denial). The READ endpoint denies
    cross-user access but does so with HTTP 200 + {"error":"forbidden"} instead of
    403. The data is NOT disclosed; it only LOOKS like a leak at the status line."""
    __tablename__ = "documents"

    id = Column(Integer, primary_key=True)  # explicit; == owner_id for clarity
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    title = Column(String(128), nullable=False)
    content = Column(Text, nullable=False, default="")

    owner = relationship("User", back_populates="document")


class Note(Base):
    """Note — object behind T-WEAK (weak-signal IDOR). Cross-user read IS allowed
    (real vuln), but every user's note is the same length/shape so the size/diff
    signal is faint (only a few characters differ)."""
    __tablename__ = "notes"

    id = Column(Integer, primary_key=True)  # explicit; == owner_id for clarity
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    text = Column(String(256), nullable=False)

    owner = relationship("User", back_populates="note")


class Theme(Base):
    """Theme — object behind T-SILENT2 (silent BOLA, theme family). The POST has no
    ownership check (real vuln) but returns an opaque 200 {"status":"ok"}; the
    cross-user write is only observable via a GET read-back."""
    __tablename__ = "themes"

    id = Column(Integer, primary_key=True, autoincrement=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    theme = Column(String(32), nullable=False, default="light")

    owner = relationship("User", back_populates="theme")


# ------------------------------------------------------------------------------
# Seed data — Alice (id=1, user) and Bob (id=2, user) are normal users; Carol
# (id=3, admin) is the privileged account used by the Vuln C test case. Each user
# owns one order, one profile, one notification setting, and one avatar.
# Tokens are static and predictable on purpose (documented in README.md).
# ------------------------------------------------------------------------------
SEED_USERS = [
    {
        "id": 1,
        "username": "alice",
        "token": "alice-token-aaaa",
        "role": "user",
        "order": {"item": "Vintage Typewriter", "amount": 249.99, "currency": "USD"},
        "profile": {"display_name": "Alice"},
        "setting": {"notifications": "email"},
        "avatar": {"avatar_url": "https://avatars.local/alice.png"},
        # T-REAL: Alice's invoice is small (one short line item).
        "invoice": {"number": "INV-1001", "amount": 49.90, "details": "1x Coffee Mug"},
        # T-TRAP: Alice's own document (she may read it).
        "document": {"title": "Alice Memo", "content": "Alice private memo: lunch at noon."},
        # T-WEAK: near-identical to Bob's note (only the last word differs).
        "note": {"text": "Remember to buy milk"},
        # T-SILENT2: theme behind the silent BOLA.
        "theme": {"theme": "light"},
    },
    {
        "id": 2,
        "username": "bob",
        "token": "bob-token-bbbb",
        "role": "user",
        "order": {"item": "Mechanical Keyboard Set + Artisan Keycaps Bundle", "amount": 1875.50, "currency": "EUR"},
        "profile": {"display_name": "Bob"},
        "setting": {"notifications": "sms"},
        "avatar": {"avatar_url": "https://avatars.local/bob.png"},
        # T-REAL: Bob's invoice is clearly LARGER (big amount + long itemized body).
        "invoice": {
            "number": "INV-2002",
            "amount": 9875.40,
            "details": (
                "12x Standing Desk; 12x Ergonomic Chair; 40x 27-inch Monitor; "
                "40x Docking Station; 200x USB-C Cable; 1x Enterprise Support Plan "
                "(annual); 1x On-site Installation; 5x Conference Room AV Kit; "
                "Bulk procurement order for Q3 office expansion — net 30 terms."
            ),
        },
        # T-TRAP: Bob's confidential document Alice must NOT be able to read.
        "document": {
            "title": "Bob Confidential",
            "content": "Bob CONFIDENTIAL: salary band L6, equity refresh 1,200 RSU, SSN on file.",
        },
        # T-WEAK: same length/shape as Alice's note (only the last word differs).
        "note": {"text": "Remember to buy eggs"},
        "theme": {"theme": "dark"},
    },
    {
        "id": 3,
        "username": "carol",
        "token": "carol-token-cccc",
        "role": "admin",
        "order": {"item": "Server Rack PDU", "amount": 540.00, "currency": "USD"},
        "profile": {"display_name": "Carol"},
        "setting": {"notifications": "none"},
        "avatar": {"avatar_url": "https://avatars.local/carol.png"},
        "invoice": {"number": "INV-3003", "amount": 120.00, "details": "1x Mechanical Keyboard"},
        "document": {"title": "Carol Memo", "content": "Carol admin notes: rotate keys."},
        "note": {"text": "Remember to buy tea_"},
        "theme": {"theme": "system"},
    },
]


async def _seed(session: AsyncSession) -> None:
    existing = (await session.execute(select(User))).scalars().first()
    if existing is not None:
        return  # already seeded
    for u in SEED_USERS:
        session.add(User(id=u["id"], username=u["username"], token=u["token"], role=u["role"]))
        session.add(Order(owner_id=u["id"], **u["order"]))
        session.add(Profile(owner_id=u["id"], **u["profile"]))
        session.add(Setting(owner_id=u["id"], **u["setting"]))
        session.add(Avatar(owner_id=u["id"], **u["avatar"]))
        # New benchmark objects (id seeded == owner_id for invoice/document/note).
        session.add(Invoice(id=u["id"], owner_id=u["id"], **u["invoice"]))
        session.add(Document(id=u["id"], owner_id=u["id"], **u["document"]))
        session.add(Note(id=u["id"], owner_id=u["id"], **u["note"]))
        session.add(Theme(owner_id=u["id"], **u["theme"]))
    await session.commit()
    logger.info("Seeded users: %s", ", ".join(u["username"] for u in SEED_USERS))


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with async_session_factory() as session:
        await _seed(session)
    yield
    await engine.dispose()


app = FastAPI(
    title="Vulnerable Test Target",
    description="Deliberately-insecure local practice target. Localhost only. Never deploy.",
    version="1.0.0",
    lifespan=lifespan,
)


# ------------------------------------------------------------------------------
# DB session dependency
# ------------------------------------------------------------------------------
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


# ------------------------------------------------------------------------------
# Trivial token auth. The token is passed as an Authorization header
# ("Bearer <token>") OR an X-Token header OR a `token` cookie. We resolve it to a
# User. NO crypto, NO expiry — this is a practice target.
#
# NOTE: This dependency authenticates *who you are*. The planted bugs are that
# the endpoints below never check that the requested resource belongs to YOU.
# ------------------------------------------------------------------------------
async def get_current_user(
    db: AsyncSession = Depends(get_db),
    authorization: Optional[str] = Header(default=None),
    x_token: Optional[str] = Header(default=None),
    token: Optional[str] = None,
) -> User:
    raw = None
    if authorization:
        raw = authorization[7:] if authorization.lower().startswith("bearer ") else authorization
    elif x_token:
        raw = x_token
    elif token:
        raw = token
    if not raw:
        raise HTTPException(status_code=401, detail="Missing token")

    user = (await db.execute(select(User).where(User.token == raw))).scalars().first()
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid token")
    return user


# ------------------------------------------------------------------------------
# Pydantic schemas
# ------------------------------------------------------------------------------
class LoginRequest(BaseModel):
    username: str = Field(..., examples=["alice"])


class LoginResponse(BaseModel):
    user_id: int
    username: str
    role: str
    token: str


class OrderResponse(BaseModel):
    order_id: int
    owner_id: int
    item: str
    amount: float
    currency: str


class ProfileUpdateRequest(BaseModel):
    display_name: str = Field(..., min_length=1, max_length=128)


class ProfileResponse(BaseModel):
    user_id: int
    display_name: str


class AdminUserEntry(BaseModel):
    id: int
    username: str
    role: str


class AdminUserListResponse(BaseModel):
    count: int
    users: list[AdminUserEntry]


class SettingsUpdateRequest(BaseModel):
    notifications: str = Field(..., min_length=1, max_length=32)


class SettingsResponse(BaseModel):
    user_id: int
    notifications: str


class AvatarUpdateRequest(BaseModel):
    avatar_url: str = Field(..., min_length=1, max_length=256)


class AvatarResponse(BaseModel):
    user_id: int
    avatar_url: str


class InvoiceResponse(BaseModel):
    invoice_id: int
    owner_id: int
    number: str
    amount: float
    details: str


class NoteResponse(BaseModel):
    note_id: int
    owner_id: int
    text: str


class ThemeUpdateRequest(BaseModel):
    theme: str = Field(..., min_length=1, max_length=32)


class ThemeResponse(BaseModel):
    user_id: int
    theme: str


# ------------------------------------------------------------------------------
# Auth — trivial "login". Returns the static token that identifies the user.
# ------------------------------------------------------------------------------
@app.post("/login", response_model=LoginResponse, tags=["auth"])
async def login(payload: LoginRequest, db: AsyncSession = Depends(get_db)):
    user = (
        await db.execute(select(User).where(User.username == payload.username.lower()))
    ).scalars().first()
    if user is None:
        raise HTTPException(status_code=404, detail="No such user")
    return LoginResponse(
        user_id=user.id, username=user.username, role=user.role, token=user.token
    )


# ------------------------------------------------------------------------------
# Vuln A — BLATANT BOLA.
#
# GET /api/orders/{order_id} returns the full order. The bug: it authenticates
# the caller (any valid token) but NEVER checks Order.owner_id == current_user.id.
# Alice's token can therefore read Bob's order. The two seeded orders differ
# wildly in item/amount/currency, so the response body length and content differ
# — a single-shot size/diff oracle WILL catch this.
# ------------------------------------------------------------------------------
@app.get("/api/orders/{order_id}", response_model=OrderResponse, tags=["orders"])
async def get_order(
    order_id: int = Path(..., ge=1),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    order = (
        await db.execute(select(Order).where(Order.id == order_id))
    ).scalars().first()
    if order is None:
        raise HTTPException(status_code=404, detail="Order not found")

    # VULNERABLE: no ownership check. Should require order.owner_id == current_user.id.
    return OrderResponse(
        order_id=order.id,
        owner_id=order.owner_id,
        item=order.item,
        amount=order.amount,
        currency=order.currency,
    )


# ------------------------------------------------------------------------------
# Vuln B — SILENT BOLA  (the important one).
#
# POST /api/users/{user_id}/profile updates a user's display name. The bug: it
# authenticates the caller but NEVER checks that {user_id} == current_user.id, so
# Alice can overwrite Bob's profile.
#
# CRITICAL DESIGN: the response is ALWAYS exactly 200 {"status":"ok"} regardless
# of WHOSE profile was changed (or even whether anything changed) — identical
# status code, identical Content-Length, identical body every single time. A
# single-shot, diff-based oracle CANNOT distinguish "changed my own profile"
# from "changed someone else's profile". The write only becomes observable via a
# SECOND request: GET /api/users/{user_id}/profile to read the name back.
# ------------------------------------------------------------------------------
@app.post("/api/users/{user_id}/profile", tags=["profile"])
async def update_profile(
    payload: ProfileUpdateRequest,
    user_id: int = Path(..., ge=1),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    profile = (
        await db.execute(select(Profile).where(Profile.owner_id == user_id))
    ).scalars().first()

    # VULNERABLE: no check that user_id == current_user.id. The write happens for
    # whatever {user_id} was requested.
    if profile is not None:
        profile.display_name = payload.display_name
        await db.flush()

    # Intentionally opaque, constant response — no echo of the new name, no id,
    # no "updated" flag. Always the same bytes. This is what makes the vuln SILENT.
    return {"status": "ok"}


@app.get("/api/users/{user_id}/profile", response_model=ProfileResponse, tags=["profile"])
async def read_profile(
    user_id: int = Path(..., ge=1),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    profile = (
        await db.execute(select(Profile).where(Profile.owner_id == user_id))
    ).scalars().first()
    if profile is None:
        raise HTTPException(status_code=404, detail="Profile not found")
    return ProfileResponse(user_id=user_id, display_name=profile.display_name)


# ------------------------------------------------------------------------------
# Vuln C — VERTICAL PRIVILEGE ESCALATION.
#
# GET /api/admin/users is meant to be an admin-only endpoint returning the full
# user roster (sensitive: it exposes every user's role). The bug: it authenticates
# the caller but NEVER checks current_user.role == "admin". So a NORMAL user
# (Alice) can call it and receive the admin-only list. The response is clearly
# richer than any normal-user endpoint — it returns ALL users and their roles —
# so the privilege boundary is genuinely crossed, not just a cosmetic difference.
# ------------------------------------------------------------------------------
@app.get("/api/admin/users", response_model=AdminUserListResponse, tags=["admin"])
async def admin_list_users(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    # VULNERABLE: should require current_user.role == "admin". It does not.
    users = (await db.execute(select(User).order_by(User.id))).scalars().all()
    return AdminUserListResponse(
        count=len(users),
        users=[AdminUserEntry(id=u.id, username=u.username, role=u.role) for u in users],
    )


# ------------------------------------------------------------------------------
# Vuln D — SILENT BOLA (regression case, same shape as Vuln B).
#
# POST /api/users/{user_id}/settings updates a user's notification setting with
# the SAME flaw as Vuln B: no ownership check, always an opaque 200 {"status":"ok"}.
# The cross-user write is only observable via a follow-up GET read-back. This
# exists to prove the write-then-read oracle still works on a fresh endpoint.
# ------------------------------------------------------------------------------
@app.post("/api/users/{user_id}/settings", tags=["settings"])
async def update_settings(
    payload: SettingsUpdateRequest,
    user_id: int = Path(..., ge=1),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    setting = (
        await db.execute(select(Setting).where(Setting.owner_id == user_id))
    ).scalars().first()

    # VULNERABLE: no check that user_id == current_user.id. The write happens for
    # whatever {user_id} was requested.
    if setting is not None:
        setting.notifications = payload.notifications
        await db.flush()

    # Opaque, constant response — byte-identical to the SAFE endpoint below.
    return {"status": "ok"}


@app.get("/api/users/{user_id}/settings", response_model=SettingsResponse, tags=["settings"])
async def read_settings(
    user_id: int = Path(..., ge=1),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    setting = (
        await db.execute(select(Setting).where(Setting.owner_id == user_id))
    ).scalars().first()
    if setting is None:
        raise HTTPException(status_code=404, detail="Settings not found")
    return SettingsResponse(user_id=user_id, notifications=setting.notifications)


# ------------------------------------------------------------------------------
# SAFE CONTROL — a hard trap that LOOKS exactly like Vuln B/D but is NOT vulnerable.
#
# POST /api/users/{user_id}/avatar returns the SAME opaque 200 {"status":"ok"} as
# the vulnerable endpoints, so a single-shot oracle sees something identical to a
# real silent BOLA. BUT the backend DOES enforce ownership: if {user_id} != the
# authenticated caller's id, the write is SILENTLY IGNORED (no change is made) and
# it STILL returns 200 {"status":"ok"} — it deliberately does NOT return 403. That
# missing 403 is what makes this a hard trap: only a write-then-read check reveals
# the value was NOT changed by a cross-user attempt. Correct verdict: NOT vulnerable.
# ------------------------------------------------------------------------------
@app.post("/api/users/{user_id}/avatar", tags=["avatar"])
async def update_avatar(
    payload: AvatarUpdateRequest,
    user_id: int = Path(..., ge=1),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    # SECURE: ownership IS enforced. Only the owner's own avatar is ever written.
    if user_id == current_user.id:
        avatar = (
            await db.execute(select(Avatar).where(Avatar.owner_id == user_id))
        ).scalars().first()
        if avatar is not None:
            avatar.avatar_url = payload.avatar_url
            await db.flush()
    # Cross-user attempt falls through with NO write — but the response is the
    # SAME opaque 200 {"status":"ok"}, never a 403. That is the trap.
    return {"status": "ok"}


@app.get("/api/users/{user_id}/avatar", response_model=AvatarResponse, tags=["avatar"])
async def read_avatar(
    user_id: int = Path(..., ge=1),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    avatar = (
        await db.execute(select(Avatar).where(Avatar.owner_id == user_id))
    ).scalars().first()
    if avatar is None:
        raise HTTPException(status_code=404, detail="Avatar not found")
    return AvatarResponse(user_id=user_id, avatar_url=avatar.avatar_url)


# ------------------------------------------------------------------------------
# T-REAL — STRONG-SIGNAL IDOR (baseline real vuln).
#
# GET /api/invoices/{invoice_id} returns an invoice with NO ownership check, so
# Alice can read Bob's invoice. Bob's invoice body is clearly larger/different
# from Alice's, so even a single-shot size/diff oracle catches it. Planted: REAL.
# ------------------------------------------------------------------------------
@app.get("/api/invoices/{invoice_id}", response_model=InvoiceResponse, tags=["invoices"])
async def get_invoice(
    invoice_id: int = Path(..., ge=1),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    inv = (
        await db.execute(select(Invoice).where(Invoice.id == invoice_id))
    ).scalars().first()
    if inv is None:
        raise HTTPException(status_code=404, detail="Invoice not found")

    # VULNERABLE: no ownership check. Should require inv.owner_id == current_user.id.
    return InvoiceResponse(
        invoice_id=inv.id, owner_id=inv.owner_id,
        number=inv.number, amount=inv.amount, details=inv.details,
    )


# ------------------------------------------------------------------------------
# T-TRAP — SOFT-200 DENIAL (false-positive killer).
#
# GET /api/documents/{document_id}: a cross-user read is DENIED, but with the
# common bad pattern of HTTP 200 + {"error":"forbidden"} instead of a 403. The
# confidential content is NEVER disclosed to a non-owner. Planted: SECURE — the
# only "bug" is the misleading status code; there is no data exposure. A correct
# verifier must read the body, not just the status line, and conclude NOT vuln.
# ------------------------------------------------------------------------------
@app.get("/api/documents/{document_id}", tags=["documents"])
async def get_document(
    document_id: int = Path(..., ge=1),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    doc = (
        await db.execute(select(Document).where(Document.id == document_id))
    ).scalars().first()
    if doc is None:
        raise HTTPException(status_code=404, detail="Document not found")

    # SECURE: ownership IS enforced. A non-owner is denied — but with a soft 200
    # error body (bad practice) rather than a 403. No content is leaked.
    if doc.owner_id != current_user.id:
        return {"error": "forbidden"}

    return {"document_id": doc.id, "owner_id": doc.owner_id,
            "title": doc.title, "content": doc.content}


# ------------------------------------------------------------------------------
# T-WEAK — WEAK-SIGNAL IDOR (probes verifier sensitivity).
#
# GET /api/notes/{note_id} returns a note with NO ownership check, so Alice CAN
# read Bob's note (a REAL cross-user access). But every user's note is the same
# length/shape (only the last word differs), so the size/diff signal is faint.
# Planted: REAL (but subtle).
# ------------------------------------------------------------------------------
@app.get("/api/notes/{note_id}", response_model=NoteResponse, tags=["notes"])
async def get_note(
    note_id: int = Path(..., ge=1),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    note = (
        await db.execute(select(Note).where(Note.id == note_id))
    ).scalars().first()
    if note is None:
        raise HTTPException(status_code=404, detail="Note not found")

    # VULNERABLE: no ownership check. The cross-user read succeeds; the bodies are
    # nearly identical, so the differential signal is intentionally faint.
    return NoteResponse(note_id=note.id, owner_id=note.owner_id, text=note.text)


# ------------------------------------------------------------------------------
# T-SILENT2 — SILENT BOLA (theme family; probes write-then-read necessity).
#
# POST /api/users/{user_id}/theme updates a UI theme with NO ownership check
# (REAL silent BOLA, same family as Vuln D), returning an opaque 200 {"status":
# "ok"}. The cross-user write is ONLY observable via GET /api/users/{user_id}/theme.
# Planted: REAL.
# ------------------------------------------------------------------------------
@app.post("/api/users/{user_id}/theme", tags=["theme"])
async def update_theme(
    payload: ThemeUpdateRequest,
    user_id: int = Path(..., ge=1),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    theme = (
        await db.execute(select(Theme).where(Theme.owner_id == user_id))
    ).scalars().first()

    # VULNERABLE: no check that user_id == current_user.id.
    if theme is not None:
        theme.theme = payload.theme
        await db.flush()

    return {"status": "ok"}


@app.get("/api/users/{user_id}/theme", response_model=ThemeResponse, tags=["theme"])
async def read_theme(
    user_id: int = Path(..., ge=1),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    theme = (
        await db.execute(select(Theme).where(Theme.owner_id == user_id))
    ).scalars().first()
    if theme is None:
        raise HTTPException(status_code=404, detail="Theme not found")
    return ThemeResponse(user_id=user_id, theme=theme.theme)


@app.get("/", tags=["meta"])
async def root():
    return {
        "service": "Vulnerable Test Target",
        "warning": "Deliberately insecure. Localhost practice target only.",
        "endpoints": [
            "POST /login",
            "GET /api/orders/{order_id}         (Vuln A: blatant BOLA)",
            "POST /api/users/{user_id}/profile  (Vuln B: silent BOLA)",
            "GET /api/users/{user_id}/profile   (read-back oracle for Vuln B)",
            "GET /api/admin/users               (Vuln C: vertical priv-esc)",
            "POST /api/users/{user_id}/settings (Vuln D: silent BOLA regression)",
            "GET /api/users/{user_id}/settings  (read-back oracle for Vuln D)",
            "POST /api/users/{user_id}/avatar   (SAFE control: secured look-alike)",
            "GET /api/users/{user_id}/avatar    (read-back oracle for SAFE control)",
            "GET /api/invoices/{invoice_id}     (T-REAL: strong-signal IDOR)",
            "GET /api/documents/{document_id}   (T-TRAP: soft-200 denial, SECURE)",
            "GET /api/notes/{note_id}           (T-WEAK: weak-signal IDOR)",
            "POST /api/users/{user_id}/theme    (T-SILENT2: silent BOLA)",
            "GET /api/users/{user_id}/theme     (read-back oracle for T-SILENT2)",
        ],
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("vulnerable_target.main:app", host="127.0.0.1", port=8001, reload=False)
