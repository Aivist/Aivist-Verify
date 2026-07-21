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
#   * X-CROSS    — cross-path BOLA        : POST /api/users/{user_id}/display-name (REAL; confirm via GET /api/audit-log, NO same-path GET)
#   * X-SAFE     — cross-path SAFE control: POST /api/users/{user_id}/nickname     (SECURE; cross-user write dropped, no audit row)
#   * X-SILENT-VULN — silent write, confirm via cross-path STATE read (M1.2(A)):
#                 POST /api/users/{user_id}/gizmo    (REAL; opaque 200, NO same-path GET; state at GET /api/gizmos/{id})
#   * X-SILENT-SAFE — secure mirror of X-SILENT-VULN (M1.2(A)):
#                 POST /api/users/{user_id}/sprocket (SECURE; cross-user write dropped; state at GET /api/sprockets/{id})
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
    identity = relationship("Identity", back_populates="owner", uselist=False)
    statement = relationship("Statement", back_populates="owner", uselist=False)
    ledger = relationship("Ledger", back_populates="owner", uselist=False)
    gizmo = relationship("Gizmo", back_populates="owner", uselist=False)
    sprocket = relationship("Sprocket", back_populates="owner", uselist=False)
    relic = relationship("Relic", back_populates="owner", uselist=False)
    badge = relationship("Badge", back_populates="owner", uselist=False)
    seal = relationship("Seal", back_populates="owner", uselist=False)
    membership = relationship("Membership", back_populates="owner", uselist=False)
    subscription = relationship("Subscription", back_populates="owner", uselist=False)


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


class Identity(Base):
    """Identity holds two writable fields behind the D18 Phase-2 CROSS-PATH cases:
    display_name (X-CROSS, REAL) and nickname (X-SAFE, SECURE control). There is
    deliberately NO same-path GET for either field — the ONLY way to observe whether
    a write landed is the cross-path GET /api/audit-log on a DIFFERENT path."""
    __tablename__ = "identities"

    id = Column(Integer, primary_key=True, autoincrement=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    display_name = Column(String(128), nullable=False)
    nickname = Column(String(128), nullable=False)

    owner = relationship("User", back_populates="identity")


class AuditEvent(Base):
    """Append-only audit log. A row is appended ONLY when a write actually lands; a
    silently-dropped (secure) cross-user write appends nothing. The presence or
    absence of a row here is the cross-path ground truth for X-CROSS / X-SAFE."""
    __tablename__ = "audit_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    event = Column(String(64), nullable=False)
    user_id = Column(Integer, nullable=False)
    new_value = Column(String(256), nullable=False)


class Statement(Base):
    """Object behind X-EQUIV-VULN (read-type semantic-equivalence BOLA). The SAME
    statement object is reachable two ways: an owner-scoped canonical path
    (GET /api/users/{user_id}/statement) AND a flat resource path
    (GET /api/statements/{statement_id}). The flat path has NO ownership check — that
    is the bug. Bodies are shaped EQUAL-LENGTH across users (fixed-width uuid + fixed
    period/status; only id/owner_id identity content differs) so the size/diff oracle
    cannot decide and leaves it `suspicious` for the AI to judge by semantics."""
    __tablename__ = "statements"

    id = Column(Integer, primary_key=True)  # == owner_id for predictability
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    account_ref = Column(String(36), nullable=False)  # UUID, always 36 chars
    period = Column(String(16), nullable=False, default="2026-Q1")
    status = Column(String(8), nullable=False, default="OPEN")

    owner = relationship("User", back_populates="statement")


class Ledger(Base):
    """Object behind X-EQUIV-SAFE (SECURE control, mirror of Statement). Same two-path
    shape (GET /api/users/{user_id}/ledger and GET /api/ledgers/{ledger_id}) but BOTH
    paths enforce ownership. A cross-user read is refused with an EQUAL-LENGTH soft-200
    (owner_id 0, status DENY, a zero-uuid) — never a 403, never the victim's data — so
    it also lands `suspicious`; the AI must see through the look-alike and NOT verify."""
    __tablename__ = "ledgers"

    id = Column(Integer, primary_key=True)  # == owner_id for predictability
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    account_ref = Column(String(36), nullable=False)
    period = Column(String(16), nullable=False, default="2026-Q1")
    status = Column(String(8), nullable=False, default="OPEN")

    owner = relationship("User", back_populates="ledger")


class Gizmo(Base):
    """Object behind X-SILENT-VULN (M1.2(A)): silent cross-path WRITE confirmed by the
    object's OWN STATE read on a DIFFERENT path. The write POST /api/users/{id}/gizmo has
    NO ownership check (REAL) and returns the SAME opaque 200 {"status":"ok"} as the secure
    mirror; there is deliberately NO same-path GET. The only observation point is the
    cross-path state read GET /api/gizmos/{gizmo_id}, which returns owner_id + the written
    `code` — so whether the cross-user write LANDED is visible only in that state, never in
    the write response. id seeded == owner_id (so /api/gizmos/2 is Bob's)."""
    __tablename__ = "gizmos"

    id = Column(Integer, primary_key=True)  # == owner_id for predictability
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    code = Column(String(128), nullable=False, default="")

    owner = relationship("User", back_populates="gizmo")


class Sprocket(Base):
    """Object behind X-SILENT-SAFE (M1.2(A)): the SECURE mirror of Gizmo. POST
    /api/users/{id}/sprocket returns the SAME opaque 200 {"status":"ok"} but ownership IS
    enforced — a cross-user write is SILENTLY DROPPED (no change, no error, still 200,
    never a 403). Like Gizmo there is NO same-path GET; the cross-path state read
    GET /api/sprockets/{sprocket_id} exposes owner_id + `code`, so a write-then-read shows
    the value UNCHANGED for a cross-user attempt. Correct verdict: NOT vulnerable — a
    `verified` here is a FALSE POSITIVE. id seeded == owner_id."""
    __tablename__ = "sprockets"

    id = Column(Integer, primary_key=True)  # == owner_id for predictability
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    code = Column(String(128), nullable=False, default="")

    owner = relationship("User", back_populates="sprocket")


class Relic(Base):
    """Object behind X-DELETE-VULN-HARD (M1.3): a HARD-delete BOLA. DELETE
    /api/users/{id}/relic has NO ownership check (REAL) and PHYSICALLY removes the row, but
    returns the SAME opaque 200 {"status":"ok"} as the secure mirror. There is NO same-path
    GET; the cross-path state read GET /api/relics/{relic_id} returns the object while it
    exists and 404 once it is gone. Confirmation is a from-EXISTS-to-ABSENT jump. id == owner_id."""
    __tablename__ = "relics"

    id = Column(Integer, primary_key=True)  # == owner_id for predictability
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    label = Column(String(128), nullable=False, default="")

    owner = relationship("User", back_populates="relic")


class Badge(Base):
    """Object behind X-DELETE-VULN-SOFT (M1.3): a SOFT-delete BOLA. DELETE
    /api/users/{id}/badge has NO ownership check (REAL) but instead of removing the row it
    flips a `status` lifecycle field active -> revoked, still returning the SAME opaque 200.
    The cross-path state read GET /api/badges/{badge_id} stays 200 but its `status` shows the
    deletion — exercising the LOGICAL (soft) track of the negative assertion. id == owner_id."""
    __tablename__ = "badges"

    id = Column(Integer, primary_key=True)  # == owner_id for predictability
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    status = Column(String(32), nullable=False, default="active")
    label = Column(String(128), nullable=False, default="")

    owner = relationship("User", back_populates="badge")


class Seal(Base):
    """Object behind X-DELETE-SAFE (M1.3): the SECURE mirror of Relic. DELETE
    /api/users/{id}/seal returns the SAME opaque 200 {"status":"ok"} but ownership IS enforced
    — a cross-user delete is SILENTLY DROPPED (the row is NOT removed). Like Relic there is NO
    same-path GET; the cross-path state read GET /api/seals/{seal_id} still returns the object
    UNCHANGED after a cross-user attempt. Correct verdict: NOT vulnerable — a `verified` here is
    a FALSE POSITIVE. id == owner_id."""
    __tablename__ = "seals"

    id = Column(Integer, primary_key=True)  # == owner_id for predictability
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    label = Column(String(128), nullable=False, default="")

    owner = relationship("User", back_populates="seal")


class Membership(Base):
    """Object behind X-MASS-VULN (M1.4): MASS-ASSIGNMENT BOLA. PATCH /api/users/{id}/membership
    has NO ownership check AND binds EVERY writable column present in the request body — including
    `role`, which a caller must never be able to set. `plan` is the legitimate, user-settable field.
    `role` is nullable: when NULL the state read OMITS it, modelling a privileged field HIDDEN from
    a non-privileged caller (the MISSING original state). id == owner_id."""
    __tablename__ = "memberships"

    id = Column(Integer, primary_key=True)  # == owner_id for predictability
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    plan = Column(String(64), nullable=False, default="basic")
    role = Column(String(32), nullable=True)   # privileged; NULL => hidden from the state read

    owner = relationship("User", back_populates="membership")


class Subscription(Base):
    """Object behind X-MASS-SAFE (M1.4): the SECURE mirror of Membership. Same shape, same opaque
    response, but the write binds an explicit ALLOW-LIST (`plan` only) and silently STRIPS `role` —
    the real-world fix for mass assignment. A `verified` here is a FALSE POSITIVE. id == owner_id."""
    __tablename__ = "subscriptions"

    id = Column(Integer, primary_key=True)  # == owner_id for predictability
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    plan = Column(String(64), nullable=False, default="basic")
    role = Column(String(32), nullable=True)

    owner = relationship("User", back_populates="subscription")


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
        # D18 Phase 2: identity behind X-CROSS (display-name) + X-SAFE (nickname).
        "identity": {"display_name": "alice_dn", "nickname": "alice_nick"},
        # M1.1: statement (X-EQUIV-VULN) + ledger (X-EQUIV-SAFE). Fixed-width uuid.
        "statement": {"account_ref": "11111111-1111-1111-1111-111111111111"},
        "ledger": {"account_ref": "11111111-1111-1111-1111-1111111111aa"},
        # M1.2(A): gizmo (X-SILENT-VULN) + sprocket (X-SILENT-SAFE). Seeded `code`.
        "gizmo": {"code": "gizmo_alice_v0"},
        "sprocket": {"code": "sprocket_alice_v0"},
        # M1.3: relic (X-DELETE-VULN-HARD) + badge (X-DELETE-VULN-SOFT) + seal (X-DELETE-SAFE).
        "relic": {"label": "relic_alice"},
        "badge": {"label": "badge_alice"},
        "seal": {"label": "seal_alice"},
        # M1.4: membership (X-MASS-VULN) + subscription (X-MASS-SAFE).
        "membership": {"plan": "basic", "role": "member"},
        "subscription": {"plan": "basic", "role": "member"},
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
        "identity": {"display_name": "bob_dn", "nickname": "bob_nick"},
        "statement": {"account_ref": "22222222-2222-2222-2222-222222222222"},
        "ledger": {"account_ref": "22222222-2222-2222-2222-2222222222bb"},
        "gizmo": {"code": "gizmo_bob_v0"},
        "sprocket": {"code": "sprocket_bob_v0"},
        "relic": {"label": "relic_bob"},
        "badge": {"label": "badge_bob"},
        "seal": {"label": "seal_bob"},
        "membership": {"plan": "basic", "role": "member"},
        "subscription": {"plan": "basic", "role": "member"},
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
        "identity": {"display_name": "carol_dn", "nickname": "carol_nick"},
        "statement": {"account_ref": "33333333-3333-3333-3333-333333333333"},
        "ledger": {"account_ref": "33333333-3333-3333-3333-3333333333cc"},
        "gizmo": {"code": "gizmo_carol_v0"},
        "sprocket": {"code": "sprocket_carol_v0"},
        "relic": {"label": "relic_carol"},
        "badge": {"label": "badge_carol"},
        "seal": {"label": "seal_carol"},
        "membership": {"plan": "basic", "role": None},
        "subscription": {"plan": "basic", "role": None},
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
        session.add(Identity(owner_id=u["id"], **u["identity"]))
        session.add(Statement(id=u["id"], owner_id=u["id"], **u["statement"]))
        session.add(Ledger(id=u["id"], owner_id=u["id"], **u["ledger"]))
        session.add(Gizmo(id=u["id"], owner_id=u["id"], **u["gizmo"]))
        session.add(Sprocket(id=u["id"], owner_id=u["id"], **u["sprocket"]))
        session.add(Relic(id=u["id"], owner_id=u["id"], **u["relic"]))
        session.add(Badge(id=u["id"], owner_id=u["id"], **u["badge"]))
        session.add(Seal(id=u["id"], owner_id=u["id"], **u["seal"]))
        session.add(Membership(id=u["id"], owner_id=u["id"], **u["membership"]))
        session.add(Subscription(id=u["id"], owner_id=u["id"], **u["subscription"]))
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


class DisplayNameUpdateRequest(BaseModel):
    display_name: str = Field(..., min_length=1, max_length=128)


class NicknameUpdateRequest(BaseModel):
    nickname: str = Field(..., min_length=1, max_length=128)


class GizmoUpdateRequest(BaseModel):
    code: str = Field(..., min_length=1, max_length=128)


class GizmoResponse(BaseModel):
    id: int
    owner_id: int
    code: str


class SprocketUpdateRequest(BaseModel):
    code: str = Field(..., min_length=1, max_length=128)


class SprocketResponse(BaseModel):
    id: int
    owner_id: int
    code: str


class RelicResponse(BaseModel):
    id: int
    owner_id: int
    label: str


class BadgeResponse(BaseModel):
    id: int
    owner_id: int
    status: str
    label: str


class SealResponse(BaseModel):
    id: int
    owner_id: int
    label: str


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


# ------------------------------------------------------------------------------
# X-CROSS — REAL CROSS-PATH BOLA (display-name).
#
# POST /api/users/{user_id}/display-name updates the identity display name with NO
# ownership check (REAL vuln) and returns the SAME opaque 200 {"status":"ok"} as the
# other silent writes. CRITICAL: there is NO GET for display-name — the cross-user
# write is observable ONLY via the cross-path GET /api/audit-log (a DIFFERENT path),
# something a same-resource-GET placeholder could never synthesize. A landed write
# appends an audit row.
# ------------------------------------------------------------------------------
@app.post("/api/users/{user_id}/display-name", tags=["identity"])
async def update_display_name(
    payload: DisplayNameUpdateRequest,
    user_id: int = Path(..., ge=1),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    identity = (
        await db.execute(select(Identity).where(Identity.owner_id == user_id))
    ).scalars().first()

    # VULNERABLE: no check that user_id == current_user.id. The write lands for
    # whatever {user_id} was requested; a landed write appends an audit row.
    if identity is not None:
        identity.display_name = payload.display_name
        db.add(AuditEvent(
            event="display_name.update", user_id=user_id, new_value=payload.display_name
        ))
        await db.flush()

    # Opaque, constant response — gives nothing away about whose name changed.
    return {"status": "ok"}


# ------------------------------------------------------------------------------
# X-SAFE — SECURE CROSS-PATH control (nickname).
#
# POST /api/users/{user_id}/nickname returns the SAME opaque 200 {"status":"ok"} but
# ownership IS enforced: a cross-user write is SILENTLY DROPPED (no error, still 200)
# and appends NOTHING to the audit log; only an owner's write lands + audits. Like
# display-name, there is NO GET for nickname — confirmation is cross-path via the
# audit log. The missing 403 on a cross-user attempt is the trap. Correct verdict:
# NOT vulnerable.
# ------------------------------------------------------------------------------
@app.post("/api/users/{user_id}/nickname", tags=["identity"])
async def update_nickname(
    payload: NicknameUpdateRequest,
    user_id: int = Path(..., ge=1),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    # SECURE: ownership IS enforced. Only the owner's own nickname is ever written,
    # and only a landed write appends an audit row. A cross-user attempt falls
    # through with NO write and NO audit entry — but the SAME opaque 200 {"status":
    # "ok"}, never a 403.
    if user_id == current_user.id:
        identity = (
            await db.execute(select(Identity).where(Identity.owner_id == user_id))
        ).scalars().first()
        if identity is not None:
            identity.nickname = payload.nickname
            db.add(AuditEvent(
                event="nickname.update", user_id=user_id, new_value=payload.nickname
            ))
            await db.flush()

    return {"status": "ok"}


# ------------------------------------------------------------------------------
# Cross-path read-back. GET /api/audit-log returns the append-only audit trail (auth
# required; any authenticated user). This is the ONLY observation point for the
# display-name / nickname writes above — a DIFFERENT path from the write.
# ------------------------------------------------------------------------------
@app.get("/api/audit-log", tags=["audit"])
async def get_audit_log(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    rows = (
        await db.execute(select(AuditEvent).order_by(AuditEvent.id))
    ).scalars().all()
    return {"events": [
        {"id": e.id, "event": e.event, "user_id": e.user_id, "new_value": e.new_value}
        for e in rows
    ]}


# ------------------------------------------------------------------------------
# X-EQUIV-VULN — READ-TYPE SEMANTIC-EQUIVALENCE cross-path BOLA (M1.1).
#
# The SAME statement object is reachable two equivalent ways: an owner-scoped canonical
# path AND a flat resource path. The flat path (get_statement) has NO ownership check —
# so an authenticated user reads another user's statement. The response is shaped
# EQUAL-LENGTH across users (fixed-width uuid + fixed period/status; only id/owner_id
# identity differs), so a size/diff oracle cannot decide and leaves it `suspicious`; the
# AI must recognize from SEMANTIC content (owner_id) that the returned object is another
# user's. Planted: REAL. Decisive evidence = owner_id in the leaked body == the victim id.
# ------------------------------------------------------------------------------
_DENY_REF = "00000000-0000-0000-0000-000000000000"  # 36-char zero UUID (no victim data)


def _statement_body(st: "Statement") -> dict:
    return {"id": st.id, "owner_id": st.owner_id, "account_ref": st.account_ref,
            "period": st.period, "status": st.status}


@app.get("/api/users/{user_id}/statement", tags=["statements"])
async def read_user_statement(
    user_id: int = Path(..., ge=1),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    # SECURE canonical path: ownership enforced (equal-length soft-200 on cross-user).
    if user_id != current_user.id:
        return {"id": 0, "owner_id": 0, "account_ref": _DENY_REF, "period": "2026-Q1", "status": "DENY"}
    st = (await db.execute(select(Statement).where(Statement.owner_id == user_id))).scalars().first()
    if st is None:
        raise HTTPException(status_code=404, detail="Statement not found")
    return _statement_body(st)


@app.get("/api/statements/{statement_id}", tags=["statements"])
async def get_statement(
    statement_id: int = Path(..., ge=1),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    st = (await db.execute(select(Statement).where(Statement.id == statement_id))).scalars().first()
    if st is None:
        raise HTTPException(status_code=404, detail="Statement not found")
    # VULNERABLE: no ownership check. Returns the SAME object the canonical path guards.
    return _statement_body(st)


# ------------------------------------------------------------------------------
# X-EQUIV-SAFE — SECURE mirror of X-EQUIV-VULN (M1.1).
#
# Same two-path shape (canonical + flat) but BOTH paths enforce ownership. A cross-user
# read is refused with an EQUAL-LENGTH soft-200 that carries NO victim identity (id 0,
# owner_id 0, zero-uuid, status DENY) — never a 403, never the victim's data. It also
# lands `suspicious`; the AI must see through the look-alike and NOT verify. Planted:
# SECURE. A `verified` here is a FALSE POSITIVE.
# ------------------------------------------------------------------------------
def _ledger_body(led: "Ledger") -> dict:
    return {"id": led.id, "owner_id": led.owner_id, "account_ref": led.account_ref,
            "period": led.period, "status": led.status}


def _ledger_deny() -> dict:
    return {"id": 0, "owner_id": 0, "account_ref": _DENY_REF, "period": "2026-Q1", "status": "DENY"}


@app.get("/api/users/{user_id}/ledger", tags=["ledgers"])
async def read_user_ledger(
    user_id: int = Path(..., ge=1),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if user_id != current_user.id:
        return _ledger_deny()
    led = (await db.execute(select(Ledger).where(Ledger.owner_id == user_id))).scalars().first()
    if led is None:
        raise HTTPException(status_code=404, detail="Ledger not found")
    return _ledger_body(led)


@app.get("/api/ledgers/{ledger_id}", tags=["ledgers"])
async def get_ledger(
    ledger_id: int = Path(..., ge=1),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    led = (await db.execute(select(Ledger).where(Ledger.id == ledger_id))).scalars().first()
    if led is None:
        raise HTTPException(status_code=404, detail="Ledger not found")
    # SECURE: ownership enforced; cross-user -> equal-length soft-200 DENY (no victim data).
    if led.owner_id != current_user.id:
        return _ledger_deny()
    return _ledger_body(led)


# ------------------------------------------------------------------------------
# X-SILENT-VULN — SILENT cross-path WRITE, confirmed by the object's OWN STATE (M1.2(A)).
#
# POST /api/users/{user_id}/gizmo updates the gizmo `code` with NO ownership check (REAL
# vuln) and returns the SAME opaque 200 {"status":"ok"} as the secure mirror. There is NO
# same-path GET; the cross-user write is observable ONLY via the cross-path STATE read
# GET /api/gizmos/{gizmo_id}, which returns owner_id + the written code. A landed cross-user
# write shows up as the attacker's value in the victim's object state. Planted: REAL.
# ------------------------------------------------------------------------------
@app.post("/api/users/{user_id}/gizmo", tags=["gizmos"])
async def update_gizmo(
    payload: GizmoUpdateRequest,
    user_id: int = Path(..., ge=1),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    gizmo = (
        await db.execute(select(Gizmo).where(Gizmo.owner_id == user_id))
    ).scalars().first()

    # VULNERABLE: no check that user_id == current_user.id. The write lands for whatever
    # {user_id} was requested; only the cross-path STATE read reveals whose code changed.
    if gizmo is not None:
        gizmo.code = payload.code
        await db.flush()

    # Opaque, constant response — byte-identical to the SAFE sprocket endpoint below.
    return {"status": "ok"}


@app.get("/api/gizmos/{gizmo_id}", response_model=GizmoResponse, tags=["gizmos"])
async def get_gizmo(
    gizmo_id: int = Path(..., ge=1),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    # STATE read-back (the cross-path observation point). Authenticated; returns the object's
    # own state (owner_id + code) so a write-then-read can confirm whether the cross-user
    # write landed. Reads are permissive by design — this mirrors the avatar SAFE control's
    # permissive read-back; the property under test is the WRITE's ownership enforcement.
    gizmo = (
        await db.execute(select(Gizmo).where(Gizmo.id == gizmo_id))
    ).scalars().first()
    if gizmo is None:
        raise HTTPException(status_code=404, detail="Gizmo not found")
    return GizmoResponse(id=gizmo.id, owner_id=gizmo.owner_id, code=gizmo.code)


# ------------------------------------------------------------------------------
# X-SILENT-SAFE — SECURE mirror of X-SILENT-VULN (M1.2(A)).
#
# POST /api/users/{user_id}/sprocket returns the SAME opaque 200 {"status":"ok"} but
# ownership IS enforced: a cross-user write is SILENTLY DROPPED (no change, still 200, never
# a 403). Like the gizmo there is NO same-path GET; the cross-path STATE read
# GET /api/sprockets/{sprocket_id} shows the value UNCHANGED for a cross-user attempt.
# Correct verdict: NOT vulnerable — a `verified` here is a FALSE POSITIVE.
# ------------------------------------------------------------------------------
@app.post("/api/users/{user_id}/sprocket", tags=["sprockets"])
async def update_sprocket(
    payload: SprocketUpdateRequest,
    user_id: int = Path(..., ge=1),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    # SECURE: ownership IS enforced. Only the owner's own sprocket is ever written; a
    # cross-user attempt falls through with NO write — but the SAME opaque 200 {"status":
    # "ok"}, never a 403. That missing 403 is the trap.
    if user_id == current_user.id:
        sprocket = (
            await db.execute(select(Sprocket).where(Sprocket.owner_id == user_id))
        ).scalars().first()
        if sprocket is not None:
            sprocket.code = payload.code
            await db.flush()

    return {"status": "ok"}


@app.get("/api/sprockets/{sprocket_id}", response_model=SprocketResponse, tags=["sprockets"])
async def get_sprocket(
    sprocket_id: int = Path(..., ge=1),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    # STATE read-back (cross-path observation point), permissive like get_gizmo. For a
    # cross-user write attempt the dropped write means this returns the ORIGINAL code.
    sprocket = (
        await db.execute(select(Sprocket).where(Sprocket.id == sprocket_id))
    ).scalars().first()
    if sprocket is None:
        raise HTTPException(status_code=404, detail="Sprocket not found")
    return SprocketResponse(id=sprocket.id, owner_id=sprocket.owner_id, code=sprocket.code)


# ------------------------------------------------------------------------------
# X-DELETE-VULN-HARD — REAL delete BOLA, PHYSICAL delete (M1.3).
#
# DELETE /api/users/{user_id}/relic has NO ownership check (REAL) and removes the row, but
# returns the SAME opaque 200 {"status":"ok"} as the secure mirror. There is NO same-path GET;
# whether the cross-user delete landed is observable ONLY via the cross-path state read
# GET /api/relics/{relic_id}, which returns the object while it exists and 404 once it is gone.
# Confirmation is a from-EXISTS-to-ABSENT jump. Planted: REAL.
# ------------------------------------------------------------------------------
@app.delete("/api/users/{user_id}/relic", tags=["relics"])
async def delete_relic(
    user_id: int = Path(..., ge=1),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    relic = (
        await db.execute(select(Relic).where(Relic.owner_id == user_id))
    ).scalars().first()

    # VULNERABLE: no check that user_id == current_user.id. The delete lands for whatever
    # {user_id} was requested; only the cross-path STATE read reveals whose object vanished.
    if relic is not None:
        await db.delete(relic)      # HARD delete — the row is physically removed
        await db.flush()

    # Opaque, constant response — byte-identical to the SAFE seal endpoint below.
    return {"status": "ok"}


@app.get("/api/relics/{relic_id}", response_model=RelicResponse, tags=["relics"])
async def get_relic(
    relic_id: int = Path(..., ge=1),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    # STATE read-back (the cross-path observation point), permissive like the other state reads.
    # Returns 404 once the object has been (physically) deleted.
    relic = (
        await db.execute(select(Relic).where(Relic.id == relic_id))
    ).scalars().first()
    if relic is None:
        raise HTTPException(status_code=404, detail="Relic not found")
    return RelicResponse(id=relic.id, owner_id=relic.owner_id, label=relic.label)


# ------------------------------------------------------------------------------
# X-DELETE-VULN-SOFT — REAL delete BOLA, LOGICAL (soft) delete (M1.3).
#
# DELETE /api/users/{user_id}/badge has NO ownership check (REAL) but instead of removing the
# row it flips a `status` lifecycle field from "active" to "revoked", returning the SAME opaque
# 200 {"status":"ok"}. The cross-path state read GET /api/badges/{badge_id} stays 200 but its
# `status` shows the deletion — the LOGICAL track of the negative assertion. Planted: REAL.
# ------------------------------------------------------------------------------
@app.delete("/api/users/{user_id}/badge", tags=["badges"])
async def delete_badge(
    user_id: int = Path(..., ge=1),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    badge = (
        await db.execute(select(Badge).where(Badge.owner_id == user_id))
    ).scalars().first()

    # VULNERABLE: no ownership check. Soft-delete: flip the lifecycle field, keep the row.
    if badge is not None:
        badge.status = "revoked"
        await db.flush()

    return {"status": "ok"}


@app.get("/api/badges/{badge_id}", response_model=BadgeResponse, tags=["badges"])
async def get_badge(
    badge_id: int = Path(..., ge=1),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    badge = (
        await db.execute(select(Badge).where(Badge.id == badge_id))
    ).scalars().first()
    if badge is None:
        raise HTTPException(status_code=404, detail="Badge not found")
    return BadgeResponse(id=badge.id, owner_id=badge.owner_id, status=badge.status, label=badge.label)


# ------------------------------------------------------------------------------
# X-DELETE-SAFE — SECURE mirror of X-DELETE-VULN (M1.3).
#
# DELETE /api/users/{user_id}/seal returns the SAME opaque 200 {"status":"ok"} but ownership IS
# enforced: a cross-user delete is SILENTLY DROPPED (the row is NOT removed), never a 403. Like
# the relic there is NO same-path GET; the cross-path state read GET /api/seals/{seal_id} still
# returns the object UNCHANGED after a cross-user attempt. Correct verdict: NOT vulnerable — a
# `verified` here is a FALSE POSITIVE.
# ------------------------------------------------------------------------------
@app.delete("/api/users/{user_id}/seal", tags=["seals"])
async def delete_seal(
    user_id: int = Path(..., ge=1),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    # SECURE: ownership IS enforced. Only the owner's own seal is ever deleted; a cross-user
    # attempt falls through with NO delete — but the SAME opaque 200, never a 403.
    if user_id == current_user.id:
        seal = (
            await db.execute(select(Seal).where(Seal.owner_id == user_id))
        ).scalars().first()
        if seal is not None:
            await db.delete(seal)
            await db.flush()

    return {"status": "ok"}


@app.get("/api/seals/{seal_id}", response_model=SealResponse, tags=["seals"])
async def get_seal(
    seal_id: int = Path(..., ge=1),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    seal = (
        await db.execute(select(Seal).where(Seal.id == seal_id))
    ).scalars().first()
    if seal is None:
        raise HTTPException(status_code=404, detail="Seal not found")
    return SealResponse(id=seal.id, owner_id=seal.owner_id, label=seal.label)


# ------------------------------------------------------------------------------
# X-MASS-VULN — REAL mass-assignment BOLA (M1.4).
#
# PATCH /api/users/{user_id}/membership has NO ownership check AND binds EVERY writable column
# present in the request body. `plan` is the legitimate, user-settable field; `role` is privileged
# and must never be settable by a caller — but there is no allow-list, so it binds too. The
# response is the SAME opaque 200 {"status":"ok"} as the secure mirror, so the write alone cannot
# distinguish them; only the cross-path state read GET /api/memberships/{id} differs.
#
# The injected value is LOW-ENTROPY ("admin"), so "the field reads admin" proves nothing on its
# own — confirmation requires the field to have MOVED from its pre-attack state. Planted: REAL.
# ------------------------------------------------------------------------------
_MEMBERSHIP_COLUMNS = {"plan", "role"}     # every writable column — NO allow-list (that is the bug)


@app.patch("/api/users/{user_id}/membership", tags=["memberships"])
async def update_membership(
    payload: dict,
    user_id: int = Path(..., ge=1),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    membership = (
        await db.execute(select(Membership).where(Membership.owner_id == user_id))
    ).scalars().first()

    # VULNERABLE: no check that user_id == current_user.id, and every column named in the body is
    # bound — including the privileged `role`. This is the mass-assignment bug.
    if membership is not None:
        for _k, _v in (payload or {}).items():
            if _k in _MEMBERSHIP_COLUMNS and isinstance(_v, (str, int, float, bool)):
                setattr(membership, _k, str(_v))
        await db.flush()

    return {"status": "ok"}


@app.get("/api/memberships/{membership_id}", tags=["memberships"])
async def get_membership(
    membership_id: int = Path(..., ge=1),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    # STATE read-back (the cross-path observation point). `role` is OMITTED while NULL — modelling
    # a privileged field HIDDEN from a non-privileged caller, i.e. the MISSING original state.
    membership = (
        await db.execute(select(Membership).where(Membership.id == membership_id))
    ).scalars().first()
    if membership is None:
        raise HTTPException(status_code=404, detail="Membership not found")
    body = {"id": membership.id, "owner_id": membership.owner_id, "plan": membership.plan}
    if membership.role is not None:
        body["role"] = membership.role
    return body


# ------------------------------------------------------------------------------
# X-MASS-SAFE — SECURE mirror of X-MASS-VULN (M1.4).
#
# Identical shape and identical opaque 200 {"status":"ok"}, but the write binds an explicit
# ALLOW-LIST (`plan` only) and silently STRIPS `role` — the real-world fix for mass assignment.
# The cross-path state read shows `role` UNCHANGED (or still absent). Correct verdict: NOT
# vulnerable — a `verified` here is a FALSE POSITIVE.
# ------------------------------------------------------------------------------
_SUBSCRIPTION_ALLOWED = {"plan"}           # explicit allow-list; `role` is privileged -> stripped


@app.patch("/api/users/{user_id}/subscription", tags=["subscriptions"])
async def update_subscription(
    payload: dict,
    user_id: int = Path(..., ge=1),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    subscription = (
        await db.execute(select(Subscription).where(Subscription.owner_id == user_id))
    ).scalars().first()

    # SECURE against mass assignment: only allow-listed fields are bound. `role` in the body is
    # silently ignored — no error, no 403, the SAME opaque 200. That silence is the trap.
    if subscription is not None:
        for _k, _v in (payload or {}).items():
            if _k in _SUBSCRIPTION_ALLOWED and isinstance(_v, (str, int, float, bool)):
                setattr(subscription, _k, str(_v))
        await db.flush()

    return {"status": "ok"}


@app.get("/api/subscriptions/{subscription_id}", tags=["subscriptions"])
async def get_subscription(
    subscription_id: int = Path(..., ge=1),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    subscription = (
        await db.execute(select(Subscription).where(Subscription.id == subscription_id))
    ).scalars().first()
    if subscription is None:
        raise HTTPException(status_code=404, detail="Subscription not found")
    body = {"id": subscription.id, "owner_id": subscription.owner_id, "plan": subscription.plan}
    if subscription.role is not None:
        body["role"] = subscription.role
    return body


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
            "POST /api/users/{user_id}/display-name (X-CROSS: REAL cross-path BOLA)",
            "POST /api/users/{user_id}/nickname     (X-SAFE: SECURE cross-path control)",
            "GET /api/audit-log                 (cross-path read-back for display-name/nickname)",
            "POST /api/users/{user_id}/gizmo    (X-SILENT-VULN: silent write, cross-path STATE read)",
            "GET /api/gizmos/{gizmo_id}         (cross-path STATE read-back for gizmo)",
            "POST /api/users/{user_id}/sprocket (X-SILENT-SAFE: SECURE mirror)",
            "GET /api/sprockets/{sprocket_id}   (cross-path STATE read-back for sprocket)",
            "DELETE /api/users/{user_id}/relic  (X-DELETE-VULN-HARD: physical delete BOLA)",
            "GET /api/relics/{relic_id}         (cross-path STATE read-back for relic; 404 once gone)",
            "DELETE /api/users/{user_id}/badge  (X-DELETE-VULN-SOFT: soft delete BOLA, status flips)",
            "GET /api/badges/{badge_id}         (cross-path STATE read-back for badge)",
            "DELETE /api/users/{user_id}/seal   (X-DELETE-SAFE: SECURE mirror)",
            "GET /api/seals/{seal_id}           (cross-path STATE read-back for seal)",
            "PATCH /api/users/{user_id}/membership  (X-MASS-VULN: mass-assignment BOLA, binds `role`)",
            "GET /api/memberships/{membership_id}   (cross-path STATE read-back; `role` hidden while NULL)",
            "PATCH /api/users/{user_id}/subscription (X-MASS-SAFE: allow-list strips `role`)",
            "GET /api/subscriptions/{subscription_id} (cross-path STATE read-back for subscription)",
        ],
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("vulnerable_target.main:app", host="127.0.0.1", port=8001, reload=False)
