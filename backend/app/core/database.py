# ==============================================================================
# Commercial-Grade AI Penetration Testing & Vulnerability Audit Platform
# Module: Asynchronous Database Core Adapter
# ==============================================================================

import logging
from typing import AsyncGenerator
from sqlalchemy import event
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import declarative_base
from backend.app.core.config import settings

logger = logging.getLogger("app.core.database")

# 1. Instantiating the high-performance asynchronous SQLAlchemy engine
# Enables clean dynamic URL loading, preventing hardcoded path parameters.
# In production, SQLite's check_same_thread should be disabled to prevent thread cross-overs.
connect_args = {}
if settings.DATABASE_URL.startswith("sqlite"):
    connect_args["check_same_thread"] = False

# Spawn async engine
engine = create_async_engine(
    settings.DATABASE_URL,
    connect_args=connect_args,
    echo=False,  # Set to True only when debugging SQL query performance
    future=True
)


# ------------------------------------------------------------------------------
# Step 8 · SQLite concurrency hardening
# ------------------------------------------------------------------------------
# The parallel fuzzing engine uses a Single-Writer Consumer: one coroutine owns
# the only write session, while UI polling reads via separate connections.
#
# WAL (Write-Ahead Logging) lets those reads proceed WITHOUT being blocked by the
# in-flight writer (default DELETE journaling would lock the whole DB file).
# busy_timeout gives any connection up to 5s to wait out a transient lock instead
# of failing instantly with "database is locked".
if settings.DATABASE_URL.startswith("sqlite"):

    @event.listens_for(engine.sync_engine, "connect")
    def _set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA busy_timeout=5000")
            cursor.execute("PRAGMA synchronous=NORMAL")
        finally:
            cursor.close()

# 2. Configure highly resilient Async Session factory
# expire_on_commit is set to False to prevent session context drop out during active background logs ingestion.
async_session_factory = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False
)

# 3. Establish base declarative standard for all entity mappings
Base = declarative_base()

# 4. Dependency Injection Provider (Generative context broker)
# Safely yields sessions within FastAPI routes and ensures clean context releases.
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Asynchronous database session injector.
    Yields an active database session for transaction processing, guarantees automatic 
    release and resource cleanup at the end of the generator cycle.
    """
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception as e:
            logger.error(f"[DB ACCESS TRANSACTION ERROR] Rolling back session due to: {e}")
            await session.rollback()
            raise e
        finally:
            await session.close()
