# ==============================================================================
# Commercial-Grade AI Penetration Testing & Vulnerability Audit Platform
# Application Core Bootstrap Layer (with Lifespan Database Auto-Initialization)
# ==============================================================================

import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Core Config, Database, Routing, and Model imports
from backend.app.core.config import settings
from backend.app.core.database import engine, Base
from backend.app.api.v1.scan import router as scan_router_v1
from backend.app.api.v1.hunter import router as hunter_router_v1
from backend.app.services.proxy_pipeline import get_writer_service, get_ingest_pipeline
from backend.app.services.proxy_manager import get_proxy_manager

# Import models to register ORM structures within Base metadata prior to engine.run_sync
from backend.app.models.scan import ScanTask, VulnerabilityFinding, FuzzingRecord

# 1. Initialize structured logging diagnostics
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
    format="[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("app.main")


def _verify_schema_integrity(sync_conn) -> None:
    """
    D1 guard — detect schema drift instead of failing deep inside an INSERT.

    ``create_all`` creates missing *tables* but never ALTERs existing ones, so
    an older DB file can be missing columns added to the ORM later (this already
    bit Step D). We diff each ORM table's expected columns against the live
    ``PRAGMA table_info`` and raise a clear, actionable error at startup if any
    expected column is absent. This does NOT auto-migrate (no Alembic yet).
    """
    from sqlalchemy import inspect as sa_inspect

    inspector = sa_inspect(sync_conn)
    drift: dict[str, list[str]] = {}
    for table_name, table in Base.metadata.tables.items():
        if not inspector.has_table(table_name):
            drift[table_name] = ["<entire table missing>"]
            continue
        existing_cols = {col["name"] for col in inspector.get_columns(table_name)}
        expected_cols = {col.name for col in table.columns}
        missing = sorted(expected_cols - existing_cols)
        if missing:
            drift[table_name] = missing

    if drift:
        details = "; ".join(f"{t} -> missing {cols}" for t, cols in drift.items())
        raise RuntimeError(
            "Database schema drift detected (D1: no migrations). The existing "
            f"database is missing columns the ORM now expects: {details}. Because "
            "this project uses create_all (which never ALTERs existing tables), "
            "either delete the SQLite DB file and restart to recreate it, or apply "
            "a migration. Refusing to start with a broken schema."
        )


# 2. Modern FastAPI Lifespan Handler for Startup/Shutdown Events
# Enforces automated database table synchronization, preventing 'no such table' errors on first launch.
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("[LIFESPAN STARTUP] Synchronizing async database schema tables...")
    try:
        # Asynchronous table creation mapping directly onto target aiosqlite context
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
            # D1: fail fast with a clear message on schema drift (missing columns)
            await conn.run_sync(_verify_schema_integrity)
        logger.info("[LIFESPAN STARTUP] Async database ORM schema sync completed successfully.")
    except Exception as e:
        logger.critical(f"[LIFESPAN STARTUP FAILURE] Database schema initialization/verification failed: {e}")
        raise e

    # Step 9: bring up the app-wide single SQLite writer + proxy ingest pipeline.
    # The writer is the SOLE DB writer (fuzzing records + captured flows funnel
    # through it). The ingest pipeline idles until the radar is started.
    await get_writer_service().start()
    await get_ingest_pipeline().start()
    logger.info("[LIFESPAN STARTUP] Unified writer service + proxy ingest pipeline online.")

    yield  # Hand over control to FastAPI execution loop

    logger.info("[LIFESPAN SHUTDOWN] Application environment teardown complete. Releasing core resources.")
    # Order matters: kill the proxy subprocess first (no new flows), then drain
    # the ingest pipeline, then drain the writer, then release the DB engine.
    await get_proxy_manager().shutdown()
    await get_ingest_pipeline().stop()
    await get_writer_service().stop()
    # Safe release of database async engine pool on hot-reload/shutdown
    await engine.dispose()
    logger.info("[LIFESPAN SHUTDOWN] Async database connection pools released.")


# Application metadata constants (single source of truth)
_APP_TITLE = "AI-Powered Automated Penetration Testing Platform"
_APP_VERSION = "1.0.0"

# 3. Instantiate Enterprise FastAPI Application with Lifespan
app = FastAPI(
    title=_APP_TITLE,
    description="Commercial-grade vulnerability audit and AI orchestration backend engine.",
    version=_APP_VERSION,
    docs_url="/api/docs",      # Custom documentation endpoints
    redoc_url="/api/redoc",
    lifespan=lifespan          # Register the startup/shutdown database orchestrator
)


# 4. Dynamic CORS (Cross-Origin Resource Sharing) Security Settings
origins_list = []
if settings.CORS_ALLOWED_ORIGINS:
    origins_list = [origin.strip() for origin in settings.CORS_ALLOWED_ORIGINS.split(",") if origin.strip()]

# Security & Development support: Append 'null' to CORS list to allow local file:// double-click previews
if "null" not in origins_list:
    origins_list.append("null")

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins_list,
    allow_credentials=True,
    allow_methods=["*"],  # Restrict to safe method mappings in hardened productions
    allow_headers=["*"],
)

logger.info(f"[BOOTSTRAP] CORS Middleware successfully registered. Allowed Origins: {origins_list}")


# 5. RESTful Route Registrations
# Namespacing routes cleanly under '/api/v1' to support API version control
#
# SECURITY NOTE (D2 — authentication DEFERRED, tracked in docs/TECH_DEBT.md):
# None of these routes are authenticated yet. Anyone who can reach the bound
# host:port can launch scans and active fuzzing against arbitrary targets.
# This is acceptable ONLY for local / trusted-network use (the current usage:
# share the dashboard URL with a teammate while the server runs, then stop it).
# Add an API key / local token here before any shared or hosted deployment.
app.include_router(scan_router_v1, prefix="/api/v1")
app.include_router(hunter_router_v1, prefix="/api/v1")

logger.info("[BOOTSTRAP] API v1 routes (scan + hunter) successfully mapped and active.")


@app.get("/", tags=["Diagnostic Systems"])
async def root_health_check():
    """
    Standard heartbeat checking endpoint for API gateways and microservice orchestrators.
    """
    return {
        "status": "online",
        "service": _APP_TITLE,
        "version": _APP_VERSION,
        "diagnostics": {
            "nuclei_configured_path": settings.NUCLEI_BINARY_PATH,
            "database_url_configured": settings.DATABASE_URL,
            "logging_level": settings.LOG_LEVEL
        }
    }
