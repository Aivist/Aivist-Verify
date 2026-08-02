# ==============================================================================
# Commercial-Grade AI Penetration Testing & Vulnerability Audit Platform
# Server Bootstrap Runner (Development & Production Entrypoint)
# ==============================================================================

import sys
import asyncio

# Critical Windows Platform Patch:
# On Windows, asyncio.create_subprocess_exec requires WindowsProactorEventLoopPolicy
# to spawn subprocess transports safely and avoid NotImplementedError.
if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

import uvicorn
import logging
from backend.app.core.config import settings

logger = logging.getLogger("app.run")

if __name__ == "__main__":
    logger.info(
        f"[STARTING SERVER] Launching FastAPI ASGI runner on port: {settings.API_PORT} "
        f"with hot-reload enabled."
    )
    
    # Run uvicorn programmatically.
    # Both host and port are read dynamically from Pydantic Settings (no hardcoding).
    #
    # SECURITY NOTE (N5 + D2 — deferred): API_HOST defaults to "127.0.0.1"
    # (loopback), so the server is reachable only from this machine — the safe
    # default, because there is NO authentication yet (D2). Set API_HOST=0.0.0.0
    # to expose it on ALL interfaces for authorized remote testing, and only on a
    # trusted network, never via public port-forwarding, and stop the server when
    # you are done.
    uvicorn.run(
        "backend.app.main:app",
        host=settings.API_HOST,
        port=settings.API_PORT,
        reload=True,
        log_level=settings.LOG_LEVEL.lower()
    )
