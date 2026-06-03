# ==============================================================================
# Commercial-Grade AI Penetration Testing & Vulnerability Audit Platform
# Module: Step 9 Proxy Radar — Unified Writer Service, SSE Hub, Ingest Pipeline
#
# This module hosts the three long-lived, app-wide async primitives that back
# the Passive Traffic Ingestion Proxy Radar:
#
#   1. WriterService    — the SOLE SQLite writer for the whole app (generalized
#                         from the Step 8 single-writer consumer). Both captured
#                         proxy flows AND fuzzing records funnel through it, so
#                         there is never more than one concurrent SQLite writer.
#   2. SSEHub           — fan-out registry for Server-Sent-Events radar clients
#                         with bounded per-client queues + disconnect cleanup.
#   3. ProxyIngestPipeline — bounded ingest queue (backpressure) + Tier-2 async
#                         scoring (reuses pruner.calculate_exposure_score) that
#                         runs OFF the browser's connection path.
#
# All three are started in the FastAPI lifespan and stopped on shutdown.
# ==============================================================================

import asyncio
import logging
import datetime
from typing import Awaitable, Callable, Dict, List, Optional, Set, Any

from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.config import settings
from backend.app.core.database import async_session_factory
from backend.app.models.scan import CapturedFlow
from backend.app.services.pruner import calculate_exposure_score, detect_login_candidate

logger = logging.getLogger("app.services.proxy_pipeline")

# A write job: a callable that performs session.add(...) (NO commit — the writer
# owns commit cadence). Kept model-agnostic so this module never imports the
# fuzzer (avoids a circular dependency; the fuzzer imports US).
WriteJob = Callable[[AsyncSession], None]

_SENTINEL = object()

# Writer batching: commit every N rows or every T seconds of idleness so the
# polling UI / SSE stream see steady progress without per-row commit overhead.
_WRITER_BATCH_SIZE = 50
_WRITER_FLUSH_INTERVAL = 0.5


async def commit_with_retry(db: AsyncSession, attempts: int = 5, base_delay: float = 0.1) -> None:
    """
    Commit with bounded exponential backoff on transient 'database is locked'.
    WAL + busy_timeout handle most contention; this is the last line of defense.
    """
    for i in range(attempts):
        try:
            await db.commit()
            return
        except OperationalError as e:
            if "locked" in str(e).lower() and i < attempts - 1:
                await asyncio.sleep(base_delay * (2 ** i))
                continue
            await db.rollback()
            raise
        except Exception:
            await db.rollback()
            raise


# ==============================================================================
# 1. WriterService — the single app-wide SQLite writer
# ==============================================================================
class WriterService:
    """
    Owns the ONLY long-lived write AsyncSession for the application. Producers
    submit `WriteJob` callables; this one coroutine applies and batch-commits
    them. Because exactly one coroutine ever touches the session, there is no
    AsyncSession misuse and no competing SQLite writer — network/compute layers
    parallelize while writes stay serialized.
    """

    def __init__(self) -> None:
        self._queue: "Optional[asyncio.Queue]" = None
        self._task: "Optional[asyncio.Task]" = None
        self._running: bool = False

    @property
    def is_running(self) -> bool:
        return self._running and self._task is not None and not self._task.done()

    async def start(self) -> None:
        if self.is_running:
            return
        self._queue = asyncio.Queue()
        self._running = True
        self._task = asyncio.create_task(self._run(), name="writer-service")
        logger.info("[WRITER] Unified writer service started.")

    async def stop(self) -> None:
        if not self._running or self._queue is None:
            return
        await self._queue.put(_SENTINEL)
        try:
            await asyncio.wait_for(self._task, timeout=30)
        except asyncio.TimeoutError:
            logger.error("[WRITER] Writer did not drain in time; cancelling.")
            self._task.cancel()
        finally:
            self._running = False
            logger.info("[WRITER] Unified writer service stopped.")

    async def submit(self, job: WriteJob) -> None:
        """Enqueue a write job. No-op-safe even if called before start()."""
        if self._queue is None:
            raise RuntimeError("WriterService.submit called before start().")
        await self._queue.put(job)

    async def _run(self) -> None:
        async with async_session_factory() as db:
            pending = 0
            while True:
                try:
                    job = await asyncio.wait_for(self._queue.get(), timeout=_WRITER_FLUSH_INTERVAL)
                except asyncio.TimeoutError:
                    if pending:
                        await commit_with_retry(db)
                        pending = 0
                    continue
                try:
                    if job is _SENTINEL:
                        if pending:
                            await commit_with_retry(db)
                        return
                    job(db)
                    pending += 1
                    if pending >= _WRITER_BATCH_SIZE:
                        await commit_with_retry(db)
                        pending = 0
                except Exception:
                    logger.exception("[WRITER] Failed to apply/commit a write job")
                finally:
                    self._queue.task_done()


# ==============================================================================
# 2. SSEHub — bounded fan-out to radar stream clients
# ==============================================================================
class SSEHub:
    """
    Registry of connected SSE clients. Each client gets its OWN bounded queue;
    producers fan an event out to every queue. On overflow we drop the oldest
    event for that client (radar is latest-wins) so a slow browser tab can never
    grow memory without bound. Disconnect cleanup is the caller's responsibility
    via `unregister` in the route generator's finally block.
    """

    def __init__(self) -> None:
        self._clients: "Set[asyncio.Queue]" = set()

    @property
    def client_count(self) -> int:
        return len(self._clients)

    def at_capacity(self) -> bool:
        return len(self._clients) >= settings.PROXY_SSE_MAX_CLIENTS

    def register(self) -> "asyncio.Queue":
        q: "asyncio.Queue" = asyncio.Queue(maxsize=settings.PROXY_SSE_CLIENT_QUEUE_MAX)
        self._clients.add(q)
        return q

    def unregister(self, q: "asyncio.Queue") -> None:
        self._clients.discard(q)

    def publish(self, event: Dict[str, Any]) -> None:
        """Non-blocking fan-out; drops oldest on a full client queue."""
        for q in list(self._clients):
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                try:
                    q.get_nowait()       # evict oldest
                    q.put_nowait(event)
                except Exception:
                    pass


# ==============================================================================
# 3. ProxyIngestPipeline — bounded queue + Tier-2 async enrichment
# ==============================================================================
class ProxyIngestPipeline:
    """
    Receives validated flow dicts from the internal-ingest endpoint, applies
    backpressure via a bounded queue, then (off the browser path) computes the
    Tier-2 exposure score, builds a CapturedFlow, hands persistence to the
    WriterService, and publishes a lightweight projection to the SSE hub.
    """

    def __init__(self, writer: WriterService, hub: SSEHub) -> None:
        self._writer = writer
        self._hub = hub
        self._queue: "Optional[asyncio.Queue]" = None
        self._task: "Optional[asyncio.Task]" = None
        self._running = False
        self.dropped_flows = 0

    @property
    def is_running(self) -> bool:
        return self._running and self._task is not None and not self._task.done()

    @property
    def queue_depth(self) -> int:
        return self._queue.qsize() if self._queue is not None else 0

    async def start(self) -> None:
        if self.is_running:
            return
        self._queue = asyncio.Queue(maxsize=settings.PROXY_INGEST_QUEUE_MAX)
        self._running = True
        self._task = asyncio.create_task(self._run(), name="proxy-ingest")
        logger.info("[PROXY-INGEST] Ingest pipeline started.")

    async def stop(self) -> None:
        if not self._running or self._queue is None:
            return
        await self._queue.put(_SENTINEL)
        try:
            await asyncio.wait_for(self._task, timeout=10)
        except asyncio.TimeoutError:
            self._task.cancel()
        finally:
            self._running = False
            logger.info("[PROXY-INGEST] Ingest pipeline stopped.")

    def enqueue(self, flow: Dict[str, Any]) -> bool:
        """
        Non-blocking enqueue. Returns False (→ caller responds 503) when the
        queue is full so the addon applies local backpressure.
        """
        if self._queue is None:
            return False
        try:
            self._queue.put_nowait(flow)
            return True
        except asyncio.QueueFull:
            self.dropped_flows += 1
            return False

    async def _run(self) -> None:
        while True:
            item = await self._queue.get()
            try:
                if item is _SENTINEL:
                    return
                await self._handle(item)
            except Exception:
                logger.exception("[PROXY-INGEST] Failed to process a captured flow")
            finally:
                self._queue.task_done()

    async def _handle(self, flow: Dict[str, Any]) -> None:
        req = flow.get("request", {}) or {}
        resp = flow.get("response", {}) or {}
        method = (flow.get("method") or "GET").upper()
        scheme = flow.get("scheme") or "http"
        host = flow.get("host") or ""
        port = flow.get("port")
        path = flow.get("path") or "/"
        query_params = req.get("query_params", {}) or {}
        req_body = req.get("body")
        cap = settings.PROXY_BODY_CAP

        # Tier-2 (server-side, off browser path): heuristic exposure score.
        parsed_request = {
            "method": method,
            "path": path,
            "query_params": query_params,
            "headers": req.get("headers", {}) or {},
            "body": req_body,
        }
        try:
            exposure = calculate_exposure_score(parsed_request)
        except Exception:
            exposure = None
        is_login = detect_login_candidate(method, path, req_body)
        in_scope = bool((flow.get("tier1") or {}).get("in_scope", True))

        # Build a denormalized URL for display / re-issue.
        netloc = host
        if port and port not in (80, 443):
            netloc = f"{host}:{port}"
        url = f"{scheme}://{netloc}{path}"

        row = CapturedFlow(
            flow_id=flow.get("flow_id"),
            captured_at=_parse_dt(flow.get("captured_at")),
            scheme=scheme,
            method=method,
            host=host,
            port=port,
            path=path[:4096],
            url=url[:4096],
            request_headers=req.get("headers", {}) or {},
            request_query=query_params,
            request_body=(req_body[:cap] if isinstance(req_body, str) else req_body),
            response_status=resp.get("status_code"),
            response_headers=resp.get("headers", {}) or {},
            response_body=(resp.get("body")[:cap] if isinstance(resp.get("body"), str) else resp.get("body")),
            elapsed_ms=resp.get("elapsed_ms"),
            exposure_score=exposure,
            is_login_candidate=is_login,
            in_scope=in_scope,
            source="proxy",
        )

        # Persist through the SINGLE app-wide writer (never a second writer).
        await self._writer.submit(lambda s, _row=row: s.add(_row))

        # Live fan-out to radar subscribers (projection only — no heavy bodies).
        self._hub.publish({
            "event": "flow",
            "data": {
                "id": row.id,
                "flow_id": row.flow_id,
                "captured_at": row.captured_at.isoformat() if row.captured_at else None,
                "method": method,
                "host": host,
                "path": path,
                "url": url,
                "response_status": row.response_status,
                "exposure_score": exposure,
                "is_login_candidate": is_login,
                "in_scope": in_scope,
            },
        })


def _parse_dt(value: Optional[str]) -> datetime.datetime:
    """Parse an ISO-8601 captured_at to naive-UTC; fall back to now()."""
    if value:
        try:
            dt = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
            if dt.tzinfo is not None:
                dt = dt.astimezone(datetime.timezone.utc).replace(tzinfo=None)
            return dt
        except (ValueError, TypeError):
            pass
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


# ==============================================================================
# Module-level singletons + accessors
# ==============================================================================
writer_service = WriterService()
sse_hub = SSEHub()
ingest_pipeline = ProxyIngestPipeline(writer_service, sse_hub)


def get_writer_service() -> WriterService:
    return writer_service


def is_writer_running() -> bool:
    """Used by the fuzzer to decide: submit to the shared writer vs spin an
    ephemeral per-batch writer (the latter preserves standalone test behavior)."""
    return writer_service.is_running


def get_sse_hub() -> SSEHub:
    return sse_hub


def get_ingest_pipeline() -> ProxyIngestPipeline:
    return ingest_pipeline
