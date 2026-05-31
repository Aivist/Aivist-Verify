# ==============================================================================
# Commercial-Grade AI Penetration Testing & Vulnerability Audit Platform
# Module: API Router Controller - Scan Services (Database Integration)
# ==============================================================================

import uuid
import logging
import datetime
from fastapi import APIRouter, BackgroundTasks, status, HTTPException, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.schemas.scan import ScanRequest, ScanResponse, ScanTaskState, FindingDetails
from backend.app.services.nuclei import execute_nuclei_scan_async
from backend.app.core.database import get_db
from backend.app.models.scan import ScanTask, VulnerabilityFinding
from sqlalchemy import select

# Create standard API router for vulnerability scan namespace
router = APIRouter(prefix="/scan", tags=["Vulnerability Scanner Control"])

# Initialize logging diagnostics
logger = logging.getLogger("app.api.v1.scan")

@router.post(
    "/start",
    response_model=ScanResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Trigger a non-blocking asynchronous vulnerability audit scan using Nuclei.",
    response_description="Returns a task tracking ID and initial queue status."
)
async def start_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db)
):
    """
    Penetration Test Execution Dispatcher (with Database Integration):
    
    1. Generates a robust tracking UUID (Scan ID) for request auditing.
    2. Persists the initial task context inside SQL Database (ScanTask) in the 'running' state.
    3. Enqueues the long-running Nuclei process onto FastAPI's worker event loop.
    4. Responds immediately to the client with HTTP Status 202 (Accepted) to guarantee UI responsiveness.
    
    All inputs undergo validation beforehand through Pydantic validators.
    """
    try:
        # Generate target UUID for secure state mapping
        scan_id = str(uuid.uuid4())
        
        # Cast HttpUrl to standard string for safe subprocess list consumption
        target_str = str(request.target_url)
        cookie_header = request.cookie
        
        logger.info(
            f"[API ROUTE] Received scan request for target: '{target_str}'. "
            f"Assigning Scan UUID: {scan_id}"
        )
        
        # 1. Persist the initial scan task in the database with the "running" state
        scan_task = ScanTask(
            id=scan_id,
            target_url=target_str,
            status="running",
            cookie=cookie_header,
            created_at=datetime.datetime.utcnow(),
            updated_at=datetime.datetime.utcnow()
        )
        db.add(scan_task)
        await db.commit()
        await db.refresh(scan_task)
        
        logger.info(f"[API ROUTE] Task row successfully persisted in DB. State: RUNNING. Scan ID: {scan_id}")

        # 2. Hand off the long-running security scan task to BackgroundTasks.
        # This prevents blocking the HTTP socket connection while scanning.
        background_tasks.add_task(
            execute_nuclei_scan_async,
            target_url=target_str,
            cookie=cookie_header,
            scan_id=scan_id
        )
        
        # Build strict RESTful JSON response payload
        return ScanResponse(
            scan_id=scan_id,
            status="started",
            message=f"Vulnerability scanner successfully initialized for target: '{target_str}' and database record persisted."
        )
        
    except Exception as e:
        logger.error(f"[API ROUTE ERROR] Failed to initialize scan dispatcher: {e}")
        # Make sure database transaction rolling back is handled (handled automatically by get_db if exception raised,
        # but here we raise HTTPException to the client)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Core database or scanner execution pipeline could not be initialized: {str(e)}"
        )

@router.get(
    "/{scan_id}",
    response_model=ScanTaskState,
    summary="Retrieve the current tracking status of a specific scan task."
)
async def get_scan_status(
    scan_id: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Scan Task Status Monitor:
    Queries the SQLite ScanTask table to fetch the real-time processing status of a scan ID.
    """
    try:
        result = await db.execute(select(ScanTask).where(ScanTask.id == scan_id))
        task = result.scalar_one_or_none()
        
        if not task:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Scan task with ID '{scan_id}' not found."
            )
            
        return ScanTaskState(
            scan_id=task.id,
            target_url=task.target_url,
            status=task.status,
            updated_at=task.updated_at.isoformat()
        )
    except HTTPException as he:
        raise he
    except Exception as e:
        logger.error(f"[API ROUTE ERROR] Failed retrieving scan status for ID {scan_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database inquiry failed: {str(e)}"
        )

@router.get(
    "/{scan_id}/findings",
    response_model=list[FindingDetails],
    summary="Retrieve all parsed vulnerability threat findings for a specific scan task."
)
async def get_scan_findings(
    scan_id: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Threat Finding Aggregator:
    Queries the SQLite VulnerabilityFinding table to fetch all target vulnerabilities,
    exploit payload traces, and high-remediation Gemini patches linked to a specific scan ID.
    """
    try:
        # First verify the parent task actually exists
        task_check = await db.execute(select(ScanTask).where(ScanTask.id == scan_id))
        if not task_check.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Scan task with ID '{scan_id}' not found."
            )

        # Retrieve findings matching scan_id
        result = await db.execute(
            select(VulnerabilityFinding)
            .where(VulnerabilityFinding.scan_id == scan_id)
            .order_by(VulnerabilityFinding.id)
        )
        findings = result.scalars().all()
        
        return [
            FindingDetails(
                id=f.id,
                scan_id=f.scan_id,
                source=f.source,
                template_id=f.template_id,
                severity=f.severity,
                matched_at=f.matched_at,
                poc_request=f.poc_request,
                poc_response=f.poc_response,
                ai_patch=f.ai_patch,
                created_at=f.created_at.isoformat()
            )
            for f in findings
        ]
    except HTTPException as he:
        raise he
    except Exception as e:
        logger.error(f"[API ROUTE ERROR] Failed retrieving scan findings for ID {scan_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database inquiry failed: {str(e)}"
        )

