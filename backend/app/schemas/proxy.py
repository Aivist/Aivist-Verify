# ==============================================================================
# Commercial-Grade AI Penetration Testing & Vulnerability Audit Platform
# Module: Pydantic Contracts — Step 9 Passive Traffic Ingestion Proxy Radar
# ==============================================================================

from typing import Optional, Dict, List
from pydantic import BaseModel, Field


# ------------------------------------------------------------------------------
# IPC contract: mitmdump radar addon  ->  POST /hunter/proxy/internal-ingest
# ------------------------------------------------------------------------------
class ProxyTier1(BaseModel):
    """Verdicts the addon already computed inline (Tier-1, <5ms, on hook)."""
    in_scope: bool = True
    is_static: bool = False


class ProxyIngestRequestPart(BaseModel):
    headers: Dict[str, str] = Field(default_factory=dict)
    query_params: Dict[str, str] = Field(default_factory=dict)
    body: Optional[str] = None
    body_truncated: bool = False


class ProxyIngestResponsePart(BaseModel):
    status_code: Optional[int] = None
    headers: Dict[str, str] = Field(default_factory=dict)
    body: Optional[str] = None
    body_truncated: bool = False
    elapsed_ms: Optional[float] = None


class ProxyIngestFlow(BaseModel):
    """One intercepted exchange shipped from the addon's separate interpreter."""
    schema_version: int = 1
    flow_id: str = Field(..., max_length=64)
    captured_at: Optional[str] = None
    scheme: str = "http"
    method: str = "GET"
    host: str = Field(..., max_length=255)
    port: Optional[int] = None
    path: str = Field(default="/", max_length=4096)
    tier1: ProxyTier1 = Field(default_factory=ProxyTier1)
    request: ProxyIngestRequestPart = Field(default_factory=ProxyIngestRequestPart)
    response: ProxyIngestResponsePart = Field(default_factory=ProxyIngestResponsePart)


# ------------------------------------------------------------------------------
# Control plane: start / stop / status
# ------------------------------------------------------------------------------
class ProxyStartRequest(BaseModel):
    """
    Operator-supplied radar configuration. ``scope`` is the approved host/domain
    allow-list enforced inline by Tier-1; an empty list means "no host filter"
    (every flow is treated as in-scope). ``listen_port`` overrides the configured
    default for this run.
    """
    scope: List[str] = Field(default_factory=list)
    listen_port: Optional[int] = None


class ProxyControlResponse(BaseModel):
    state: str
    listen_port: int
    pid: Optional[int] = None
    scope: List[str] = Field(default_factory=list)
    message: str


class ProxyStatusResponse(BaseModel):
    state: str
    pid: Optional[int] = None
    listen_port: Optional[int] = None
    uptime_seconds: Optional[float] = None
    dropped_flows: int = 0
    sse_clients: int = 0
    queue_depth: int = 0
    scope: List[str] = Field(default_factory=list)
    ca_cert_available: bool = False
    message: Optional[str] = None


# ------------------------------------------------------------------------------
# Read / stream projection (list endpoint + SSE 'flow' event payload)
# ------------------------------------------------------------------------------
class ProxyFlowProjection(BaseModel):
    id: str
    flow_id: Optional[str] = None
    captured_at: Optional[str] = None
    method: str
    host: str
    path: str
    url: str
    response_status: Optional[int] = None
    exposure_score: Optional[float] = None
    is_login_candidate: bool = False
    in_scope: bool = True
    promoted_finding_id: Optional[int] = None
