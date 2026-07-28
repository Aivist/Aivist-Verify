# ==============================================================================
# Commercial-Grade AI Penetration Testing & Vulnerability Audit Platform
# Module: Scan Database Tables Mapping (ORM Entities)
# ==============================================================================

import uuid
import datetime
from sqlalchemy import Column, String, Integer, Text, DateTime, ForeignKey, JSON, Boolean, Float
from sqlalchemy.orm import relationship
from backend.app.core.database import Base

def generate_uuid() -> str:
    """Helper method to generate safe dynamic string representation UUIDs"""
    return str(uuid.uuid4())


def utcnow() -> datetime.datetime:
    """
    Naive UTC 'now' (D9).

    Replaces the deprecated stdlib ``datetime.utcnow()`` (slated for removal in
    a future Python) while preserving the EXACT prior behavior: a timezone-naive
    datetime expressed in UTC. The DateTime columns here are not declared with
    ``timezone=True``, so emitting naive values keeps SQLite storage and all
    existing comparisons identical (avoids offset-naive vs offset-aware errors).
    """
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)

class VulnerabilityFinding(Base):
    """
    VulnerabilityFinding captures parsed diagnostic vulnerability logs
    and stores high-reasoning code remediation responses returned from Google Gemini.
    """
    __tablename__ = "vulnerability_findings"

    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True
    )
    
    # Vestigial after the nuclei scan subsystem was removed: a plain nullable
    # column (no longer a ForeignKey to the dropped scan_tasks table). Hunter
    # findings leave it NULL; kept so existing DBs are undisturbed (create_all
    # never ALTERs, and there is no Alembic).
    scan_id = Column(
        String(36),
        nullable=True
    )

    # Producer discriminator. The only producer now is the AI Logic Hunter
    # (nuclei removed); Hunter always sets source="hunter" explicitly.
    source = Column(
        String(16),
        nullable=False,
        default="hunter"
    )

    template_id = Column(
        String(256),
        nullable=False
    )
    
    severity = Column(
        String(64),
        nullable=False
    )
    
    matched_at = Column(
        String(2048),
        nullable=False
    )
    
    poc_request = Column(
        Text,
        nullable=True
    )
    
    poc_response = Column(
        Text,
        nullable=True
    )
    
    ai_patch = Column(
        Text,
        nullable=True
    )

    # ----------------------------------------------------------------------
    # Step D: explicit, typed structured-data columns for the fuzzing engine.
    # These replace the legacy convention of embedding JSON inside the
    # ai_patch / poc_request text columns. The fuzzer reads these first and
    # only falls back to parsing the text columns for backward compatibility.
    # ----------------------------------------------------------------------
    parsed_request = Column(
        JSON,
        nullable=True
    )

    automation_payloads = Column(
        JSON,
        nullable=True
    )

    auth_refresh_request = Column(
        JSON,
        nullable=True
    )

    created_at = Column(
        DateTime,
        nullable=False,
        default=utcnow
    )

    # Forward relationship to FuzzingRecord for automated verification results
    fuzz_records = relationship(
        "FuzzingRecord",
        back_populates="finding",
        cascade="all, delete-orphan",
        passive_deletes=True
    )


class FuzzingRecord(Base):
    """
    FuzzingRecord captures each individual fuzz-test execution result:
    the mutated request sent, the raw response received, and the differential
    analysis verdict used to confirm or deny vulnerability exploitability.
    """
    __tablename__ = "fuzzing_records"

    id = Column(
        String(36),
        primary_key=True,
        default=generate_uuid
    )

    finding_id = Column(
        Integer,
        ForeignKey("vulnerability_findings.id", ondelete="CASCADE"),
        nullable=False
    )

    payload_index = Column(
        Integer,
        nullable=False,
        default=0
    )

    sent_request = Column(
        Text,
        nullable=True
    )

    received_response = Column(
        Text,
        nullable=True
    )

    verification_status = Column(
        String(32),
        nullable=False,
        default="untested"
    )

    diff_details = Column(
        JSON,
        nullable=True
    )

    created_at = Column(
        DateTime,
        nullable=False,
        default=utcnow
    )

    # Inverse relationship mapper back to the parent finding
    finding = relationship(
        "VulnerabilityFinding",
        back_populates="fuzz_records"
    )


class CapturedFlow(Base):
    """
    CapturedFlow — a single HTTP exchange intercepted by the Step 9 Passive
    Traffic Ingestion Proxy Radar.

    Rationale for a dedicated table (the three existing tables are insufficient):
      * ``vulnerability_findings`` models a *triaged finding* (severity,
        template_id, AI payloads) with NOT NULL semantics that don't fit raw
        traffic.
      * ``fuzzing_records`` is *verification output* bound to a finding_id.
      * Neither captures a live request/response pair with timing, scope, and
        the Tier-2 exposure score the radar needs.

    This is a brand-new table, so ``create_all`` provisions it cleanly and the
    D1 schema-drift guard never trips (it only fires on missing columns of
    pre-existing tables). No existing table is altered.

    ``promoted_finding_id`` is a deliberately decoupled, nullable back-reference
    (NOT a ForeignKey) recording that an operator pushed this flow into the
    Hunter pipeline via POST /hunter/findings — keeping capture and analysis
    loosely coupled and migration-free.
    """
    __tablename__ = "captured_flows"

    id = Column(
        String(36),
        primary_key=True,
        default=generate_uuid
    )

    # Addon-assigned correlation id for the originating mitmproxy flow.
    flow_id = Column(
        String(64),
        nullable=True
    )

    captured_at = Column(
        DateTime,
        nullable=False,
        default=utcnow
    )

    scheme = Column(String(8), nullable=False, default="http")
    method = Column(String(16), nullable=False, default="GET")
    host = Column(String(255), nullable=False)
    port = Column(Integer, nullable=True)
    path = Column(String(4096), nullable=False, default="/")
    # Fully-qualified URL kept denormalized for convenient display / re-issue.
    url = Column(String(4096), nullable=False)

    request_headers = Column(JSON, nullable=True)
    request_query = Column(JSON, nullable=True)
    request_body = Column(Text, nullable=True)

    response_status = Column(Integer, nullable=True)
    response_headers = Column(JSON, nullable=True)
    response_body = Column(Text, nullable=True)
    elapsed_ms = Column(Float, nullable=True)

    # Tier-2 (async, server-side) heuristic exposure score from the pruner.
    exposure_score = Column(Float, nullable=True)

    # Deterministic login/identity-endpoint hint (powers Identity Anchor pre-fill).
    is_login_candidate = Column(Boolean, nullable=False, default=False)

    # Tier-1 scope verdict: out-of-scope flows are captured-but-inert.
    in_scope = Column(Boolean, nullable=False, default=True)

    source = Column(String(16), nullable=False, default="proxy")

    # One-way, decoupled link set when the flow is promoted into a finding.
    promoted_finding_id = Column(Integer, nullable=True)
