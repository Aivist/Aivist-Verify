# ==============================================================================
# Commercial-Grade AI Penetration Testing & Vulnerability Audit Platform
# Module: Scan Database Tables Mapping (ORM Entities)
# ==============================================================================

import uuid
import datetime
from sqlalchemy import Column, String, Integer, Text, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from backend.app.core.database import Base

def generate_uuid() -> str:
    """Helper method to generate safe dynamic string representation UUIDs"""
    return str(uuid.uuid4())

class ScanTask(Base):
    """
    ScanTask stores structural properties of targeted scanning tasks.
    Coordinates overall progress status and serves as root key for vulnerability findings.
    """
    __tablename__ = "scan_tasks"

    id = Column(
        String(36),
        primary_key=True,
        default=generate_uuid
    )
    
    target_url = Column(
        String(1024),
        nullable=False
    )
    
    status = Column(
        String(32),
        nullable=False,
        default="pending"
    )
    
    cookie = Column(
        Text,
        nullable=True
    )
    
    created_at = Column(
        DateTime,
        nullable=False,
        default=datetime.datetime.utcnow
    )
    
    updated_at = Column(
        DateTime,
        nullable=False,
        default=datetime.datetime.utcnow,
        onupdate=datetime.datetime.utcnow
    )

    # Establishes cascading relationship to automatically drop findings if parent task is purged.
    findings = relationship(
        "VulnerabilityFinding",
        back_populates="task",
        cascade="all, delete-orphan",
        passive_deletes=True
    )


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
    
    # Step D: nullable so AI-Hunter findings (which have no parent Nuclei scan)
    # can live in the same table. Nuclei findings still set scan_id; Hunter
    # findings leave it NULL (and are therefore naturally excluded from the
    # scan-scoped GET /scan/{id}/findings query).
    scan_id = Column(
        String(36),
        ForeignKey("scan_tasks.id", ondelete="CASCADE"),
        nullable=True
    )

    # Step D: discriminator distinguishing the two producers of this row.
    # "nuclei" = template scanner finding; "hunter" = AI Logic Hunter analysis.
    source = Column(
        String(16),
        nullable=False,
        default="nuclei"
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
        default=datetime.datetime.utcnow
    )

    # Inverse relationship mapper pointing to the primary scan task controller
    task = relationship(
        "ScanTask",
        back_populates="findings"
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
        default=datetime.datetime.utcnow
    )

    # Inverse relationship mapper back to the parent finding
    finding = relationship(
        "VulnerabilityFinding",
        back_populates="fuzz_records"
    )
