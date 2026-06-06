"""Core data models for Erebos."""

from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator


class Severity(str, Enum):
    """Vulnerability severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Phase(str, Enum):
    """Pentest execution phases."""

    IDLE = "idle"
    RECON = "recon"
    DISCOVERY = "discovery"
    VULN_SCAN = "vuln-scan"
    VALIDATION = "validation"
    REPORTING = "reporting"
    COMPLETE = "complete"
    ABORTED = "aborted"


class ScanMode(str, Enum):
    """Scan mode affecting decision-engine behavior."""

    STEALTH = "stealth"
    NORMAL = "normal"
    AGGRESSIVE = "aggressive"


class FindingEvidence(BaseModel):
    """Evidence associated with a finding."""

    url: Optional[str] = None
    payload: Optional[str] = None
    output: Optional[str] = None
    http_banner: Optional[str] = None


class ExploitRef(BaseModel):
    """Reference to an ExploitDB exploit."""

    edb_id: str
    cve: Optional[str] = None
    description: Optional[str] = None
    file_path: Optional[str] = None
    author: Optional[str] = None
    platform: Optional[str] = None


class Finding(BaseModel):
    """Canonical finding model from security tools."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    tool: str
    severity: Severity
    title: str
    description: str
    target: Optional[str] = None
    evidence: FindingEvidence = Field(default_factory=FindingEvidence)
    # Legacy single-CVE field kept for backward compat; use cves for multiple
    cve: Optional[str] = None
    # New multi-CVE support
    cves: List[str] = Field(default_factory=list)
    # CVSS score 0.0-10.0
    cvss: Optional[float] = Field(default=None, ge=0.0, le=10.0)
    # ExploitDB references
    exploits: List[ExploitRef] = Field(default_factory=list)
    cwe: Optional[str] = None
    suggested_fix: Optional[str] = None
    validated_manually: bool = False
    degraded: bool = False
    fallback_source: Optional[str] = None
    phase_found: Phase
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    # Exploitation status tracking (shannon-pipeline-upgrade)
    exploitation_status: Optional[str] = None  # pending|exploited|potential|false_positive|skipped
    # Validation pipeline results (raptor-validation-pipeline)
    validation_stage: Optional[str] = None  # Last stage completed (A|B|C|D)
    validation_confidence: Optional[float] = None  # 0.0-1.0 confidence from pipeline
    validation_short_circuited: Optional[str] = None  # Stage that short-circuited (if FP)
    # SAST correlation
    correlated_sast: bool = False  # Whether DAST finding has SAST cross-validation
    correlation_score: Optional[float] = None  # 0.0-1.0 DAST↔SAST correlation

    @field_validator("cvss")
    @classmethod
    def cvss_in_range(cls, v: Optional[float]) -> Optional[float]:
        if v is not None and (v < 0.0 or v > 10.0):
            raise ValueError("cvss must be between 0.0 and 10.0")
        return v

    class Config:
        use_enum_values = True
