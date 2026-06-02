"""Domain models for Erebos control plane (REQ-001).

Defines the core entities for autonomous engagement management.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field
from ulid import ULID


def _ulid_str() -> str:
    """Generate a ULID string for use as default ID."""
    return str(ULID())


def _now_utc() -> datetime:
    """Return current UTC timestamp."""
    return datetime.now(timezone.utc)


# ─── Enums ──────────────────────────────────────────────────────────────────


class EngagementStatus(str, Enum):
    """Overall engagement lifecycle status."""

    CREATED = "created"
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    ABORTED = "aborted"


class EngagementPhase(str, Enum):
    """Phases of an autonomous engagement."""

    PLANNING = "planning"
    RECON = "recon"
    ENUMERATION = "enumeration"
    EXPLOITATION = "exploitation"
    POST_EXPLOIT = "post_exploit"
    REPORTING = "reporting"
    COMPLETED = "completed"
    ABORTED = "aborted"


class AccessLevel(str, Enum):
    """Access level achieved on a target."""

    NONE = "none"
    UNAUTHENTICATED = "unauthenticated"
    USER = "user"
    PRIVILEGED = "privileged"
    ROOT = "root"


class TargetType(str, Enum):
    """Type of engagement target."""

    HOST = "host"
    NETWORK = "network"
    WEB_APP = "web_app"
    API = "api"
    SERVICE = "service"


class ObservationType(str, Enum):
    """Type of observation made during engagement."""

    PORT_OPEN = "port_open"
    SERVICE_DETECTED = "service_detected"
    VULNERABILITY_FOUND = "vulnerability_found"
    CREDENTIAL_FOUND = "credential_found"
    ACCESS_GAINED = "access_gained"
    DATA_EXFIL = "data_exfil"
    ERROR = "error"


class HypothesisStatus(str, Enum):
    """Status of a hypothesis about a target."""

    PROPOSED = "proposed"
    TESTING = "testing"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"


class ActionType(str, Enum):
    """Type of action the agent can take."""

    SCAN = "scan"
    ENUMERATE = "enumerate"
    EXPLOIT = "exploit"
    PIVOT = "pivot"
    EXFILTRATE = "exfiltrate"
    PERSIST = "persist"
    CLEANUP = "cleanup"


class ImpactLevel(str, Enum):
    """Potential impact level of an action."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ActionStatus(str, Enum):
    """Status of a planned action."""

    PROPOSED = "proposed"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"
    ABORTED = "aborted"


class SessionStatus(str, Enum):
    """Status of an engagement session."""

    ACTIVE = "active"
    IDLE = "idle"
    TERMINATED = "terminated"


# ─── Models ─────────────────────────────────────────────────────────────────


class Target(BaseModel):
    """A target within an engagement."""

    id: str = Field(default_factory=_ulid_str)
    address: str
    target_type: TargetType = TargetType.HOST
    hostname: Optional[str] = None
    ports: List[int] = Field(default_factory=list)
    access_level: AccessLevel = AccessLevel.NONE
    notes: str = ""
    created_at: datetime = Field(default_factory=_now_utc)


class Observation(BaseModel):
    """An observation made during engagement."""

    id: str = Field(default_factory=_ulid_str)
    engagement_id: str
    target_id: Optional[str] = None
    observation_type: ObservationType
    data: Dict[str, Any] = Field(default_factory=dict)
    phase: EngagementPhase
    timestamp: datetime = Field(default_factory=_now_utc)


class Hypothesis(BaseModel):
    """A hypothesis about a target to test."""

    id: str = Field(default_factory=_ulid_str)
    engagement_id: str
    target_id: str
    description: str
    status: HypothesisStatus = HypothesisStatus.PROPOSED
    evidence: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=_now_utc)
    updated_at: datetime = Field(default_factory=_now_utc)


class PlannedAction(BaseModel):
    """An action planned by the agent."""

    id: str = Field(default_factory=_ulid_str)
    engagement_id: str
    target_id: str
    action_type: ActionType
    command: str
    description: str
    impact_level: ImpactLevel = ImpactLevel.LOW
    status: ActionStatus = ActionStatus.PROPOSED
    requires_approval: bool = False
    phase: EngagementPhase
    created_at: datetime = Field(default_factory=_now_utc)
    executed_at: Optional[datetime] = None


class PolicyDecision(BaseModel):
    """Result of policy evaluation for an action."""

    allowed: bool
    reason: str
    requires_approval: bool = False
    action_id: str
    policy_version: str = "1.0"
    evaluated_at: datetime = Field(default_factory=_now_utc)


class ExecutionArtifact(BaseModel):
    """Artifact produced by executing an action."""

    id: str = Field(default_factory=_ulid_str)
    action_id: str
    engagement_id: str
    output: str = ""
    exit_code: Optional[int] = None
    duration_seconds: float = 0.0
    created_at: datetime = Field(default_factory=_now_utc)


class RulesOfEngagement(BaseModel):
    """Rules of Engagement definition."""

    targets: List[str] = Field(default_factory=list)
    excluded: List[str] = Field(default_factory=list)
    techniques: List[str] = Field(default_factory=list)
    time_window: Optional[Dict[str, str]] = None
    emergency_contact: Optional[str] = None
    data_handling: str = "no_exfil"
    operator: str = "unknown"
    max_depth: int = 3
    allowed_action_classes: List[str] = Field(
        default_factory=lambda: ["scan", "enumerate"]
    )


class Session(BaseModel):
    """An engagement session tracking state."""

    id: str = Field(default_factory=_ulid_str)
    engagement_id: str
    status: SessionStatus = SessionStatus.ACTIVE
    started_at: datetime = Field(default_factory=_now_utc)
    ended_at: Optional[datetime] = None
    pid: Optional[int] = None
    tmux_session: Optional[str] = None


class Engagement(BaseModel):
    """Top-level engagement entity."""

    id: str = Field(default_factory=_ulid_str)
    name: str
    status: EngagementStatus = EngagementStatus.CREATED
    phase: EngagementPhase = EngagementPhase.PLANNING
    targets: List[Target] = Field(default_factory=list)
    roe: RulesOfEngagement = Field(default_factory=RulesOfEngagement)
    sessions: List[Session] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=_now_utc)
    updated_at: datetime = Field(default_factory=_now_utc)
    aborted_at: Optional[datetime] = None
    abort_reason: Optional[str] = None
