"""Dashboard data models."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field


class AgentStateView(str, Enum):
    """Agent state for dashboard display."""

    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class AgentStatusView(BaseModel):
    """Agent status for dashboard display."""

    role: str
    state: AgentStateView = AgentStateView.IDLE
    phase: Optional[str] = None
    findings_count: int = 0
    last_activity: Optional[datetime] = None


class SeverityCounts(BaseModel):
    """Finding counts by severity."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0

    @property
    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low + self.info


class ExploitationCounts(BaseModel):
    """Finding counts by exploitation status."""

    pending: int = 0
    exploited: int = 0
    potential: int = 0
    false_positive: int = 0
    skipped: int = 0


class ProgressView(BaseModel):
    """Scan progress for dashboard display."""

    current_phase: str = "idle"
    phases_completed: List[str] = Field(default_factory=list)
    total_phases: int = 7
    percentage: float = 0.0
    started_at: Optional[datetime] = None
    eta_seconds: Optional[int] = None


class FindingSummaryView(BaseModel):
    """Top finding for display."""

    id: str
    title: str
    severity: str
    target: Optional[str] = None
    cve: Optional[str] = None
    tool: str


class DashboardSnapshot(BaseModel):
    """Complete dashboard state snapshot."""

    scan_id: Optional[str] = None
    target: Optional[str] = None
    is_active: bool = False
    progress: ProgressView = Field(default_factory=ProgressView)
    severity_counts: SeverityCounts = Field(default_factory=SeverityCounts)
    exploitation_counts: ExploitationCounts = Field(default_factory=ExploitationCounts)
    agents: List[AgentStatusView] = Field(default_factory=list)
    top_findings: List[FindingSummaryView] = Field(default_factory=list)
    total_findings: int = 0
    last_updated: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class BusEvent(BaseModel):
    """A single event from the FindingsBus for live streaming."""

    timestamp: datetime
    role: str
    message_type: str
    summary: str
