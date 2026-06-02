"""TUI data models."""

from datetime import datetime
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field


class ToolStatus(str, Enum):
    """Tool execution status."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"
    SKIPPED = "skipped"


class SeverityFilter(str, Enum):
    """Severity filter options for TUI."""

    ALL = "all"
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class PhaseFilter(str, Enum):
    """Phase filter options for TUI."""

    ALL = "all"
    RECON = "recon"
    DISCOVERY = "discovery"
    VULN_SCAN = "vuln-scan"
    VALIDATION = "validation"
    REPORTING = "reporting"


class FindingDisplay(BaseModel):
    """Display model for a finding in the TUI."""

    id: str
    tool: str
    severity: str
    title: str
    description: str
    url: Optional[str] = None
    phase_found: str
    timestamp: str
    cve: Optional[str] = None
    cwe: Optional[str] = None


class ScanDisplay(BaseModel):
    """Display model for a scan in the TUI."""

    scan_id: str
    target: str
    phase: str
    profile: str
    started_at: str
    findings_count: int = 0
    tool_status: dict[str, str] = Field(default_factory=dict)
    status_message: str = "idle"

    @property
    def phase_emoji(self) -> str:
        """Get emoji for phase."""
        emojis = {
            "idle": "⏸",
            "recon": "🔍",
            "discovery": "🕵️",
            "vuln-scan": "⚠️",
            "validation": "✅",
            "reporting": "📋",
            "complete": "✅",
            "aborted": "🛑",
        }
        return emojis.get(self.phase, "❓")


class TUIState(BaseModel):
    """Global TUI state model."""

    scans: List[ScanDisplay] = Field(default_factory=list)
    selected_scan_id: Optional[str] = None
    refresh_interval: int = 2  # seconds
    severity_filter: SeverityFilter = SeverityFilter.ALL
    phase_filter: PhaseFilter = PhaseFilter.ALL
    auto_refresh: bool = True
    last_refresh: Optional[datetime] = None

    def get_selected_scan(self) -> Optional[ScanDisplay]:
        """Get the currently selected scan."""
        if not self.selected_scan_id:
            return None
        for scan in self.scans:
            if scan.scan_id == self.selected_scan_id:
                return scan
        return None

    def filtered_findings(
        self,
        findings: List[FindingDisplay],
    ) -> List[FindingDisplay]:
        """Apply severity and phase filters to findings."""
        result = findings
        if self.severity_filter != SeverityFilter.ALL:
            result = [f for f in result if f.severity == self.severity_filter.value]
        if self.phase_filter != PhaseFilter.ALL:
            result = [f for f in result if f.phase_found == self.phase_filter.value]
        return result
