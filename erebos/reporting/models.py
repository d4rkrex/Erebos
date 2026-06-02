"""Report data models for Erebos professional reporting.

VT-Spec R6: Professional Reporting
VT-Spec INJ-03: Relative paths in report output by default.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional


class RiskLevel(str, Enum):
    """Overall risk level for executive summary."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ReportFormat(str, Enum):
    """Supported report output formats."""

    MARKDOWN = "md"
    HTML = "html"
    JSON = "json"
    PDF = "pdf"


@dataclass
class ReportConfig:
    """Configuration for report generation.

    VT-Spec INJ-03: Default to relative paths. Offer --redact-paths flag.
    """

    format: ReportFormat = ReportFormat.MARKDOWN
    output_dir: str = "./erebos-reports"
    # VT-Spec INJ-03: Default to relative paths in report output
    relative_paths: bool = True
    redact_paths: bool = False
    include_evidence: bool = True
    include_remediation: bool = True
    max_findings: int = 200


@dataclass
class RiskScore:
    """Numeric risk score with breakdown.

    Formula: min(100, critical*25 + high*10 + medium*3 + low*1)
    """

    score: int
    level: RiskLevel
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0

    @classmethod
    def calculate(
        cls,
        critical: int = 0,
        high: int = 0,
        medium: int = 0,
        low: int = 0,
        info: int = 0,
    ) -> "RiskScore":
        """Calculate risk score from severity counts."""
        score = min(100, critical * 25 + high * 10 + medium * 3 + low * 1)

        if critical > 0:
            level = RiskLevel.CRITICAL
        elif high > 0:
            level = RiskLevel.HIGH
        elif medium > 0:
            level = RiskLevel.MEDIUM
        elif low > 0:
            level = RiskLevel.LOW
        else:
            level = RiskLevel.INFO

        return cls(
            score=score,
            level=level,
            critical_count=critical,
            high_count=high,
            medium_count=medium,
            low_count=low,
            info_count=info,
        )


@dataclass
class ScanMetadata:
    """Metadata about the scan for reporting."""

    target: str
    scan_id: str
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    duration_seconds: float = 0.0
    agents_completed: int = 0
    agents_failed: int = 0
    endpoints_discovered: int = 0
    services_discovered: int = 0
    phases_completed: List[str] = field(default_factory=list)
    tool_version: str = "Erebos"


@dataclass
class ExecSummaryData:
    """Executive summary output data."""

    overall_risk: RiskLevel
    risk_score: RiskScore
    findings_by_severity: Dict[str, int]
    top_findings: List[str]
    attack_surface: Dict[str, int]
    exploitation_rate: float
    timeline: Dict[str, str]
    key_recommendations: List[str]


def sanitize_report_path(target: str) -> str:
    """Convert target URL to filesystem-safe filename.

    VT-Spec R7: Sanitize report filenames to remove characters invalid
    in filesystem paths (: / ? * etc).

    Examples:
        https://juice.labs.manuel-roldan.cloud → juice-labs-manuel-roldan-cloud
        http://192.168.1.1:8080/api → 192-168-1-1-8080-api
    """
    # Remove scheme
    name = re.sub(r"^https?://", "", target)
    # Replace unsafe chars with dash
    name = re.sub(r"[^a-zA-Z0-9._-]", "-", name)
    # Collapse multiple dashes
    name = re.sub(r"-+", "-", name)
    # Trim leading/trailing dashes and limit length
    return name.strip("-")[:100]


def make_paths_relative(path: str, base_path: str = "") -> str:
    """VT-Spec INJ-03: Convert absolute paths to relative.

    Strips common prefix from absolute paths to avoid information disclosure.
    """
    if not path:
        return path
    if not path.startswith("/"):
        return path
    if base_path and path.startswith(base_path):
        relative = path[len(base_path):]
        return relative.lstrip("/")
    # Fallback: strip to last 3 path components
    parts = path.split("/")
    if len(parts) > 3:
        return "/".join(parts[-3:])
    return path


class PathRedactor:
    """VT-Spec INJ-03: Redact paths with opaque identifiers.

    When --redact-paths is enabled, replaces file paths with
    [FILE-001], [FILE-002] etc.
    """

    def __init__(self) -> None:
        self._mapping: Dict[str, str] = {}
        self._counter: int = 0

    def redact(self, path: str) -> str:
        """Replace a path with an opaque identifier."""
        if path not in self._mapping:
            self._counter += 1
            self._mapping[path] = f"[FILE-{self._counter:03d}]"
        return self._mapping[path]

    @property
    def mapping(self) -> Dict[str, str]:
        """Return the path-to-identifier mapping (for appendix)."""
        return dict(self._mapping)
