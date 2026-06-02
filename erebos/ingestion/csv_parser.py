"""Generic CSV findings parser.

Expected format: url,vuln_type,severity,description

VT-Spec R8: Generic CSV format support.
VT-Spec INJ-01: All fields sanitized at parse time.
"""

from __future__ import annotations

import csv
import io
import logging
from typing import Dict, List, Optional

from erebos.core.finding import (
    Finding,
    FindingEvidence,
    Phase,
    Severity,
)
from erebos.ingestion.base import (
    MAX_DESCRIPTION_LENGTH,
    MAX_EVIDENCE_LENGTH,
    MAX_TITLE_LENGTH,
    FindingsParser,
    sanitize_text,
)

logger = logging.getLogger(__name__)

# Severity string mapping (case-insensitive)
_SEVERITY_MAP: Dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
}


class CSVParser(FindingsParser):
    """Parser for generic CSV format: url,vuln_type,severity,description."""

    @property
    def format_name(self) -> str:
        return "csv"

    def detect(self, content: bytes) -> bool:
        """Detect CSV by checking for expected header row."""
        try:
            text = content[:1024].decode("utf-8", errors="ignore")
            first_line = text.split("\n")[0].lower().strip()
            # Check for expected columns
            return (
                "url" in first_line
                and "severity" in first_line
                and ("vuln" in first_line or "type" in first_line or "description" in first_line)
            )
        except Exception:
            return False

    def parse(self, content: bytes) -> List[Finding]:
        """Parse CSV content into Finding objects.

        VT-Spec INJ-01: All text fields sanitized before creating Findings.
        """
        findings: List[Finding] = []

        try:
            text = content.decode("utf-8", errors="replace")
        except Exception as e:
            logger.warning("Failed to decode CSV content: %s", e)
            return []

        reader = csv.DictReader(io.StringIO(text))

        for row in reader:
            finding = self._parse_row(row)
            if finding:
                findings.append(finding)

        return findings

    def _parse_row(self, row: Dict[str, Optional[str]]) -> Optional[Finding]:
        """Parse a single CSV row into a Finding."""
        # Normalize column names (case-insensitive)
        normalized: Dict[str, str] = {}
        for key, value in row.items():
            if key is not None:
                normalized[key.lower().strip()] = (value or "").strip()

        url = normalized.get("url", "") or normalized.get("target", "")
        vuln_type = (
            normalized.get("vuln_type", "")
            or normalized.get("type", "")
            or normalized.get("vulnerability", "")
        )
        severity_str = normalized.get("severity", "medium").lower()
        description = normalized.get("description", "") or normalized.get("details", "")

        severity = _SEVERITY_MAP.get(severity_str, Severity.MEDIUM)

        if not vuln_type and not description:
            return None

        title = vuln_type if vuln_type else "CSV Finding"

        # VT-Spec INJ-01: Sanitize all fields at parse time
        title = sanitize_text(title, MAX_TITLE_LENGTH)
        description = sanitize_text(description, MAX_DESCRIPTION_LENGTH)
        target = sanitize_text(url, MAX_EVIDENCE_LENGTH) if url else None

        evidence = FindingEvidence(
            url=target,
        )

        return Finding(
            tool="csv-import",
            severity=severity,
            title=title,
            description=description,
            target=target,
            evidence=evidence,
            phase_found=Phase.VULN_SCAN,
        )
