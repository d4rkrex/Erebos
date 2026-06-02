"""Semgrep JSON output parser.

VT-Spec R8: Semgrep JSON format support.
VT-Spec INJ-01: All fields sanitized at parse time.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

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

# Semgrep severity mapping
_SEVERITY_MAP: Dict[str, Severity] = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}


class SemgrepParser(FindingsParser):
    """Parser for Semgrep JSON output format."""

    @property
    def format_name(self) -> str:
        return "semgrep"

    def detect(self, content: bytes) -> bool:
        """Detect Semgrep JSON by checking for 'results' key with check_id."""
        try:
            text = content[:4096].decode("utf-8", errors="ignore")
            return '"results"' in text and '"check_id"' in text
        except Exception:
            return False

    def parse(self, content: bytes) -> List[Finding]:
        """Parse Semgrep JSON output into Finding objects.

        VT-Spec INJ-01: All text fields sanitized before creating Findings.
        """
        try:
            data = json.loads(content)
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            logger.warning("Failed to parse Semgrep JSON: %s", e)
            return []

        findings: List[Finding] = []
        results = data.get("results", [])

        for result in results:
            finding = self._parse_result(result)
            if finding:
                findings.append(finding)

        return findings

    def _parse_result(self, result: Dict[str, Any]) -> Optional[Finding]:
        """Parse a single Semgrep result."""
        check_id = result.get("check_id", "unknown")
        severity_str = result.get("extra", {}).get("severity", "WARNING")
        severity = _SEVERITY_MAP.get(severity_str, Severity.MEDIUM)

        # Message
        message = result.get("extra", {}).get("message", "")

        # Location
        path = result.get("path", "")
        start = result.get("start", {})
        end = result.get("end", {})
        start_line = start.get("line", 0)
        end_line = end.get("line", 0)

        target = f"{path}:{start_line}" if path else None

        # Extract matched code snippet
        matched_lines = result.get("extra", {}).get("lines", "")

        # CWE from metadata
        metadata = result.get("extra", {}).get("metadata", {})
        cwe_list = metadata.get("cwe", [])
        cwe: Optional[str] = None
        if isinstance(cwe_list, list) and cwe_list:
            cwe = cwe_list[0] if isinstance(cwe_list[0], str) else None
        elif isinstance(cwe_list, str):
            cwe = cwe_list

        # VT-Spec INJ-01: Sanitize all fields at parse time
        title = sanitize_text(check_id, MAX_TITLE_LENGTH)
        description = sanitize_text(message, MAX_DESCRIPTION_LENGTH)

        evidence = FindingEvidence(
            url=sanitize_text(target, MAX_EVIDENCE_LENGTH) if target else None,
            output=sanitize_text(matched_lines, MAX_EVIDENCE_LENGTH) if matched_lines else None,
        )

        return Finding(
            tool="semgrep",
            severity=severity,
            title=title,
            description=description,
            target=target,
            evidence=evidence,
            cwe=cwe,
            phase_found=Phase.VULN_SCAN,
        )
