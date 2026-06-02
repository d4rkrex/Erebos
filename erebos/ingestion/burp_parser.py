"""Burp Suite XML export parser.

VT-Spec R8: Burp Suite XML format support.
VT-Spec INJ-01: All fields sanitized at parse time.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional
from xml.etree import ElementTree as ET

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

# Burp severity mapping
_SEVERITY_MAP: Dict[str, Severity] = {
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "information": Severity.INFO,
    "info": Severity.INFO,
}


class BurpParser(FindingsParser):
    """Parser for Burp Suite XML issue exports."""

    @property
    def format_name(self) -> str:
        return "burp"

    def detect(self, content: bytes) -> bool:
        """Detect Burp XML by looking for <issues> root element."""
        try:
            text = content[:2048].decode("utf-8", errors="ignore")
            return "<issues" in text.lower() and "<issue>" in text.lower()
        except Exception:
            return False

    def parse(self, content: bytes) -> List[Finding]:
        """Parse Burp Suite XML into Finding objects.

        VT-Spec INJ-01: All text fields sanitized before creating Findings.
        """
        findings: List[Finding] = []

        try:
            root = ET.fromstring(content)
        except ET.ParseError as e:
            logger.warning("Failed to parse Burp XML: %s", e)
            return []

        issues = root.findall(".//issue")
        if not issues:
            issues = root.findall("issue")

        for issue in issues:
            finding = self._parse_issue(issue)
            if finding:
                findings.append(finding)

        return findings

    def _parse_issue(self, issue: ET.Element) -> Optional[Finding]:
        """Parse a single Burp issue element."""
        name = self._get_text(issue, "name") or "Unknown Issue"
        severity_str = (self._get_text(issue, "severity") or "medium").lower()
        severity = _SEVERITY_MAP.get(severity_str, Severity.MEDIUM)

        # Build target URL from host + path
        host_elem = issue.find("host")
        host = host_elem.text if host_elem is not None and host_elem.text else ""
        path = self._get_text(issue, "path") or ""
        target = f"{host}{path}" if host else path if path else None

        # Description and remediation
        description = self._get_text(issue, "issueDetail") or ""
        background = self._get_text(issue, "issueBackground") or ""
        if background:
            description = f"{description}\n\n{background}" if description else background

        remediation = self._get_text(issue, "remediationBackground") or ""
        confidence = self._get_text(issue, "confidence") or ""

        # VT-Spec INJ-01: Sanitize all fields at parse time
        title = sanitize_text(name, MAX_TITLE_LENGTH)
        description = sanitize_text(description, MAX_DESCRIPTION_LENGTH)
        suggested_fix = sanitize_text(remediation, MAX_DESCRIPTION_LENGTH) if remediation else None

        evidence = FindingEvidence(
            url=sanitize_text(target, MAX_EVIDENCE_LENGTH) if target else None,
            output=sanitize_text(f"Confidence: {confidence}", MAX_EVIDENCE_LENGTH)
            if confidence
            else None,
        )

        return Finding(
            tool="burp",
            severity=severity,
            title=title,
            description=description,
            target=target,
            evidence=evidence,
            suggested_fix=suggested_fix,
            phase_found=Phase.VULN_SCAN,
        )

    def _get_text(self, elem: ET.Element, tag: str) -> Optional[str]:
        """Safely get text from a child element."""
        child = elem.find(tag)
        if child is not None and child.text:
            return child.text
        return None
