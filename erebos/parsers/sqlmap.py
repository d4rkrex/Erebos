"""SQLMap parser for text and JSON output."""

import json
import re
from typing import List, Optional

from erebos.core.finding import Finding, FindingEvidence, Phase, Severity
from erebos.parsers.base import Parser


class SqlmapParser(Parser):
    """Parser for SQLMap output."""

    tool_name = "sqlmap"

    SEVERITY_MAP = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
    }

    def can_parse(self, output: str) -> bool:
        """Check if output is SQLMap format."""
        # Check for JSON format
        try:
            data = json.loads(output)
            if isinstance(data, dict) and "data" in data:
                return True
        except json.JSONDecodeError:
            pass

        # Check for text format indicators
        text_indicators = [
            "sqlmap",
            "Parameter:",
            "Type:",
            "Title:",
            "Payload:",
            "is vulnerable",
            "vulnerable to",
        ]

        return any(indicator.lower() in output.lower() for indicator in text_indicators)

    def parse(self, output: str) -> List[Finding]:
        """Parse SQLMap output into Finding models."""
        findings = []

        # Try JSON format first
        try:
            data = json.loads(output)
            if isinstance(data, dict) and "data" in data:
                findings = self._parse_json(data)
                return findings
        except json.JSONDecodeError:
            pass

        # Parse text format
        findings = self._parse_text(output)
        return findings

    def _parse_json(self, data: dict) -> List[Finding]:
        """Parse SQLMap JSON output."""
        findings = []

        data_section = data.get("data", [])
        if not isinstance(data_section, list):
            data_section = [data_section]

        for item in data_section:
            if not isinstance(item, dict):
                continue

            # Extract vulnerability info
            parameter = item.get("parameter", "")
            injection_type = item.get("type", "")
            title = item.get("title", "")
            payload = item.get("payload", "")
            data_info = item.get("data", "")

            # Determine severity from title
            severity = Severity.HIGH
            title_lower = title.lower()
            if "blind" in title_lower or "stacked" in title_lower:
                severity = Severity.CRITICAL
            elif "union" in title_lower:
                severity = Severity.HIGH
            elif "error" in title_lower:
                severity = Severity.MEDIUM

            # Build description
            description = f"SQLMap detected {injection_type} injection"
            if parameter:
                description += f" in parameter '{parameter}'"
            if title:
                description += f" - {title}"

            # Create finding
            finding = Finding(
                tool="sqlmap",
                severity=severity,
                title=title[:100] if title else f"SQL Injection in {parameter}",
                description=description,
                evidence=FindingEvidence(
                    payload=payload,
                    output=data_info if isinstance(data_info, str) else json.dumps(data_info),
                ),
                cwe=item.get("cwe_id"),
                cve=item.get("cve_id"),
                phase_found=Phase.VULN_SCAN,
            )
            findings.append(finding)

        return findings

    def _parse_text(self, output: str) -> List[Finding]:
        """Parse SQLMap text output."""
        findings = []

        lines = output.split("\n")
        current_finding = {}

        for i, line in enumerate(lines):
            line = line.strip()

            # Parse parameter
            if line.startswith("Parameter:"):
                if current_finding:
                    finding = self._create_finding_from_dict(current_finding)
                    if finding:
                        findings.append(finding)
                current_finding = {"parameter": line.split(":", 1)[1].strip()}

            # Parse type
            elif line.startswith("Type:"):
                current_finding["type"] = line.split(":", 1)[1].strip()

            # Parse title
            elif line.startswith("Title:"):
                current_finding["title"] = line.split(":", 1)[1].strip()

            # Parse payload
            elif line.startswith("Payload:"):
                current_finding["payload"] = line.split(":", 1)[1].strip()

            # Parse confidence
            elif line.startswith("Confidence:"):
                current_finding["confidence"] = line.split(":", 1)[1].strip()

        # Don't forget the last finding
        if current_finding:
            finding = self._create_finding_from_dict(current_finding)
            if finding:
                findings.append(finding)

        # Also look for vulnerable status lines
        vulnerable_pattern = re.compile(r"(.*?)\s+is vulnerable to\s+(.*)", re.IGNORECASE)
        for line in lines:
            match = vulnerable_pattern.search(line)
            if match:
                url = match.group(1).strip()
                vuln_type = match.group(2).strip()

                finding = Finding(
                    tool="sqlmap",
                    severity=Severity.CRITICAL,
                    title=f"SQL Injection: {vuln_type}",
                    description=f"SQLMap found {vuln_type} vulnerability",
                    evidence=FindingEvidence(url=url, output=line),
                    phase_found=Phase.VULN_SCAN,
                )
                findings.append(finding)

        return findings

    def _create_finding_from_dict(self, data: dict) -> Optional[Finding]:
        """Create a Finding from parsed data dictionary."""
        if not data:
            return None

        # Determine severity from title
        severity = Severity.HIGH
        title = data.get("title", "")
        title_lower = title.lower() if title else ""

        if "blind" in title_lower or "stacked" in title_lower:
            severity = Severity.CRITICAL
        elif "union" in title_lower:
            severity = Severity.HIGH
        elif "error" in title_lower:
            severity = Severity.MEDIUM
        elif not title:
            severity = Severity.INFO

        # Build description
        description = f"SQLMap detected {data.get('type', 'unknown')} injection"
        if data.get("parameter"):
            description += f" in parameter '{data['parameter']}'"
        if data.get("confidence"):
            description += f" (confidence: {data['confidence']})"
        if title:
            description += f" - {title}"

        return Finding(
            tool="sqlmap",
            severity=severity,
            title=title[:100] if title else f"SQL Injection in {data.get('parameter', 'unknown')}",
            description=description,
            evidence=FindingEvidence(
                payload=data.get("payload"),
                output=data.get("payload", ""),
            ),
            phase_found=Phase.VULN_SCAN,
        )
