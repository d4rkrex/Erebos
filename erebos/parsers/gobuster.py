"""Gobuster parser for directory/file scanning."""

import json
import re
from typing import List

from erebos.core.finding import Finding, FindingEvidence, Phase, Severity
from erebos.parsers.base import Parser


class GobusterParser(Parser):
    """Parser for Gobuster output (dir, dns, vhost, fuzz)."""

    tool_name = "gobuster"

    SEVERITY_MAP = {
        "200": Severity.HIGH,
        "201": Severity.HIGH,
        "301": Severity.MEDIUM,
        "302": Severity.MEDIUM,
        "401": Severity.MEDIUM,
        "403": Severity.LOW,
        "404": Severity.INFO,
        "500": Severity.HIGH,
    }

    def can_parse(self, output: str) -> bool:
        """Check if output is Gobuster format."""
        # Gobuster outputs lines like:
        # /admin                   (Status: 200) [Size: 1234]
        # /api                    (Status: 301) [Size: 185]
        # Or JSON format
        lines = output.strip().split("\n")
        if not lines:
            return False

        # Check for JSON format
        try:
            data = json.loads(output)
            if isinstance(data, dict) and "result" in data:
                return True
        except json.JSONDecodeError:
            pass

        # Check for text format
        for line in lines:
            if "(Status:" in line and ("[Size:" in line or "[<dir>" in line or "[<file>" in line):
                return True

        return False

    def parse(self, output: str) -> List[Finding]:
        """Parse Gobuster output into Finding models."""
        findings = []

        # Try JSON format first
        try:
            data = json.loads(output)
            if isinstance(data, dict) and "result" in data:
                findings = self._parse_json(data)
                return findings
        except json.JSONDecodeError:
            pass

        # Parse text format
        findings = self._parse_text(output)
        return findings

    def _parse_json(self, data: dict) -> List[Finding]:
        """Parse Gobuster JSON output."""
        findings = []

        result = data.get("result", {})
        if isinstance(result, dict):
            result = [result]

        for item in result:
            url = item.get("url", "")
            status_code = item.get("statuscode", 0)
            length = item.get("length", 0)
            method = item.get("method", "GET")

            # Determine severity
            status_str = str(status_code)
            severity = self.SEVERITY_MAP.get(status_str, Severity.MEDIUM)

            # Check if it's a directory or file
            if item.get("type") == "dir":
                title = f"Gobuster Dir: {status_code} - {url}"
            else:
                title = f"Gobuster: {status_code} - {url}"

            description = f"Gobuster discovered {method} {url} with status {status_code}"
            if length:
                description += f", size {length}"

            finding = Finding(
                tool="gobuster",
                severity=severity,
                title=title[:100],
                description=description,
                evidence=FindingEvidence(
                    url=url,
                    output=json.dumps(
                        {
                            "status": status_code,
                            "length": length,
                            "method": method,
                        }
                    ),
                ),
                phase_found=Phase.RECON,
            )
            findings.append(finding)

        return findings

    def _parse_text(self, output: str) -> List[Finding]:
        """Parse Gobuster text output."""
        findings = []

        lines = output.split("\n")

        for line in lines:
            # Skip progress lines and empty lines
            if (
                not line.strip()
                or "Progress:" in line
                or "================================" in line
            ):
                continue

            # Parse status line
            # Format: /path                   (Status: 200) [Size: 1234]
            match = re.search(r"(\S+)\s+\(Status:\s*(\d+)\)\s+\[Size:\s*(\d+)\]", line)
            if match:
                url = match.group(1)
                status = int(match.group(2))
                size = int(match.group(3))

                # Determine severity
                status_str = str(status)
                severity = self.SEVERITY_MAP.get(status_str, Severity.MEDIUM)

                # Determine if directory or file
                is_dir = "[<dir>]" in line
                is_file = "[<file>]" in line

                if is_dir:
                    title = f"Gobuster Dir: {status} - {url}"
                elif is_file:
                    title = f"Gobuster File: {status} - {url}"
                else:
                    title = f"Gobuster: {status} - {url}"

                description = f"Gobuster discovered {url} with status {status}, size {size}"

                finding = Finding(
                    tool="gobuster",
                    severity=severity,
                    title=title[:100],
                    description=description,
                    evidence=FindingEvidence(
                        url=url,
                        output=line.strip(),
                    ),
                    phase_found=Phase.RECON,
                )
                findings.append(finding)

        return findings
