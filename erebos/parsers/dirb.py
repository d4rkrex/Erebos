"""Dirb parser for directory scanning."""

import json
import re
from typing import List

from erebos.core.finding import Finding, FindingEvidence, Phase, Severity
from erebos.parsers.base import Parser


class DirbParser(Parser):
    """Parser for DIRB output."""

    tool_name = "dirb"

    SEVERITY_MAP = {
        "200": Severity.HIGH,
        "201": Severity.HIGH,
        "301": Severity.MEDIUM,
        "302": Severity.MEDIUM,
        "401": Severity.MEDIUM,
        "403": Severity.LOW,
        "404": Severity.INFO,
    }

    def can_parse(self, output: str) -> bool:
        """Check if output is DIRB format."""
        # DIRB outputs lines like:
        # + http://example.com/admin (CODE:200|SIZE:1234)
        # + http://example.com/login (CODE:302|SIZE:0)
        # or
        # ==> DIRECTORY: http://example.com/images/
        # or
        # "+" at the beginning of a line

        lines = output.strip().split("\n")
        if not lines:
            return False

        # Check for DIRB-specific patterns
        for line in lines:
            if line.startswith("+ ") and ("(CODE:" in line or "(SIZE:" in line):
                return True
            if "DIRECTORY:" in line or "FILE:" in line:
                return True
            if line.startswith("----"):
                return True
            if "GENERATED" in line:
                return True

        return False

    def parse(self, output: str) -> List[Finding]:
        """Parse DIRB output into Finding models."""
        findings = []

        lines = output.split("\n")

        for line in lines:
            line = line.strip()

            # Skip progress and header lines
            if not line:
                continue
            if line.startswith("----"):
                continue
            if line.startswith("GENERATED"):
                continue
            if "SESSION" in line or "TOTAL" in line:
                continue
            if "SCAN" in line or "STATUS" in line or "WORDLIST" in line:
                continue

            # Parse found entries: + http://example.com/path (CODE:200|SIZE:1234)
            if line.startswith("+ "):
                finding = self._parse_found_line(line)
                if finding:
                    findings.append(finding)

            # Parse directories: ==> DIRECTORY: http://example.com/path/
            elif "DIRECTORY:" in line:
                finding = self._parse_directory_line(line)
                if finding:
                    findings.append(finding)

            # Parse files: ==> FILE: http://example.com/file.txt
            elif "FILE:" in line:
                finding = self._parse_file_line(line)
                if finding:
                    findings.append(finding)

        return findings

    def _parse_found_line(self, line: str) -> Finding:
        """Parse a line starting with '+ '."""
        try:
            # Format: + http://example.com/path (CODE:200|SIZE:1234)
            # Extract URL
            url_match = re.search(r"\+ (https?://[^\s]+)", line)
            if not url_match:
                return None

            url = url_match.group(1).rstrip(")")

            # Extract status code
            code_match = re.search(r"CODE:(\d+)", line)
            status = int(code_match.group(1)) if code_match else 0

            # Extract size
            size_match = re.search(r"SIZE:(\d+)", line)
            size = int(size_match.group(1)) if size_match else 0

            # Determine severity
            status_str = str(status)
            severity = self.SEVERITY_MAP.get(status_str, Severity.MEDIUM)

            # Determine if directory or file
            is_dir = url.endswith("/")
            if is_dir:
                title = f"DIRB Dir: {status} - {url}"
            else:
                title = f"DIRB: {status} - {url}"

            description = f"DIRB discovered {url} with status {status}"
            if size:
                description += f", size {size} bytes"

            return Finding(
                tool="dirb",
                severity=severity,
                title=title[:100],
                description=description,
                evidence=FindingEvidence(
                    url=url,
                    output=line,
                ),
                phase_found=Phase.RECON,
            )

        except (AttributeError, ValueError) as e:
            return None

    def _parse_directory_line(self, line: str) -> Finding:
        """Parse a directory line."""
        try:
            # Format: ==> DIRECTORY: http://example.com/path/
            url_match = re.search(r"DIRECTORY:\s*(https?://[^\s]+)", line)
            if not url_match:
                return None

            url = url_match.group(1)

            return Finding(
                tool="dirb",
                severity=Severity.MEDIUM,
                title=f"DIRB Dir: {url}",
                description=f"DIRB discovered directory: {url}",
                evidence=FindingEvidence(url=url, output=line),
                phase_found=Phase.RECON,
            )

        except (AttributeError, ValueError):
            return None

    def _parse_file_line(self, line: str) -> Finding:
        """Parse a file line."""
        try:
            # Format: ==> FILE: http://example.com/file.txt
            url_match = re.search(r"FILE:\s*(https?://[^\s]+)", line)
            if not url_match:
                return None

            url = url_match.group(1)

            return Finding(
                tool="dirb",
                severity=Severity.MEDIUM,
                title=f"DIRB File: {url}",
                description=f"DIRB discovered file: {url}",
                evidence=FindingEvidence(url=url, output=line),
                phase_found=Phase.RECON,
            )

        except (AttributeError, ValueError):
            return None
