"""Nikto parser for text output."""

import re
from typing import List

from erebos.core.finding import Finding, FindingEvidence, Phase, Severity
from erebos.parsers.base import Parser


class NiktoParser(Parser):
    """Parser for Nikto text output."""

    tool_name = "nikto"

    # Severity indicators in Nikto output
    SEVERITY_KEYWORDS = {
        "+ ": Severity.INFO,  # General info
        "- ": Severity.LOW,  # Low severity
    }

    def can_parse(self, output: str) -> bool:
        """Check if output is Nikto format."""
        return "Nikto" in output or "- Target:" in output

    def parse(self, output: str) -> List[Finding]:
        """Parse Nikto text output into Finding models."""
        findings = []
        lines = output.split("\n")

        current_finding = None

        for line in lines:
            # Skip empty lines and headers
            if not line.strip() or line.startswith("- ") or line.startswith("=="):
                continue

            # Parse finding lines
            if line.startswith("+ "):
                # Extract OSVDB or other IDs
                osvdb_match = re.search(r"OSVDB-(\d+)", line)
                cve_match = re.search(r"CVE[-\s]?(\d+-\d+)", line, re.IGNORECASE)

                # Determine severity from line content
                severity = Severity.MEDIUM
                if "ERROR" in line.upper():
                    severity = Severity.HIGH
                elif "SQL" in line.upper() or "XSS" in line.upper():
                    severity = Severity.HIGH
                elif "information" in line.lower() or "info" in line.lower():
                    severity = Severity.INFO

                # Extract description
                description = line[2:].strip()  # Remove "+ "
                if "-" in description:
                    description = description.split("-", 1)[1].strip()

                # Create finding
                finding = Finding(
                    tool="nikto",
                    severity=severity,
                    title=description[:100] if description else "Nikto Finding",
                    description=description,
                    evidence=FindingEvidence(output=line),
                    cve=cve_match.group(1) if cve_match else None,
                    phase_found=Phase.RECON,
                )
                findings.append(finding)

        return findings
