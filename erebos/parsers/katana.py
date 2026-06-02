"""Katana parser for URL extraction."""

import json
import re
from typing import List

from erebos.core.finding import Finding, FindingEvidence, Phase, Severity
from erebos.parsers.base import Parser


class KatanaParser(Parser):
    """Parser for Katana output (URL extraction)."""

    tool_name = "katana"

    def can_parse(self, output: str) -> bool:
        """Check if output is Katana format (JSON lines or plain URLs)."""
        # Could be JSON lines or plain URLs
        lines = output.strip().split("\n")
        if not lines:
            return False

        # Check if it looks like URLs
        first_line = lines[0].strip()
        return (
            first_line.startswith("http://")
            or first_line.startswith("https://")
            or first_line.startswith("[")
        )

    def parse(self, output: str) -> List[Finding]:
        """Parse Katana output into Finding models (URLs as findings)."""
        findings = []

        # First try to parse as a full JSON array
        try:
            data = json.loads(output)
            if isinstance(data, list):
                for item in data:
                    url = item.get("url") or item.get("href")
                    if url:
                        finding = Finding(
                            tool="katana",
                            severity=Severity.INFO,
                            title=f"Discovered URL: {url[:50]}...",
                            description="Katana discovered this URL during crawling",
                            evidence=FindingEvidence(url=url),
                            phase_found=Phase.RECON,
                        )
                        findings.append(finding)
                return findings
        except json.JSONDecodeError:
            pass

        # Fall back to line-by-line parsing
        lines = output.strip().split("\n")

        urls_found = set()

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Try JSON format first
            try:
                data = json.loads(line)
                if isinstance(data, dict):
                    url = data.get("url") or data.get("href")
                    if url and url not in urls_found:
                        urls_found.add(url)
                        finding = Finding(
                            tool="katana",
                            severity=Severity.INFO,
                            title=f"Discovered URL: {url[:50]}...",
                            description="Katana discovered this URL during crawling",
                            evidence=FindingEvidence(url=url),
                            phase_found=Phase.RECON,
                        )
                        findings.append(finding)
            except json.JSONDecodeError:
                # Plain URL format
                if line.startswith("http://") or line.startswith("https://"):
                    if line not in urls_found:
                        urls_found.add(line)
                        finding = Finding(
                            tool="katana",
                            severity=Severity.INFO,
                            title=f"Discovered URL: {line[:50]}...",
                            description="Katana discovered this URL during crawling",
                            evidence=FindingEvidence(url=line),
                            phase_found=Phase.RECON,
                        )
                        findings.append(finding)

        return findings
