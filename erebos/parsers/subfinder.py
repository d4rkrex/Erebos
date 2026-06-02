"""Subfinder parser for line-separated subdomain output."""

from typing import List

from erebos.core.finding import Finding, FindingEvidence, Phase, Severity
from erebos.parsers.base import Parser


class SubfinderParser(Parser):
    """Parser for Subfinder line-separated subdomain output."""

    tool_name = "subfinder"

    def can_parse(self, output: str) -> bool:
        """Check if output is Subfinder format.

        Subfinder with -silent outputs one subdomain per line.
        Format: subdomain.example.com
        Lines starting with [+] or [WRN] or [ERR] are info/warning/error lines.
        """
        if not output.strip():
            return False

        lines = [l.strip() for l in output.strip().split("\n") if l.strip()]

        # Should have at least one domain-like line
        domain_lines = [
            l
            for l in lines
            if not l.startswith("[")
            and not l.startswith("#")
            and "." in l
            and not l.startswith("http")
        ]

        # If most non-comment lines look like subdomains, it's subfinder output
        return len(domain_lines) > 0

    def parse(self, output: str) -> List[Finding]:
        """Parse Subfinder output into Finding models."""
        findings = []

        if not output.strip():
            return findings

        lines = [l.strip() for l in output.strip().split("\n") if l.strip()]

        seen = set()
        for line in lines:
            # Skip info/warning/error/info lines from subfinder
            if line.startswith("[") or line.startswith("#") or line.startswith("http"):
                continue

            # Skip empty lines
            if not line or "." not in line:
                continue

            # Deduplicate
            if line in seen:
                continue
            seen.add(line)

            # Create finding
            finding = Finding(
                tool="subfinder",
                severity=Severity.INFO,
                title=f"Subdomain: {line}",
                description=f"Subfinder discovered subdomain: {line}",
                evidence=FindingEvidence(
                    url=line,
                    output=line,
                ),
                phase_found=Phase.RECON,
            )
            findings.append(finding)

        return findings
