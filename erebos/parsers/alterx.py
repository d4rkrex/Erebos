"""alterx parser — line-separated permutation/mutation output."""

from typing import List

from erebos.core.finding import Finding, FindingEvidence, Phase, Severity
from erebos.parsers.base import Parser


class AlterxParser(Parser):
    """Parser for alterx output (subdomain permutations, one per line).

    alterx generates subdomain permutations/mutations based on patterns.
    Output: one generated subdomain per line.
    """

    tool_name = "alterx"

    def can_parse(self, output: str) -> bool:
        """Check if output is alterx format (domain-like lines)."""
        if not output.strip():
            return False
        lines = [l.strip() for l in output.strip().split("\n") if l.strip()]
        domain_lines = [
            l for l in lines[:20]
            if "." in l
            and not l.startswith("[")
            and not l.startswith("{")
            and not l.startswith("http")
            and " " not in l
        ]
        return len(domain_lines) >= 1

    def parse(self, output: str) -> List[Finding]:
        """Parse alterx output into Finding models."""
        findings: List[Finding] = []
        if not output.strip():
            return findings

        seen: set = set()
        for line in output.strip().split("\n"):
            domain = line.strip()
            if not domain or "." not in domain or domain in seen:
                continue
            if domain.startswith("[") or domain.startswith("{") or domain.startswith("#"):
                continue
            seen.add(domain)

            findings.append(Finding(
                tool="alterx",
                severity=Severity.INFO,
                title=f"Permutation: {domain}",
                description=f"alterx generated subdomain permutation: {domain}",
                evidence=FindingEvidence(url=domain, output=domain),
                phase_found=Phase.RECON,
            ))

        return findings
