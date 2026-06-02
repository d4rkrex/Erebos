"""assetfinder parser — line-separated subdomain output."""

from typing import List

from erebos.core.finding import Finding, FindingEvidence, Phase, Severity
from erebos.parsers.base import Parser


class AssetfinderParser(Parser):
    """Parser for assetfinder output (one subdomain per line).

    assetfinder outputs discovered subdomains/assets one per line, similar to subfinder.
    """

    tool_name = "assetfinder"

    def can_parse(self, output: str) -> bool:
        """Check if output is assetfinder format (domain-like lines)."""
        if not output.strip():
            return False
        lines = [l.strip() for l in output.strip().split("\n") if l.strip()]
        domain_lines = [
            l for l in lines
            if "." in l
            and not l.startswith("[")
            and not l.startswith("{")
            and not l.startswith("#")
            and " " not in l
        ]
        return len(domain_lines) > 0

    def parse(self, output: str) -> List[Finding]:
        """Parse assetfinder output into Finding models."""
        findings: List[Finding] = []
        if not output.strip():
            return findings

        seen: set = set()
        for line in output.strip().split("\n"):
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("["):
                continue
            # Assetfinder may output URLs or bare domains
            domain = line.split("//")[-1].rstrip("/").split("/")[0]
            if "." not in domain or domain in seen:
                continue
            seen.add(domain)

            findings.append(Finding(
                tool="assetfinder",
                severity=Severity.INFO,
                title=f"Asset: {domain}",
                description=f"assetfinder discovered asset: {domain}",
                evidence=FindingEvidence(url=domain, output=domain),
                phase_found=Phase.RECON,
            ))

        return findings
