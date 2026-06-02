"""gau parser — line-separated URL output from GetAllUrls."""

from typing import List

from erebos.core.finding import Finding, FindingEvidence, Phase, Severity
from erebos.parsers.base import Parser


class GauParser(Parser):
    """Parser for gau (GetAllUrls) output.

    gau collects URLs from AlienVault OTX, Wayback Machine, and Common Crawl.
    Output: one URL per line.
    """

    tool_name = "gau"

    def can_parse(self, output: str) -> bool:
        """Check if output is gau format (URLs, one per line)."""
        if not output.strip():
            return False
        lines = [l.strip() for l in output.strip().split("\n") if l.strip()]
        url_lines = [l for l in lines[:20] if l.startswith("http://") or l.startswith("https://")]
        return len(url_lines) >= 1

    def parse(self, output: str) -> List[Finding]:
        """Parse gau output into Finding models."""
        findings: List[Finding] = []
        if not output.strip():
            return findings

        seen: set = set()
        for line in output.strip().split("\n"):
            url = line.strip()
            if not url or not (url.startswith("http://") or url.startswith("https://")):
                continue
            if url in seen:
                continue
            seen.add(url)

            findings.append(Finding(
                tool="gau",
                severity=Severity.INFO,
                title=f"Historical URL: {url[:80]}",
                description=f"gau discovered URL from passive sources: {url}",
                evidence=FindingEvidence(url=url),
                phase_found=Phase.RECON,
            ))

        return findings
