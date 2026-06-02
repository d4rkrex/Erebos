"""waybackurls parser — line-separated URLs from Wayback Machine."""

from typing import List

from erebos.core.finding import Finding, FindingEvidence, Phase, Severity
from erebos.parsers.base import Parser


class WaybackurlsParser(Parser):
    """Parser for waybackurls output (one URL per line from Wayback Machine).

    Output format is identical to gau — one URL per line.
    """

    tool_name = "waybackurls"

    def can_parse(self, output: str) -> bool:
        """Check if output is waybackurls format."""
        if not output.strip():
            return False
        lines = [l.strip() for l in output.strip().split("\n") if l.strip()]
        url_lines = [l for l in lines[:20] if l.startswith("http://") or l.startswith("https://")]
        return len(url_lines) >= 1

    def parse(self, output: str) -> List[Finding]:
        """Parse waybackurls output into Finding models."""
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
                tool="waybackurls",
                severity=Severity.INFO,
                title=f"Wayback URL: {url[:80]}",
                description=f"waybackurls found archived URL: {url}",
                evidence=FindingEvidence(url=url),
                phase_found=Phase.RECON,
            ))

        return findings
