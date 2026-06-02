"""bxss parser — blind XSS callback detection output."""

from typing import List

from erebos.core.finding import Finding, FindingEvidence, Phase, Severity
from erebos.parsers.base import Parser


class BxssParser(Parser):
    """Parser for bxss output (blind XSS tester).

    bxss injects blind XSS payloads pointing to a callback server.
    Output typically indicates:
    - Injected URLs/parameters
    - Callback hits (confirmed blind XSS)

    Format varies; common output:
      [INJECT] https://target.com/form?name=<payload> - injected
      [HIT] Callback received from https://target.com/admin (param: name)
    Or JSON-lines with status.
    """

    tool_name = "bxss"

    def can_parse(self, output: str) -> bool:
        """Check if output is bxss format."""
        if not output.strip():
            return False
        lines = output.strip().split("\n")
        bxss_indicators = sum(
            1 for l in lines[:20]
            if "[INJECT]" in l or "[HIT]" in l or "bxss" in l.lower() or "blind" in l.lower()
        )
        return bxss_indicators >= 1

    def parse(self, output: str) -> List[Finding]:
        """Parse bxss output into Finding models."""
        findings: List[Finding] = []
        if not output.strip():
            return findings

        for line in output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue

            # Confirmed blind XSS callbacks
            if "[HIT]" in line or "callback" in line.lower():
                url = self._extract_url(line)
                findings.append(Finding(
                    tool="bxss",
                    severity=Severity.HIGH,
                    title=f"Blind XSS confirmed: {url[:60] if url else 'target'}",
                    description=(
                        f"bxss received callback confirming blind XSS execution. "
                        f"Detail: {line[:200]}"
                    ),
                    cwe="CWE-79",
                    evidence=FindingEvidence(
                        url=url or "",
                        output=line[:1000],
                    ),
                    phase_found=Phase.VULN_SCAN,
                ))
            elif "[INJECT]" in line:
                url = self._extract_url(line)
                findings.append(Finding(
                    tool="bxss",
                    severity=Severity.LOW,
                    title=f"Blind XSS injected: {url[:60] if url else 'target'}",
                    description=(
                        f"bxss injected blind XSS payload. Awaiting callback. "
                        f"Detail: {line[:200]}"
                    ),
                    cwe="CWE-79",
                    evidence=FindingEvidence(
                        url=url or "",
                        output=line[:500],
                    ),
                    phase_found=Phase.VULN_SCAN,
                ))

        return findings

    @staticmethod
    def _extract_url(line: str) -> str:
        """Extract first URL from a line."""
        for part in line.split():
            if part.startswith("http://") or part.startswith("https://"):
                return part.rstrip(",;)")
        return ""
