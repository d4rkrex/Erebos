"""kxss parser — reflected parameter detection output."""

from typing import List

from erebos.core.finding import Finding, FindingEvidence, Phase, Severity
from erebos.parsers.base import Parser


class KxssParser(Parser):
    """Parser for kxss output (reflected parameter detector).

    kxss checks which parameters reflect unfiltered in responses.
    Output format (one per line):
      URL  PARAM  UNFILTERED_CHARS
      https://example.com/search?q=test  q  <>"'
    """

    tool_name = "kxss"

    def can_parse(self, output: str) -> bool:
        """Check if output is kxss format."""
        if not output.strip():
            return False
        lines = [l.strip() for l in output.strip().split("\n") if l.strip()]
        # kxss output contains URLs with reflected chars info
        url_lines = [
            l for l in lines[:20]
            if ("http://" in l or "https://" in l) and not l.startswith("{")
        ]
        return len(url_lines) >= 1

    def parse(self, output: str) -> List[Finding]:
        """Parse kxss output into Finding models."""
        findings: List[Finding] = []
        if not output.strip():
            return findings

        seen: set = set()

        for line in output.strip().split("\n"):
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("["):
                continue

            # Parse format: URL [param] [unfiltered chars]
            # Various formats: tab-separated or space-separated
            parts = line.split()
            if len(parts) < 1:
                continue

            url = ""
            param = ""
            unfiltered = ""

            for part in parts:
                if part.startswith("http://") or part.startswith("https://"):
                    url = part
                elif not param and part.isalnum():
                    param = part
                else:
                    unfiltered += part

            if not url:
                # Fallback: entire line might be tab-separated
                tab_parts = line.split("\t")
                if tab_parts:
                    url = tab_parts[0].strip()
                    param = tab_parts[1].strip() if len(tab_parts) > 1 else ""
                    unfiltered = tab_parts[2].strip() if len(tab_parts) > 2 else ""

            if not url:
                continue

            key = f"{url}|{param}"
            if key in seen:
                continue
            seen.add(key)

            # Determine severity based on unfiltered characters
            dangerous_chars = set("<>\"'")
            reflected_dangerous = dangerous_chars.intersection(set(unfiltered))
            severity = Severity.MEDIUM if reflected_dangerous else Severity.LOW

            title = f"Reflected param: {param or 'unknown'} on {url[:60]}"
            desc = (
                f"kxss detected parameter '{param}' reflects unfiltered in response. "
                f"Unfiltered chars: {unfiltered or 'some'}. Potential XSS vector."
            )

            findings.append(Finding(
                tool="kxss",
                severity=severity,
                title=title,
                description=desc,
                cwe="CWE-79",
                evidence=FindingEvidence(
                    url=url,
                    payload=f"{param}=<test>" if param else None,
                    output=line[:500],
                ),
                phase_found=Phase.VULN_SCAN,
            ))

        return findings
