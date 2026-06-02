"""arjun parser — JSON output for discovered HTTP parameters."""

import json
from typing import List

from erebos.core.finding import Finding, FindingEvidence, Phase, Severity
from erebos.parsers.base import Parser


class ArjunParser(Parser):
    """Parser for arjun output (hidden parameter discovery).

    arjun -oJ outputs JSON:
    {
      "url": "https://example.com/page",
      "method": "GET",
      "params": ["id", "page", "debug", "admin"]
    }
    Or array of such objects.
    """

    tool_name = "arjun"

    def can_parse(self, output: str) -> bool:
        """Check if output is arjun JSON format."""
        if not output.strip():
            return False
        stripped = output.strip()
        try:
            data = json.loads(stripped)
            if isinstance(data, dict):
                return "params" in data or "url" in data
            if isinstance(data, list) and data:
                return "params" in data[0] or "url" in data[0]
        except (json.JSONDecodeError, ValueError, IndexError):
            pass
        return False

    def parse(self, output: str) -> List[Finding]:
        """Parse arjun output into Finding models."""
        findings: List[Finding] = []
        if not output.strip():
            return findings

        try:
            data = json.loads(output.strip())
        except json.JSONDecodeError:
            return findings

        results = data if isinstance(data, list) else [data]

        for entry in results:
            if not isinstance(entry, dict):
                continue
            url = entry.get("url", "unknown")
            method = entry.get("method", "GET")
            params = entry.get("params", [])

            if not params:
                continue

            for param in params:
                findings.append(Finding(
                    tool="arjun",
                    severity=Severity.LOW,
                    title=f"Hidden param: {param} ({method} {url[:60]})",
                    description=(
                        f"arjun discovered hidden parameter '{param}' "
                        f"via {method} on {url}. May reveal debug/admin functionality."
                    ),
                    evidence=FindingEvidence(
                        url=url,
                        payload=f"{param}=FUZZ",
                        output=f"Method: {method}, Param: {param}",
                    ),
                    phase_found=Phase.DISCOVERY,
                ))

        return findings
