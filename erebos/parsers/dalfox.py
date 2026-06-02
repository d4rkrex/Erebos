"""dalfox parser — JSON output for XSS vulnerability scanning."""

import json
from typing import List

from erebos.core.finding import Finding, FindingEvidence, Phase, Severity
from erebos.parsers.base import Parser


class DalfoxParser(Parser):
    """Parser for dalfox output (XSS scanner).

    dalfox --format json outputs JSON-lines:
    {
      "type": "vuln"|"reflected"|"verify",
      "inject_type": "inHTML-none"|"inATTR-double",
      "poc_type": "plain"|"curl"|"httpie",
      "method": "GET",
      "data": "https://target.com/path?param=<payload>",
      "param": "q",
      "payload": "<script>alert(1)</script>",
      "evidence": "...",
      "cwe": "CWE-79",
      "severity": "High"
    }
    """

    tool_name = "dalfox"

    def can_parse(self, output: str) -> bool:
        """Check if output is dalfox JSON-lines format."""
        if not output.strip():
            return False
        first_line = output.strip().split("\n")[0].strip()
        try:
            data = json.loads(first_line)
            return isinstance(data, dict) and (
                "inject_type" in data or "poc_type" in data or "type" in data
            )
        except (json.JSONDecodeError, ValueError):
            return False

    def parse(self, output: str) -> List[Finding]:
        """Parse dalfox JSON-lines output into Finding models."""
        findings: List[Finding] = []
        if not output.strip():
            return findings

        for line in output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            if not isinstance(data, dict):
                continue

            vuln_type = data.get("type", "")
            # Only care about confirmed vulnerabilities and verified reflections
            if vuln_type not in ("vuln", "verified", "verify"):
                # "reflected" is informational but worth noting
                pass

            inject_type = data.get("inject_type", "")
            param = data.get("param", "unknown")
            payload = data.get("payload", "")
            url = data.get("data", "")
            method = data.get("method", "GET")
            cwe = data.get("cwe", "CWE-79")
            raw_severity = data.get("severity", "").lower()

            # Map dalfox severity
            if vuln_type in ("vuln", "verified", "verify"):
                severity = Severity.HIGH
            elif raw_severity == "critical":
                severity = Severity.CRITICAL
            elif raw_severity == "high":
                severity = Severity.HIGH
            elif raw_severity == "medium" or vuln_type == "reflected":
                severity = Severity.MEDIUM
            else:
                severity = Severity.LOW

            title = f"XSS ({inject_type}): {param} on {url[:60]}"
            desc = (
                f"dalfox found {vuln_type} XSS via {method} parameter '{param}'. "
                f"Injection context: {inject_type}."
            )

            findings.append(Finding(
                tool="dalfox",
                severity=severity,
                title=title,
                description=desc,
                evidence=FindingEvidence(
                    url=url,
                    payload=payload[:500],
                    output=data.get("evidence", "")[:1000],
                ),
                cwe=cwe,
                phase_found=Phase.VULN_SCAN,
            ))

        return findings
