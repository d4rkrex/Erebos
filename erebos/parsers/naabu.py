"""naabu parser — port scanning output from ProjectDiscovery naabu."""

import json
from typing import List

from erebos.core.finding import Finding, FindingEvidence, Phase, Severity
from erebos.parsers.base import Parser


class NaabuParser(Parser):
    """Parser for naabu output.

    naabu outputs discovered ports as:
    - Plain: host:port (one per line)
    - JSON (-json): {"host":"x","port":80,"protocol":"tcp"} per line
    """

    tool_name = "naabu"

    def can_parse(self, output: str) -> bool:
        """Check if output is naabu format."""
        if not output.strip():
            return False
        lines = [l.strip() for l in output.strip().split("\n") if l.strip()]
        if not lines:
            return False
        first = lines[0]
        # JSON format
        if first.startswith("{"):
            try:
                data = json.loads(first)
                return "port" in data or "host" in data
            except (json.JSONDecodeError, ValueError):
                return False
        # Plain format: host:port
        if ":" in first:
            parts = first.rsplit(":", 1)
            return len(parts) == 2 and parts[1].isdigit()
        return False

    def parse(self, output: str) -> List[Finding]:
        """Parse naabu output into Finding models."""
        findings: List[Finding] = []
        if not output.strip():
            return findings

        seen: set = set()

        for line in output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue

            host = ""
            port = 0
            protocol = "tcp"

            # Try JSON
            if line.startswith("{"):
                try:
                    data = json.loads(line)
                    host = data.get("host", data.get("ip", ""))
                    port = int(data.get("port", 0))
                    protocol = data.get("protocol", "tcp")
                except (json.JSONDecodeError, ValueError, TypeError):
                    continue
            else:
                # Plain format: host:port
                parts = line.rsplit(":", 1)
                if len(parts) == 2 and parts[1].isdigit():
                    host = parts[0]
                    port = int(parts[1])
                else:
                    continue

            if not host or not port:
                continue

            key = f"{host}:{port}"
            if key in seen:
                continue
            seen.add(key)

            findings.append(Finding(
                tool="naabu",
                severity=Severity.INFO,
                title=f"Open port: {host}:{port}/{protocol}",
                description=f"naabu discovered open port {port}/{protocol} on {host}",
                evidence=FindingEvidence(
                    url=f"{host}:{port}",
                    output=line[:500],
                ),
                phase_found=Phase.RECON,
            ))

        return findings
