"""Masscan parser for JSON and grepable output."""

import json
import re
from typing import List

from erebos.core.finding import Finding, FindingEvidence, Phase, Severity
from erebos.parsers.base import Parser


class MasscanParser(Parser):
    """Parser for Masscan JSON and grepable output formats."""

    tool_name = "masscan"

    SEVERITY_MAP = {
        "open": Severity.HIGH,
        "closed": Severity.INFO,
        "filtered": Severity.MEDIUM,
        "open|filtered": Severity.MEDIUM,
    }

    def can_parse(self, output: str) -> bool:
        """Check if output is Masscan format."""
        if not output.strip():
            return False

        # Check for JSON format (Masscan JSON has "services" array)
        try:
            data = json.loads(output)
            if isinstance(data, dict) and "services" in data:
                return True
            if isinstance(data, list) and len(data) > 0 and "port" in data[0]:
                return True
        except json.JSONDecodeError:
            pass

        # Check for grepable format (Masscan grepable has "# " header line)
        lines = output.strip().split("\n")
        if lines and lines[0].startswith("# "):
            return True
        # Also check for known grepable pattern: ip:port:state:protocol
        for line in lines:
            if not line.strip() or line.startswith("#"):
                continue
            if re.match(r"^[^:]+:\d+:\w+:\w+$", line):
                return True

        return False

    def parse(self, output: str) -> List[Finding]:
        """Parse Masscan output into Finding models."""
        findings = []

        if not output.strip():
            return findings

        # Try JSON format first
        try:
            data = json.loads(output)
            findings = self._parse_json(data)
            if findings:
                return findings
        except json.JSONDecodeError:
            pass

        # Fall back to grepable format
        findings = self._parse_grepable(output)
        return findings

    def _parse_json(self, data) -> List[Finding]:
        """Parse Masscan JSON output."""
        findings = []

        # Handle {"services": [...]} format
        if isinstance(data, dict):
            services = data.get("services", [])
            for service in services:
                finding = self._service_to_finding(service)
                if finding:
                    findings.append(finding)

        # Handle direct list of services
        elif isinstance(data, list):
            for service in data:
                finding = self._service_to_finding(service)
                if finding:
                    findings.append(finding)

        return findings

    def _service_to_finding(self, service: dict) -> Finding | None:
        """Convert a Masscan service dict to a Finding."""
        ip = service.get("ip", service.get("address", ""))
        port = service.get("port", 0)
        protocol = service.get("protocol", "tcp").upper()
        state = service.get("state", "unknown")
        service_name = (
            service.get("service", {}).get("name", "")
            if isinstance(service.get("service"), dict)
            else service.get("service", "")
        )

        if not ip or not port:
            return None

        # Skip closed ports
        if state == "closed":
            return None

        severity = self.SEVERITY_MAP.get(state, Severity.MEDIUM)
        url = f"{ip}:{port}"
        title = f"Port Scan: {port}/{protocol} - {service_name or 'unknown'}"
        description = f"Masscan discovered {state} port {port}/{protocol}"
        if service_name:
            description += f" running {service_name}"

        return Finding(
            tool="masscan",
            severity=severity,
            title=title[:100],
            description=description,
            evidence=FindingEvidence(
                url=url,
                output=json.dumps(
                    {
                        "ip": ip,
                        "port": port,
                        "protocol": protocol,
                        "state": state,
                        "service": service_name,
                    }
                ),
            ),
            phase_found=Phase.RECON,
        )

    def _parse_grepable(self, output: str) -> List[Finding]:
        """Parse Masscan grepable output format.

        Grepable format header:
        #masscan 1.0 (protocol "masscan/" "1.0")
        # target: file: (inherited)
        #:-----------------ip----proto-port---state-----service-----version-----
        Records: ip:protocol:port:state:service:version:banner

        Example line:
        192.168.1.1:tcp:80:open:http:Apache/2.4.41
        """
        findings = []

        lines = output.strip().split("\n")

        for line in lines:
            line = line.strip()
            # Skip comments and empty lines
            if not line or line.startswith("#"):
                continue

            # Parse grepable format: ip:protocol:port:state:service:version:banner
            parts = line.split(":")
            if len(parts) < 4:
                continue

            ip = parts[0]
            protocol = parts[1].upper()
            port = parts[2]
            state = parts[3]
            service = parts[4] if len(parts) > 4 else ""
            version = parts[5] if len(parts) > 5 else ""

            # Skip closed ports
            if state == "closed":
                continue

            severity = self.SEVERITY_MAP.get(state, Severity.MEDIUM)
            url = f"{ip}:{port}"

            title = f"Port Scan: {port}/{protocol} - {service or 'unknown'}"
            description = f"Masscan discovered {state} port {port}/{protocol}"
            if service:
                description += f" running {service}"
            if version:
                description += f" ({version})"

            finding = Finding(
                tool="masscan",
                severity=severity,
                title=title[:100],
                description=description,
                evidence=FindingEvidence(
                    url=url,
                    output=line,
                ),
                phase_found=Phase.RECON,
            )
            findings.append(finding)

        return findings
