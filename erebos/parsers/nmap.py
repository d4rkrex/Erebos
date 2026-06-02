"""Nmap parser for XML and text output."""

import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from erebos.core.finding import Finding, FindingEvidence, Phase, Severity
from erebos.parsers.base import Parser


# ---------------------------------------------------------------------------
# Data models for structured nmap scan results (consumed by InferenceEngine)
# ---------------------------------------------------------------------------


@dataclass
class PortInfo:
    """Structured port/service data extracted from nmap XML."""

    port: str
    protocol: str
    state: str
    service: str
    product: str = ""
    version: str = ""
    cpe: str = ""
    host: str = ""
    hostname: str = ""


@dataclass
class OsMatch:
    """OS match data from nmap XML."""

    name: str
    accuracy: int = 0


@dataclass
class ScriptResult:
    """Nmap script result from a <script> element."""

    port: str
    script_id: str
    output: str


@dataclass
class NmapScanResult:
    """Complete structured result of an nmap scan.

    Replaces the old `List[Finding]` return type from `parse()`. Consumers
    that still need Finding objects should call `parse_to_findings()`.
    """

    ports: List[PortInfo] = field(default_factory=list)
    os_matches: List[OsMatch] = field(default_factory=list)
    script_results: List[ScriptResult] = field(default_factory=list)

    def get_open_ports(self) -> List[Tuple[str, str, str]]:
        """Return list of (host, port, protocol) for all non-closed ports."""
        return [(p.host, p.port, p.protocol) for p in self.ports if p.state not in ("closed",)]

    def get_service_versions(self) -> List[Tuple[str, str, str, str]]:
        """Return (host, product, version, cpe) for ports with version info."""
        return [(p.host, p.product, p.version, p.cpe) for p in self.ports if p.product or p.version]


# ---------------------------------------------------------------------------
# NmapParser
# ---------------------------------------------------------------------------


class NmapParser(Parser):
    """Parser for Nmap scan output."""

    tool_name = "nmap"

    SEVERITY_MAP = {
        "open": Severity.HIGH,
        "filtered": Severity.MEDIUM,
        "closed": Severity.INFO,
    }

    def can_parse(self, output: str) -> bool:
        """Check if output is Nmap format."""
        # Check for XML format
        if output.strip().startswith("<?xml") or "<nmaprun" in output:
            return True
        # Check for text format with nmap headers
        if "Nmap" in output and ("Host:" in output or "Port:" in output):
            return True
        return False

    def parse(self, output: str) -> NmapScanResult:
        """Parse Nmap output into NmapScanResult for InferenceEngine consumption.

        NOTE: This method now returns NmapScanResult (not List[Finding]).
        For backward compatibility with existing Finding consumers, use
        parse_to_findings() instead.
        """
        # Try XML format first
        if output.strip().startswith("<?xml") or "<nmaprun" in output:
            return self._parse_xml(output)
        else:
            # Fall back to text format
            return self._parse_text(output)

    def parse_to_findings(self, output: str) -> List[Finding]:
        """Parse Nmap output into List[Finding] for backward compatibility.

        This is the legacy interface. New code should work with
        NmapScanResult returned by parse() directly.
        """
        result = self.parse(output)
        findings = []

        for port in result.ports:
            if port.state == "closed":
                continue
            severity = self.SEVERITY_MAP.get(port.state, Severity.MEDIUM)

            description = f"Nmap discovered {port.state} port {port.port}/{port.protocol}"
            if port.service:
                description += f" running {port.service}"
            if port.product:
                description += f" ({port.product}"
                if port.version:
                    description += f" {port.version}"
                description += ")"

            extra_data: Dict[str, object] = {
                "host": port.host,
                "hostname": port.hostname,
                "port": port.port,
                "protocol": port.protocol,
                "state": port.state,
                "service": port.service,
                "product": port.product,
                "version": port.version,
            }
            if port.cpe:
                extra_data["cpe"] = port.cpe

            finding = Finding(
                tool="nmap",
                severity=severity,
                title=f"Open Port: {port.port}/{port.protocol} - {port.service or 'unknown'}"[:100],
                description=description,
                evidence=FindingEvidence(
                    url=f"{port.hostname or port.host}:{port.port}",
                    output=json.dumps(extra_data),
                ),
                phase_found=Phase.RECON,
            )
            findings.append(finding)

        for os_match in result.os_matches:
            if os_match.name:
                finding = Finding(
                    tool="nmap",
                    severity=Severity.INFO,
                    title=f"OS Detection: {os_match.name}",
                    description=f"Nmap detected operating system: {os_match.name} (accuracy: {os_match.accuracy}%)",
                    evidence=FindingEvidence(
                        url=(result.ports[0].host if result.ports else "unknown"),
                        output=os_match.name,
                    ),
                    phase_found=Phase.RECON,
                )
                findings.append(finding)

        return findings

    def _parse_xml(self, output: str) -> NmapScanResult:
        """Parse Nmap XML output into NmapScanResult."""
        ports: List[PortInfo] = []
        os_matches: List[OsMatch] = []
        script_results: List[ScriptResult] = []

        try:
            root = ET.fromstring(output)

            for host in root.findall(".//host"):
                # Host address
                address_elem = host.find("address")
                host_addr: str = address_elem.get("addr") if address_elem is not None else "unknown"

                # Hostnames
                hostnames = host.find("hostnames")
                hostname = ""
                if hostnames is not None:
                    hostname_elem = hostnames.find("hostname")
                    if hostname_elem is not None:
                        hostname = hostname_elem.get("name", "")

                # OS matches
                for os_elem in host.findall(".//osmatch"):
                    os_name = os_elem.get("name", "")
                    os_accuracy_str = os_elem.get("accuracy", "0")
                    try:
                        os_accuracy = int(os_accuracy_str)
                    except ValueError:
                        os_accuracy = 0
                    if os_name:
                        os_matches.append(OsMatch(name=os_name, accuracy=os_accuracy))

                # Ports
                for port in host.findall(".//port"):
                    port_id = port.get("portid", "")
                    protocol = port.get("protocol", "tcp")

                    state_elem = port.find("state")
                    state = (
                        state_elem.get("state", "unknown") if state_elem is not None else "unknown"
                    )

                    service_elem = port.find("service")
                    service_name = ""
                    product = ""
                    version = ""
                    cpe = ""
                    if service_elem is not None:
                        service_name = service_elem.get("name", "")
                        product = service_elem.get("product", "")
                        version = service_elem.get("version", "")
                        # Extract CPE string from <cpe> child element
                        cpe_elem = service_elem.find("cpe")
                        if cpe_elem is not None and cpe_elem.text:
                            cpe = cpe_elem.text.strip()

                    # Script results
                    for script in port.findall("script"):
                        script_id = script.get("id", "")
                        script_output = script.get("output", "")
                        if script_id:
                            script_results.append(
                                ScriptResult(
                                    port=port_id,
                                    script_id=script_id,
                                    output=script_output,
                                )
                            )

                    ports.append(
                        PortInfo(
                            port=port_id,
                            protocol=protocol,
                            state=state,
                            service=service_name,
                            product=product,
                            version=version,
                            cpe=cpe,
                            host=host_addr,  # type: ignore[arg-type]
                            hostname=hostname,
                        )
                    )

        except ET.ParseError:
            pass

        return NmapScanResult(ports=ports, os_matches=os_matches, script_results=script_results)

    def _parse_text(self, output: str) -> NmapScanResult:
        """Parse Nmap text output into NmapScanResult (best-effort)."""
        ports: List[PortInfo] = []
        os_matches: List[OsMatch] = []
        script_results: List[ScriptResult] = []

        lines = output.split("\n")
        current_host = None

        for line in lines:
            # Parse host section
            host_match = re.match(r"Host: ([\w\.\-]+)(?:\s+\(([\w\.\-]+)\))?", line)
            if host_match:
                current_host = host_match.group(1)
                continue

            # Parse port line
            port_match = re.match(r"(\d+)/(tcp|udp)\s+(\w+)\s+(\w+)\s*(.*)", line)
            if port_match and current_host:
                port_id = port_match.group(1)
                protocol = port_match.group(2)
                state = port_match.group(3)
                service = port_match.group(4)
                extra = port_match.group(5)

                # Extract version info
                version = ""
                version_match = re.search(r"(\S+\s+\S+)", extra)
                if version_match:
                    version = version_match.group(1)

                ports.append(
                    PortInfo(
                        port=port_id,
                        protocol=protocol,
                        state=state,
                        service=service,
                        version=version,
                        host=current_host,
                    )
                )

        return NmapScanResult(ports=ports, os_matches=os_matches, script_results=script_results)
