"""Amass parser for JSON output."""

import json
import re
from typing import List

from erebos.core.finding import Finding, FindingEvidence, Phase, Severity
from erebos.parsers.base import Parser


class AmassParser(Parser):
    """Parser for Amass enum/subdomain enumeration JSON output."""

    tool_name = "amass"

    def can_parse(self, output: str) -> bool:
        """Check if output is Amass JSON format."""
        if not output.strip():
            return False
        # Amass JSON output has "timestamp", "name", "domain" fields
        try:
            data = json.loads(output)
            if isinstance(data, list):
                return all(
                    "name" in item and "domain" in item for item in data if isinstance(item, dict)
                )
            elif isinstance(data, dict):
                return bool(data.get("name")) and bool(data.get("domain"))
        except json.JSONDecodeError:
            pass
        return False

    def parse(self, output: str) -> List[Finding]:
        """Parse Amass JSON output into Finding models."""
        findings = []

        if not output.strip():
            return findings

        try:
            data = json.loads(output)

            # Handle list of records (common Amass JSON format)
            if isinstance(data, list):
                findings = self._parse_list(data)
            elif isinstance(data, dict):
                # Handle single record or nested structure
                findings = self._parse_dict(data)
        except json.JSONDecodeError:
            pass

        return findings

    def _parse_list(self, data: list) -> List[Finding]:
        """Parse a list of Amass JSON records."""
        findings = []

        for record in data:
            if not isinstance(record, dict):
                continue

            name = record.get("name", "")
            domain = record.get("domain", "")
            record_type = record.get("type", "")
            source = record.get("source", "")
            timestamp = record.get("timestamp", "")
            # extra tags field (if present)

            if not name:
                continue

            # Determine severity based on record type
            severity = self._severity_for_type(record_type)

            # Build URL (FQDN)
            url = name if "@" not in name else name

            # Build description
            description = f"Amass discovered subdomain '{name}'"
            if domain:
                description += f" in domain '{domain}'"
            if record_type:
                description += f" (type: {record_type})"
            if source:
                description += f" via {source}"

            finding = Finding(
                tool="amass",
                severity=severity,
                title=f"Subdomain: {name}",
                description=description,
                evidence=FindingEvidence(
                    url=url,
                    output=json.dumps(
                        {
                            "name": name,
                            "domain": domain,
                            "type": record_type,
                            "source": source,
                            "timestamp": timestamp,
                        }
                    ),
                ),
                phase_found=Phase.RECON,
            )
            findings.append(finding)

        return findings

    def _parse_dict(self, data: dict) -> List[Finding]:
        """Parse a single Amass JSON record (dict format)."""
        return self._parse_list([data])

    def _severity_for_type(self, record_type: str) -> Severity:
        """Map DNS record type to severity."""
        type_map = {
            "A": Severity.INFO,
            "AAAA": Severity.INFO,
            "MX": Severity.INFO,
            "TXT": Severity.INFO,
            "NS": Severity.INFO,
            "CNAME": Severity.LOW,
            "PTR": Severity.LOW,
            "SOA": Severity.INFO,
            "SRV": Severity.LOW,
            "SPF": Severity.INFO,
            "DKIM": Severity.INFO,
            "DMARC": Severity.INFO,
            "WS": Severity.INFO,
            "WSS": Severity.INFO,
            "SVCB": Severity.INFO,
            "HTTPS": Severity.INFO,
        }
        return type_map.get(record_type.upper(), Severity.INFO)
