"""Nuclei parser for JSON output."""

import json
from typing import List

from erebos.core.finding import Finding, FindingEvidence, Phase, Severity
from erebos.parsers.base import Parser


class NucleiParser(Parser):
    """Parser for Nuclei JSON output."""

    tool_name = "nuclei"

    SEVERITY_MAP = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
    }

    def can_parse(self, output: str) -> bool:
        """Check if output is Nuclei JSON format."""
        items = self._load_items(output)
        return bool(items) and ("template-id" in items[0] or "info" in items[0])

    def parse(self, output: str) -> List[Finding]:
        """Parse Nuclei JSON output into Finding models."""
        findings = []

        for item in self._load_items(output):
            info = item.get("info", {})
            severity_str = item.get("severity", "info")
            if not severity_str or severity_str == "info":
                severity_str = info.get("severity", "info")
            severity_str = severity_str.lower()
            severity = self.SEVERITY_MAP.get(severity_str, Severity.INFO)
            cve = None
            cwe = None

            if "cve-id" in info:
                cve = info["cve-id"]
            if "cwe" in info:
                cwe = info["cwe"]

            matched_at = item.get("matched-at", "")
            extracted_results = item.get("extracted-results", [])

            evidence = FindingEvidence(
                url=matched_at,
                output=json.dumps(extracted_results) if extracted_results else None,
            )

            description = info.get("description", "")
            if not description:
                description = info.get("name", "")

            finding = Finding(
                tool="nuclei",
                severity=severity,
                title=info.get("name", "Unknown"),
                description=description,
                target=item.get("host", matched_at),
                evidence=evidence,
                cve=cve,
                cwe=cwe,
                suggested_fix=", ".join(info["reference"]) if isinstance(info.get("reference"), list) else info.get("reference"),
                phase_found=Phase.VULN_SCAN,
            )
            findings.append(finding)

        return findings

    def _load_items(self, output: str) -> List[dict]:
        stripped = output.strip()
        if not stripped:
            return []

        try:
            data = json.loads(stripped)
        except json.JSONDecodeError:
            items: List[dict] = []
            for line in stripped.splitlines():
                line = line.strip()
                if not line or line.startswith("["):
                    # Skip empty lines and nuclei v3 warning/info lines like [WRN], [INF]
                    if not line.startswith("{"):
                        continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue  # Skip non-JSON lines (warnings, banners)
                if isinstance(item, dict):
                    items.append(item)
            return items

        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        if isinstance(data, dict):
            return [data]
        return []
