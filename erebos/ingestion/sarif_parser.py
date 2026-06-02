"""SARIF 2.1 JSON parser for external findings ingestion.

VT-Spec R8: SARIF 2.1 format support.
VT-Spec INJ-01: All fields sanitized at parse time.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

from erebos.core.finding import (
    Finding,
    FindingEvidence,
    Phase,
    Severity,
)
from erebos.ingestion.base import (
    MAX_DESCRIPTION_LENGTH,
    MAX_EVIDENCE_LENGTH,
    MAX_TITLE_LENGTH,
    FindingsParser,
    sanitize_text,
)

logger = logging.getLogger(__name__)

# SARIF level to Severity mapping
_LEVEL_MAP: Dict[str, Severity] = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "note": Severity.LOW,
    "none": Severity.INFO,
}


class SARIFParser(FindingsParser):
    """Parser for SARIF 2.1.0 JSON format.

    Supports output from tools like Semgrep, CodeQL, ESLint, etc.
    """

    @property
    def format_name(self) -> str:
        return "sarif"

    def detect(self, content: bytes) -> bool:
        """Detect SARIF format by checking for version field."""
        try:
            text = content[:4096].decode("utf-8", errors="ignore")
            return '"version"' in text and '"2.1.0"' in text and '"runs"' in text
        except Exception:
            return False

    def parse(self, content: bytes) -> List[Finding]:
        """Parse SARIF 2.1 JSON into Finding objects.

        VT-Spec INJ-01: All text fields sanitized before creating Findings.
        """
        try:
            data = json.loads(content)
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            logger.warning("Failed to parse SARIF JSON: %s", e)
            return []

        findings: List[Finding] = []

        for run in data.get("runs", []):
            tool_name = self._extract_tool_name(run)
            rules = self._build_rules_map(run)

            for result in run.get("results", []):
                finding = self._parse_result(result, tool_name, rules)
                if finding:
                    findings.append(finding)

        return findings

    def _extract_tool_name(self, run: Dict[str, Any]) -> str:
        """Extract tool name from SARIF run."""
        tool = run.get("tool", {})
        driver = tool.get("driver", {})
        return sanitize_text(driver.get("name", "unknown"), MAX_TITLE_LENGTH)

    def _build_rules_map(self, run: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        """Build a map of ruleId -> rule metadata."""
        rules: Dict[str, Dict[str, Any]] = {}
        tool = run.get("tool", {})
        driver = tool.get("driver", {})
        for rule in driver.get("rules", []):
            rule_id = rule.get("id", "")
            rules[rule_id] = rule
        return rules

    def _parse_result(
        self,
        result: Dict[str, Any],
        tool_name: str,
        rules: Dict[str, Dict[str, Any]],
    ) -> Optional[Finding]:
        """Parse a single SARIF result into a Finding."""
        rule_id = result.get("ruleId", "unknown")
        level = result.get("level", "warning")
        severity = _LEVEL_MAP.get(level, Severity.MEDIUM)

        # Get message text
        message = result.get("message", {})
        description = message.get("text", "") or message.get("markdown", "")

        # Get title from rule metadata or use ruleId
        rule_meta = rules.get(rule_id, {})
        title = rule_meta.get("shortDescription", {}).get("text", "") or rule_id

        # Get CWE from rule properties
        cwe = self._extract_cwe(rule_meta)

        # Extract location info
        target, evidence_url, location_info = self._extract_location(result)

        # VT-Spec INJ-01: Sanitize all fields at parse time
        title = sanitize_text(title, MAX_TITLE_LENGTH)
        description = sanitize_text(description, MAX_DESCRIPTION_LENGTH)

        evidence = FindingEvidence(
            url=sanitize_text(evidence_url, MAX_EVIDENCE_LENGTH) if evidence_url else None,
            output=sanitize_text(location_info, MAX_EVIDENCE_LENGTH) if location_info else None,
        )

        return Finding(
            tool=tool_name,
            severity=severity,
            title=title,
            description=description,
            target=target,
            evidence=evidence,
            cwe=cwe,
            phase_found=Phase.VULN_SCAN,
        )

    def _extract_cwe(self, rule_meta: Dict[str, Any]) -> Optional[str]:
        """Extract CWE from SARIF rule metadata."""
        properties = rule_meta.get("properties", {})
        tags = properties.get("tags", [])
        for tag in tags:
            if isinstance(tag, str) and tag.startswith("CWE-"):
                return tag
        # Also check relationships for CWE taxonomy
        relationships = rule_meta.get("relationships", [])
        for rel in relationships:
            target = rel.get("target", {})
            tool_component = target.get("toolComponent", {})
            if tool_component.get("name", "").lower() == "cwe":
                return f"CWE-{target.get('id', '')}"
        return None

    def _extract_location(
        self, result: Dict[str, Any]
    ) -> tuple[Optional[str], Optional[str], Optional[str]]:
        """Extract target URL and location info from SARIF result."""
        locations = result.get("locations", [])
        if not locations:
            return None, None, None

        location = locations[0]
        physical = location.get("physicalLocation", {})
        artifact = physical.get("artifactLocation", {})
        uri = artifact.get("uri", "")
        region = physical.get("region", {})

        start_line = region.get("startLine")
        location_info = f"{uri}:{start_line}" if start_line else uri

        # For SAST findings, the target is the file path
        target = uri if uri else None

        return target, uri, location_info
