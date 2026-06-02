"""Purple Team Mode for Erebos (REQ-004).

Generates defensive recommendations: Sigma detection rules,
hardening recommendations, MITRE ATT&CK coverage maps.

# VT-Spec REQ-004: Per-technique Sigma rules and hardening
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from erebos.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


# ── MITRE ATT&CK Technique Metadata ──────────────────────────────────────────

TECHNIQUE_METADATA: Dict[str, Dict[str, str]] = {
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution"},
    "T1059.001": {"name": "PowerShell", "tactic": "Execution"},
    "T1059.003": {"name": "Windows Command Shell", "tactic": "Execution"},
    "T1059.004": {"name": "Unix Shell", "tactic": "Execution"},
    "T1021": {"name": "Remote Services", "tactic": "Lateral Movement"},
    "T1021.001": {"name": "Remote Desktop Protocol", "tactic": "Lateral Movement"},
    "T1021.002": {"name": "SMB/Windows Admin Shares", "tactic": "Lateral Movement"},
    "T1021.004": {"name": "SSH", "tactic": "Lateral Movement"},
    "T1046": {"name": "Network Service Discovery", "tactic": "Discovery"},
    "T1071": {"name": "Application Layer Protocol", "tactic": "Command and Control"},
    "T1078": {"name": "Valid Accounts", "tactic": "Persistence"},
    "T1110": {"name": "Brute Force", "tactic": "Credential Access"},
    "T1133": {"name": "External Remote Services", "tactic": "Initial Access"},
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "T1210": {"name": "Exploitation of Remote Services", "tactic": "Lateral Movement"},
    "T1505": {"name": "Server Software Component", "tactic": "Persistence"},
    "T1505.003": {"name": "Web Shell", "tactic": "Persistence"},
    "T1543": {"name": "Create or Modify System Process", "tactic": "Persistence"},
    "T1548": {"name": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation"},
    "T1562": {"name": "Impair Defenses", "tactic": "Defense Evasion"},
    "T1595": {"name": "Active Scanning", "tactic": "Reconnaissance"},
}


@dataclass
class SigmaRule:
    """A Sigma detection rule."""

    title: str
    description: str
    technique_id: str
    log_source: Dict[str, str]
    detection: Dict[str, Any]
    level: str = "medium"
    tags: List[str] = field(default_factory=list)

    def to_yaml_str(self) -> str:
        """Convert to Sigma YAML string format."""
        lines = [
            f"title: {self.title}",
            f"description: {self.description}",
            f"status: experimental",
            f"level: {self.level}",
            f"tags:",
        ]
        for tag in self.tags:
            lines.append(f"  - {tag}")
        lines.append("logsource:")
        for k, v in self.log_source.items():
            lines.append(f"  {k}: {v}")
        lines.append("detection:")
        lines.append("  selection:")
        for k, v in self.detection.get("selection", {}).items():
            if isinstance(v, list):
                lines.append(f"    {k}:")
                for item in v:
                    lines.append(f"      - '{item}'")
            else:
                lines.append(f"    {k}: '{v}'")
        lines.append("  condition: selection")
        return "\n".join(lines)


@dataclass
class HardeningRecommendation:
    """A hardening recommendation for a finding."""

    finding_title: str
    severity: str
    cve: Optional[str]
    patch_version: Optional[str] = None
    configuration_changes: List[str] = field(default_factory=list)
    compensating_controls: List[str] = field(default_factory=list)


@dataclass
class CoverageEntry:
    """An entry in the ATT&CK coverage map."""

    technique_id: str
    technique_name: str
    tactic: str
    tested: bool = False
    succeeded: bool = False


class PurpleTeamAdvisor:
    """Generates defensive recommendations from offensive findings.

    Per REQ-004:
    - Sigma detection rules per technique
    - Hardening recommendations per finding
    - MITRE ATT&CK coverage map
    - Defensive gaps analysis
    """

    def __init__(self, techniques_used: Optional[List[str]] = None):
        self._techniques_used: List[str] = techniques_used or []
        self._techniques_succeeded: Set[str] = set()

    def add_technique(self, technique_id: str, succeeded: bool = False) -> None:
        """Record a technique that was used."""
        if technique_id not in self._techniques_used:
            self._techniques_used.append(technique_id)
        if succeeded:
            self._techniques_succeeded.add(technique_id)

    def generate_sigma_rules(self) -> List[SigmaRule]:
        """Generate Sigma detection rules for each technique used.

        Per REQ-004 Scenario: Sigma-format detection rules with
        log source, detection logic, and severity level.
        """
        rules: List[SigmaRule] = []

        for tech_id in self._techniques_used:
            rule = self._sigma_rule_for_technique(tech_id)
            if rule:
                rules.append(rule)

        return rules

    def _sigma_rule_for_technique(self, technique_id: str) -> Optional[SigmaRule]:
        """Generate a Sigma rule for a specific technique."""
        meta = TECHNIQUE_METADATA.get(technique_id)
        if not meta:
            # Generic rule for unknown techniques
            return SigmaRule(
                title=f"Erebos Detection: {technique_id}",
                description=f"Detects activity matching MITRE ATT&CK technique {technique_id}",
                technique_id=technique_id,
                log_source={"category": "process_creation", "product": "linux"},
                detection={"selection": {"CommandLine|contains": [technique_id]}},
                level="medium",
                tags=[f"attack.{technique_id.lower()}"],
            )

        # Technique-specific rules
        if technique_id.startswith("T1059"):
            return SigmaRule(
                title=f"Erebos: {meta['name']} Execution Detected",
                description=f"Detects {meta['name']} execution patterns observed during pentest",
                technique_id=technique_id,
                log_source={"category": "process_creation", "product": "linux"},
                detection={
                    "selection": {
                        "CommandLine|contains": ["/bin/sh", "/bin/bash", "python", "perl", "ruby"],
                        "ParentImage|endswith": ["/sshd", "/apache2", "/nginx"],
                    }
                },
                level="high",
                tags=[f"attack.execution", f"attack.{technique_id.lower()}"],
            )
        elif technique_id.startswith("T1021"):
            return SigmaRule(
                title=f"Erebos: {meta['name']} Lateral Movement",
                description=f"Detects {meta['name']} used for lateral movement",
                technique_id=technique_id,
                log_source={"category": "network_connection", "product": "firewall"},
                detection={
                    "selection": {
                        "DestinationPort": ["22", "3389", "445", "5985"],
                        "Action": ["allow"],
                    }
                },
                level="medium",
                tags=[f"attack.lateral_movement", f"attack.{technique_id.lower()}"],
            )
        elif technique_id == "T1190":
            return SigmaRule(
                title="Erebos: Public-Facing Application Exploitation",
                description="Detects exploitation attempts against public-facing applications",
                technique_id=technique_id,
                log_source={"category": "webserver", "product": "apache"},
                detection={
                    "selection": {
                        "cs-uri-query|contains": ["../", "cmd=", "exec(", "UNION SELECT"],
                        "sc-status": ["200", "500"],
                    }
                },
                level="high",
                tags=["attack.initial_access", "attack.t1190"],
            )
        elif technique_id == "T1046":
            return SigmaRule(
                title="Erebos: Network Service Discovery (Port Scan)",
                description="Detects port scanning activity from pentest",
                technique_id=technique_id,
                log_source={"category": "network_connection", "product": "firewall"},
                detection={
                    "selection": {
                        "Action": ["blocked", "denied"],
                    }
                },
                level="low",
                tags=["attack.discovery", "attack.t1046"],
            )
        else:
            return SigmaRule(
                title=f"Erebos: {meta['name']}",
                description=f"Detects {meta['name']} ({meta['tactic']})",
                technique_id=technique_id,
                log_source={"category": "process_creation", "product": "linux"},
                detection={"selection": {"CommandLine|contains": [technique_id]}},
                level="medium",
                tags=[f"attack.{meta['tactic'].lower().replace(' ', '_')}", f"attack.{technique_id.lower()}"],
            )

    def generate_hardening_recommendations(
        self, findings: List[Finding]
    ) -> List[HardeningRecommendation]:
        """Generate hardening recommendations per finding.

        Per REQ-004: Specific hardening steps tied to each finding.
        """
        recommendations: List[HardeningRecommendation] = []

        for finding in findings:
            rec = HardeningRecommendation(
                finding_title=finding.title,
                severity=str(finding.severity),
                cve=finding.cve,
            )

            # Generate specific recommendations based on severity and type
            if finding.cve:
                rec.patch_version = f"Apply patch for {finding.cve}"

            sev_str = str(finding.severity).upper()
            if sev_str in ("CRITICAL", "HIGH"):
                rec.configuration_changes.append(
                    "Implement WAF rules to block exploitation attempts"
                )
                rec.compensating_controls.append(
                    "Network segmentation to limit blast radius"
                )

            if finding.suggested_fix:
                rec.configuration_changes.append(finding.suggested_fix)

            # Add generic controls based on finding characteristics
            rec.compensating_controls.append("Monitor for exploitation indicators (see Sigma rules)")
            rec.compensating_controls.append("Ensure logging is enabled for affected service")

            recommendations.append(rec)

        return recommendations

    def generate_coverage_map(
        self, scope_techniques: Optional[List[str]] = None
    ) -> List[CoverageEntry]:
        """Generate MITRE ATT&CK coverage map.

        Shows which techniques were tested, succeeded, and identifies gaps.
        """
        # Default scope: all known techniques
        all_techniques = scope_techniques or list(TECHNIQUE_METADATA.keys())

        coverage: List[CoverageEntry] = []
        for tech_id in all_techniques:
            meta = TECHNIQUE_METADATA.get(tech_id, {"name": tech_id, "tactic": "unknown"})
            entry = CoverageEntry(
                technique_id=tech_id,
                technique_name=meta["name"],
                tactic=meta["tactic"],
                tested=tech_id in self._techniques_used,
                succeeded=tech_id in self._techniques_succeeded,
            )
            coverage.append(entry)

        return coverage

    def generate_gaps_analysis(
        self, scope_techniques: Optional[List[str]] = None
    ) -> Dict[str, List[str]]:
        """Identify defensive gaps — untested techniques in scope.

        Returns dict of tactic -> list of untested technique IDs.
        """
        coverage = self.generate_coverage_map(scope_techniques)
        gaps: Dict[str, List[str]] = {}

        for entry in coverage:
            if not entry.tested:
                gaps.setdefault(entry.tactic, []).append(entry.technique_id)

        return gaps

    def generate_report(
        self,
        findings: List[Finding],
        scope_techniques: Optional[List[str]] = None,
    ) -> str:
        """Generate full purple team markdown report."""
        lines: List[str] = []

        lines.append("# Purple Team Report")
        lines.append("")
        lines.append("## Overview")
        lines.append("")

        if not self._techniques_used:
            lines.append(
                "No active exploitation techniques were used during this engagement. "
                "Only reconnaissance was performed. A full pentest is recommended "
                "for comprehensive ATT&CK coverage assessment."
            )
            lines.append("")
            return "\n".join(lines)

        lines.append(f"- **Techniques Tested:** {len(self._techniques_used)}")
        lines.append(f"- **Techniques Succeeded:** {len(self._techniques_succeeded)}")
        lines.append("")

        # Sigma Rules
        rules = self.generate_sigma_rules()
        if rules:
            lines.append("## Detection Rules (Sigma Format)")
            lines.append("")
            for rule in rules:
                lines.append(f"### {rule.title}")
                lines.append("")
                lines.append(f"**Technique:** {rule.technique_id}")
                lines.append(f"**Level:** {rule.level}")
                lines.append("")
                lines.append("```yaml")
                lines.append(rule.to_yaml_str())
                lines.append("```")
                lines.append("")

        # Hardening
        recommendations = self.generate_hardening_recommendations(findings)
        if recommendations:
            lines.append("## Hardening Recommendations")
            lines.append("")
            for rec in recommendations:
                lines.append(f"### {rec.finding_title} ({rec.severity})")
                if rec.cve:
                    lines.append(f"**CVE:** {rec.cve}")
                if rec.patch_version:
                    lines.append(f"**Patch:** {rec.patch_version}")
                if rec.configuration_changes:
                    lines.append("**Configuration Changes:**")
                    for change in rec.configuration_changes:
                        lines.append(f"  - {change}")
                if rec.compensating_controls:
                    lines.append("**Compensating Controls:**")
                    for ctrl in rec.compensating_controls:
                        lines.append(f"  - {ctrl}")
                lines.append("")

        # Coverage Map
        coverage = self.generate_coverage_map(scope_techniques)
        lines.append("## MITRE ATT&CK Coverage Map")
        lines.append("")
        lines.append("| Technique | Name | Tactic | Tested | Succeeded |")
        lines.append("|-----------|------|--------|--------|-----------|")
        for entry in coverage:
            tested = "✅" if entry.tested else "❌"
            succeeded = "✅" if entry.succeeded else ("❌" if entry.tested else "—")
            lines.append(
                f"| {entry.technique_id} | {entry.technique_name} | {entry.tactic} | {tested} | {succeeded} |"
            )
        lines.append("")

        # Gaps
        gaps = self.generate_gaps_analysis(scope_techniques)
        if gaps:
            lines.append("## Defensive Gaps (Untested Techniques)")
            lines.append("")
            for tactic, techs in gaps.items():
                lines.append(f"### {tactic}")
                for t in techs:
                    meta = TECHNIQUE_METADATA.get(t, {"name": t})
                    lines.append(f"  - {t}: {meta['name']}")
            lines.append("")

        return "\n".join(lines)
