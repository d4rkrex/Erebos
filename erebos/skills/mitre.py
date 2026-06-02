"""MITRE ATT&CK Mapping for Erebos (REQ-007).

Maps skills to MITRE techniques and tracks engagement coverage.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional

from pydantic import BaseModel

from erebos.skills.catalog import Skill

logger = logging.getLogger(__name__)


class TechniqueInfo(BaseModel):
    """MITRE ATT&CK technique information."""

    technique_id: str
    tactic: str
    name: str
    description: str = ""


# Built-in MITRE ATT&CK mapping database
MITRE_DATABASE: Dict[str, TechniqueInfo] = {
    "T1046": TechniqueInfo(
        technique_id="T1046",
        tactic="discovery",
        name="Network Service Discovery",
        description="Adversaries may attempt to get a listing of services running on remote hosts.",
    ),
    "T1595": TechniqueInfo(
        technique_id="T1595",
        tactic="reconnaissance",
        name="Active Scanning",
        description="Adversaries may execute active reconnaissance scans to gather information.",
    ),
    "T1595.001": TechniqueInfo(
        technique_id="T1595.001",
        tactic="reconnaissance",
        name="Scanning IP Blocks",
        description="Adversaries may scan IP blocks to gather victim network information.",
    ),
    "T1595.002": TechniqueInfo(
        technique_id="T1595.002",
        tactic="reconnaissance",
        name="Vulnerability Scanning",
        description="Adversaries may scan victims for vulnerabilities.",
    ),
    "T1190": TechniqueInfo(
        technique_id="T1190",
        tactic="initial-access",
        name="Exploit Public-Facing Application",
        description="Adversaries may exploit vulnerabilities in internet-facing applications.",
    ),
    "T1078": TechniqueInfo(
        technique_id="T1078",
        tactic="initial-access",
        name="Valid Accounts",
        description="Adversaries may obtain and use credentials of existing accounts.",
    ),
    "T1110": TechniqueInfo(
        technique_id="T1110",
        tactic="credential-access",
        name="Brute Force",
        description="Adversaries may use brute force techniques to gain access to accounts.",
    ),
    "T1210": TechniqueInfo(
        technique_id="T1210",
        tactic="lateral-movement",
        name="Exploitation of Remote Services",
        description="Adversaries may exploit remote services to gain access to internal systems.",
    ),
    "T1059": TechniqueInfo(
        technique_id="T1059",
        tactic="execution",
        name="Command and Scripting Interpreter",
        description="Adversaries may abuse command and script interpreters to execute commands.",
    ),
    "T1592": TechniqueInfo(
        technique_id="T1592",
        tactic="reconnaissance",
        name="Gather Victim Host Information",
        description="Adversaries may gather information about the victim's hosts.",
    ),
    "T1018": TechniqueInfo(
        technique_id="T1018",
        tactic="discovery",
        name="Remote System Discovery",
        description="Adversaries may attempt to get a listing of other systems on a network.",
    ),
}


class MitreMapper:
    """Maps skills to MITRE ATT&CK techniques and tracks coverage."""

    def __init__(self) -> None:
        self._coverage: Dict[str, Dict[str, List[str]]] = {}  # engagement_id → {tactic: [techniques]}

    def map_skill(self, skill: Skill) -> Optional[TechniqueInfo]:
        """Map a skill to its MITRE ATT&CK technique."""
        if not skill.technique_id:
            return None
        return MITRE_DATABASE.get(skill.technique_id)

    def record_technique_used(self, engagement_id: str, technique_id: str) -> None:
        """Record that a technique was used in an engagement."""
        if engagement_id not in self._coverage:
            self._coverage[engagement_id] = {}

        info = MITRE_DATABASE.get(technique_id)
        if not info:
            return

        tactic = info.tactic
        if tactic not in self._coverage[engagement_id]:
            self._coverage[engagement_id][tactic] = []

        if technique_id not in self._coverage[engagement_id][tactic]:
            self._coverage[engagement_id][tactic].append(technique_id)

    def get_coverage(self, engagement_id: str) -> Dict[str, List[str]]:
        """Get MITRE coverage for an engagement (tactic → techniques attempted)."""
        return self._coverage.get(engagement_id, {})

    def suggest_untried(self, engagement_id: str) -> List[TechniqueInfo]:
        """Suggest techniques not yet tried in this engagement."""
        tried: set[str] = set()
        coverage = self._coverage.get(engagement_id, {})
        for techniques in coverage.values():
            tried.update(techniques)

        suggestions = []
        for tech_id, info in MITRE_DATABASE.items():
            if tech_id not in tried:
                suggestions.append(info)

        return suggestions

    def generate_coverage_report(self, engagement_id: str) -> dict:
        """Generate a coverage report for the engagement."""
        coverage = self.get_coverage(engagement_id)
        all_tactics = set(info.tactic for info in MITRE_DATABASE.values())
        covered_tactics = set(coverage.keys())

        total_techniques = len(MITRE_DATABASE)
        tried_techniques = sum(len(v) for v in coverage.values())

        return {
            "engagement_id": engagement_id,
            "tactics_covered": list(covered_tactics),
            "tactics_total": list(all_tactics),
            "tactic_coverage_pct": (
                round(len(covered_tactics) / len(all_tactics) * 100, 1)
                if all_tactics
                else 0
            ),
            "techniques_tried": tried_techniques,
            "techniques_total": total_techniques,
            "technique_coverage_pct": (
                round(tried_techniques / total_techniques * 100, 1)
                if total_techniques
                else 0
            ),
            "coverage_by_tactic": coverage,
        }
