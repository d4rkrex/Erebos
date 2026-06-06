"""Evidence chain builder — constructs multi-finding attack chains.

Links related findings into coherent attack narratives:
- Groups by same target + path
- Identifies CWE escalation patterns (info-leak → injection → RCE)
- Assigns chain severity = max(individual) + chain_bonus
- Produces narratives for executive reporting
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from erebos.core.finding import Finding

logger = logging.getLogger(__name__)

# CWE escalation graph: finding one CWE can lead to exploitation of another
CWE_ESCALATION: Dict[str, List[str]] = {
    # Info disclosure → further attacks
    "CWE-200": ["CWE-89", "CWE-78", "CWE-287"],  # info leak → injection/auth bypass
    "CWE-532": ["CWE-200", "CWE-287"],  # log exposure → info/auth
    "CWE-548": ["CWE-200", "CWE-22"],  # dir listing → info/path traversal
    # Injection chains
    "CWE-89": ["CWE-78", "CWE-284"],  # SQLi → OS cmd / access control
    "CWE-78": ["CWE-250", "CWE-269"],  # cmd injection → privilege escalation
    "CWE-917": ["CWE-78", "CWE-94"],  # SSTI → cmd injection / code injection
    # Auth/session chains
    "CWE-287": ["CWE-284", "CWE-269"],  # auth bypass → access control / priv esc
    "CWE-384": ["CWE-287"],  # session fixation → auth bypass
    "CWE-613": ["CWE-287"],  # session expiration → auth bypass
    # File-based chains
    "CWE-22": ["CWE-94", "CWE-434"],  # path traversal → code injection / file upload
    "CWE-434": ["CWE-78", "CWE-94"],  # file upload → cmd injection / code exec
    # Deserialization
    "CWE-502": ["CWE-78", "CWE-94"],  # deserialization → RCE
    # XSS chains
    "CWE-79": ["CWE-384", "CWE-352"],  # XSS → session hijack / CSRF
    # SSRF
    "CWE-918": ["CWE-200", "CWE-284"],  # SSRF → internal info / access control
}

SEVERITY_ORDER = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}

# Bonus severity for chain length
CHAIN_BONUS: Dict[int, str] = {
    2: "LOW",  # 2-step chain: minor bonus
    3: "MEDIUM",  # 3-step: notable
    4: "HIGH",  # 4+: significant escalation path
}


@dataclass
class ChainLink:
    """A single link in an evidence chain."""

    finding: Finding
    position: int  # 0-indexed position in chain
    role: str  # "entry_point" | "pivot" | "escalation" | "impact"
    contributes_cwe: Optional[str] = None

    @property
    def summary(self) -> str:
        """One-line summary for reporting."""
        return f"[{self.role.upper()}] {self.finding.severity} — {self.finding.title}"


@dataclass
class EvidenceChain:
    """A complete attack chain linking multiple findings."""

    chain_id: str
    links: List[ChainLink] = field(default_factory=list)
    target: str = ""
    narrative: str = ""
    chain_severity: str = "LOW"
    chain_confidence: float = 0.0
    tags: List[str] = field(default_factory=list)

    @property
    def length(self) -> int:
        return len(self.links)

    @property
    def entry_point(self) -> Optional[ChainLink]:
        """First link in the chain."""
        return self.links[0] if self.links else None

    @property
    def impact(self) -> Optional[ChainLink]:
        """Final/highest-severity link."""
        return self.links[-1] if self.links else None

    @property
    def finding_ids(self) -> List[str]:
        return [link.finding.id for link in self.links]

    def to_dict(self) -> Dict[str, Any]:
        """Serialize for reporting."""
        return {
            "chain_id": self.chain_id,
            "target": self.target,
            "severity": self.chain_severity,
            "confidence": self.chain_confidence,
            "length": self.length,
            "narrative": self.narrative,
            "tags": self.tags,
            "links": [
                {
                    "position": link.position,
                    "role": link.role,
                    "finding_title": link.finding.title,
                    "severity": link.finding.severity,
                    "cwe": link.finding.cwe,
                }
                for link in self.links
            ],
        }


class ChainBuilder:
    """Builds evidence chains from a collection of findings.

    Strategies:
    1. Target grouping: findings on same target/endpoint
    2. CWE escalation: known escalation paths between CWEs
    3. Phase progression: recon → discovery → vuln → exploit
    """

    def __init__(self, min_chain_length: int = 2, max_chain_length: int = 6):
        self._min_length = min_chain_length
        self._max_length = max_chain_length

    def build_chains(self, findings: List[Finding]) -> List[EvidenceChain]:
        """Build all evidence chains from findings.

        Returns chains sorted by severity (highest first).
        """
        if not findings:
            return []

        chains: List[EvidenceChain] = []

        # Strategy 1: CWE escalation chains
        cwe_chains = self._build_cwe_escalation_chains(findings)
        chains.extend(cwe_chains)

        # Strategy 2: Target-based chains (same endpoint, different vulns)
        target_chains = self._build_target_chains(findings)
        chains.extend(target_chains)

        # Deduplicate (don't use same finding in multiple chains)
        chains = self._deduplicate_chains(chains)

        # Sort by severity
        chains.sort(key=lambda c: SEVERITY_ORDER.get(c.chain_severity, 0), reverse=True)

        return chains

    def _build_cwe_escalation_chains(self, findings: List[Finding]) -> List[EvidenceChain]:
        """Build chains based on CWE escalation patterns."""
        chains: List[EvidenceChain] = []
        cwe_to_findings: Dict[str, List[Finding]] = {}

        for f in findings:
            if f.cwe:
                cwe_to_findings.setdefault(f.cwe, []).append(f)

        # For each finding, try to build an escalation path
        visited: Set[str] = set()
        for cwe, cwe_findings in cwe_to_findings.items():
            if cwe in visited:
                continue

            # Try to build chain from this CWE
            chain_cwes = self._trace_escalation(cwe, cwe_to_findings, visited)
            if len(chain_cwes) >= self._min_length:
                chain = self._cwes_to_chain(chain_cwes, cwe_to_findings)
                if chain:
                    chains.append(chain)

        return chains

    def _trace_escalation(
        self,
        start_cwe: str,
        available: Dict[str, List[Finding]],
        visited: Set[str],
    ) -> List[str]:
        """Trace an escalation path from a starting CWE using BFS."""
        path = [start_cwe]
        visited.add(start_cwe)
        current = start_cwe

        for _ in range(self._max_length - 1):
            next_cwes = CWE_ESCALATION.get(current, [])
            # Find next CWE that we have findings for
            found_next = False
            for next_cwe in next_cwes:
                if next_cwe in available and next_cwe not in visited:
                    path.append(next_cwe)
                    visited.add(next_cwe)
                    current = next_cwe
                    found_next = True
                    break
            if not found_next:
                break

        return path

    def _cwes_to_chain(
        self, cwes: List[str], cwe_to_findings: Dict[str, List[Finding]]
    ) -> Optional[EvidenceChain]:
        """Convert a CWE escalation path to an evidence chain."""
        links: List[ChainLink] = []
        target = ""

        for i, cwe in enumerate(cwes):
            findings_for_cwe = cwe_to_findings.get(cwe, [])
            if not findings_for_cwe:
                continue

            # Pick highest-severity finding for this CWE
            f = max(findings_for_cwe, key=lambda x: SEVERITY_ORDER.get(x.severity, 0))
            if not target and f.target:
                target = f.target

            role = "entry_point" if i == 0 else ("impact" if i == len(cwes) - 1 else "escalation")
            links.append(
                ChainLink(finding=f, position=i, role=role, contributes_cwe=cwe)
            )

        if len(links) < self._min_length:
            return None

        chain_id = f"chain-cwe-{'-'.join(cwes[:3])}"
        chain = EvidenceChain(
            chain_id=chain_id,
            links=links,
            target=target,
            tags=["cwe-escalation"],
        )
        chain.chain_severity = self._compute_chain_severity(links)
        chain.chain_confidence = self._compute_chain_confidence(links)
        chain.narrative = self._generate_narrative(chain)
        return chain

    def _build_target_chains(self, findings: List[Finding]) -> List[EvidenceChain]:
        """Build chains from findings on the same target with different phases."""
        chains: List[EvidenceChain] = []
        by_target: Dict[str, List[Finding]] = {}

        for f in findings:
            key = self._normalize_target(f.target)
            if key:
                by_target.setdefault(key, []).append(f)

        for target, target_findings in by_target.items():
            if len(target_findings) < self._min_length:
                continue

            # Sort by phase order
            phase_order = {"recon": 0, "discovery": 1, "vuln-scan": 2, "validation": 3}
            sorted_findings = sorted(
                target_findings,
                key=lambda f: phase_order.get(str(f.phase_found), 5),
            )

            # Only create chain if we have findings from different phases
            phases = {str(f.phase_found) for f in sorted_findings}
            if len(phases) < 2:
                continue

            links = []
            for i, f in enumerate(sorted_findings[: self._max_length]):
                role = (
                    "entry_point"
                    if i == 0
                    else ("impact" if i == len(sorted_findings) - 1 else "pivot")
                )
                links.append(ChainLink(finding=f, position=i, role=role, contributes_cwe=f.cwe))

            chain = EvidenceChain(
                chain_id=f"chain-target-{hashlib.sha256(target.encode()).hexdigest()[:8]}",
                links=links,
                target=target,
                tags=["target-progression"],
            )
            chain.chain_severity = self._compute_chain_severity(links)
            chain.chain_confidence = self._compute_chain_confidence(links)
            chain.narrative = self._generate_narrative(chain)
            chains.append(chain)

        return chains

    def _compute_chain_severity(self, links: List[ChainLink]) -> str:
        """Compute chain severity: max(individual) + length bonus."""
        if not links:
            return "LOW"

        max_sev = max(SEVERITY_ORDER.get(link.finding.severity, 0) for link in links)

        # Chain length bonus
        bonus = CHAIN_BONUS.get(min(len(links), 4), "LOW")
        bonus_val = SEVERITY_ORDER.get(bonus, 0)

        # Cap at CRITICAL
        final = min(max_sev + (bonus_val // 2), 5)

        # Reverse lookup
        for sev, val in SEVERITY_ORDER.items():
            if val == final:
                return sev
        return "HIGH"

    def _compute_chain_confidence(self, links: List[ChainLink]) -> float:
        """Compute chain confidence from individual finding confidences."""
        if not links:
            return 0.0

        confidences = []
        for link in links:
            conf = link.finding.validation_confidence
            confidences.append(conf if conf and conf > 0 else 0.5)

        # Chain confidence degrades slightly with length (more assumptions)
        avg = sum(confidences) / len(confidences)
        length_penalty = 0.95 ** (len(links) - 1)
        return round(avg * length_penalty, 3)

    def _generate_narrative(self, chain: EvidenceChain) -> str:
        """Generate human-readable attack narrative."""
        if not chain.links:
            return ""

        parts = []
        for link in chain.links:
            cwe_str = f" ({link.contributes_cwe})" if link.contributes_cwe else ""
            parts.append(f"{link.finding.title}{cwe_str}")

        entry = chain.links[0].finding
        impact = chain.links[-1].finding

        narrative = (
            f"Attack chain on {chain.target or 'target'}: "
            f"Starting from {entry.title} [{entry.severity}], "
        )
        if len(chain.links) > 2:
            mid_steps = [f"{link.finding.title}" for link in chain.links[1:-1]]
            narrative += f"escalating through {', '.join(mid_steps)}, "
        narrative += (
            f"leading to {impact.title} [{impact.severity}]. "
            f"Chain severity: {chain.chain_severity}."
        )
        return narrative

    def _normalize_target(self, target: Optional[str]) -> str:
        """Normalize target for grouping."""
        if not target:
            return ""
        from urllib.parse import urlparse

        try:
            parsed = urlparse(target)
            if parsed.hostname:
                return f"{parsed.hostname}{parsed.path}".rstrip("/")
        except Exception:
            pass
        return target.strip().rstrip("/")

    def _deduplicate_chains(self, chains: List[EvidenceChain]) -> List[EvidenceChain]:
        """Remove chains that reuse the same findings."""
        used_findings: Set[str] = set()
        result: List[EvidenceChain] = []

        # Sort by severity (keep best chains)
        chains.sort(key=lambda c: SEVERITY_ORDER.get(c.chain_severity, 0), reverse=True)

        for chain in chains:
            chain_finding_ids = set(chain.finding_ids)
            # Allow partial overlap (>50% new findings)
            overlap = chain_finding_ids & used_findings
            if len(overlap) <= len(chain_finding_ids) / 2:
                result.append(chain)
                used_findings.update(chain_finding_ids)

        return result
