"""Inter-agent correlation engine — multi-signal finding prioritization.

VT-Spec T-01: Confidence threshold + source diversity validation.
VT-Spec D-01: Cap at 500 findings, 30s timeout on correlation.
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set

from pydantic import BaseModel, Field

from erebos.agents.base import AgentMessage, AgentRole, FindingsBus

logger = logging.getLogger(__name__)

# VT-Spec D-01: Correlation limits
MAX_CORRELATION_FINDINGS = 500
CORRELATION_TIMEOUT_SECONDS = 30


class CorrelatedFinding(BaseModel):
    """A finding enriched with correlation data."""

    title: str
    target: str = ""
    severity: str = "INFO"
    cve: Optional[str] = None
    cwe: Optional[str] = None
    signals: List[str] = Field(default_factory=list)  # roles that reported it
    signal_count: int = 0
    priority_score: int = 0
    correlation_boost: int = 0
    source_findings: List[Dict[str, Any]] = Field(default_factory=list)


class PriorityScorer:
    """Compute priority score (0-100) for findings.

    Scoring formula:
    - Severity: critical=40, high=30, medium=20, low=10, info=0
    - Correlation boost: +20 per additional signal (cap +40)
    - Exploitability: template_available=+15, auth_gap_confirmed=+10
    """

    SEVERITY_WEIGHTS = {
        "CRITICAL": 40,
        "HIGH": 30,
        "MEDIUM": 20,
        "LOW": 10,
        "INFO": 0,
    }

    def score(
        self,
        finding: CorrelatedFinding,
        template_available: bool = False,
        auth_gap_confirmed: bool = False,
    ) -> int:
        """Compute priority score for a correlated finding."""
        score = 0

        # Severity weight
        score += self.SEVERITY_WEIGHTS.get(finding.severity.upper(), 0)

        # Correlation boost: +20 per extra signal, capped at +40
        extra_signals = max(0, finding.signal_count - 1)
        correlation_boost = min(extra_signals * 20, 40)
        score += correlation_boost

        # Exploitability bonuses
        if template_available:
            score += 15
        if auth_gap_confirmed:
            score += 10

        return min(score, 100)


class CorrelationEngine:
    """Correlates findings from multiple agents for prioritized exploitation.

    VT-Spec T-01: Only processes validated bus messages, requires source diversity.
    VT-Spec D-01: Capped at 500 findings, 30s wall-clock timeout.
    """

    def __init__(self, bus: FindingsBus, scorer: Optional[PriorityScorer] = None):
        self._bus = bus
        self._scorer = scorer or PriorityScorer()

    def correlate(self) -> List[CorrelatedFinding]:
        """Run correlation across all bus findings.

        VT-Spec D-01: Caps input and enforces timeout.
        VT-Spec T-01: Validates source diversity (same role = no boost).
        """
        start = time.time()

        # Gather findings from bus (D-01: cap at MAX)
        raw_findings = self._gather_findings()

        # Group by correlation key (target + normalized title/CWE)
        groups = self._group_findings(raw_findings)

        # Build correlated findings with priority scores
        results: List[CorrelatedFinding] = []
        for key, group in groups.items():
            # D-01: Timeout check
            if time.time() - start > CORRELATION_TIMEOUT_SECONDS:
                logger.warning("D-01: Correlation timeout (30s) — returning partial results")
                break

            correlated = self._build_correlated(key, group)
            results.append(correlated)

        # Sort by priority score descending
        results.sort(key=lambda f: f.priority_score, reverse=True)

        duration_ms = (time.time() - start) * 1000
        logger.info(
            f"Correlation complete: {len(results)} correlated findings "
            f"from {len(raw_findings)} raw ({duration_ms:.0f}ms)"
        )

        return results

    def publish_results(self, results: List[CorrelatedFinding]) -> None:
        """Publish correlation results to bus."""
        for correlated in results[:50]:  # Cap published correlations
            self._bus.publish(AgentMessage(
                id=f"correlation-{correlated.target}-{correlated.priority_score}",
                role=AgentRole.ORCHESTRATOR,
                message_type="correlation",
                payload=correlated.model_dump(mode="json"),
            ))

    def _gather_findings(self) -> List[Dict[str, Any]]:
        """Read findings from bus with cap (D-01)."""
        findings: List[Dict[str, Any]] = []

        for msg in self._bus.subscribe(message_types=["finding"]):
            findings.append({
                "role": msg.role.value,
                "payload": msg.payload,
            })
            # D-01: Cap
            if len(findings) >= MAX_CORRELATION_FINDINGS:
                logger.warning(
                    f"D-01: Correlation capped at {MAX_CORRELATION_FINDINGS} findings"
                )
                break

        return findings

    def _group_findings(
        self, findings: List[Dict[str, Any]]
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Group findings by correlation key (target + CWE/title)."""
        groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

        for f in findings:
            payload = f.get("payload", {})
            target = (payload.get("target") or "").lower().split(":")[0]
            # Use CWE if available, else normalized title
            cwe = payload.get("cwe", "")
            title = (payload.get("title") or "").lower()[:50]
            key = f"{target}|{cwe or title}"
            groups[key].append(f)

        return dict(groups)

    def _build_correlated(
        self, key: str, group: List[Dict[str, Any]]
    ) -> CorrelatedFinding:
        """Build a CorrelatedFinding from a group of raw findings.

        VT-Spec T-01: Source diversity — same role doesn't count as extra signal.
        """
        # T-01: Count unique roles (source diversity)
        unique_roles: Set[str] = set()
        for f in group:
            unique_roles.add(f["role"])

        # Use highest severity from group
        severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        max_severity = "INFO"
        for f in group:
            sev = (f["payload"].get("severity") or "INFO").upper()
            if sev in severities and severities.index(sev) < severities.index(max_severity):
                max_severity = sev

        # First finding provides base data
        first = group[0]["payload"]
        target_parts = key.split("|", 1)

        correlated = CorrelatedFinding(
            title=first.get("title", "Unknown"),
            target=target_parts[0] if target_parts else "",
            severity=max_severity,
            cve=first.get("cve"),
            cwe=first.get("cwe"),
            signals=sorted(unique_roles),
            signal_count=len(unique_roles),
            source_findings=[f["payload"] for f in group[:5]],  # Cap stored sources
        )

        # Check for auth gap (code-audit signal)
        auth_gap = "code-audit" in unique_roles
        # Check template availability (we'd need TemplateEngine, approximate here)
        template_avail = correlated.cwe is not None

        correlated.priority_score = self._scorer.score(
            correlated,
            template_available=template_avail,
            auth_gap_confirmed=auth_gap,
        )
        correlated.correlation_boost = min((len(unique_roles) - 1) * 20, 40)

        return correlated
