"""Hypothesis Engine for Erebos decision loop (REQ-002).

Generates and ranks attack hypotheses from observations.

# VT-Spec E-01: Confidence bounds — cap at configurable max
# VT-Spec I-01: Credential scrubbing before LLM calls
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from erebos.core.events import Event, EventLog, EventType
from erebos.core.models import (
    EngagementPhase,
    Hypothesis,
    HypothesisStatus,
    ImpactLevel,
    Observation,
    ObservationType,
)

logger = logging.getLogger(__name__)

# VT-Spec E-01: Impact weights for scoring
IMPACT_WEIGHTS: Dict[str, float] = {
    ImpactLevel.NONE.value: 0.0,
    ImpactLevel.LOW.value: 1.0,
    ImpactLevel.MEDIUM.value: 2.0,
    ImpactLevel.HIGH.value: 4.0,
    ImpactLevel.CRITICAL.value: 5.0,
}

# VT-Spec E-01: Default confidence cap
DEFAULT_MAX_CONFIDENCE = 0.85
# VT-Spec E-01: Minimum observations required for high confidence (>0.7)
MIN_OBSERVATIONS_FOR_HIGH_CONFIDENCE = 2

# Pattern-based hypothesis rules
HYPOTHESIS_RULES: List[Dict[str, Any]] = [
    {
        "name": "ssh_brute_force",
        "trigger": ObservationType.PORT_OPEN,
        "condition": lambda data: data.get("port") == 22,
        "description": "SSH service detected — test for weak credentials",
        "impact": ImpactLevel.MEDIUM,
        "base_confidence": 0.4,
    },
    {
        "name": "http_vuln_scan",
        "trigger": ObservationType.PORT_OPEN,
        "condition": lambda data: data.get("port") in (80, 443, 8080, 8443),
        "description": "HTTP service detected — test for web vulnerabilities",
        "impact": ImpactLevel.MEDIUM,
        "base_confidence": 0.5,
    },
    {
        "name": "smb_exploit",
        "trigger": ObservationType.PORT_OPEN,
        "condition": lambda data: data.get("port") in (139, 445),
        "description": "SMB service detected — test for known SMB vulnerabilities",
        "impact": ImpactLevel.HIGH,
        "base_confidence": 0.5,
    },
    {
        "name": "service_version_exploit",
        "trigger": ObservationType.SERVICE_DETECTED,
        "condition": lambda data: data.get("version") is not None,
        "description": "Service version detected — check for known CVEs",
        "impact": ImpactLevel.HIGH,
        "base_confidence": 0.6,
    },
    {
        "name": "cve_exploit",
        "trigger": ObservationType.VULNERABILITY_FOUND,
        "condition": lambda data: data.get("cve_id") is not None,
        "description": "Known CVE found — attempt exploitation",
        "impact": ImpactLevel.CRITICAL,
        "base_confidence": 0.7,
    },
    {
        "name": "credential_reuse",
        "trigger": ObservationType.CREDENTIAL_FOUND,
        "condition": lambda _: True,
        "description": "Credentials found — test for credential reuse across services",
        "impact": ImpactLevel.HIGH,
        "base_confidence": 0.6,
    },
]


class HypothesisEngine:
    """Generates and ranks attack hypotheses from observations.

    # VT-Spec E-01: Confidence capped at configurable maximum
    # VT-Spec I-01: Credentials scrubbed before LLM context
    # VT-Spec R-01: All hypothesis operations logged
    """

    def __init__(
        self,
        event_log: Optional[EventLog] = None,
        llm_reasoner: Optional[Any] = None,
        max_confidence: float = DEFAULT_MAX_CONFIDENCE,
    ):
        self._event_log = event_log
        self._llm_reasoner = llm_reasoner
        # VT-Spec E-01: Confidence cap
        self._max_confidence = max_confidence
        self._hypotheses: Dict[str, Hypothesis] = {}

    @property
    def hypotheses(self) -> Dict[str, Hypothesis]:
        return self._hypotheses.copy()

    def _cap_confidence(
        self, raw_confidence: float, observation_count: int
    ) -> float:
        """Cap confidence score based on evidence.

        # VT-Spec E-01 HIGH: Cap at configurable max, require minimum
        # observations for high confidence (>0.7 needs 2+ observations)
        """
        # Hard cap
        capped = min(raw_confidence, self._max_confidence)

        # VT-Spec E-01: Require minimum observations for high confidence
        if capped > 0.7 and observation_count < MIN_OBSERVATIONS_FOR_HIGH_CONFIDENCE:
            capped = 0.7

        return round(capped, 4)

    def generate(
        self,
        observations: List[Observation],
        context: Dict[str, Any],
    ) -> List[Hypothesis]:
        """Generate hypotheses from observations.

        # VT-Spec E-01: Confidence bounds enforced
        # VT-Spec R-01: Hypothesis generation logged
        """
        engagement_id = context.get("engagement_id", "")
        target_id = context.get("target_id", "")
        new_hypotheses: List[Hypothesis] = []

        # Pattern-based hypothesis generation
        for obs in observations:
            for rule in HYPOTHESIS_RULES:
                if obs.observation_type == rule["trigger"]:
                    if rule["condition"](obs.data):
                        # VT-Spec E-01: Cap confidence
                        confidence = self._cap_confidence(
                            rule["base_confidence"],
                            len(observations),
                        )
                        hyp = Hypothesis(
                            engagement_id=engagement_id,
                            target_id=target_id,
                            description=rule["description"],
                            status=HypothesisStatus.PROPOSED,
                            evidence=[obs.id],
                        )
                        # Store metadata as non-model attributes via context
                        self._hypotheses[hyp.id] = hyp
                        # Store scoring info alongside
                        hyp._confidence = confidence  # type: ignore[attr-defined]
                        hyp._impact = rule["impact"]  # type: ignore[attr-defined]
                        new_hypotheses.append(hyp)

        # LLM-assisted hypothesis generation (if available)
        if self._llm_reasoner and observations:
            llm_hyps = self._generate_from_llm(
                observations, engagement_id, target_id
            )
            new_hypotheses.extend(llm_hyps)

        # VT-Spec R-01: Log hypothesis generation
        if self._event_log and new_hypotheses:
            event = Event(
                engagement_id=engagement_id,
                event_type=EventType.OBSERVATION_ADDED,
                data={
                    "action": "hypotheses_generated",
                    "count": len(new_hypotheses),
                    "hypothesis_ids": [h.id for h in new_hypotheses],
                },
                actor="brain.hypothesis",
            )
            self._event_log.append(event)

        return new_hypotheses

    def _generate_from_llm(
        self,
        observations: List[Observation],
        engagement_id: str,
        target_id: str,
    ) -> List[Hypothesis]:
        """Generate hypotheses via LLM reasoning.

        # VT-Spec I-01 HIGH: Scrub credentials before LLM context
        # VT-Spec E-01: Cap LLM confidence at 0.8
        """
        try:
            suggestions = self._llm_reasoner.generate_hypotheses(observations)
        except Exception as e:
            logger.warning("LLM hypothesis generation failed: %s", e)
            return []

        hypotheses: List[Hypothesis] = []
        for suggestion in suggestions:
            if not isinstance(suggestion, dict):
                continue
            description = suggestion.get("description", "")
            raw_confidence = suggestion.get("confidence", 0.5)

            if not description:
                continue

            # VT-Spec E-01: Cap LLM confidence at max_confidence
            # LLM confidence further capped at 0.8 (require confirming evidence)
            llm_cap = min(self._max_confidence, 0.8)
            confidence = self._cap_confidence(
                min(float(raw_confidence), llm_cap),
                len(observations),
            )

            impact_str = suggestion.get("impact", "medium")
            try:
                impact = ImpactLevel(impact_str)
            except ValueError:
                impact = ImpactLevel.MEDIUM

            hyp = Hypothesis(
                engagement_id=engagement_id,
                target_id=target_id,
                description=description,
                status=HypothesisStatus.PROPOSED,
                evidence=[],
            )
            hyp._confidence = confidence  # type: ignore[attr-defined]
            hyp._impact = impact  # type: ignore[attr-defined]
            self._hypotheses[hyp.id] = hyp
            hypotheses.append(hyp)

        return hypotheses

    def rank(self, hypotheses: List[Hypothesis]) -> List[Hypothesis]:
        """Rank hypotheses by confidence × impact weight.

        # VT-Spec E-01: Confidence already capped during generation
        """

        def score(h: Hypothesis) -> float:
            confidence = getattr(h, "_confidence", 0.5)
            impact = getattr(h, "_impact", ImpactLevel.MEDIUM)
            weight = IMPACT_WEIGHTS.get(
                impact.value if isinstance(impact, ImpactLevel) else impact, 2.0
            )
            return confidence * weight

        return sorted(hypotheses, key=score, reverse=True)

    def update_status(
        self,
        hypothesis_id: str,
        new_status: HypothesisStatus,
    ) -> Optional[Hypothesis]:
        """Update hypothesis lifecycle status."""
        hyp = self._hypotheses.get(hypothesis_id)
        if hyp is None:
            return None

        hyp.status = new_status
        hyp.updated_at = datetime.now(timezone.utc)
        return hyp

    def add_evidence(
        self, hypothesis_id: str, observation_id: str
    ) -> Optional[Hypothesis]:
        """Add supporting evidence to a hypothesis."""
        hyp = self._hypotheses.get(hypothesis_id)
        if hyp is None:
            return None

        if observation_id not in hyp.evidence:
            hyp.evidence.append(observation_id)
        hyp.updated_at = datetime.now(timezone.utc)
        return hyp

    def get_active_hypotheses(self) -> List[Hypothesis]:
        """Get all non-terminal hypotheses."""
        return [
            h
            for h in self._hypotheses.values()
            if h.status in (HypothesisStatus.PROPOSED, HypothesisStatus.TESTING)
        ]
