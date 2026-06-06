"""Multi-LLM consensus voting for finding validation."""

from __future__ import annotations

import asyncio
import logging
import os
import re
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional

from erebos.core.finding import Finding
from erebos.core.scorecard import ModelScorecard

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = "You are a security expert evaluating a potential vulnerability finding."
_PROMPT_TEMPLATE = """You are a security expert evaluating a potential vulnerability finding.

## Finding
- Title: {title}
- Severity: {severity}
- CWE: {cwe}
- Tool: {tool}
- Description: {description}
- Evidence: {evidence}
{context_section}
## Task
Determine if this is a real, exploitable vulnerability or a false positive.

Respond with EXACTLY one of:
- VULNERABLE: This is a real, exploitable vulnerability
- NOT_VULNERABLE: This is a false positive or not exploitable
- UNCERTAIN: Cannot determine with available information

Then explain your reasoning in 1-2 sentences.

Format: VERDICT: <your reasoning>
"""
_DEFAULT_PROVIDERS = ["copilot", "claude", "openrouter"]
_VERDICT_PATTERN = re.compile(r"(NOT[\s_-]*VULNERABLE|VULNERABLE|UNCERTAIN)", re.IGNORECASE)
_RESPONSE_PATTERN = re.compile(
    r"^\s*(?:VERDICT\s*[:\-]\s*)?(NOT[\s_-]*VULNERABLE|VULNERABLE|UNCERTAIN)\s*[:\-]?\s*(.*)$",
    re.IGNORECASE | re.DOTALL,
)
_CONFIDENCE_PATTERN = re.compile(r"confidence\s*[:=]?\s*(\d+(?:\.\d+)?)\s*(%?)", re.IGNORECASE)
_DEFAULT_CONFIDENCE = {
    "vulnerable": 0.85,
    "not_vulnerable": 0.85,
    "uncertain": 0.5,
}


class VoteStrategy(str, Enum):
    """Supported vote aggregation strategies."""

    MAJORITY = "majority"
    SUPERMAJORITY = "supermajority"
    UNANIMOUS = "unanimous"
    WEIGHTED = "weighted"


@dataclass
class Vote:
    """Single model's vote on a finding."""

    model: str
    verdict: str
    confidence: float
    reasoning: str
    weight: float = 1.0


@dataclass
class ConsensusResult:
    """Aggregated consensus decision."""

    finding_id: str
    final_verdict: str
    agreement_ratio: float
    confidence: float
    votes: List[Vote]
    strategy_used: VoteStrategy
    consensus_reached: bool

    @property
    def is_confident(self) -> bool:
        """Whether a strong and confident consensus was reached."""
        return self.consensus_reached and self.confidence >= 0.7


class ConsensusVoter:
    """Multi-LLM consensus voting for finding validation."""

    def __init__(
        self,
        providers: Optional[List[str]] = None,
        strategy: VoteStrategy = VoteStrategy.WEIGHTED,
        min_voters: int = 2,
        scorecard: Optional[ModelScorecard] = None,
    ):
        self._providers = providers or list(_DEFAULT_PROVIDERS)
        self._strategy = strategy
        self._min_voters = max(1, min_voters)
        self._scorecard = scorecard
        self._provider_timeout = 30.0
        self._provider_clients: Dict[str, object] = {}

    async def vote_on_finding(
        self,
        finding: Finding,
        context: Optional[str] = None,
    ) -> ConsensusResult:
        """Get consensus vote on a single finding."""
        prompt = self._build_prompt(finding, context)
        tasks = [
            self._request_vote(provider_name, finding, prompt) for provider_name in self._providers
        ]
        responses = await asyncio.gather(*tasks)
        votes = [vote for vote in responses if vote is not None]
        return self._aggregate_votes(finding.id, votes)

    async def vote_batch(
        self,
        findings: List[Finding],
        contexts: Optional[Dict[str, str]] = None,
    ) -> List[ConsensusResult]:
        """Vote on multiple findings in parallel."""
        context_map = contexts or {}
        tasks = [
            self.vote_on_finding(finding, context=context_map.get(finding.id))
            for finding in findings
        ]
        return list(await asyncio.gather(*tasks))

    def _build_prompt(self, finding: Finding, context: Optional[str]) -> str:
        """Build the voting prompt for LLMs."""
        evidence = self._extract_evidence_snippet(finding)
        context_section = ""
        if context:
            context_section = f"## Additional Context\n{context.strip()}\n\n"
        return _PROMPT_TEMPLATE.format(
            title=finding.title,
            severity=getattr(finding.severity, "value", finding.severity),
            cwe=finding.cwe or "unknown",
            tool=finding.tool,
            description=finding.description,
            evidence=evidence,
            context_section=context_section,
        )

    def _parse_vote(self, model: str, response: str) -> Vote:
        """Parse an LLM response into a Vote."""
        text = response.strip()
        match = _RESPONSE_PATTERN.match(text)
        if match:
            verdict = self._normalize_verdict(match.group(1))
            reasoning = match.group(2).strip() or text
        else:
            verdict_match = _VERDICT_PATTERN.search(text)
            verdict = self._normalize_verdict(
                verdict_match.group(1) if verdict_match else "UNCERTAIN"
            )
            reasoning = text

        confidence_match = _CONFIDENCE_PATTERN.search(text)
        if confidence_match:
            confidence = float(confidence_match.group(1))
            if confidence_match.group(2) == "%" or confidence > 1.0:
                confidence /= 100.0
            confidence = max(0.0, min(confidence, 1.0))
        else:
            confidence = _DEFAULT_CONFIDENCE[verdict]

        return Vote(
            model=model,
            verdict=verdict,
            confidence=confidence,
            reasoning=reasoning[:500],
        )

    def _aggregate_votes(self, finding_id: str, votes: List[Vote]) -> ConsensusResult:
        """Aggregate votes using the configured strategy."""
        if not votes:
            return ConsensusResult(
                finding_id=finding_id,
                final_verdict="uncertain",
                agreement_ratio=0.0,
                confidence=0.0,
                votes=[],
                strategy_used=self._strategy,
                consensus_reached=False,
            )

        avg_confidence = sum(vote.confidence for vote in votes) / len(votes)
        if self._strategy == VoteStrategy.WEIGHTED:
            agreement_ratio, leading_verdict, has_tie = self._weighted_ratio(votes)
        else:
            agreement_ratio, leading_verdict, has_tie = self._count_ratio(votes)

        if len(votes) < self._min_voters or has_tie:
            consensus_reached = False
        elif self._strategy == VoteStrategy.MAJORITY:
            consensus_reached = agreement_ratio > 0.5
        elif self._strategy == VoteStrategy.SUPERMAJORITY:
            consensus_reached = agreement_ratio >= (2 / 3)
        elif self._strategy == VoteStrategy.UNANIMOUS:
            consensus_reached = agreement_ratio == 1.0
        else:
            consensus_reached = agreement_ratio > 0.5

        return ConsensusResult(
            finding_id=finding_id,
            final_verdict=leading_verdict if consensus_reached else "uncertain",
            agreement_ratio=agreement_ratio,
            confidence=agreement_ratio * avg_confidence,
            votes=votes,
            strategy_used=self._strategy,
            consensus_reached=consensus_reached,
        )

    def _calculate_weight(self, model: str, cwe: Optional[str]) -> float:
        """Get vote weight from scorecard reliability."""
        if self._scorecard is None:
            return 1.0

        cwe_class = cwe or "generic"
        entry = self._scorecard.get_entry(model, cwe_class)
        if entry is None and cwe_class != "generic":
            entry = self._scorecard.get_entry(model, "generic")
        if entry is None or entry.total == 0:
            return 1.0
        return entry.accuracy

    async def _request_vote(
        self,
        provider_name: str,
        finding: Finding,
        prompt: str,
    ) -> Optional[Vote]:
        try:
            response = await asyncio.wait_for(
                self._ask_provider(provider_name, prompt),
                timeout=self._provider_timeout,
            )
        except asyncio.TimeoutError:
            logger.warning(
                "Consensus provider %s timed out for finding %s", provider_name, finding.id
            )
            return None
        except Exception as exc:
            logger.warning(
                "Consensus provider %s failed for finding %s: %s",
                provider_name,
                finding.id,
                exc,
            )
            return None

        if not response:
            return None

        vote = self._parse_vote(provider_name, response)
        vote.weight = self._calculate_weight(provider_name, finding.cwe)
        return vote

    async def _ask_provider(self, provider_name: str, prompt: str) -> Optional[str]:
        """Send the prompt to a configured provider and return raw text."""
        provider = self._provider_clients.get(provider_name)
        if provider is None:
            provider = self._build_provider(provider_name)
            if provider is None:
                return None
            self._provider_clients[provider_name] = provider

        response, _usage = await provider.generate(prompt, _SYSTEM_PROMPT)
        return response

    def _build_provider(self, provider_name: str):
        """Instantiate a provider from environment-backed configuration."""
        from erebos.exploits.llm_cascade import (
            ClaudeProvider,
            CopilotProvider,
            OpenRouterProvider,
        )

        env_map = {
            "copilot": "GITHUB_COPILOT_API_KEY",
            "claude": "ANTHROPIC_API_KEY",
            "openrouter": "OPENROUTER_API_KEY",
        }
        provider_factories = {
            "copilot": CopilotProvider,
            "claude": ClaudeProvider,
            "openrouter": OpenRouterProvider,
        }

        if provider_name not in provider_factories:
            logger.debug("Unknown consensus provider: %s", provider_name)
            return None

        if provider_name == "copilot" and not os.environ.get(env_map[provider_name]):
            try:
                return CopilotProvider.from_gh_session()
            except Exception as exc:
                logger.debug("Unable to initialize copilot provider from gh session: %s", exc)
                return None

        api_key = os.environ.get(env_map[provider_name], "")
        if not api_key:
            logger.debug("No API key configured for provider %s", provider_name)
            return None

        provider_cls = provider_factories[provider_name]
        return provider_cls(api_key=api_key)

    @staticmethod
    def _extract_evidence_snippet(finding: Finding) -> str:
        evidence = finding.evidence
        for candidate in (evidence.output, evidence.payload, evidence.http_banner, evidence.url):
            if candidate:
                snippet = str(candidate).strip()
                return snippet[:500]
        return "No evidence snippet provided"

    @staticmethod
    def _normalize_verdict(raw_verdict: str) -> str:
        normalized = raw_verdict.strip().upper().replace("-", "_").replace(" ", "_")
        if normalized == "NOT_VULNERABLE":
            return "not_vulnerable"
        if normalized == "VULNERABLE":
            return "vulnerable"
        return "uncertain"

    @staticmethod
    def _count_ratio(votes: List[Vote]) -> tuple[float, str, bool]:
        counts: Dict[str, int] = {}
        for vote in votes:
            counts[vote.verdict] = counts.get(vote.verdict, 0) + 1

        max_count = max(counts.values())
        leaders = [verdict for verdict, count in counts.items() if count == max_count]
        leading_verdict = leaders[0]
        return max_count / len(votes), leading_verdict, len(leaders) > 1

    @staticmethod
    def _weighted_ratio(votes: List[Vote]) -> tuple[float, str, bool]:
        weights: Dict[str, float] = {}
        total_weight = sum(vote.weight for vote in votes)
        for vote in votes:
            weights[vote.verdict] = weights.get(vote.verdict, 0.0) + vote.weight

        max_weight = max(weights.values())
        leaders = [verdict for verdict, weight in weights.items() if weight == max_weight]
        leading_verdict = leaders[0]
        ratio = 0.0 if total_weight <= 0 else max_weight / total_weight
        return ratio, leading_verdict, len(leaders) > 1
