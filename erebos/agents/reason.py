"""Adaptive reasoning loop for Erebos agents."""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4

from pydantic import BaseModel, Field

from erebos.agents.fact_graph import FactGraph, FactType
from erebos.security.scope import AllowlistValidator

logger = logging.getLogger(__name__)


class IntentAction(str, Enum):
    """Allowed intent action types (EP-01: strict allowlist)."""

    EXPLOIT = "exploit"
    DISCOVER = "discover"
    PROBE = "probe"
    REPORT = "report"
    SCAN = "scan"
    AUTHENTICATE = "authenticate"


class Intent(BaseModel):
    """A single action the Reason Loop wants to execute."""

    id: str = Field(default_factory=lambda: f"intent-{uuid4().hex[:8]}")
    action: IntentAction
    target: str = ""
    params: Dict[str, Any] = Field(default_factory=dict)
    priority: int = Field(default=5, ge=1, le=10)
    rationale: str = ""


class IntentDispatcher:
    """Validates and dispatches intents to workers.

    Security EP-01: ALL intent target URLs validated against AllowlistValidator.
    """

    def __init__(self, allowlist: List[str], fact_graph: Optional[FactGraph]):
        self._allowlist = [host.lower().strip() for host in allowlist]
        self._graph = fact_graph
        self._validator = AllowlistValidator(self._allowlist)
        self._dispatched: List[Intent] = []
        self._rejected: List[tuple[Intent, str]] = []

    def validate_and_dispatch(self, intents: List[Intent]) -> List[Intent]:
        """Filter intents through scope validation, return only valid ones.

        EP-01: Every intent with a target URL must pass scope check.
        """
        valid: List[Intent] = []

        for intent in sorted(intents, key=lambda item: item.priority):
            if intent.target and not self._is_in_scope(intent.target):
                self._rejected.append((intent, "scope_violation"))
                logger.warning(
                    "Intent rejected (scope): %s → %s",
                    intent.action.value,
                    intent.target,
                )
                continue

            if not isinstance(intent.action, IntentAction):
                self._rejected.append((intent, "invalid_action"))
                continue

            valid.append(intent)
            self._dispatched.append(intent)

        return valid

    def _is_in_scope(self, target: str) -> bool:
        """Check if a target URL/host is within the allowed scope."""
        if not target:
            return True

        normalized = target.strip()
        if not normalized:
            return True

        if "://" not in normalized and normalized.startswith(("/", "?", "#")):
            return True

        if self._validator.is_allowed(normalized):
            return True

        parsed = self._validator._parse_target(normalized)
        if not parsed:
            return False

        domain = parsed.get("domain")
        if not domain:
            return False

        for allowed in self._allowlist:
            if "/" in allowed:
                continue
            allowed_domain = allowed[2:] if allowed.startswith("*.") else allowed
            if domain.endswith("." + allowed_domain):
                return True

        return False

    @property
    def rejected_count(self) -> int:
        return len(self._rejected)

    @property
    def dispatched_count(self) -> int:
        return len(self._dispatched)

    def get_rejection_summary(self) -> List[Dict[str, str]]:
        """Get summary of rejected intents for audit."""
        return [
            {
                "intent_id": intent.id,
                "action": intent.action.value,
                "target": intent.target,
                "reason": reason,
            }
            for intent, reason in self._rejected
        ]


class ReasonLoop:
    """Adaptive decision engine — observes facts, reasons about next actions.

    Security controls:
    - DOS-01: Max iterations capped at MAX_ITERATIONS
    - EP-01: Only IntentAction enum values allowed
    - S-01: Facts sanitized before LLM via FactGraph.summary_for_llm()
    - RE-01: All decisions logged to audit trail
    """

    MAX_ITERATIONS = 10
    FAILURE_RATE_THRESHOLD = 0.8

    def __init__(
        self,
        fact_graph: FactGraph,
        llm_fn: Optional[Callable[[str], Awaitable[str]]] = None,
        audit_log_path: Optional[Path] = None,
        total_budget: int = 500,
    ):
        self._graph = fact_graph
        self._llm_fn = llm_fn
        self._audit_path = audit_log_path or Path("./erebos-storage/reason-audit.jsonl")
        self._audit_path.parent.mkdir(parents=True, exist_ok=True)
        self._total_budget = total_budget
        self._budget_used = 0
        self._iteration = 0
        self._intent_results: List[Dict[str, Any]] = []
        self._last_facts_hash: Optional[str] = None
        self._cached_intents: Optional[List[Intent]] = None

    @property
    def budget_remaining(self) -> int:
        return max(0, self._total_budget - self._budget_used)

    @property
    def should_continue(self) -> bool:
        """Check if the loop should continue."""
        if self._iteration >= self.MAX_ITERATIONS:
            logger.info("Reason loop: max iterations reached")
            return False
        if self.budget_remaining <= 0:
            logger.info("Reason loop: budget exhausted")
            return False
        if self._failure_rate > self.FAILURE_RATE_THRESHOLD and self._iteration > 2:
            logger.info(
                "Reason loop: failure rate %s exceeds threshold",
                f"{self._failure_rate:.0%}",
            )
            return False
        return True

    @property
    def _failure_rate(self) -> float:
        """Calculate recent intent failure rate."""
        if not self._intent_results:
            return 0.0
        recent = self._intent_results[-10:]
        failures = sum(1 for result in recent if not result.get("success", False))
        return failures / len(recent)

    async def reason(self) -> List[Intent]:
        """Generate next intents from current fact state.

        Returns cached intents if fact state hasn't changed (NF4).
        """
        self._iteration += 1

        facts_summary = self._graph.summary_for_llm(max_facts=30)
        facts_hash = hashlib.sha256(facts_summary.encode()).hexdigest()[:16]

        if facts_hash == self._last_facts_hash and self._cached_intents:
            logger.debug("Reason loop: facts unchanged, returning cached intents")
            return self._cached_intents

        self._last_facts_hash = facts_hash

        if self._llm_fn:
            intents = await self._reason_with_llm(facts_summary)
        else:
            intents = self._reason_heuristic()

        valid_intents = [intent for intent in intents if isinstance(intent.action, IntentAction)]

        self._cached_intents = valid_intents
        self._audit_decision(facts_hash, valid_intents)

        return valid_intents

    async def _reason_with_llm(self, facts_summary: str) -> List[Intent]:
        """Use LLM to generate intents from facts."""
        prompt = self._build_reason_prompt(facts_summary)

        try:
            llm_fn = self._llm_fn
            if llm_fn is None:
                return self._reason_heuristic()
            response = await llm_fn(prompt)
            return self._parse_llm_intents(response)
        except Exception as exc:
            logger.warning("Reason LLM failed: %s, falling back to heuristic", exc)
            return self._reason_heuristic()

    def _reason_heuristic(self) -> List[Intent]:
        """Fallback: generate intents from facts without LLM.

        Simple rules:
        1. Unexploited vulns with high confidence → exploit
        2. Endpoints not yet probed → probe/discover
        3. Credentials found → authenticate then exploit
        """
        intents: List[Intent] = []

        unexploited = self._graph.get_unexploited_vulns()
        for vuln in sorted(unexploited, key=lambda fact: -fact.confidence)[:5]:
            url = vuln.data.get("url") or vuln.data.get("endpoint") or ""
            cwe = vuln.data.get("cwe") or vuln.data.get("cwe_id") or ""
            intents.append(
                Intent(
                    action=IntentAction.EXPLOIT,
                    target=url,
                    params={"cwe": cwe, "fact_id": vuln.id},
                    priority=2 if "89" in cwe or "79" in cwe else 4,
                    rationale=f"Unexploited {cwe} with confidence {vuln.confidence:.1f}",
                )
            )

        creds = self._graph.get_credentials()
        if creds and not any(intent.action == IntentAction.AUTHENTICATE for intent in intents):
            intents.append(
                Intent(
                    action=IntentAction.AUTHENTICATE,
                    target=creds[0].data.get("url", ""),
                    params={"credential_fact_id": creds[0].id},
                    priority=1,
                    rationale="Credentials available, authenticate for deeper access",
                )
            )

        endpoints = self._graph.get_facts(FactType.ENDPOINT)
        if len(endpoints) < 20:
            intents.append(
                Intent(
                    action=IntentAction.DISCOVER,
                    target="",
                    params={"scope": "full"},
                    priority=3,
                    rationale=f"Only {len(endpoints)} endpoints known, discover more",
                )
            )

        return intents

    def _build_reason_prompt(self, facts_summary: str) -> str:
        """Build the prompt for LLM reasoning."""
        return f"""You are a penetration testing strategist. Based on the current knowledge graph, decide the next actions.

## Current State
{facts_summary}

## Budget
- Remaining requests: {self.budget_remaining}
- Iteration: {self._iteration}/{self.MAX_ITERATIONS}
- Recent failure rate: {self._failure_rate:.0%}

## Rules
- Only output actions from: exploit, discover, probe, scan, authenticate, report
- Prioritize HIGH confidence vulnerabilities (SQLi, XSS first)
- If budget < 50, only attempt high-confidence exploits
- If failure rate > 50%, try different attack vectors

## Output Format (JSON array)
[
  {{"action": "exploit", "target": "URL", "params": {{"cwe": "CWE-89"}}, "priority": 1, "rationale": "why"}}
]

Output ONLY the JSON array, no other text."""

    def _parse_llm_intents(self, response: str) -> List[Intent]:
        """Parse LLM response into Intent objects."""
        try:
            import re

            match = re.search(r"\[.*\]", response, re.DOTALL)
            if not match:
                return []

            items = json.loads(match.group())
            intents: List[Intent] = []
            for item in items[:10]:
                try:
                    action = IntentAction(item.get("action", "probe"))
                    intents.append(
                        Intent(
                            action=action,
                            target=str(item.get("target", "")),
                            params=item.get("params", {}),
                            priority=min(10, max(1, int(item.get("priority", 5)))),
                            rationale=str(item.get("rationale", ""))[:200],
                        )
                    )
                except (TypeError, ValueError, KeyError):
                    continue
            return intents
        except (json.JSONDecodeError, Exception) as exc:
            logger.warning("Failed to parse LLM intents: %s", exc)
            return []

    def record_intent_result(
        self,
        intent_id: str,
        success: bool,
        requests_used: int = 0,
    ) -> None:
        """Record the outcome of an intent execution."""
        self._intent_results.append(
            {
                "intent_id": intent_id,
                "success": success,
                "requests_used": requests_used,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )
        self._budget_used += requests_used

    def conclude(self) -> Dict[str, Any]:
        """Force conclude with partial results (R11)."""
        total_intents = len(self._intent_results)
        successful = sum(1 for result in self._intent_results if result.get("success"))
        return {
            "iterations": self._iteration,
            "total_intents": total_intents,
            "successful_intents": successful,
            "failure_rate": self._failure_rate,
            "budget_used": self._budget_used,
            "budget_remaining": self.budget_remaining,
            "concluded_reason": self._conclude_reason(),
        }

    def _conclude_reason(self) -> str:
        if self._iteration >= self.MAX_ITERATIONS:
            return "max_iterations"
        if self.budget_remaining <= 0:
            return "budget_exhausted"
        if self._failure_rate > self.FAILURE_RATE_THRESHOLD:
            return "high_failure_rate"
        return "objectives_met"

    def _audit_decision(self, facts_hash: str, intents: List[Intent]) -> None:
        """Log Reason decision to audit trail."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "iteration": self._iteration,
            "facts_hash": facts_hash,
            "intents": [intent.model_dump(mode="json") for intent in intents],
            "budget_remaining": self.budget_remaining,
            "failure_rate": self._failure_rate,
        }
        try:
            with self._audit_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, default=str) + "\n")
        except Exception as exc:
            logger.warning("Failed to write reason audit: %s", exc)
