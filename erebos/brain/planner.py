"""Planner for Erebos decision loop (REQ-003).

Converts ranked hypotheses into policy-constrained PlannedActions.

# VT-Spec T-02 CRITICAL: List-based command construction ONLY
# VT-Spec R-01: All planning decisions logged via EventLog
"""

from __future__ import annotations

import logging
import shlex
from typing import Any, Dict, List, Optional

from erebos.brain.state_machine import EngagementStateMachine
from erebos.control.policy import PolicyEngine
from erebos.control.scope import ScopeValidator
from erebos.core.events import Event, EventLog, EventType
from erebos.core.models import (
    ActionStatus,
    ActionType,
    Engagement,
    EngagementPhase,
    Hypothesis,
    HypothesisStatus,
    ImpactLevel,
    PlannedAction,
)

logger = logging.getLogger(__name__)

# VT-Spec T-02: Allowed tool binaries whitelist
ALLOWED_TOOLS = frozenset([
    "nmap",
    "nikto",
    "gobuster",
    "dirb",
    "sqlmap",
    "hydra",
    "curl",
    "wget",
    "whatweb",
    "wpscan",
    "nuclei",
    "ffuf",
    "feroxbuster",
    "enum4linux",
    "smbclient",
    "crackmapexec",
    "searchsploit",
])

# VT-Spec T-02: Strict argument validation patterns per tool
TOOL_ARG_PATTERNS: Dict[str, List[str]] = {
    "nmap": ["-sV", "-sS", "-sC", "-sT", "-sU", "-A", "-O", "-p", "-Pn", "--top-ports",
             "-oN", "-oX", "-oG", "--script", "-T0", "-T1", "-T2", "-T3", "-T4", "-T5",
             "--open", "-v", "-vv", "--min-rate", "--max-rate"],
    "nikto": ["-h", "-p", "-ssl", "-C", "-T", "-o", "-Format"],
    "gobuster": ["dir", "-u", "-w", "-t", "-o", "-x", "-s", "-b", "--wildcard"],
}

# Hypothesis description → action type mapping
HYPOTHESIS_TO_ACTION: Dict[str, ActionType] = {
    "ssh": ActionType.SCAN,
    "http": ActionType.SCAN,
    "smb": ActionType.SCAN,
    "version": ActionType.ENUMERATE,
    "cve": ActionType.EXPLOIT,
    "credential": ActionType.EXPLOIT,
    "web vuln": ActionType.SCAN,
}


def _build_command_list(tool: str, args: List[str]) -> str:
    """Build command string from list of components using shlex.quote.

    # VT-Spec T-02 CRITICAL: List-based command construction ONLY.
    # Never use string format/interpolation with untrusted data.
    """
    # VT-Spec T-02: Validate tool is in whitelist
    if tool not in ALLOWED_TOOLS:
        raise ValueError(f"VT-Spec T-02: Tool '{tool}' not in allowed whitelist")

    # VT-Spec T-02: shlex.quote() all dynamic arguments
    safe_args = [shlex.quote(arg) for arg in args]
    return " ".join([tool] + safe_args)


class Planner:
    """Converts hypotheses to policy-constrained PlannedActions.

    # VT-Spec T-02 CRITICAL: List-based command construction
    # VT-Spec R-01: All decisions logged
    """

    def __init__(
        self,
        policy_engine: PolicyEngine,
        scope_validator: ScopeValidator,
        state_machine: EngagementStateMachine,
        event_log: Optional[EventLog] = None,
    ):
        self._policy = policy_engine
        self._scope = scope_validator
        self._state_machine = state_machine
        self._event_log = event_log

    def plan(
        self,
        hypotheses: List[Hypothesis],
        engagement: Engagement,
    ) -> List[PlannedAction]:
        """Convert hypotheses to PlannedActions with full policy enforcement.

        # VT-Spec T-02: List-based command construction
        # VT-Spec R-01: Log every planning decision
        """
        planned: List[PlannedAction] = []

        for hyp in hypotheses:
            if hyp.status not in (HypothesisStatus.PROPOSED, HypothesisStatus.TESTING):
                continue

            action = self._plan_single(hyp, engagement)
            if action is not None:
                planned.append(action)

        return planned

    def _plan_single(
        self,
        hypothesis: Hypothesis,
        engagement: Engagement,
    ) -> Optional[PlannedAction]:
        """Plan a single action from a hypothesis."""
        # Determine action type from hypothesis
        action_type = self._determine_action_type(hypothesis)
        impact = getattr(hypothesis, "_impact", ImpactLevel.LOW)
        if isinstance(impact, str):
            impact = ImpactLevel(impact)

        # Phase gating check
        # VT-Spec E-03: Phase-appropriate actions only
        if not self._state_machine.is_action_allowed_in_phase(action_type.value):
            self._log_rejection(
                engagement.id,
                hypothesis,
                f"Action '{action_type.value}' not allowed in phase "
                f"'{self._state_machine.current_phase.value}'",
            )
            return None

        # Build command
        try:
            command = self._build_command(hypothesis, engagement)
        except ValueError as e:
            self._log_rejection(engagement.id, hypothesis, str(e))
            return None

        # Scope validation
        # VT-Spec T-02: ScopeValidator.validate_command() on final command
        scope_ok, scope_reason = self._scope.validate_command(command)
        if not scope_ok:
            self._log_rejection(
                engagement.id, hypothesis, f"Scope violation: {scope_reason}"
            )
            return None

        # Create PlannedAction
        action = PlannedAction(
            engagement_id=engagement.id,
            target_id=hypothesis.target_id,
            action_type=action_type,
            command=command,
            description=hypothesis.description,
            impact_level=impact,
            status=ActionStatus.PROPOSED,
            phase=self._state_machine.current_phase,
        )

        # Policy evaluation
        decision = self._policy.evaluate(action)

        if not decision.allowed:
            self._log_rejection(
                engagement.id,
                hypothesis,
                f"Policy rejected: {decision.reason}",
            )
            # VT-Spec R-01: Log policy evaluation
            if self._event_log:
                self._event_log.append(
                    Event(
                        engagement_id=engagement.id,
                        event_type=EventType.POLICY_EVALUATED,
                        data={
                            "action_id": action.id,
                            "allowed": False,
                            "reason": decision.reason,
                        },
                        actor="brain.planner",
                    )
                )
            return None

        # Set approval flag from policy
        if decision.requires_approval:
            action.requires_approval = True
            action.status = ActionStatus.PENDING_APPROVAL

        # VT-Spec R-01: Log action planned
        if self._event_log:
            self._event_log.append(
                Event(
                    engagement_id=engagement.id,
                    event_type=EventType.ACTION_PLANNED,
                    data={
                        "action_id": action.id,
                        "action_type": action.action_type.value,
                        "command": action.command,
                        "impact_level": action.impact_level.value,
                        "requires_approval": action.requires_approval,
                        "hypothesis_id": hypothesis.id,
                    },
                    actor="brain.planner",
                )
            )

        return action

    def _log_rejection(
        self,
        engagement_id: str,
        hypothesis: Hypothesis,
        reason: str,
    ) -> None:
        """Log a planning rejection."""
        logger.info(
            "Planner rejected hypothesis %s: %s", hypothesis.id, reason
        )
        if self._event_log:
            self._event_log.append(
                Event(
                    engagement_id=engagement_id,
                    event_type=EventType.ACTION_REJECTED,
                    data={
                        "hypothesis_id": hypothesis.id,
                        "reason": reason,
                    },
                    actor="brain.planner",
                )
            )

    def _determine_action_type(self, hypothesis: Hypothesis) -> ActionType:
        """Determine action type from hypothesis description."""
        desc_lower = hypothesis.description.lower()
        for keyword, action_type in HYPOTHESIS_TO_ACTION.items():
            if keyword in desc_lower:
                return action_type
        return ActionType.SCAN  # Default to scan (least privileged)

    def _build_command(
        self,
        hypothesis: Hypothesis,
        engagement: Engagement,
    ) -> str:
        """Build a safe command from hypothesis context.

        # VT-Spec T-02 CRITICAL: List-based command construction.
        # NEVER use f-string/format with untrusted data.
        """
        desc_lower = hypothesis.description.lower()
        target = ""
        if engagement.targets:
            target = engagement.targets[0].address

        if not target:
            raise ValueError("No target available for command construction")

        # VT-Spec T-02: All dynamic values go through shlex.quote via _build_command_list
        if "ssh" in desc_lower or "port 22" in desc_lower:
            return _build_command_list("nmap", ["-sV", "-p", "22", target])
        elif "http" in desc_lower or "web" in desc_lower:
            return _build_command_list("nikto", ["-h", target])
        elif "smb" in desc_lower:
            return _build_command_list("nmap", ["-sV", "-p", "139,445", "--script", "smb-vuln*", target])
        elif "version" in desc_lower or "service" in desc_lower:
            return _build_command_list("nmap", ["-sV", "-sC", target])
        elif "cve" in desc_lower:
            return _build_command_list("nmap", ["-sV", "--script", "vulners", target])
        elif "credential" in desc_lower:
            return _build_command_list("nmap", ["-sV", "-p", "22,21,3389", target])
        else:
            # Default: basic scan
            return _build_command_list("nmap", ["-sV", target])
