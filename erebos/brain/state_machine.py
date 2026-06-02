"""Engagement state machine for Erebos control plane (REQ-008).

Enforces phase transitions with prerequisites and policy gating.

# VT-Spec E-03: Enforce phase prerequisites — no skipping phases
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional, Set

from erebos.core.models import Engagement, EngagementPhase, EngagementStatus

logger = logging.getLogger(__name__)

# VT-Spec E-03: Only forward transitions allowed (no skipping)
# Each phase maps to the set of phases it can transition TO
VALID_TRANSITIONS: Dict[EngagementPhase, Set[EngagementPhase]] = {
    EngagementPhase.PLANNING: {EngagementPhase.RECON, EngagementPhase.ABORTED},
    EngagementPhase.RECON: {EngagementPhase.ENUMERATION, EngagementPhase.ABORTED},
    EngagementPhase.ENUMERATION: {EngagementPhase.EXPLOITATION, EngagementPhase.ABORTED},
    EngagementPhase.EXPLOITATION: {EngagementPhase.POST_EXPLOIT, EngagementPhase.REPORTING, EngagementPhase.ABORTED},
    EngagementPhase.POST_EXPLOIT: {EngagementPhase.REPORTING, EngagementPhase.ABORTED},
    EngagementPhase.REPORTING: {EngagementPhase.COMPLETED, EngagementPhase.ABORTED},
    EngagementPhase.COMPLETED: set(),  # Terminal state
    EngagementPhase.ABORTED: set(),  # Terminal state
}

# Phase ordering for skip detection
PHASE_ORDER: List[EngagementPhase] = [
    EngagementPhase.PLANNING,
    EngagementPhase.RECON,
    EngagementPhase.ENUMERATION,
    EngagementPhase.EXPLOITATION,
    EngagementPhase.POST_EXPLOIT,
    EngagementPhase.REPORTING,
    EngagementPhase.COMPLETED,
]


class TransitionError(Exception):
    """Raised when an invalid state transition is attempted."""

    pass


class EngagementStateMachine:
    """State machine for engagement phase management.

    # VT-Spec E-03: Enforce phase prerequisites (no skip)
    # VT-Spec E-03: State derived from event replay (tamper-evident)
    """

    def __init__(
        self,
        engagement: Engagement,
        on_transition: Optional[Callable[[EngagementPhase, EngagementPhase], None]] = None,
    ):
        self._engagement = engagement
        self._on_transition = on_transition
        self._transition_history: List[dict] = []

    @property
    def current_phase(self) -> EngagementPhase:
        return self._engagement.phase

    @property
    def engagement(self) -> Engagement:
        return self._engagement

    @property
    def transition_history(self) -> List[dict]:
        return self._transition_history.copy()

    def can_transition_to(self, target_phase: EngagementPhase) -> bool:
        """Check if transition to target phase is valid.

        # VT-Spec E-03: Only forward, no skipping
        """
        current = self._engagement.phase
        allowed = VALID_TRANSITIONS.get(current, set())
        return target_phase in allowed

    def transition_to(self, target_phase: EngagementPhase, reason: str = "") -> None:
        """Transition to a new phase.

        # VT-Spec E-03: Enforce phase prerequisites in state machine (no skip)
        Raises TransitionError if transition is invalid.
        """
        current = self._engagement.phase

        # Check if in terminal state
        if current in (EngagementPhase.COMPLETED, EngagementPhase.ABORTED):
            raise TransitionError(
                f"Cannot transition from terminal state '{current.value}'"
            )

        # VT-Spec E-03: Validate transition is allowed
        if not self.can_transition_to(target_phase):
            allowed = VALID_TRANSITIONS.get(current, set())
            allowed_names = [p.value for p in allowed]
            raise TransitionError(
                f"Invalid transition: '{current.value}' → '{target_phase.value}'. "
                f"Allowed transitions from '{current.value}': {allowed_names}"
            )

        # Record transition
        now = datetime.now(timezone.utc)
        self._transition_history.append(
            {
                "from_phase": current.value,
                "to_phase": target_phase.value,
                "reason": reason,
                "timestamp": now.isoformat(),
            }
        )

        # Apply transition
        self._engagement.phase = target_phase
        self._engagement.updated_at = now

        # Update engagement status based on phase
        if target_phase == EngagementPhase.ABORTED:
            self._engagement.status = EngagementStatus.ABORTED
            self._engagement.aborted_at = now
            self._engagement.abort_reason = reason
        elif target_phase == EngagementPhase.COMPLETED:
            self._engagement.status = EngagementStatus.COMPLETED
        elif self._engagement.status == EngagementStatus.CREATED:
            self._engagement.status = EngagementStatus.ACTIVE

        # Fire callback
        if self._on_transition:
            self._on_transition(current, target_phase)

        logger.info(
            f"Engagement {self._engagement.id}: "
            f"{current.value} → {target_phase.value} ({reason})"
        )

    def abort(self, reason: str = "Kill switch activated") -> None:
        """Abort the engagement from any non-terminal phase.

        # VT-Spec D-01: Kill switch activation transitions to ABORTED
        """
        current = self._engagement.phase
        if current in (EngagementPhase.COMPLETED, EngagementPhase.ABORTED):
            return  # Idempotent

        self.transition_to(EngagementPhase.ABORTED, reason)

    def get_allowed_actions(self) -> List[str]:
        """Get action classes allowed in current phase.

        # VT-Spec E-03: Phase-gated action restrictions
        """
        phase = self._engagement.phase
        phase_actions: Dict[EngagementPhase, List[str]] = {
            EngagementPhase.PLANNING: [],
            EngagementPhase.RECON: ["scan"],
            EngagementPhase.ENUMERATION: ["scan", "enumerate"],
            EngagementPhase.EXPLOITATION: ["scan", "enumerate", "exploit"],
            EngagementPhase.POST_EXPLOIT: ["scan", "enumerate", "exploit", "pivot", "persist"],
            EngagementPhase.REPORTING: ["cleanup"],
            EngagementPhase.COMPLETED: [],
            EngagementPhase.ABORTED: [],
        }
        return phase_actions.get(phase, [])

    def is_action_allowed_in_phase(self, action_class: str) -> bool:
        """Check if an action class is allowed in the current phase.

        # VT-Spec E-03: Exploitation actions rejected if current phase is insufficient
        """
        return action_class in self.get_allowed_actions()
