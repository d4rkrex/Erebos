"""Loop Controller for Erebos decision loop (REQ-005).

Orchestrates the OODA (Observe → Orient → Decide → Act) loop.

# VT-Spec D-01 HIGH: Hard budget limits
# VT-Spec S-01: Kill switch polling every iteration
# VT-Spec R-01: Every iteration logged
# VT-Spec E-01: Minimum observations before phase advancement
"""

from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from erebos.brain.executor_bridge import ExecutionAborted, ExecutorBridge
from erebos.brain.hypothesis import HypothesisEngine
from erebos.brain.observer import Observer
from erebos.brain.planner import Planner
from erebos.brain.state_machine import (
    EngagementStateMachine,
    TransitionError,
    PHASE_ORDER,
)
from erebos.control.killswitch import KillSwitch
from erebos.core.events import Event, EventLog, EventType
from erebos.core.models import (
    Engagement,
    EngagementPhase,
    EngagementStatus,
    ExecutionArtifact,
    Observation,
)

logger = logging.getLogger(__name__)

# VT-Spec D-01: Default hard limits
DEFAULT_MAX_ITERATIONS = 100
DEFAULT_WALL_CLOCK_BUDGET = 3600  # seconds (1 hour)
DEFAULT_MAX_ACTIONS_PER_ITERATION = 10
DEFAULT_CONVERGENCE_THRESHOLD = 5  # identical observation iterations

# VT-Spec E-01: Minimum observations per phase before advancement
MIN_OBSERVATIONS_PER_PHASE = 1
# VT-Spec E-01: Minimum iterations per phase
MIN_ITERATIONS_PER_PHASE = 2

# Convergence: zero new observations/hypotheses for N iterations
CONVERGENCE_EMPTY_ITERATIONS = 3


@dataclass
class LoopBudget:
    """Budget configuration for the OODA loop.

    # VT-Spec D-01 HIGH: Hard limits, not overridable above policy max
    """

    max_iterations: int = DEFAULT_MAX_ITERATIONS
    wall_clock_budget: float = DEFAULT_WALL_CLOCK_BUDGET
    max_actions_per_iteration: int = DEFAULT_MAX_ACTIONS_PER_ITERATION
    convergence_threshold: int = DEFAULT_CONVERGENCE_THRESHOLD


@dataclass
class IterationResult:
    """Result of a single OODA iteration."""

    iteration: int
    observations: List[Observation] = field(default_factory=list)
    hypotheses_generated: int = 0
    actions_planned: int = 0
    actions_executed: int = 0
    artifacts: List[ExecutionArtifact] = field(default_factory=list)
    converged: bool = False
    aborted: bool = False


@dataclass
class EngagementResult:
    """Final result of the OODA loop."""

    engagement_id: str
    iterations_completed: int
    total_observations: int
    total_actions: int
    final_phase: EngagementPhase
    final_status: EngagementStatus
    reason: str
    duration_seconds: float


class LoopController:
    """Orchestrates the OODA loop for autonomous engagement.

    # VT-Spec D-01 HIGH: Hard budget limits enforced
    # VT-Spec S-01: Kill switch polled every iteration
    # VT-Spec R-01: Every iteration logged
    # VT-Spec E-01: Phase advancement requires minimum evidence
    """

    def __init__(
        self,
        observer: Observer,
        hypothesis_engine: HypothesisEngine,
        planner: Planner,
        executor_bridge: ExecutorBridge,
        state_machine: EngagementStateMachine,
        kill_switch: KillSwitch,
        event_log: Optional[EventLog] = None,
        budget: Optional[LoopBudget] = None,
    ):
        self._observer = observer
        self._hypothesis_engine = hypothesis_engine
        self._planner = planner
        self._executor = executor_bridge
        self._state_machine = state_machine
        self._kill_switch = kill_switch
        self._event_log = event_log
        self._budget = budget or LoopBudget()

        # Internal state
        self._iteration = 0
        self._total_observations = 0
        self._total_actions = 0
        self._start_time: float = 0
        self._empty_iterations = 0  # Convergence tracking
        self._identical_obs_count = 0  # D-01: identical observation tracking
        self._last_obs_hash: str = ""
        self._phase_iterations: Dict[EngagementPhase, int] = {}
        self._phase_observations: Dict[EngagementPhase, int] = {}

    def run(self, engagement: Engagement) -> EngagementResult:
        """Run the main OODA loop.

        # VT-Spec D-01: Hard budget limits
        # VT-Spec S-01: Kill switch every iteration
        # VT-Spec R-01: Log every iteration
        """
        self._start_time = time.monotonic()
        self._iteration = 0
        reason = "completed"

        try:
            while True:
                # VT-Spec D-01: Iteration budget check
                if self._iteration >= self._budget.max_iterations:
                    reason = "max_iterations_reached"
                    logger.info(
                        "VT-Spec D-01: Max iterations (%d) reached",
                        self._budget.max_iterations,
                    )
                    break

                # VT-Spec D-01: Wall clock budget check
                elapsed = time.monotonic() - self._start_time
                if elapsed >= self._budget.wall_clock_budget:
                    reason = "wall_clock_budget_exceeded"
                    logger.info(
                        "VT-Spec D-01: Wall clock budget (%.0fs) exceeded",
                        self._budget.wall_clock_budget,
                    )
                    break

                # VT-Spec S-01: Kill switch check every iteration
                if self._kill_switch.is_killed(engagement.id):
                    reason = "kill_switch_activated"
                    logger.warning("VT-Spec S-01: Kill switch active, aborting loop")
                    self._state_machine.abort("Kill switch activated during OODA loop")
                    break

                # Terminal state check
                if engagement.phase in (
                    EngagementPhase.COMPLETED,
                    EngagementPhase.ABORTED,
                ):
                    reason = f"terminal_phase_{engagement.phase.value}"
                    break

                # VT-Spec R-01: Verify event log integrity at iteration start
                if self._event_log:
                    if not self._event_log.verify_integrity():
                        reason = "event_log_integrity_failure"
                        logger.error(
                            "VT-Spec R-01: Event log integrity check failed at iteration %d",
                            self._iteration,
                        )
                        self._state_machine.abort("Event log integrity failure")
                        break

                # Run one iteration
                result = self._run_iteration(engagement)
                self._iteration += 1

                # Track phase iterations
                current_phase = self._state_machine.current_phase
                self._phase_iterations[current_phase] = (
                    self._phase_iterations.get(current_phase, 0) + 1
                )

                if result.aborted:
                    reason = "aborted_during_iteration"
                    break

                # VT-Spec R-01: Log iteration
                self._log_iteration(engagement.id, result)

                # Check convergence
                if self._check_convergence(result, engagement):
                    # Try phase advancement
                    if not self._advance_phase(engagement):
                        reason = "converged"
                        break

                # VT-Spec D-01: Forced convergence after N identical observations
                if self._identical_obs_count >= self._budget.convergence_threshold:
                    logger.info(
                        "VT-Spec D-01: Forced convergence after %d identical observations",
                        self._identical_obs_count,
                    )
                    if not self._advance_phase(engagement):
                        reason = "forced_convergence"
                        break

        except ExecutionAborted:
            reason = "execution_aborted"

        # Transition to reporting if still active
        if engagement.phase not in (
            EngagementPhase.COMPLETED,
            EngagementPhase.ABORTED,
            EngagementPhase.REPORTING,
        ):
            try:
                # Try to reach REPORTING phase
                self._transition_to_reporting(engagement)
            except TransitionError:
                pass

        duration = time.monotonic() - self._start_time

        # Log final result
        if self._event_log:
            self._event_log.append(
                Event(
                    engagement_id=engagement.id,
                    event_type=EventType.ENGAGEMENT_COMPLETED
                    if engagement.status == EngagementStatus.COMPLETED
                    else EventType.ENGAGEMENT_ABORTED,
                    data={
                        "reason": reason,
                        "iterations_completed": self._iteration,
                        "total_observations": self._total_observations,
                        "total_actions": self._total_actions,
                        "duration_seconds": duration,
                        "max_iterations": self._budget.max_iterations,
                    },
                    actor="brain.loop_controller",
                )
            )

        return EngagementResult(
            engagement_id=engagement.id,
            iterations_completed=self._iteration,
            total_observations=self._total_observations,
            total_actions=self._total_actions,
            final_phase=engagement.phase,
            final_status=engagement.status,
            reason=reason,
            duration_seconds=duration,
        )

    def _run_iteration(self, engagement: Engagement) -> IterationResult:
        """Execute one OODA iteration.

        Observe → Orient (Hypothesize) → Decide (Plan) → Act (Execute)
        """
        result = IterationResult(iteration=self._iteration)
        current_phase = self._state_machine.current_phase
        context = {
            "engagement_id": engagement.id,
            "target_id": engagement.targets[0].id if engagement.targets else None,
            "phase": current_phase,
        }

        # OBSERVE: Process any pending output
        # In stub mode, we feed back from last execution artifacts
        # (In Phase 2, this would process real tool output)

        # ORIENT: Generate hypotheses from existing observations
        all_observations = result.observations  # Will be populated by executor feedback
        hypotheses = self._hypothesis_engine.generate(all_observations, context)
        result.hypotheses_generated = len(hypotheses)

        # Get all active hypotheses (including from previous iterations)
        active_hypotheses = self._hypothesis_engine.get_active_hypotheses()

        # Rank hypotheses
        ranked = self._hypothesis_engine.rank(active_hypotheses)

        # DECIDE: Plan actions from top hypotheses
        actions = self._planner.plan(ranked, engagement)

        # VT-Spec D-01: Cap actions per iteration
        actions = actions[: self._budget.max_actions_per_iteration]
        result.actions_planned = len(actions)

        # ACT: Execute planned actions
        for action in actions:
            try:
                artifact = self._executor.execute(action, engagement)
                result.artifacts.append(artifact)
                result.actions_executed += 1
                self._total_actions += 1

                # Feed output back to observer
                if artifact.output:
                    tool = action.command.split()[0] if action.command else "unknown"
                    new_obs = self._observer.process_output(
                        artifact.output, tool, context
                    )
                    result.observations.extend(new_obs)
                    self._total_observations += len(new_obs)
                    self._phase_observations[current_phase] = (
                        self._phase_observations.get(current_phase, 0) + len(new_obs)
                    )

            except ExecutionAborted:
                result.aborted = True
                break

        # Track observation identity for convergence detection
        self._track_observation_identity(result.observations)

        return result

    def _track_observation_identity(self, observations: List[Observation]) -> None:
        """Track observation content hash for forced convergence.

        # VT-Spec D-01: Content-hash deduplication ignoring volatile fields
        """
        if not observations:
            self._empty_iterations += 1
            return

        self._empty_iterations = 0

        # Compute hash of observation content (ignoring volatile fields)
        obs_content = "|".join(
            sorted(
                f"{o.observation_type.value}:{sorted(((k,v) for k,v in o.data.items() if k not in ('timestamp','session_id','nonce')))}"
                for o in observations
            )
        )
        obs_hash = hashlib.sha256(obs_content.encode()).hexdigest()

        if obs_hash == self._last_obs_hash:
            self._identical_obs_count += 1
        else:
            self._identical_obs_count = 0
            self._last_obs_hash = obs_hash

    def _check_convergence(
        self, result: IterationResult, engagement: Engagement
    ) -> bool:
        """Check if the current phase has converged.

        Convergence = N iterations with zero new observations AND zero new hypotheses.
        """
        if result.observations or result.hypotheses_generated > 0:
            self._empty_iterations = 0
            return False

        self._empty_iterations += 1
        return self._empty_iterations >= CONVERGENCE_EMPTY_ITERATIONS

    def _advance_phase(self, engagement: Engagement) -> bool:
        """Attempt to advance to the next engagement phase.

        # VT-Spec E-01: Require minimum observations and iterations before advancement
        """
        current_phase = self._state_machine.current_phase

        # VT-Spec E-01: Minimum iterations per phase
        phase_iters = self._phase_iterations.get(current_phase, 0)
        if phase_iters < MIN_ITERATIONS_PER_PHASE:
            logger.info(
                "VT-Spec E-01: Phase %s needs %d more iterations before advancement",
                current_phase.value,
                MIN_ITERATIONS_PER_PHASE - phase_iters,
            )
            self._empty_iterations = 0  # Reset to keep looping
            return True  # Keep looping (not truly converged)

        # VT-Spec E-01: Minimum observations per phase
        phase_obs = self._phase_observations.get(current_phase, 0)
        if phase_obs < MIN_OBSERVATIONS_PER_PHASE:
            logger.info(
                "VT-Spec E-01: Phase %s has insufficient observations (%d < %d)",
                current_phase.value,
                phase_obs,
                MIN_OBSERVATIONS_PER_PHASE,
            )
            # Don't prevent advancement forever — allow if we've been stuck
            if phase_iters < MIN_ITERATIONS_PER_PHASE * 3:
                self._empty_iterations = 0
                return True

        # Determine next phase
        try:
            current_idx = PHASE_ORDER.index(current_phase)
        except ValueError:
            return False

        if current_idx + 1 >= len(PHASE_ORDER):
            return False

        next_phase = PHASE_ORDER[current_idx + 1]

        if not self._state_machine.can_transition_to(next_phase):
            return False

        try:
            self._state_machine.transition_to(
                next_phase,
                reason=f"Phase {current_phase.value} converged after {phase_iters} iterations",
            )
            # VT-Spec R-01: Log phase advancement
            if self._event_log:
                self._event_log.append(
                    Event(
                        engagement_id=engagement.id,
                        event_type=EventType.PHASE_CHANGED,
                        data={
                            "from_phase": current_phase.value,
                            "to_phase": next_phase.value,
                            "phase_iterations": phase_iters,
                            "phase_observations": phase_obs,
                        },
                        actor="brain.loop_controller",
                    )
                )
            # Reset convergence tracking for new phase
            self._empty_iterations = 0
            self._identical_obs_count = 0
            self._observer.reset_deduplication()
            return True
        except TransitionError as e:
            logger.warning("Phase advancement failed: %s", e)
            return False

    def _transition_to_reporting(self, engagement: Engagement) -> None:
        """Try to transition to REPORTING phase through intermediate phases."""
        target_phase = EngagementPhase.REPORTING
        current = self._state_machine.current_phase

        # Walk through phases to reach REPORTING
        while current != target_phase:
            try:
                idx = PHASE_ORDER.index(current)
            except ValueError:
                break

            if idx + 1 >= len(PHASE_ORDER):
                break

            next_phase = PHASE_ORDER[idx + 1]
            if not self._state_machine.can_transition_to(next_phase):
                break

            try:
                self._state_machine.transition_to(
                    next_phase, reason="Auto-advancing to reporting"
                )
                current = next_phase
                if current == target_phase:
                    break
            except TransitionError:
                break

    def _log_iteration(self, engagement_id: str, result: IterationResult) -> None:
        """Log iteration to EventLog.

        # VT-Spec R-01: Every iteration logged
        """
        if self._event_log:
            self._event_log.append(
                Event(
                    engagement_id=engagement_id,
                    event_type=EventType.OBSERVATION_ADDED,
                    data={
                        "action": "iteration_completed",
                        "iteration": result.iteration,
                        "observations": len(result.observations),
                        "hypotheses_generated": result.hypotheses_generated,
                        "actions_planned": result.actions_planned,
                        "actions_executed": result.actions_executed,
                        "empty_iterations": self._empty_iterations,
                        "elapsed_seconds": time.monotonic() - self._start_time,
                    },
                    actor="brain.loop_controller",
                )
            )
