"""Executor Bridge for Erebos decision loop (REQ-004, REQ-007).

Dispatches actions through the full control gate pipeline.
Phase 2: Real execution layer integration via ExecutorDispatcher.

# VT-Spec S-01: Kill switch check at start of every execution
# VT-Spec E-02: Approval enforcement with HMAC verification
# VT-Spec R-01: Every decision logged to EventLog
# VT-Spec AC-001 CRITICAL: Double scope validation — bridge + executor level
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Optional

from erebos.control.approval import ApprovalGate, ApprovalRequest, ApprovalStatus
from erebos.control.killswitch import KillSwitch
from erebos.control.policy import PolicyEngine
from erebos.control.scope import ScopeValidator
from erebos.core.events import Event, EventLog, EventType
from erebos.core.models import (
    ActionStatus,
    Engagement,
    ExecutionArtifact,
    PlannedAction,
)
from erebos.executor.base import ExecutorDispatcher, ExecutionResult

logger = logging.getLogger(__name__)


class ExecutionAborted(Exception):
    """Raised when execution is aborted by kill switch."""

    pass


class ExecutorBridge:
    """Dispatches actions through scope → policy → approval → execute pipeline.

    # VT-Spec S-01: Kill switch check at start of every execution
    # VT-Spec E-02: Approval enforcement at this layer
    # VT-Spec R-01: Every decision logged
    # VT-Spec AC-001 CRITICAL: Double scope validation at bridge + executor level
    """

    def __init__(
        self,
        scope_validator: ScopeValidator,
        policy_engine: PolicyEngine,
        approval_gate: Optional[ApprovalGate],
        kill_switch: KillSwitch,
        event_log: Optional[EventLog] = None,
        executor_dispatcher: Optional[ExecutorDispatcher] = None,
    ):
        self._scope = scope_validator
        self._policy = policy_engine
        self._approval = approval_gate
        self._kill_switch = kill_switch
        self._event_log = event_log
        # VT-Spec REQ-007: Real executor dispatcher (replaces stub)
        self._dispatcher = executor_dispatcher

    def execute(
        self,
        action: PlannedAction,
        engagement: Engagement,
    ) -> ExecutionArtifact:
        """Execute an action through the full control gate pipeline.

        Pipeline: kill_switch → scope → policy → approval → execute → observe

        # VT-Spec S-01 MEDIUM: Kill switch check first
        # VT-Spec E-02: Approval HMAC verification mandatory
        # VT-Spec R-01: All decisions logged
        """
        # VT-Spec S-01: Kill switch check as FIRST operation
        if self._kill_switch.is_killed(engagement.id):
            action.status = ActionStatus.ABORTED
            self._log_event(
                engagement.id,
                EventType.KILL_SWITCH_ACTIVATED,
                {
                    "action_id": action.id,
                    "reason": "Kill switch active — execution aborted",
                },
            )
            raise ExecutionAborted(
                f"Kill switch active for engagement {engagement.id}"
            )

        # Step 1: Scope validation
        scope_ok, scope_reason = self._scope.validate_command(action.command)
        if not scope_ok:
            action.status = ActionStatus.REJECTED
            self._log_event(
                engagement.id,
                EventType.ACTION_REJECTED,
                {
                    "action_id": action.id,
                    "reason": f"Scope violation: {scope_reason}",
                    "command": action.command,
                },
            )
            return ExecutionArtifact(
                action_id=action.id,
                engagement_id=engagement.id,
                output=f"Rejected: {scope_reason}",
                exit_code=-1,
            )

        # Step 2: Policy evaluation
        decision = self._policy.evaluate(action)
        self._log_event(
            engagement.id,
            EventType.POLICY_EVALUATED,
            {
                "action_id": action.id,
                "allowed": decision.allowed,
                "reason": decision.reason,
                "requires_approval": decision.requires_approval,
            },
        )

        if not decision.allowed:
            action.status = ActionStatus.REJECTED
            self._log_event(
                engagement.id,
                EventType.ACTION_REJECTED,
                {"action_id": action.id, "reason": decision.reason},
            )
            return ExecutionArtifact(
                action_id=action.id,
                engagement_id=engagement.id,
                output=f"Policy rejected: {decision.reason}",
                exit_code=-1,
            )

        # Step 3: Approval check (if required)
        # VT-Spec E-02: Approval enforcement at execution layer
        if action.requires_approval or decision.requires_approval:
            if not self._check_approval(action, engagement):
                return ExecutionArtifact(
                    action_id=action.id,
                    engagement_id=engagement.id,
                    output="Awaiting approval or approval denied",
                    exit_code=-1,
                )

        # VT-Spec S-01: Kill switch re-check before dispatch
        if self._kill_switch.is_killed(engagement.id):
            action.status = ActionStatus.ABORTED
            self._log_event(
                engagement.id,
                EventType.KILL_SWITCH_ACTIVATED,
                {
                    "action_id": action.id,
                    "reason": "Kill switch activated during gate checks",
                },
            )
            raise ExecutionAborted(
                f"Kill switch active for engagement {engagement.id}"
            )

        # Step 4: Execute via real executor dispatcher (REQ-007)
        action.status = ActionStatus.EXECUTING
        action.executed_at = datetime.now(timezone.utc)

        start = time.monotonic()
        artifact = self._dispatch_execute(action, engagement)
        artifact.duration_seconds = time.monotonic() - start

        # Step 5: Log execution — preserve FAILED status if set by dispatcher
        if action.status != ActionStatus.FAILED:
            action.status = ActionStatus.COMPLETED
        self._log_event(
            engagement.id,
            EventType.ACTION_EXECUTED,
            {
                "action_id": action.id,
                "artifact_id": artifact.id,
                "exit_code": artifact.exit_code,
                "duration_seconds": artifact.duration_seconds,
            },
        )

        # VT-Spec S-01: Kill switch check after execution
        if self._kill_switch.is_killed(engagement.id):
            logger.warning(
                "VT-Spec S-01: Kill switch activated during execution of %s",
                action.id,
            )

        return artifact

    def _check_approval(
        self, action: PlannedAction, engagement: Engagement
    ) -> bool:
        """Check approval status for an action.

        # VT-Spec E-02: HMAC verification mandatory for approved actions
        """
        if self._approval is None:
            # No approval gate configured — deny by default for actions requiring approval
            action.status = ActionStatus.REJECTED
            self._log_event(
                engagement.id,
                EventType.ACTION_REJECTED,
                {
                    "action_id": action.id,
                    "reason": "Approval required but no approval gate configured",
                },
            )
            return False

        # Check if already has an approval request
        approval_id = getattr(action, "_approval_id", None)

        if approval_id:
            # Check timeout first
            self._approval.check_timeout(approval_id)

            # VT-Spec E-02: Verify approval with HMAC check
            if self._approval.verify_approval(approval_id):
                return True
            else:
                # Not yet approved or rejected
                action.status = ActionStatus.PENDING_APPROVAL
                return False

        # Create new approval request
        request = ApprovalRequest(
            action_id=action.id,
            engagement_id=engagement.id,
            summary=f"Action: {action.action_type.value} — {action.description}",
            risk_level=action.impact_level.value,
        )
        self._approval.request_approval(request)
        action._approval_id = request.id  # type: ignore[attr-defined]
        action.status = ActionStatus.PENDING_APPROVAL

        self._log_event(
            engagement.id,
            EventType.APPROVAL_REQUESTED,
            {
                "action_id": action.id,
                "approval_id": request.id,
                "risk_level": action.impact_level.value,
            },
        )
        return False

    def _dispatch_execute(
        self, action: PlannedAction, engagement: Engagement
    ) -> ExecutionArtifact:
        """Dispatch to real executor or fall back to stub.

        # VT-Spec REQ-007: Routes via ExecutorDispatcher.
        # VT-Spec AC-001: Scope already validated at bridge level; executor validates again.

        Handles executor failures gracefully (retry once, then mark failed).
        """
        if self._dispatcher is None:
            # Fallback to stub if no dispatcher configured
            return self._stub_execute(action, engagement)

        # VT-Spec R-01: Log executor selection
        executor_type = self._dispatcher.resolve_executor_type(action)
        self._log_event(
            engagement.id,
            EventType.ACTION_EXECUTED,
            {
                "action_id": action.id,
                "executor_type": executor_type.value,
                "phase": "dispatch",
            },
        )

        # Execute with retry (once on failure)
        result: Optional[ExecutionResult] = None
        for attempt in range(2):
            try:
                result = self._dispatcher.dispatch(action, engagement.id)
                if result.exit_code != -1 or attempt == 1:
                    break
                # Retry once on failure
                logger.warning(
                    "Executor failed for action %s (attempt %d), retrying",
                    action.id,
                    attempt + 1,
                )
            except Exception as e:
                logger.error(
                    "Executor error for action %s: %s", action.id, e
                )
                if attempt == 1:
                    action.status = ActionStatus.FAILED
                    return ExecutionArtifact(
                        action_id=action.id,
                        engagement_id=engagement.id,
                        output=f"Executor failed: {type(e).__name__}",
                        exit_code=-1,
                    )

        if result is None:
            return ExecutionArtifact(
                action_id=action.id,
                engagement_id=engagement.id,
                output="Executor returned no result",
                exit_code=-1,
            )

        return ExecutionArtifact(
            action_id=action.id,
            engagement_id=engagement.id,
            output=result.stdout or result.stderr,
            exit_code=result.exit_code if result.exit_code is not None else -1,
        )

    def _stub_execute(
        self, action: PlannedAction, engagement: Engagement
    ) -> ExecutionArtifact:
        """Stub executor — fallback when no dispatcher configured.

        Returns a placeholder artifact.
        """
        return ExecutionArtifact(
            action_id=action.id,
            engagement_id=engagement.id,
            output=f"[STUB] Would execute: {action.command}",
            exit_code=0,
        )

    def _log_event(
        self,
        engagement_id: str,
        event_type: EventType,
        data: dict,
    ) -> None:
        """Log an event to EventLog.

        # VT-Spec R-01: Every decision logged
        """
        if self._event_log:
            event = Event(
                engagement_id=engagement_id,
                event_type=event_type,
                data=data,
                actor="brain.executor_bridge",
            )
            self._event_log.append(event)
