"""Executor Interface for Erebos (REQ-001).

Defines the base executor ABC, ExecutionResult dataclass, and dispatcher.

# VT-Spec AC-001 CRITICAL: Double scope validation at bridge + executor level
# VT-Spec R-01: All executor lifecycle events logged
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

from erebos.core.models import PlannedAction

logger = logging.getLogger(__name__)


@dataclass
class ExecutionResult:
    """Result of executing a command/action."""

    stdout: str = ""
    stderr: str = ""
    exit_code: int = -1
    artifacts: list[Path] = field(default_factory=list)
    duration_seconds: float = 0.0
    truncated: bool = False


class ExecutorType(str, Enum):
    """Types of executors available."""

    SHELL = "shell"
    METASPLOIT = "metasploit"
    SANDBOX = "sandbox"


class BaseExecutor(ABC):
    """Abstract base class for all executors.

    # VT-Spec AC-001: Every executor MUST validate scope before execution.
    """

    @abstractmethod
    def execute(self, action: PlannedAction, engagement_id: str) -> ExecutionResult:
        """Execute a planned action.

        Args:
            action: The action to execute (pre-validated by bridge).
            engagement_id: The engagement this action belongs to.

        Returns:
            ExecutionResult with stdout, stderr, exit_code, artifacts.
        """
        ...

    @abstractmethod
    def cleanup(self, engagement_id: str) -> None:
        """Clean up all resources for an engagement.

        Args:
            engagement_id: The engagement to clean up.
        """
        ...

    @abstractmethod
    def abort(self, engagement_id: str) -> None:
        """Abort all running operations for an engagement.

        # VT-Spec EoP-02: Must terminate ALL descendant processes.

        Args:
            engagement_id: The engagement to abort.
        """
        ...


class ExecutorDispatcher:
    """Routes PlannedAction to correct executor based on action attributes.

    # VT-Spec AC-001 CRITICAL: Double scope validation — bridge + executor level.
    # VT-Spec R-01: Logs executor selection decisions.
    """

    def __init__(
        self,
        shell_executor: Optional[BaseExecutor] = None,
        metasploit_executor: Optional[BaseExecutor] = None,
        sandbox_executor: Optional[BaseExecutor] = None,
    ):
        self._executors: dict[ExecutorType, BaseExecutor] = {}
        if shell_executor:
            self._executors[ExecutorType.SHELL] = shell_executor
        if metasploit_executor:
            self._executors[ExecutorType.METASPLOIT] = metasploit_executor
        if sandbox_executor:
            self._executors[ExecutorType.SANDBOX] = sandbox_executor

    def resolve_executor_type(self, action: PlannedAction) -> ExecutorType:
        """Determine executor type for an action.

        Routing logic:
          - If action has requires_sandbox attribute set → SANDBOX
          - If action tool is 'metasploit' or 'msfconsole' → METASPLOIT
          - Otherwise → SHELL
        """
        # Check for sandbox requirement
        requires_sandbox = getattr(action, "requires_sandbox", False)
        if requires_sandbox:
            return ExecutorType.SANDBOX

        # Check for metasploit tool
        tool = self._extract_tool(action.command)
        if tool in ("metasploit", "msfconsole", "msfvenom", "msfrpc"):
            return ExecutorType.METASPLOIT

        return ExecutorType.SHELL

    def dispatch(self, action: PlannedAction, engagement_id: str) -> ExecutionResult:
        """Dispatch action to the appropriate executor.

        # VT-Spec AC-001: Scope already validated by bridge; executor validates again.
        # VT-Spec R-01: Log dispatch decision.

        Raises:
            ValueError: If required executor is not configured.
        """
        executor_type = self.resolve_executor_type(action)

        # VT-Spec R-01: Log executor selection
        logger.info(
            "VT-Spec R-01: Dispatching action %s to %s executor",
            action.id,
            executor_type.value,
        )

        if executor_type not in self._executors:
            logger.error(
                "Executor type %s not configured for action %s",
                executor_type.value,
                action.id,
            )
            return ExecutionResult(
                stdout="",
                stderr=f"Executor {executor_type.value} not configured",
                exit_code=-1,
            )

        executor = self._executors[executor_type]
        return executor.execute(action, engagement_id)

    def abort_all(self, engagement_id: str) -> None:
        """Abort all executors for an engagement.

        # VT-Spec EoP-02: Terminate ALL processes across all executors.
        """
        for executor_type, executor in self._executors.items():
            try:
                logger.info(
                    "VT-Spec EoP-02: Aborting %s executor for engagement %s",
                    executor_type.value,
                    engagement_id,
                )
                executor.abort(engagement_id)
            except Exception as e:
                logger.error(
                    "Error aborting %s executor for %s: %s",
                    executor_type.value,
                    engagement_id,
                    e,
                )

    def cleanup_all(self, engagement_id: str) -> None:
        """Clean up all executors for an engagement."""
        for executor_type, executor in self._executors.items():
            try:
                executor.cleanup(engagement_id)
            except Exception as e:
                logger.error(
                    "Error cleaning up %s executor for %s: %s",
                    executor_type.value,
                    engagement_id,
                    e,
                )

    @staticmethod
    def _extract_tool(command: str) -> str:
        """Extract tool name from command string."""
        parts = command.strip().split()
        if not parts:
            return ""
        # Handle paths like /usr/bin/nmap → nmap
        return parts[0].rsplit("/", 1)[-1].lower()
