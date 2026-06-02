"""Erebos Executor Package — Real execution layer for autonomous engagements.

Implements REQ-001 through REQ-007 of the interactive-execution spec.
"""

from __future__ import annotations

from erebos.executor.base import (
    BaseExecutor,
    ExecutionResult,
    ExecutorDispatcher,
    ExecutorType,
)
from erebos.executor.shell import ShellManager
from erebos.executor.tools import ToolRunner
from erebos.executor.metasploit import MetasploitExecutor
from erebos.executor.sandbox import SandboxExecutor
from erebos.executor.output import OutputManager, OutputReference

__all__ = [
    "BaseExecutor",
    "ExecutionResult",
    "ExecutorDispatcher",
    "ExecutorType",
    "ShellManager",
    "ToolRunner",
    "MetasploitExecutor",
    "SandboxExecutor",
    "OutputManager",
    "OutputReference",
]
