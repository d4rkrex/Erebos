"""Parallel phase executor for concurrent tool execution.

Runs multiple security tools concurrently within a phase using asyncio,
with configurable concurrency limits and per-tool fault isolation.

VT-Spec DOS-001: Hard cap on concurrency (max 10) with fail-safe.
VT-Spec EOP-001: Only registered tools can execute; validates config.
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from erebos.core.attack_domain import AttackDomain, get_tool_domains
from erebos.core.finding import Finding, Phase
from erebos.executors.base import ToolResult, Transport
from erebos.parsers.base import Parser

logger = logging.getLogger(__name__)

# VT-Spec DOS-001: Absolute maximum concurrency to prevent resource exhaustion
MAX_CONCURRENCY_HARD_CAP = 10


@dataclass
class ToolConfig:
    """Configuration for a tool to execute."""

    name: str
    args: List[str] = field(default_factory=list)
    timeout: Optional[int] = None
    domains: List[AttackDomain] = field(default_factory=list)


@dataclass
class ToolExecutionResult:
    """Result from a single tool execution in parallel mode."""

    tool: str
    success: bool
    findings: List[Finding] = field(default_factory=list)
    error: Optional[str] = None
    duration_seconds: float = 0.0
    domains: List[AttackDomain] = field(default_factory=list)


@dataclass
class PhaseResult:
    """Aggregate result from parallel phase execution."""

    phase: Phase
    tool_results: List[ToolExecutionResult] = field(default_factory=list)
    total_findings: int = 0
    failed_tools: List[str] = field(default_factory=list)
    duration_seconds: float = 0.0

    @property
    def all_findings(self) -> List[Finding]:
        """Get all findings across all tools."""
        findings: List[Finding] = []
        for result in self.tool_results:
            findings.extend(result.findings)
        return findings

    @property
    def partial_success(self) -> bool:
        """True if at least one tool succeeded."""
        return any(r.success for r in self.tool_results)


class ParallelPhaseExecutor:
    """Executes tools concurrently within a phase.

    VT-Spec DOS-001: Enforces hard cap on concurrency.
    VT-Spec EOP-001: Validates tool names against registered tools.
    """

    def __init__(
        self,
        transport: Transport,
        parsers: Dict[str, Parser],
        max_concurrency: int = 3,
        kill_switch_check: Optional[callable] = None,
    ):
        # VT-Spec DOS-001: Enforce hard cap
        if max_concurrency < 1:
            max_concurrency = 1
        if max_concurrency > MAX_CONCURRENCY_HARD_CAP:
            logger.warning(
                f"Concurrency {max_concurrency} exceeds hard cap {MAX_CONCURRENCY_HARD_CAP}. "
                "Capping to prevent resource exhaustion (DOS-001)."
            )
            max_concurrency = MAX_CONCURRENCY_HARD_CAP

        self._transport = transport
        self._parsers = parsers
        self._max_concurrency = max_concurrency
        self._kill_switch_check = kill_switch_check
        self._semaphore: Optional[asyncio.Semaphore] = None

    @property
    def max_concurrency(self) -> int:
        return self._max_concurrency

    async def execute_phase(
        self,
        phase: Phase,
        target: str,
        tools: List[ToolConfig],
    ) -> PhaseResult:
        """Execute all tools concurrently with bounded concurrency.

        Args:
            phase: Current phase enum value.
            target: Scan target.
            tools: List of tool configurations to execute.

        Returns:
            PhaseResult with all tool results aggregated.
        """
        self._semaphore = asyncio.Semaphore(self._max_concurrency)
        start_time = time.time()

        # VT-Spec EOP-001: Validate all tools have registered parsers
        for tool_config in tools:
            if tool_config.name not in self._parsers:
                logger.warning(
                    f"Tool '{tool_config.name}' has no registered parser. "
                    "Skipping to prevent unvalidated execution (EOP-001)."
                )

        # Launch all tools concurrently (semaphore bounds actual parallelism)
        tasks = [
            self._execute_tool(tool_config, target, phase)
            for tool_config in tools
            if tool_config.name in self._parsers
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Collect results
        phase_result = PhaseResult(phase=phase)
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Tool execution raised exception: {result}")
                phase_result.failed_tools.append(str(result))
            elif isinstance(result, ToolExecutionResult):
                phase_result.tool_results.append(result)
                if result.success:
                    phase_result.total_findings += len(result.findings)
                else:
                    phase_result.failed_tools.append(result.tool)

        phase_result.duration_seconds = time.time() - start_time
        return phase_result

    async def _execute_tool(
        self,
        tool_config: ToolConfig,
        target: str,
        phase: Phase,
    ) -> ToolExecutionResult:
        """Execute a single tool with semaphore control and fault isolation.

        VT-Spec SC-02: Tool failures are isolated — one crash doesn't abort siblings.
        """
        async with self._semaphore:
            # Check kill switch before execution
            if self._kill_switch_check and self._kill_switch_check():
                return ToolExecutionResult(
                    tool=tool_config.name,
                    success=False,
                    error="Aborted by kill switch",
                )

            start_time = time.time()
            try:
                # Run synchronous transport in executor to avoid blocking
                loop = asyncio.get_event_loop()
                tool_result: ToolResult = await loop.run_in_executor(
                    None,
                    lambda: self._transport.execute(
                        tool_config.name,
                        tool_config.args + [target],
                        timeout=tool_config.timeout,
                    ),
                )

                # Parse results
                parser = self._parsers[tool_config.name]
                findings = parser.parse(tool_result.stdout)

                duration = time.time() - start_time
                domains = tool_config.domains or get_tool_domains(tool_config.name)

                return ToolExecutionResult(
                    tool=tool_config.name,
                    success=True,
                    findings=findings,
                    duration_seconds=duration,
                    domains=domains,
                )

            except Exception as e:
                # VT-Spec SC-02: Isolated failure — log and return error result
                duration = time.time() - start_time
                logger.error(
                    f"Tool '{tool_config.name}' failed after {duration:.1f}s: {e}"
                )
                return ToolExecutionResult(
                    tool=tool_config.name,
                    success=False,
                    error=str(e),
                    duration_seconds=duration,
                )

    def execute_phase_sync(
        self,
        phase: Phase,
        target: str,
        tools: List[ToolConfig],
    ) -> PhaseResult:
        """Synchronous wrapper for execute_phase.

        Convenience method for integration with the existing synchronous
        PhaseStateMachine.
        """
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # Already in async context — create new loop in thread
                import concurrent.futures

                with concurrent.futures.ThreadPoolExecutor(1) as pool:
                    future = pool.submit(
                        asyncio.run,
                        self.execute_phase(phase, target, tools),
                    )
                    return future.result()
            else:
                return loop.run_until_complete(
                    self.execute_phase(phase, target, tools)
                )
        except RuntimeError:
            # No event loop exists
            return asyncio.run(self.execute_phase(phase, target, tools))
