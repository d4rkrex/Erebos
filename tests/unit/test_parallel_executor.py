"""Tests for ParallelPhaseExecutor."""

import asyncio
from typing import Dict, Generator, List, Optional
from unittest.mock import MagicMock

import pytest

from erebos.core.attack_domain import AttackDomain
from erebos.core.finding import Finding, Phase, Severity
from erebos.core.parallel_executor import (
    MAX_CONCURRENCY_HARD_CAP,
    ParallelPhaseExecutor,
    PhaseResult,
    ToolConfig,
    ToolExecutionResult,
)
from erebos.executors.base import ToolResult, Transport
from erebos.parsers.base import Parser


class MockTransport(Transport):
    """Mock transport for testing."""

    def __init__(self, results: Dict[str, ToolResult] = None, delay: float = 0.0):
        self._results = results or {}
        self._delay = delay
        self.call_count = 0

    def execute(
        self,
        tool: str,
        args: List[str],
        env: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None,
    ) -> ToolResult:
        import time

        if self._delay:
            time.sleep(self._delay)
        self.call_count += 1
        if tool in self._results:
            return self._results[tool]
        return ToolResult(tool=tool, exit_code=0, stdout="", stderr="", duration_seconds=0.1)

    def stream(self, tool, args, env=None) -> Generator[str, None, None]:
        yield ""

    def available(self) -> bool:
        return True


class MockParser(Parser):
    """Mock parser that returns predefined findings."""

    tool_name = "mock"

    def __init__(self, findings: List[Finding] = None):
        self._findings = findings or []

    def parse(self, output: str) -> List[Finding]:
        return self._findings

    def can_parse(self, output: str) -> bool:
        return True


class TestParallelPhaseExecutor:
    def test_concurrency_hard_cap(self):
        transport = MockTransport()
        executor = ParallelPhaseExecutor(
            transport=transport,
            parsers={"nuclei": MockParser()},
            max_concurrency=999,
        )
        assert executor.max_concurrency == MAX_CONCURRENCY_HARD_CAP

    def test_concurrency_minimum(self):
        transport = MockTransport()
        executor = ParallelPhaseExecutor(
            transport=transport,
            parsers={"nuclei": MockParser()},
            max_concurrency=0,
        )
        assert executor.max_concurrency == 1

    def test_execute_phase_runs_tools(self):
        findings = [
            Finding(
                tool="nuclei",
                severity=Severity.HIGH,
                title="SQLi",
                description="SQL Injection",
                phase_found=Phase.VULN_SCAN,
            )
        ]
        transport = MockTransport()
        parsers = {"nuclei": MockParser(findings), "nikto": MockParser()}
        executor = ParallelPhaseExecutor(
            transport=transport, parsers=parsers, max_concurrency=3
        )

        tools = [
            ToolConfig(name="nuclei", args=["-t", "sqli"]),
            ToolConfig(name="nikto"),
        ]

        result = executor.execute_phase_sync(Phase.VULN_SCAN, "example.com", tools)
        assert isinstance(result, PhaseResult)
        assert result.total_findings == 1
        assert len(result.tool_results) == 2
        assert result.failed_tools == []

    def test_tool_failure_isolated(self):
        """SC-02: One tool crash doesn't abort siblings."""

        class FailingTransport(MockTransport):
            def execute(self, tool, args, env=None, timeout=None):
                if tool == "nuclei":
                    raise RuntimeError("nuclei crashed")
                return super().execute(tool, args, env, timeout)

        transport = FailingTransport()
        parsers = {"nuclei": MockParser(), "nikto": MockParser()}
        executor = ParallelPhaseExecutor(
            transport=transport, parsers=parsers, max_concurrency=3
        )

        tools = [ToolConfig(name="nuclei"), ToolConfig(name="nikto")]
        result = executor.execute_phase_sync(Phase.VULN_SCAN, "example.com", tools)

        # nikto should succeed, nuclei should fail
        assert result.partial_success is True
        assert "nuclei" in result.failed_tools

    def test_kill_switch_aborts(self):
        transport = MockTransport(delay=0.1)
        parsers = {"nuclei": MockParser(), "nikto": MockParser()}
        executor = ParallelPhaseExecutor(
            transport=transport,
            parsers=parsers,
            max_concurrency=1,
            kill_switch_check=lambda: True,  # Always aborted
        )

        tools = [ToolConfig(name="nuclei"), ToolConfig(name="nikto")]
        result = executor.execute_phase_sync(Phase.VULN_SCAN, "example.com", tools)

        # All tools should be aborted
        for tr in result.tool_results:
            assert tr.success is False
            assert "kill switch" in tr.error

    def test_unregistered_tool_skipped(self):
        """EOP-001: Only registered tools can execute."""
        transport = MockTransport()
        parsers = {"nuclei": MockParser()}  # nikto NOT registered
        executor = ParallelPhaseExecutor(
            transport=transport, parsers=parsers, max_concurrency=3
        )

        tools = [ToolConfig(name="nuclei"), ToolConfig(name="nikto")]
        result = executor.execute_phase_sync(Phase.VULN_SCAN, "example.com", tools)

        # Only nuclei should run
        assert len(result.tool_results) == 1
        assert result.tool_results[0].tool == "nuclei"
