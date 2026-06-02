"""Unit tests for intelligent error handling."""

from __future__ import annotations

import time
from typing import Dict, List, Tuple

import pytest

from erebos.core.error_handler import (
    ErrorClassifier,
    ErrorType,
    FallbackChain,
    FallbackChainManager,
    FallbackChainsConfig,
    FallbackStateStore,
    IntelligentErrorHandler,
    RecoveryStrategy,
    RecoveryStrategyRegistry,
)
from erebos.core.phase_agent import ReconAgent
from erebos.executors.retry import RetryableExecutor
from erebos.executors.base import ToolResult


class SequenceTransport:
    """Transport that returns pre-seeded results per tool."""

    def __init__(self, sequences: Dict[str, List[ToolResult]]):
        self.sequences = {tool: list(results) for tool, results in sequences.items()}
        self.calls: List[Tuple[str, List[str]]] = []

    def execute(self, tool: str, args, env=None, timeout=None) -> ToolResult:
        self.calls.append((tool, list(args)))
        results = self.sequences.get(tool, [])
        if results:
            return results.pop(0)
        return ToolResult(tool=tool, exit_code=0, stdout="", stderr="", duration_seconds=0.1)

    def stream(self, tool: str, args, env=None):
        yield tool

    def available(self) -> bool:
        return True


def make_result(tool: str, exit_code: int, stderr: str = "", stdout: str = "") -> ToolResult:
    return ToolResult(
        tool=tool,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        duration_seconds=0.1,
    )


def test_error_classifier_known_patterns():
    assert (
        ErrorClassifier.classify(make_result("masscan", 126, stderr="Permission denied"))
        == ErrorType.PERMISSION_DENIED
    )
    assert (
        ErrorClassifier.classify(make_result("ffuf", 124, stderr="timed out")) == ErrorType.TIMEOUT
    )
    assert (
        ErrorClassifier.classify(make_result("nikto", 1, stderr="Connection refused"))
        == ErrorType.NETWORK_ERROR
    )
    assert (
        ErrorClassifier.classify(make_result("nmap", 1, stderr="parse error"))
        == ErrorType.PARSE_FAILURE
    )
    assert (
        ErrorClassifier.classify(make_result("nmap", 127, stderr="command not found"))
        == ErrorType.TOOL_NOT_FOUND
    )
    assert (
        ErrorClassifier.classify(make_result("nuclei", 429, stderr="Too Many Requests"))
        == ErrorType.RATE_LIMIT
    )
    assert (
        ErrorClassifier.classify(make_result("nuclei", 255, stderr="Segmentation fault"))
        == ErrorType.UNKNOWN
    )


def test_fallback_chain_manager_loads_default_yaml():
    manager = FallbackChainManager.load()

    chain = manager.get_chain("network_scanning")
    assert chain is not None
    assert chain.primary == "masscan"
    assert chain.alternatives == ["rustscan", "nmap"]


def test_fallback_chain_manager_loads_custom_tool_override(tmp_path):
    config_path = tmp_path / "fallbacks.yaml"
    config_path.write_text(
        """
fallback_chains:
  network_scanning:
    primary: masscan
    alternatives: [rustscan]
    max_retries: 1
    retry_delay: 0.0
    strategies:
      TIMEOUT: RETRY
    tool_strategies:
      masscan:
        PARSE_FAILURE: FALLBACK
""".strip()
    )

    manager = FallbackChainManager.load(str(config_path))

    assert manager.get_chain("network_scanning") is not None
    registry = RecoveryStrategyRegistry(
        manager.config.strategies,
        manager.config.tool_strategies,
    )
    assert (
        registry.get_strategy("network_scanning", ErrorType.PARSE_FAILURE, tool="masscan")
        == RecoveryStrategy.FALLBACK
    )


def test_phase_agent_loads_custom_fallback_chain_path(tmp_path):
    config_path = tmp_path / "fallbacks.yaml"
    config_path.write_text(
        """
fallback_chains:
  network_scanning:
    primary: masscan
    alternatives: [nmap]
    max_retries: 1
    retry_delay: 0.0
    strategies:
      PERMISSION_DENIED: FALLBACK
""".strip()
    )
    transport = SequenceTransport(
        {
            "masscan": [make_result("masscan", 126, stderr="Permission denied")],
            "nmap": [make_result("nmap", 0, stdout="ok")],
        }
    )
    agent = ReconAgent(transport=transport, parsers={})

    result = agent._execute_tool(
        "masscan",
        ["example.com"],
        {
            "enable_intelligent_error_handler": True,
            "error_handler_fallback_chains_path": str(config_path),
        },
        category="network_scanning",
    )

    assert result.exit_code == 0
    assert result.fallback_source == "nmap"


def test_intelligent_error_handler_falls_back_on_permission_denied():
    transport = SequenceTransport(
        {
            "masscan": [make_result("masscan", 126, stderr="Permission denied")],
            "rustscan": [make_result("rustscan", 0, stdout="ok")],
        }
    )
    handler = IntelligentErrorHandler(transport=transport, sleep_func=lambda _: None)

    result = handler.execute_with_fallback(
        tool="masscan",
        args=["example.com"],
        category="network_scanning",
        scan_id="scan-1",
    )

    assert result.exit_code == 0
    assert result.degraded is True
    assert result.fallback_source == "rustscan"
    assert result.attempted_tools == ["masscan", "rustscan"]
    assert len(result.recovery_context["attempts"]) >= 1
    assert [call[0] for call in transport.calls] == ["masscan", "rustscan"]


def test_intelligent_error_handler_returns_primary_success_without_fallback():
    transport = SequenceTransport({"masscan": [make_result("masscan", 0, stdout="ok")]})
    handler = IntelligentErrorHandler(transport=transport, sleep_func=lambda _: None)

    result = handler.execute_with_fallback(
        tool="masscan",
        args=["example.com"],
        category="network_scanning",
        scan_id="scan-primary",
    )

    assert result.exit_code == 0
    assert result.degraded is False
    assert result.attempted_tools == ["masscan"]


def test_intelligent_error_handler_retries_timeout_before_fallback():
    transport = SequenceTransport(
        {
            "masscan": [
                make_result("masscan", 124, stderr="timed out"),
                make_result("masscan", 124, stderr="timed out"),
                make_result("masscan", 0, stdout="ok"),
            ]
        }
    )
    config = FallbackChainsConfig(
        chains={
            "network_scanning": FallbackChain(
                primary="masscan",
                alternatives=["rustscan", "nmap"],
                max_retries=2,
                retry_delay=0.0,
            )
        }
    )
    handler = IntelligentErrorHandler(transport=transport, config=config, sleep_func=lambda _: None)

    result = handler.execute_with_fallback(
        tool="masscan",
        args=["example.com"],
        category="network_scanning",
        scan_id="scan-2",
    )

    assert result.exit_code == 0
    assert [call[0] for call in transport.calls] == ["masscan", "masscan", "masscan"]


def test_intelligent_error_handler_gracefully_degrades_when_fallbacks_fail():
    transport = SequenceTransport(
        {
            "masscan": [make_result("masscan", 126, stderr="Permission denied")],
            "rustscan": [make_result("rustscan", 1, stderr="still denied")],
            "nmap": [make_result("nmap", 1, stderr="still denied")],
        }
    )
    handler = IntelligentErrorHandler(transport=transport, sleep_func=lambda _: None)

    result = handler.execute_with_fallback(
        tool="masscan",
        args=["example.com"],
        category="network_scanning",
        scan_id="scan-3",
    )

    assert result.exit_code == 1
    assert result.degraded is True
    assert result.attempted_tools == ["masscan", "rustscan", "nmap"]
    assert result.fallback_source == "nmap"


def test_error_classifier_handles_empty_values():
    result = make_result("masscan", 1, stderr="", stdout="")
    assert ErrorClassifier.classify(result) == ErrorType.UNKNOWN
    assert ErrorClassifier.classify_exception(None, stdout="", stderr="") == ErrorType.UNKNOWN


def test_recovery_strategy_registry_respects_tool_override():
    registry = RecoveryStrategyRegistry(
        overrides={"network_scanning": {ErrorType.TIMEOUT: RecoveryStrategy.RETRY}},
        tool_overrides={
            "network_scanning": {"masscan": {ErrorType.TIMEOUT: RecoveryStrategy.FALLBACK}}
        },
    )

    assert (
        registry.get_strategy("network_scanning", ErrorType.TIMEOUT, tool="masscan")
        == RecoveryStrategy.FALLBACK
    )


def test_missing_alternatives_downgrades_fallback_to_skip():
    registry = RecoveryStrategyRegistry(
        overrides={"network_scanning": {ErrorType.PERMISSION_DENIED: RecoveryStrategy.FALLBACK}}
    )

    assert (
        registry.get_strategy(
            "network_scanning",
            ErrorType.PERMISSION_DENIED,
            tool="masscan",
            has_fallback=False,
        )
        == RecoveryStrategy.SKIP
    )


def test_retry_with_backoff_records_attempts():
    transport = SequenceTransport(
        {"masscan": [make_result("masscan", 124, stderr="timed out"), make_result("masscan", 0)]}
    )
    config = FallbackChainsConfig(
        chains={
            "network_scanning": FallbackChain(
                primary="masscan",
                alternatives=[],
                max_retries=2,
                retry_delay=0.0,
            )
        }
    )
    handler = IntelligentErrorHandler(transport=transport, config=config, sleep_func=lambda _: None)

    result = handler.execute_with_fallback(
        tool="masscan",
        args=["example.com"],
        category="network_scanning",
        scan_id="retry-scan",
    )

    assert result.exit_code == 0
    assert result.attempted_tools == ["masscan", "masscan"]


def test_fallback_state_store_returns_statistics():
    transport = SequenceTransport(
        {
            "masscan": [make_result("masscan", 126, stderr="Permission denied")],
            "rustscan": [make_result("rustscan", 0, stdout="ok")],
        }
    )
    store = FallbackStateStore()
    handler = IntelligentErrorHandler(
        transport=transport,
        fallback_state_store=store,
        sleep_func=lambda _: None,
    )

    result = handler.execute_with_fallback(
        tool="masscan",
        args=["example.com"],
        category="network_scanning",
        scan_id="stats-scan",
    )

    stats = store.get_statistics("stats-scan")
    assert result.recovery_context["statistics"]["total_fallbacks"] == stats.total_fallbacks
    assert stats.total_fallbacks >= 1
    assert "masscan" in stats.tools


def test_classification_performance_under_100ms():
    result = make_result("nmap", 124, stderr="timed out")
    start = time.perf_counter()
    for _ in range(1000):
        ErrorClassifier.classify(result)
    duration = time.perf_counter() - start
    assert duration < 0.1


def test_handler_overhead_under_10ms_per_execution():
    transport = SequenceTransport(
        {"masscan": [make_result("masscan", 0, stdout="ok") for _ in range(100)]}
    )
    handler = IntelligentErrorHandler(transport=transport, sleep_func=lambda _: None)

    start = time.perf_counter()
    for _ in range(100):
        handler.execute_with_fallback(
            tool="masscan",
            args=["example.com"],
            category="network_scanning",
            scan_id="perf-scan",
        )
    duration = time.perf_counter() - start

    assert (duration / 100) < 0.01


def test_phase_agent_uses_feature_flag_for_intelligent_handler():
    transport = SequenceTransport(
        {
            "masscan": [make_result("masscan", 126, stderr="Permission denied")],
            "rustscan": [make_result("rustscan", 0, stdout="ok")],
        }
    )
    agent = ReconAgent(transport=transport, parsers={})

    disabled = agent._execute_tool(
        "masscan",
        ["example.com"],
        {"enable_intelligent_error_handler": False},
        category="network_scanning",
    )
    assert getattr(disabled, "degraded", False) is False

    transport = SequenceTransport(
        {
            "masscan": [make_result("masscan", 126, stderr="Permission denied")],
            "rustscan": [make_result("rustscan", 0, stdout="ok")],
        }
    )
    agent = ReconAgent(transport=transport, parsers={})
    enabled = agent._execute_tool(
        "masscan",
        ["example.com"],
        {"enable_intelligent_error_handler": True},
        category="network_scanning",
    )

    assert enabled.degraded is True
    assert enabled.fallback_source == "rustscan"


def test_phase_agent_applies_degraded_metadata_to_findings():
    transport = SequenceTransport({"masscan": [make_result("masscan", 0, stdout="[]")]})
    agent = ReconAgent(transport=transport, parsers={})
    findings = agent._apply_result_metadata(
        [],
        agent._execute_tool(
            "masscan",
            ["example.com"],
            {"enable_intelligent_error_handler": True},
            category="network_scanning",
        ),
    )

    assert findings == []


def test_web_scanning_timeout_skips_without_invalid_fallback_tool():
    transport = SequenceTransport(
        {
            "nikto": [
                make_result("nikto", 124, stderr="timed out"),
                make_result("nikto", 124, stderr="timed out"),
                make_result("nikto", 124, stderr="timed out"),
                make_result("nikto", 124, stderr="timed out"),
            ]
        }
    )
    handler = IntelligentErrorHandler(transport=transport, sleep_func=lambda _: None)

    result = handler.execute_with_fallback(
        tool="nikto",
        args=["-host", "example.com"],
        category="web_scanning",
        scan_id="nikto-timeout",
    )

    assert result.exit_code == 75
    assert result.fallback_source == "skip"
    assert [call[0] for call in transport.calls] == ["nikto", "nikto", "nikto", "nikto"]
    assert "niktoder" not in [call[0] for call in transport.calls]
    assert "Coverage skipped after recovery exhaustion" in result.stderr


def test_recon_agent_legacy_flow_respects_run_katana_flag(monkeypatch):
    agent = ReconAgent(transport=SequenceTransport({}), parsers={})
    called = False

    def fail_if_called(target, context):
        nonlocal called
        called = True
        raise AssertionError("katana should not run when disabled")

    monkeypatch.setattr(agent, "_run_katana", fail_if_called)

    findings = agent.execute(
        "example.com",
        {
            "enable_inference": False,
            "run_katana": False,
            "run_nmap": False,
            "run_nikto": False,
            "run_masscan": False,
            "run_amass": False,
            "run_subfinder": False,
            "run_ffuf": False,
            "run_gobuster": False,
            "run_dirb": False,
        },
    )

    assert findings == []
    assert called is False


def test_retryable_executor_delegates_to_intelligent_handler_when_enabled():
    transport = SequenceTransport(
        {
            "masscan": [make_result("masscan", 126, stderr="Permission denied")],
            "rustscan": [make_result("rustscan", 0, stdout="ok")],
        }
    )
    handler = IntelligentErrorHandler(transport=transport, sleep_func=lambda _: None)
    executor = RetryableExecutor(
        transport=transport,
        intelligent_handler=handler,
        enable_intelligent_error_handler=True,
    )

    result = executor.execute(
        "masscan",
        ["example.com"],
        tool_category="network_scanning",
        scan_id="delegated-scan",
    )

    assert result.exit_code == 0
    assert result.fallback_source == "rustscan"
