"""Executors module exports."""

from erebos.executors.base import ToolResult, Transport
from erebos.executors.cli_adapter import CLIAdapter
from erebos.executors.mcp_adapter import MCPAdapter, MCPTransportFactory
from erebos.executors.retry import (
    RetryConfig,
    RetryableExecutor,
    execute_with_retry,
    is_retryable_result,
)
from erebos.executors.tool_discovery import (
    ToolDiscovery,
    ToolInfo,
    check_tool,
    get_tool_discovery,
    is_mvp_ready,
    get_missing_tools,
)

__all__ = [
    "ToolResult",
    "Transport",
    "CLIAdapter",
    "MCPAdapter",
    "MCPTransportFactory",
    "RetryConfig",
    "RetryableExecutor",
    "execute_with_retry",
    "is_retryable_result",
    "ToolDiscovery",
    "ToolInfo",
    "check_tool",
    "get_tool_discovery",
    "is_mvp_ready",
    "get_missing_tools",
]


def get_transport(transport_type: str = "cli", **kwargs) -> Transport:
    """Get a transport instance by type."""
    if transport_type == "cli":
        return CLIAdapter()
    if transport_type == "mcp":
        return MCPAdapter(**kwargs)
    return CLIAdapter()
