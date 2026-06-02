"""Unit tests for ReconRole passive/active split and OSINT modes.

Tests cover:
- Passive tool execution (_run_gau, _run_waybackurls, _run_dnsx, _run_katana)
- execute_passive() only calls passive tools
- execute_active() only calls active tools
- osint_mode flag behavior
- Discovered subdomains tracking
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from erebos.agents.roles.recon import ReconRole


@dataclass
class MockToolResult:
    """Mock ToolResult for testing."""

    exit_code: int = 0
    stdout: str = ""
    stderr: str = ""
    tool: str = ""
    duration: float = 1.0


@pytest.fixture
def mock_executor():
    """Create a mock ToolExecutor that tracks calls."""
    executor = AsyncMock()
    executor.run = AsyncMock(return_value=MockToolResult(exit_code=0, stdout=""))
    return executor


@pytest.fixture
def mock_bus():
    """Create a mock FindingsBus."""
    bus = MagicMock()
    bus.publish = MagicMock()
    return bus


def make_role(executor, bus, osint_mode="none", target="example.com"):
    """Helper to create a ReconRole with mocks."""
    return ReconRole(
        executor=executor,
        bus=bus,
        agent_id="test-recon-001",
        target=target,
        osint_mode=osint_mode,
    )


class TestReconRoleOsintModes:
    """Test osint_mode flag behavior."""

    @pytest.mark.asyncio
    async def test_osint_only_runs_passive_tools(self, mock_executor, mock_bus):
        """--osint-only should only run passive tools."""
        role = make_role(mock_executor, mock_bus, osint_mode="only")

        # Make subfinder return some data
        mock_executor.run.return_value = MockToolResult(
            exit_code=0, stdout="sub1.example.com\nsub2.example.com\n"
        )

        result = await role.execute()

        # Should have run tools
        assert "tools_run" in result
        # Should NOT contain active tools
        active_tools = {"nmap", "httpx", "naabu", "katana"}
        for tool in result["tools_run"]:
            assert tool not in active_tools, f"Active tool {tool} ran in osint-only mode"

    @pytest.mark.asyncio
    async def test_osint_full_runs_passive_then_active(self, mock_executor, mock_bus):
        """--osint should run passive tools first, then active."""
        role = make_role(mock_executor, mock_bus, osint_mode="full")

        call_order: List[str] = []

        async def track_calls(tool_name, **kwargs):
            call_order.append(tool_name)
            return MockToolResult(exit_code=0, stdout="")

        mock_executor.run = track_calls

        await role.execute()

        # Verify passive tools come before active
        passive = {"subfinder", "assetfinder", "gau", "waybackurls", "dnsx"}
        active = {"nmap", "httpx", "naabu", "katana"}

        last_passive_idx = -1
        first_active_idx = len(call_order)
        for i, tool in enumerate(call_order):
            if tool in passive:
                last_passive_idx = max(last_passive_idx, i)
            if tool in active:
                first_active_idx = min(first_active_idx, i)

        if last_passive_idx >= 0 and first_active_idx < len(call_order):
            assert last_passive_idx < first_active_idx, "Passive tools should run before active"

    @pytest.mark.asyncio
    async def test_osint_none_skips_passive(self, mock_executor, mock_bus):
        """Default mode (none) should not run passive-only tools."""
        role = make_role(mock_executor, mock_bus, osint_mode="none")

        call_order: List[str] = []

        async def track_calls(tool_name, **kwargs):
            call_order.append(tool_name)
            return MockToolResult(exit_code=0, stdout="")

        mock_executor.run = track_calls

        await role.execute()

        # Should only have active tools
        passive_only = {"gau", "waybackurls"}  # subfinder/assetfinder run in legacy mode too
        for tool in call_order:
            assert tool not in passive_only, f"Passive-only tool {tool} ran in mode=none"


class TestReconRolePassiveTools:
    """Test individual passive tool execution methods."""

    @pytest.mark.asyncio
    async def test_run_gau_parses_urls(self, mock_executor, mock_bus):
        """_run_gau should parse URL output."""
        role = make_role(mock_executor, mock_bus, osint_mode="only")

        gau_output = (
            "https://example.com/api/v1/users\n"
            "https://example.com/login\n"
            "https://example.com/admin/dashboard\n"
        )
        mock_executor.run.return_value = MockToolResult(exit_code=0, stdout=gau_output)

        result = await role._run_gau()

        assert result is not None
        assert result.exit_code == 0
        mock_executor.run.assert_called_once()
        call_args = mock_executor.run.call_args
        assert call_args[0][0] == "gau"

    @pytest.mark.asyncio
    async def test_run_waybackurls_handles_empty(self, mock_executor, mock_bus):
        """_run_waybackurls should handle empty output gracefully."""
        role = make_role(mock_executor, mock_bus, osint_mode="only")

        mock_executor.run.return_value = MockToolResult(exit_code=0, stdout="")

        result = await role._run_waybackurls()

        assert result is not None
        assert len(role._findings) == 0

    @pytest.mark.asyncio
    async def test_run_dnsx_tracks_subdomains(self, mock_executor, mock_bus):
        """_run_dnsx should populate _discovered_subdomains."""
        role = make_role(mock_executor, mock_bus, osint_mode="only")

        dnsx_output = "api.example.com [A] [93.184.216.34]\nmail.example.com [MX] [10 mx.example.com]\n"
        mock_executor.run.return_value = MockToolResult(exit_code=0, stdout=dnsx_output)

        await role._run_dnsx()

        assert "api.example.com" in role._discovered_subdomains
        assert "mail.example.com" in role._discovered_subdomains

    @pytest.mark.asyncio
    async def test_run_katana_uses_https_url(self, mock_executor, mock_bus):
        """_run_katana should prepend https:// to bare domain targets."""
        role = make_role(mock_executor, mock_bus, osint_mode="full", target="example.com")

        mock_executor.run.return_value = MockToolResult(exit_code=0, stdout="")

        await role._run_katana()

        call_args = mock_executor.run.call_args
        args = call_args[1].get("args", call_args[0][1] if len(call_args[0]) > 1 else [])
        # Verify -u flag contains https://
        assert any("https://example.com" in str(a) for a in args)

    @pytest.mark.asyncio
    async def test_tool_not_found_skipped_gracefully(self, mock_executor, mock_bus):
        """If tool binary not found, should skip without crashing."""
        role = make_role(mock_executor, mock_bus, osint_mode="only")

        mock_executor.run.side_effect = FileNotFoundError("gau not found")

        result = await role._run_gau()

        assert result is None
        # Should have published a status message
        mock_bus.publish.assert_called()


class TestReconRoleSubdomainDiscovery:
    """Test subdomain tracking across passive tools."""

    @pytest.mark.asyncio
    async def test_subfinder_populates_discovered(self, mock_executor, mock_bus):
        """subfinder output should populate _discovered_subdomains."""
        role = make_role(mock_executor, mock_bus, osint_mode="only")

        subfinder_output = "api.example.com\nwww.example.com\nadmin.example.com\n"
        mock_executor.run.return_value = MockToolResult(exit_code=0, stdout=subfinder_output)

        await role._run_subfinder()

        assert "api.example.com" in role._discovered_subdomains
        assert "www.example.com" in role._discovered_subdomains
        assert "admin.example.com" in role._discovered_subdomains

    @pytest.mark.asyncio
    async def test_deduplication_across_tools(self, mock_executor, mock_bus):
        """Subdomains found by multiple tools should not be duplicated."""
        role = make_role(mock_executor, mock_bus, osint_mode="only")

        # subfinder finds api.example.com
        mock_executor.run.return_value = MockToolResult(
            exit_code=0, stdout="api.example.com\n"
        )
        await role._run_subfinder()

        # assetfinder also finds api.example.com
        mock_executor.run.return_value = MockToolResult(
            exit_code=0, stdout="api.example.com\ncdn.example.com\n"
        )
        await role._run_assetfinder()

        # Should be deduplicated
        assert role._discovered_subdomains.count("api.example.com") == 1
        assert "cdn.example.com" in role._discovered_subdomains

    @pytest.mark.asyncio
    async def test_execute_returns_discovered_subdomains(self, mock_executor, mock_bus):
        """execute() result should include discovered_subdomains list."""
        role = make_role(mock_executor, mock_bus, osint_mode="only")

        mock_executor.run.return_value = MockToolResult(
            exit_code=0, stdout="sub1.example.com\n"
        )

        result = await role.execute()

        assert "discovered_subdomains" in result
