"""Tests for the multi-agent architecture."""

import pytest
from unittest.mock import patch

from erebos.agents.base import (
    AgentMessage,
    AgentRole,
    FindingsBus,
    MAX_FLEET_AGENTS,
)
from erebos.agents.orchestrator import FleetConfig, FleetOrchestrator
from erebos.agents.mcp_server import MCPServer, MCPAuthError, MCP_AUTH_ENV_VAR


class TestFindingsBus:
    """Test inter-agent communication bus."""

    def test_publish_and_subscribe(self, tmp_path):
        bus = FindingsBus(tmp_path / "bus.jsonl")
        msg = AgentMessage(
            id="test-1",
            role=AgentRole.RECON,
            message_type="finding",
            payload={"endpoint": "/api/users"},
        )
        bus.publish(msg)

        messages = list(bus.subscribe())
        assert len(messages) == 1
        assert messages[0].id == "test-1"
        assert messages[0].role == AgentRole.RECON

    def test_subscribe_with_role_filter(self, tmp_path):
        bus = FindingsBus(tmp_path / "bus.jsonl")
        bus.publish(AgentMessage(id="1", role=AgentRole.RECON, message_type="finding"))
        bus.publish(AgentMessage(id="2", role=AgentRole.EXPLOIT, message_type="finding"))
        bus.publish(AgentMessage(id="3", role=AgentRole.RECON, message_type="status"))

        recon_msgs = list(bus.subscribe(roles=[AgentRole.RECON]))
        assert len(recon_msgs) == 2

    def test_subscribe_with_type_filter(self, tmp_path):
        bus = FindingsBus(tmp_path / "bus.jsonl")
        bus.publish(AgentMessage(id="1", role=AgentRole.RECON, message_type="finding"))
        bus.publish(AgentMessage(id="2", role=AgentRole.RECON, message_type="status"))

        findings = list(bus.subscribe(message_types=["finding"]))
        assert len(findings) == 1

    def test_tail_reads_only_new(self, tmp_path):
        bus = FindingsBus(tmp_path / "bus.jsonl")
        bus.publish(AgentMessage(id="1", role=AgentRole.RECON, message_type="finding"))

        # First tail
        msgs1 = bus.tail()
        assert len(msgs1) == 1

        # Add more
        bus.publish(AgentMessage(id="2", role=AgentRole.EXPLOIT, message_type="finding"))

        # Second tail should only see new
        msgs2 = bus.tail()
        assert len(msgs2) == 1
        assert msgs2[0].id == "2"

    def test_count(self, tmp_path):
        bus = FindingsBus(tmp_path / "bus.jsonl")
        bus.publish(AgentMessage(id="1", role=AgentRole.RECON, message_type="finding"))
        bus.publish(AgentMessage(id="2", role=AgentRole.RECON, message_type="status"))
        bus.publish(AgentMessage(id="3", role=AgentRole.EXPLOIT, message_type="finding"))

        assert bus.count() == 3
        assert bus.count("finding") == 2

    def test_clear(self, tmp_path):
        bus = FindingsBus(tmp_path / "bus.jsonl")
        bus.publish(AgentMessage(id="1", role=AgentRole.RECON, message_type="finding"))
        bus.clear()
        assert bus.count() == 0

    def test_empty_bus(self, tmp_path):
        bus = FindingsBus(tmp_path / "bus.jsonl")
        assert list(bus.subscribe()) == []
        assert bus.tail() == []
        assert bus.count() == 0


class TestFleetOrchestrator:
    """Test fleet mode orchestration."""

    def test_fleet_config_caps_max_agents(self):
        """VT-Spec DS-001: Hard cap on agents."""
        cfg = FleetConfig(target="https://example.com", max_agents=100)
        assert cfg.max_agents == MAX_FLEET_AGENTS  # Capped at 8

    def test_fleet_config_default_roles(self):
        cfg = FleetConfig(target="https://example.com")
        assert AgentRole.RECON in cfg.roles
        assert AgentRole.EXPLOIT in cfg.roles

    def test_fleet_run_sync(self, tmp_path):
        cfg = FleetConfig(
            target="https://example.com",
            findings_bus_path=tmp_path / "bus.jsonl",
            allowlist=["example.com"],
            roles=[AgentRole.RECON, AgentRole.REPORTER],
            max_agents=2,
        )
        orch = FleetOrchestrator(cfg)
        result = orch.run_sync()

        assert result["target"] == "https://example.com"
        assert result["agents"] == 2
        assert result["completed"] == 2
        assert result["failed"] == 0
        assert "fleet-" in result["fleet_id"]

    def test_fleet_id_is_unique(self, tmp_path):
        cfg = FleetConfig(
            target="https://example.com",
            findings_bus_path=tmp_path / "bus.jsonl",
        )
        orch1 = FleetOrchestrator(cfg)
        orch2 = FleetOrchestrator(cfg)
        assert orch1.fleet_id != orch2.fleet_id


class TestMCPServer:
    """Test MCP server for code agent integration."""

    def test_tools_manifest(self):
        server = MCPServer()
        manifest = server.get_tools_manifest()
        assert len(manifest) == 6
        names = [t["name"] for t in manifest]
        assert "erebos_scan" in names
        assert "erebos_exploit" in names
        assert "erebos_fleet" in names
        assert "erebos_auth" in names

    def test_handle_tools_list(self):
        server = MCPServer()
        result = server.handle_request("tools/list", {})
        assert "tools" in result
        assert len(result["tools"]) == 6

    def test_handle_tool_call(self):
        server = MCPServer()
        result = server.handle_request(
            "tools/call",
            {
                "name": "erebos_status",
                "arguments": {},
            },
        )
        assert "content" in result

    def test_handle_unknown_tool(self):
        server = MCPServer()
        result = server.handle_request(
            "tools/call",
            {
                "name": "nonexistent",
                "arguments": {},
            },
        )
        assert "error" in result

    def test_auth_validation_no_token_configured(self):
        """SP-001: Local-only mode when no token set."""
        with patch.dict("os.environ", {}, clear=True):
            server = MCPServer()
            assert server.validate_auth() is True

    def test_auth_validation_with_token(self):
        """SP-001: Validates token when configured."""
        with patch.dict("os.environ", {MCP_AUTH_ENV_VAR: "secret-token"}):
            server = MCPServer()
            assert server.validate_auth("secret-token") is True
            with pytest.raises(MCPAuthError):
                server.validate_auth("wrong-token")
            with pytest.raises(MCPAuthError):
                server.validate_auth(None)

    def test_generate_mcp_json(self):
        server = MCPServer()
        mcp_json = server.generate_mcp_json()
        assert "erebos" in mcp_json
        assert mcp_json["erebos"]["command"] == "erebos"
        assert "mcp-serve" in mcp_json["erebos"]["args"]
