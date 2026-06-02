"""Integration tests for agent-mode: ToolExecutor, MCP, LogIntegrity, Roles."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from erebos.agents.base import AgentMessage, AgentRole, FindingsBus
from erebos.agents.log_integrity import LogIntegrity
from erebos.agents.mcp_stdio import (
    MCPRequest,
    MCPStdioServer,
)
from erebos.agents.tool_executor import (
    SAFE_HOSTNAME_RE,
    ToolExecutor,
)


# ── ToolExecutor Tests ───────────────────────────────────────────────


class TestToolExecutor:
    """Tests for secure tool execution (T-01, D-01, E-01)."""

    def test_validates_target_hostname(self):
        """T-01: Valid hostnames pass validation."""
        executor = ToolExecutor(allowlist=["example.com"])
        # Should not raise
        executor._validate_target("example.com")
        executor._validate_target("sub.example.com")

    def test_rejects_target_not_in_allowlist(self):
        """T-01: Targets outside allowlist are rejected."""
        executor = ToolExecutor(allowlist=["example.com"])
        with pytest.raises(ValueError, match="T-01"):
            executor._validate_target("evil.com")

    def test_rejects_shell_metacharacters(self):
        """T-01: Shell metacharacters in args are blocked."""
        executor = ToolExecutor()
        with pytest.raises(ValueError, match="T-01"):
            executor._validate_argument("; rm -rf /", "nmap")

    def test_rejects_command_substitution(self):
        """T-01: Command substitution patterns are blocked."""
        executor = ToolExecutor()
        with pytest.raises(ValueError, match="T-01"):
            executor._validate_argument("$(cat /etc/passwd)", "nmap")

    def test_rejects_backtick_substitution(self):
        """T-01: Backtick substitution blocked."""
        executor = ToolExecutor()
        with pytest.raises(ValueError, match="T-01"):
            executor._validate_argument("`whoami`", "nmap")

    def test_validates_tool_path_not_found(self):
        """E-01: Non-existent tool path raises error."""
        executor = ToolExecutor()
        with pytest.raises(FileNotFoundError, match="E-01"):
            executor._validate_tool_path("/nonexistent/tool")

    def test_safe_env_excludes_secrets(self):
        """I-01: Safe env does not include secret vars."""
        os.environ["EREBOS_LOG_SECRET"] = "should_not_pass"
        executor = ToolExecutor(env_passthrough=["PATH"])
        safe_env = executor._build_safe_env()
        assert "EREBOS_LOG_SECRET" not in safe_env
        assert "PATH" in safe_env
        os.environ.pop("EREBOS_LOG_SECRET", None)

    def test_hostname_regex_valid(self):
        """T-01: Valid hostname patterns match."""
        assert SAFE_HOSTNAME_RE.match("example.com")
        assert SAFE_HOSTNAME_RE.match("sub.example.com")
        assert SAFE_HOSTNAME_RE.match("test-host.io")

    def test_hostname_regex_invalid(self):
        """T-01: Invalid hostname patterns don't match."""
        assert not SAFE_HOSTNAME_RE.match("example.com; rm -rf /")
        assert not SAFE_HOSTNAME_RE.match("$(evil)")
        assert not SAFE_HOSTNAME_RE.match("")


# ── MCP Server Tests ─────────────────────────────────────────────────


class TestMCPServer:
    """Tests for MCP JSON-RPC stdio server (T-02)."""

    def test_depth_check_valid(self):
        """T-02: Normal JSON passes depth check."""
        server = MCPStdioServer()
        assert server.validate_json_depth('{"a": {"b": {"c": 1}}}') is True

    def test_depth_check_too_deep(self):
        """T-02: Deeply nested JSON is rejected."""
        server = MCPStdioServer()
        deep = "{" * 15 + "1" + "}" * 15
        assert server.validate_json_depth(deep) is False

    def test_rate_limit(self):
        """T-02: Rate limiting blocks excessive requests."""
        server = MCPStdioServer()
        # Fill rate limit
        for _ in range(30):
            assert server.check_rate_limit() is True
        # Next should be blocked
        assert server.check_rate_limit() is False

    def test_auth_check_no_token(self):
        """SP-001: No token configured = local-only mode (allows all)."""
        server = MCPStdioServer(auth_token=None)
        assert server.check_auth({}) is True

    def test_auth_check_valid_token(self):
        """SP-001: Valid token passes."""
        server = MCPStdioServer(auth_token="secret123")
        assert server.check_auth({"_meta": {"auth_token": "secret123"}}) is True

    def test_auth_check_invalid_token(self):
        """SP-001: Invalid token rejected."""
        server = MCPStdioServer(auth_token="secret123")
        assert server.check_auth({"_meta": {"auth_token": "wrong"}}) is False

    def test_mcprequest_validation(self):
        """T-02: Valid MCPRequest is accepted."""
        req = MCPRequest(jsonrpc="2.0", id=1, method="tools/list")
        assert req.method == "tools/list"

    def test_mcprequest_invalid_jsonrpc(self):
        """T-02: Invalid jsonrpc version rejected."""
        with pytest.raises(Exception):
            MCPRequest(jsonrpc="1.0", id=1, method="test")


# ── Log Integrity Tests ──────────────────────────────────────────────


class TestLogIntegrity:
    """Tests for HMAC log integrity (I-01, AC-004)."""

    def test_sign_and_verify_valid(self):
        """HMAC segments verify correctly when untampered."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            log_path = Path(f.name)

        try:
            integrity = LogIntegrity(secret=b"x" * 32, segment_size=3)
            for i in range(6):
                integrity.append_entry(f"entry-{i}", log_path)
            integrity.flush(log_path)

            is_valid, message = integrity.verify_log_integrity(log_path)
            assert is_valid, message
            assert "2 segments" in message
        finally:
            log_path.unlink(missing_ok=True)

    def test_detects_tampering(self):
        """AC-004: Tampered logs are detected."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            log_path = Path(f.name)

        try:
            integrity = LogIntegrity(secret=b"x" * 32, segment_size=3)
            for i in range(3):
                integrity.append_entry(f"entry-{i}", log_path)

            # Tamper with the log
            content = log_path.read_text()
            content = content.replace("entry-1", "TAMPERED")
            log_path.write_text(content)

            is_valid, message = integrity.verify_log_integrity(log_path)
            assert not is_valid
            assert "tampered" in message.lower() or "mismatch" in message.lower()
        finally:
            log_path.unlink(missing_ok=True)

    def test_minimum_secret_length_warning(self, caplog):
        """I-01: Short secrets generate warning."""
        import logging

        with caplog.at_level(logging.WARNING):
            LogIntegrity(secret=b"short")
        assert "I-01" in caplog.text

    def test_env_cleared_after_load(self):
        """I-01: Secret is cleared from environment after loading."""
        os.environ["EREBOS_LOG_SECRET"] = "a" * 32
        LogIntegrity(env_var="EREBOS_LOG_SECRET")
        assert "EREBOS_LOG_SECRET" not in os.environ


# ── FindingsBus S-01 Tests ───────────────────────────────────────────


class TestBusRoleValidation:
    """Tests for S-01: Bus message role verification."""

    def test_rejects_mismatched_role(self, tmp_path):
        """S-01: Message with wrong role is rejected."""
        bus = FindingsBus(tmp_path / "bus.jsonl")
        msg = AgentMessage(
            id="test-1",
            role=AgentRole.EXPLOIT,  # Claiming exploit role
            message_type="finding",
            payload={},
        )
        # Publish with declared sender role = RECON (mismatch)
        bus.publish(msg, sender_role=AgentRole.RECON)
        # Message should NOT have been written
        assert bus.count() == 0

    def test_accepts_matching_role(self, tmp_path):
        """S-01: Message with correct role is accepted."""
        bus = FindingsBus(tmp_path / "bus.jsonl")
        msg = AgentMessage(
            id="test-1",
            role=AgentRole.RECON,
            message_type="finding",
            payload={},
        )
        bus.publish(msg, sender_role=AgentRole.RECON)
        assert bus.count() == 1

    def test_allows_publish_without_sender_check(self, tmp_path):
        """S-01: Without sender_role, backward-compatible (no check)."""
        bus = FindingsBus(tmp_path / "bus.jsonl")
        msg = AgentMessage(
            id="test-1",
            role=AgentRole.EXPLOIT,
            message_type="finding",
            payload={},
        )
        bus.publish(msg)  # No sender_role = no check
        assert bus.count() == 1
