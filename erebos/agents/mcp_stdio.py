"""MCP JSON-RPC 2.0 Stdio Server — refactored to use MCPProtocolHandler base.

VT-Spec REQ-009: Inherits shared protocol logic from mcp_protocol.py.
VT-Spec REQ-010: Backward compatible — same stdio protocol, tool registry, auth flow.
VT-Spec S-001: Token comparison uses hmac.compare_digest (timing attack fix).
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from typing import Any, Optional, Union

from pydantic import ValidationError

from erebos.agents.mcp_protocol import (
    MCPProtocolHandler,
    MCPRequest,
    MCPResponse,
    MCPError,
    MCPNotification,
    TOOL_REGISTRY,
    SERVER_CAPABILITIES,
    SERVER_INFO,
    MAX_MESSAGE_SIZE,
    MAX_JSON_DEPTH,
    MAX_INVALID_MESSAGES,
    MAX_REQUESTS_PER_MINUTE,
    RATE_WINDOW_SECONDS,
    check_json_depth,
)

logger = logging.getLogger(__name__)


# ── MCP Stdio Server ─────────────────────────────────────────────────


class MCPStdioServer(MCPProtocolHandler):
    """Full MCP JSON-RPC 2.0 server over stdio.

    VT-Spec REQ-009: Inherits from MCPProtocolHandler for shared logic.
    VT-Spec REQ-010: Backward compatible with existing stdio protocol.
    VT-Spec S-001: Auth uses hmac.compare_digest (constant-time).
    """

    def __init__(
        self,
        auth_token: Optional[str] = None,
        on_scan: Optional[Any] = None,
        on_exploit: Optional[Any] = None,
    ):
        super().__init__(auth_token=auth_token, on_scan=on_scan, on_exploit=on_exploit)
        self._running = False

    async def disconnect(self) -> None:
        """Transport-specific disconnect: stop the serve loop."""
        self._running = False

    async def serve(self) -> None:
        """Main serve loop — read from stdin, write to stdout."""
        self._running = True
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await asyncio.get_event_loop().connect_read_pipe(lambda: protocol, sys.stdin)

        logger.info("MCP stdio server started")

        while self._running:
            try:
                line = await reader.readline()
                if not line:
                    break  # EOF

                await self._handle_line(line)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Server loop error: {e}")
                if self._invalid_count >= MAX_INVALID_MESSAGES:
                    break

        logger.info("MCP stdio server stopped")

    async def _handle_line(self, raw: bytes) -> None:
        """Process a single line from stdin."""
        # VT-Spec T-02: Size limit check
        if not self.validate_message_size(raw):
            if self.increment_invalid():
                await self.disconnect()
                return
            await self._send_error(None, -32600, "Message exceeds size limit (1MB)")
            return

        # Decode
        try:
            text = raw.decode("utf-8").strip()
        except UnicodeDecodeError:
            if self.increment_invalid():
                await self.disconnect()
                return
            await self._send_error(None, -32700, "Invalid encoding")
            return

        if not text:
            return

        # VT-Spec T-02: JSON depth limit
        if not self.validate_json_depth(text):
            if self.increment_invalid():
                await self.disconnect()
                return
            await self._send_error(None, -32600, "JSON nesting exceeds limit (10)")
            return

        # Parse JSON
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            if self.increment_invalid():
                await self.disconnect()
                return
            await self._send_error(None, -32700, "Parse error")
            return

        # Validate against MCPRequest model (T-02)
        try:
            request = MCPRequest(**data)
        except (ValidationError, TypeError):
            if self.increment_invalid():
                await self.disconnect()
                return
            await self._send_error(data.get("id"), -32600, "Invalid Request")
            return

        # T-02: Rate limit check
        if not self.check_rate_limit():
            await self._send_error(request.id, -32000, "Rate limit exceeded")
            return

        # Reset invalid count on valid message
        self.reset_invalid_count()

        # Route to handler
        response = await self.route(request)
        if response.result is not None or response.error is not None:
            await self._write(response.model_dump_json())

    async def _send_error(
        self,
        req_id: Optional[Union[str, int]],
        code: int,
        message: str,
        data: Optional[Any] = None,
    ) -> None:
        """Send JSON-RPC error response."""
        response = self._make_error(req_id, code, message, data)
        await self._write(response.model_dump_json())

    async def _write(self, data: str) -> None:
        """Write a line to stdout."""
        sys.stdout.write(data + "\n")
        sys.stdout.flush()


def run_mcp_server(
    auth_token: Optional[str] = None,
    on_scan: Optional[Any] = None,
    on_exploit: Optional[Any] = None,
) -> None:
    """Entry point: run MCP stdio server."""
    server = MCPStdioServer(
        auth_token=auth_token,
        on_scan=on_scan,
        on_exploit=on_exploit,
    )
    asyncio.run(server.serve())
