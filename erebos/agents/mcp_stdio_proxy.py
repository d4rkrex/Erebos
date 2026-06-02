"""MCP Stdio Proxy — thin JSON-RPC layer that proxies to the local SSE server.

The stdio transport is stateless (process exits after stdin EOF). For stateful
operations like scans (which run in the background), we proxy requests to the
co-located SSE server that persists.

Architecture:
    Agent (remote) → SSH → docker exec → mcp-stdio-proxy → localhost:8443 (SSE)

This gives us:
- Clean stdio JSON-RPC for MCP client compatibility
- Persistent scan state managed by the SSE server
- No state lost between invocations
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from typing import Any, Dict, List, Optional
from urllib.request import Request, urlopen
from urllib.error import URLError

logger = logging.getLogger(__name__)

# MCP protocol constants
PROTOCOL_VERSION = "2024-11-05"
SERVER_INFO = {"name": "erebos-mcp", "version": "0.2.0"}


class MCPStdioProxy:
    """Stdio MCP server that proxies tool calls to the local SSE server."""

    def __init__(
        self,
        auth_token: str = "",
        sse_url: str = "http://127.0.0.1:8443/mcp",
        security_allowlist: Optional[List[str]] = None,
    ):
        self._auth_token = auth_token
        self._sse_url = sse_url
        self._allowlist = security_allowlist or []
        self._initialized = False

    async def serve(self) -> None:
        """Read JSON-RPC from stdin, proxy to SSE, write responses to stdout."""
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await asyncio.get_event_loop().connect_read_pipe(lambda: protocol, sys.stdin)

        while True:
            try:
                line = await reader.readline()
                if not line:
                    break  # EOF

                text = line.decode("utf-8").strip()
                if not text:
                    continue

                request = json.loads(text)
                response = await self._handle_request(request)

                if response is not None:
                    sys.stdout.write(json.dumps(response) + "\n")
                    sys.stdout.flush()

            except json.JSONDecodeError:
                err = self._error_response(None, -32700, "Parse error")
                sys.stdout.write(json.dumps(err) + "\n")
                sys.stdout.flush()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Proxy error: {e}")
                break

    async def _handle_request(self, request: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Route request: handle protocol locally, proxy tools to SSE."""
        method = request.get("method", "")
        req_id = request.get("id")

        # Handle protocol methods locally (no state needed)
        if method == "initialize":
            self._initialized = True
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": SERVER_INFO,
                },
                "error": None,
            }

        if method == "notifications/initialized":
            return None  # No response for notifications

        if method == "tools/list":
            return self._tools_list_response(req_id)

        if method == "tools/call":
            return self._proxy_to_sse(request)

        if method == "ping":
            return {"jsonrpc": "2.0", "id": req_id, "result": {}, "error": None}

        return self._error_response(req_id, -32601, f"Method not found: {method}")

    def _proxy_to_sse(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Forward request to the local SSE server and return response."""
        req_id = request.get("id")

        # Ensure SSE session is initialized on first proxy call
        if not hasattr(self, "_sse_initialized"):
            self._init_sse_session()

        try:
            body = json.dumps(request).encode("utf-8")
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self._auth_token}",
            }
            req = Request(self._sse_url, data=body, headers=headers, method="POST")

            with urlopen(req, timeout=660) as resp:
                data = resp.read().decode("utf-8")
                return json.loads(data)

        except URLError as e:
            return self._error_response(
                req_id, -32003, f"SSE server unavailable: {str(e)}"
            )
        except json.JSONDecodeError:
            return self._error_response(req_id, -32003, "Invalid response from SSE server")
        except Exception as e:
            return self._error_response(req_id, -32003, f"Proxy error: {str(e)}")

    def _init_sse_session(self) -> None:
        """Initialize a session with the SSE server."""
        init_req = {
            "jsonrpc": "2.0",
            "id": "__proxy_init__",
            "method": "initialize",
            "params": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "stdio-proxy", "version": "1.0"},
            },
        }
        try:
            body = json.dumps(init_req).encode("utf-8")
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self._auth_token}",
            }
            req = Request(self._sse_url, data=body, headers=headers, method="POST")
            with urlopen(req, timeout=10) as resp:
                resp.read()
            self._sse_initialized = True
        except Exception as e:
            logger.warning(f"Failed to initialize SSE session: {e}")
            self._sse_initialized = False

    def _tools_list_response(self, req_id: Any) -> Dict[str, Any]:
        """Return static tool registry."""
        tools = [
            {
                "name": "scan",
                "description": "Run a full scan against a target with fleet mode",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "Target URL or hostname"},
                        "scope": {"type": "array", "items": {"type": "string"}},
                        "dry_run": {"type": "boolean", "default": False},
                        "auth_header": {
                            "type": "string",
                            "description": "Auth header to inject (e.g. 'Authorization: Bearer ey...' or 'Cookie: session=abc')",
                        },
                        "auth_cookie": {
                            "type": "string",
                            "description": "Cookie string for authenticated scanning (e.g. 'PHPSESSID=abc; security=low')",
                        },
                    },
                    "required": ["target"],
                },
            },
            {
                "name": "status",
                "description": "Get current scan status and tool telemetry",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "scan_id": {"type": "string", "description": "Scan ID to check"},
                    },
                },
            },
            {
                "name": "findings",
                "description": "List findings from a scan, filtered by severity",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "scan_id": {"type": "string"},
                        "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                        "limit": {"type": "integer", "default": 50},
                    },
                },
            },
            {
                "name": "exploit",
                "description": "Attempt exploitation of a specific finding",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "finding_id": {"type": "string"},
                        "target": {"type": "string"},
                        "cwe": {"type": "string"},
                    },
                    "required": ["finding_id", "target"],
                },
            },
            {
                "name": "fleet",
                "description": "Launch fleet mode with parallel agents (recon, vuln-scan, exploit, code-audit, reporter)",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "Target URL or hostname"},
                        "roles": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Agent roles to spawn (default: all)",
                        },
                        "auth_header": {
                            "type": "string",
                            "description": "Auth header for authenticated scanning",
                        },
                        "auth_cookie": {
                            "type": "string",
                            "description": "Cookie string for authenticated scanning",
                        },
                    },
                    "required": ["target"],
                },
            },
            {
                "name": "auth",
                "description": (
                    "Authenticate against a target: introspect forms, register a test user, "
                    "or login to obtain a session cookie/token for authenticated scanning."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "Target URL or hostname"},
                        "action": {
                            "type": "string",
                            "enum": ["introspect", "register", "login", "auto"],
                            "description": (
                                "introspect: discover forms/fields. "
                                "register: create test user. "
                                "login: obtain session. "
                                "auto: register+login in one step."
                            ),
                        },
                        "username": {"type": "string", "description": "Username (auto-generated if omitted)"},
                        "password": {"type": "string", "description": "Password (auto-generated if omitted)"},
                        "email": {"type": "string", "description": "Email (auto-generated if omitted)"},
                    },
                    "required": ["target", "action"],
                },
            },
        ]
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"tools": tools},
            "error": None,
        }

    def _error_response(
        self, req_id: Any, code: int, message: str
    ) -> Dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": None,
            "error": {"code": code, "message": message, "data": None},
        }
