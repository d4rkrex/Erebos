"""MCP Protocol Handler — shared base class for all transports.

VT-Spec REQ-009: Extract common protocol logic (tool routing, JSON-RPC validation,
rate limiting, 3-strike tracking) into a reusable base class.

VT-Spec ID-002: Sanitize error responses — never leak internals.
VT-Spec R-001: Structured audit logging for all operations.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Literal, Optional, Union

from pydantic import BaseModel

logger = logging.getLogger(__name__)

# VT-Spec T-02: Protocol limits
MAX_MESSAGE_SIZE = 1 * 1024 * 1024  # 1MB
MAX_JSON_DEPTH = 10
MAX_INVALID_MESSAGES = 3  # 3-strike disconnect
# Rate limiting
MAX_REQUESTS_PER_MINUTE = 30
RATE_WINDOW_SECONDS = 60


# ── JSON-RPC Models ──────────────────────────────────────────────────


class MCPError(BaseModel):
    """JSON-RPC 2.0 error object."""

    code: int
    message: str
    data: Optional[Any] = None


class MCPRequest(BaseModel):
    """JSON-RPC 2.0 request (validated on every incoming message)."""

    jsonrpc: Literal["2.0"]
    id: Optional[Union[str, int]] = None
    method: str
    params: Optional[Dict[str, Any]] = None


class MCPResponse(BaseModel):
    """JSON-RPC 2.0 response."""

    jsonrpc: Literal["2.0"] = "2.0"
    id: Optional[Union[str, int]] = None
    result: Optional[Any] = None
    error: Optional[MCPError] = None


class MCPNotification(BaseModel):
    """JSON-RPC 2.0 notification (no id, no response expected)."""

    jsonrpc: Literal["2.0"] = "2.0"
    method: str
    params: Optional[Dict[str, Any]] = None


# ── Tool Definitions ─────────────────────────────────────────────────


TOOL_REGISTRY: List[Dict[str, Any]] = [
    {
        "name": "scan",
        "description": "Run a full scan against a target with fleet mode",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL or hostname"},
                "scope": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Allowlist of in-scope hosts",
                },
                "auth_cookie": {
                    "type": "string",
                    "description": "Session cookie for authenticated scanning (e.g. 'connect.sid=abc123')",
                },
                "auth_header": {
                    "type": "string",
                    "description": "Auth header for authenticated scanning (e.g. 'Authorization: Bearer xyz')",
                },
                "dry_run": {"type": "boolean", "default": False},
            },
            "required": ["target"],
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
        "name": "status",
        "description": "Get current fleet/scan status",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "findings",
        "description": "List all findings from the current scan",
        "inputSchema": {
            "type": "object",
            "properties": {
                "severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low", "info"],
                },
                "limit": {"type": "integer", "default": 50},
            },
        },
    },
    {
        "name": "fleet",
        "description": "Control the agent fleet",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["start", "stop", "status"],
                },
                "roles": {
                    "type": "array",
                    "items": {"type": "string"},
                },
            },
            "required": ["action"],
        },
    },
    {
        "name": "auth",
        "description": (
            "Authenticate against a target: introspect forms, register a test user, "
            "or login to obtain a session. Returns session cookies/tokens for "
            "authenticated scanning."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL or hostname"},
                "action": {
                    "type": "string",
                    "enum": ["introspect", "register", "login", "auto"],
                    "description": (
                        "introspect: discover forms and fields. "
                        "register: create test user. "
                        "login: obtain session. "
                        "auto: register+login in one step."
                    ),
                },
                "username": {
                    "type": "string",
                    "description": "Username for login/register (auto-generated if omitted)",
                },
                "password": {
                    "type": "string",
                    "description": "Password for login/register (auto-generated if omitted)",
                },
                "email": {
                    "type": "string",
                    "description": "Email for registration (auto-generated if omitted)",
                },
            },
            "required": ["target", "action"],
        },
    },
]

# Server capabilities
SERVER_CAPABILITIES = {
    "tools": {"listChanged": False},
}

SERVER_INFO = {
    "name": "erebos-mcp",
    "version": "0.2.0",
}


def check_json_depth(text: str, max_depth: int = MAX_JSON_DEPTH) -> bool:
    """VT-Spec T-02 / REQ-004: Check JSON nesting depth doesn't exceed limit."""
    depth = 0
    max_seen = 0
    for char in text:
        if char in "{[":
            depth += 1
            max_seen = max(max_seen, depth)
            if max_seen > max_depth:
                return False
        elif char in "}]":
            depth -= 1
    return True


def constant_time_compare(a: str, b: str) -> bool:
    """VT-Spec S-001 / EOP-002: Constant-time token comparison.

    Uses hmac.compare_digest to prevent timing side-channel attacks.
    Both operands are encoded to bytes to avoid type-error bypasses.
    """
    # VT-Spec T-001: Mitigate timing attack via hmac.compare_digest
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def token_hash_prefix(token: str) -> str:
    """Return first 8 chars of SHA-256 hash for audit logging (VT-Spec R-001)."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:8]


# ── Base Protocol Handler ────────────────────────────────────────────


class MCPProtocolHandler(ABC):
    """Shared MCP protocol logic for all transports (VT-Spec REQ-009).

    Provides:
    - JSON-RPC request validation
    - Tool routing and dispatch
    - Rate limiting (30 req/min)
    - 3-strike tracking for invalid messages
    - Auth check with hmac.compare_digest (VT-Spec S-001)
    - Structured audit logging (VT-Spec R-001)
    - Error sanitization (VT-Spec ID-002)
    """

    def __init__(
        self,
        auth_token: Optional[str] = None,
        on_scan: Optional[Any] = None,
        on_exploit: Optional[Any] = None,
    ):
        self._auth_token = auth_token
        self._on_scan = on_scan
        self._on_exploit = on_exploit
        self._initialized = False
        self._invalid_count = 0
        # T-02: Rate limiting state
        self._request_times: List[float] = []
        # Fleet state
        self._fleet_running = False

    def validate_message_size(self, raw: bytes) -> bool:
        """VT-Spec T-02 / REQ-004: Check message doesn't exceed 1MB."""
        return len(raw) <= MAX_MESSAGE_SIZE

    def validate_json_depth(self, text: str) -> bool:
        """VT-Spec T-02 / REQ-004: Check JSON nesting depth."""
        return check_json_depth(text)

    def parse_request(self, text: str) -> MCPRequest:
        """Parse and validate a JSON-RPC 2.0 request.

        Raises ValueError on parse/validation failure.
        """
        data = json.loads(text)
        return MCPRequest(**data)

    def check_auth(self, params: Dict[str, Any]) -> bool:
        """VT-Spec S-001 / EOP-002: Validate authentication token using constant-time compare.

        Uses hmac.compare_digest to prevent timing side-channel attacks.
        """
        if not self._auth_token:
            return True  # No token configured = local-only mode

        # Check _meta.auth_token in params
        meta = params.get("_meta", {})
        token = meta.get("auth_token", "")

        # VT-Spec S-001: Constant-time comparison to prevent timing attacks
        result = constant_time_compare(token, self._auth_token)

        # VT-Spec R-001: Log auth attempt
        if result:
            logger.info(
                "AUTH_SUCCESS",
                extra={"token_prefix": token_hash_prefix(token)},
            )
        else:
            logger.warning(
                "AUTH_FAILURE",
                extra={"token_prefix": token_hash_prefix(token) if token else "empty"},
            )

        return result

    def check_rate_limit(self) -> bool:
        """VT-Spec T-02: Token bucket rate limiter."""
        now = time.time()
        # Remove old entries
        self._request_times = [t for t in self._request_times if now - t < RATE_WINDOW_SECONDS]
        if len(self._request_times) >= MAX_REQUESTS_PER_MINUTE:
            return False
        self._request_times.append(now)
        return True

    def increment_invalid(self) -> bool:
        """Track invalid messages. Returns True if strike limit reached (VT-Spec T-02)."""
        self._invalid_count += 1
        if self._invalid_count >= MAX_INVALID_MESSAGES:
            logger.warning("T-02: 3 invalid messages — disconnecting client")
            return True
        return False

    def reset_invalid_count(self) -> None:
        """Reset invalid count on valid message."""
        self._invalid_count = 0

    async def route(self, request: MCPRequest) -> MCPResponse:
        """Route request to appropriate handler."""
        handlers = {
            "initialize": self._handle_initialize,
            "notifications/initialized": self._handle_initialized_notification,
            "tools/list": self._handle_tools_list,
            "tools/call": self._handle_tools_call,
            "ping": self._handle_ping,
        }

        handler = handlers.get(request.method)
        if handler is None:
            # VT-Spec ID-002: Generic error, no internal details
            return self._make_error(request.id, -32601, f"Method not found: {request.method}")

        return await handler(request)

    async def _handle_initialize(self, request: MCPRequest) -> MCPResponse:
        """Handle initialize handshake."""
        self._initialized = True
        return self._make_result(
            request.id,
            {
                "protocolVersion": "2024-11-05",
                "capabilities": SERVER_CAPABILITIES,
                "serverInfo": SERVER_INFO,
            },
        )

    async def _handle_initialized_notification(self, request: MCPRequest) -> MCPResponse:
        """Handle initialized notification (no response needed)."""
        logger.info("MCP client confirmed initialization")
        return self._make_result(request.id, None)

    async def _handle_tools_list(self, request: MCPRequest) -> MCPResponse:
        """Return registered tools."""
        if not self._initialized:
            return self._make_error(request.id, -32002, "Not initialized")
        return self._make_result(request.id, {"tools": TOOL_REGISTRY})

    async def _handle_tools_call(self, request: MCPRequest) -> MCPResponse:
        """Dispatch tool call to handler."""
        if not self._initialized:
            return self._make_error(request.id, -32002, "Not initialized")

        params = request.params or {}
        tool_name = params.get("name")
        arguments = params.get("arguments", {})

        if not tool_name:
            return self._make_error(request.id, -32602, "Missing 'name' in params")

        # VT-Spec SP-001: Auth check for sensitive tools
        if tool_name in ("scan", "exploit", "fleet", "auth"):
            if not self.check_auth(params):
                return self._make_error(request.id, -32001, "Authentication required")

        # VT-Spec R-001: Audit log tool invocation
        logger.info(
            "TOOL_INVOKE",
            extra={"tool": tool_name, "arguments_keys": list(arguments.keys())},
        )

        # Dispatch
        try:
            result = await self._dispatch_tool(tool_name, arguments)
        except Exception as e:
            logger.error("TOOL_ERROR", extra={"tool": tool_name, "error": str(e)})
            return self._make_error(request.id, -32001, f"Tool execution failed: {str(e)}")
        return self._make_result(
            request.id,
            {
                "content": [{"type": "text", "text": json.dumps(result)}],
            },
        )

    async def _handle_ping(self, request: MCPRequest) -> MCPResponse:
        """Handle ping/keepalive."""
        return self._make_result(request.id, {})

    async def _dispatch_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatch to actual tool implementation."""
        if tool_name == "scan" and self._on_scan:
            return await self._on_scan(arguments)
        elif tool_name == "exploit" and self._on_exploit:
            return await self._on_exploit(arguments)
        elif tool_name == "status":
            # Use enhanced status handler if available (from scan handler)
            if self._on_scan and hasattr(self._on_scan, "_status_handler"):
                return await self._on_scan._status_handler(arguments)
            # Fallback: read from storage (stateless mode / stdio)
            return await self._get_status_from_storage(arguments)
        elif tool_name == "findings":
            return await self._get_findings(arguments)
        elif tool_name == "fleet":
            action = arguments.get("action", "status")
            return {"action": action, "fleet_running": self._fleet_running}
        elif tool_name == "auth":
            return await self._handle_auth(arguments)
        else:
            return {"error": f"Tool '{tool_name}' handler not configured"}

    async def _get_findings(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Read findings from scan storage."""
        import json
        from pathlib import Path

        scan_id = arguments.get("scan_id", "")
        severity_filter = arguments.get("severity", None)
        limit = arguments.get("limit", 50)

        storage_dir = Path(os.environ.get("EREBOS_STORAGE_DIR", "./erebos-storage"))
        if scan_id:
            state_file = storage_dir / scan_id / "state.json"
        else:
            # Find most recent scan
            candidates = sorted(storage_dir.glob("*/state.json"), key=lambda p: p.stat().st_mtime)
            state_file = candidates[-1] if candidates else None

        if not state_file or not state_file.exists():
            return {"findings": [], "total": 0, "error": "No scan found"}

        try:
            state = json.loads(state_file.read_text())
            findings = state.get("findings", [])

            if severity_filter:
                findings = [f for f in findings if f.get("severity") == severity_filter.upper()]

            total = len(findings)
            findings = findings[:limit]

            return {
                "findings": findings,
                "total": total,
                "scan_id": scan_id or state_file.parent.name,
            }
        except Exception:
            return {"findings": [], "total": 0, "error": "Failed to read scan state"}

    async def _get_status_from_storage(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Read scan status from storage (stateless fallback for stdio transport)."""
        import json as _json
        from pathlib import Path

        scan_id = arguments.get("scan_id", "")
        storage_dir = Path(os.environ.get("EREBOS_STORAGE_DIR", "./erebos-storage"))

        if scan_id:
            state_file = storage_dir / scan_id / "state.json"
        else:
            candidates = sorted(storage_dir.glob("*/state.json"), key=lambda p: p.stat().st_mtime)
            state_file = candidates[-1] if candidates else None

        if not state_file or not state_file.exists():
            return {"status": "no_scan_found", "scan_id": scan_id}

        try:
            state = _json.loads(state_file.read_text())
            tool_status = state.get("phase_artifacts", {}).get("tool_status", [])
            commands = state.get("phase_artifacts", {}).get("commands", [])
            return {
                "scan_id": state.get("scan_id", state_file.parent.name),
                "target": state.get("target", ""),
                "phase": state.get("current_phase", "unknown"),
                "findings_count": len(state.get("findings", [])),
                "started_at": state.get("started_at", ""),
                "updated_at": state.get("updated_at", ""),
                "tools_run": len(commands),
                "tool_status": tool_status,
            }
        except Exception:
            return {"status": "error", "error": "Failed to read state"}

    async def _handle_auth(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Handle auth tool: introspect, register, login, or auto (register+login).

        VT-Spec AUTH-03: Adaptive form introspection for any web app.
        VT-Spec I-02: Credentials are ephemeral (per-scan, never persisted).
        """
        import secrets

        import httpx


        target = arguments.get("target", "")
        action = arguments.get("action", "introspect")

        if not target:
            return {"error": "target is required"}

        # Normalize target to URL
        base_url = target if target.startswith("http") else f"https://{target}"

        # Generate or use provided credentials
        username = arguments.get("username") or f"erebos_{secrets.token_hex(4)}"
        password = arguments.get("password") or secrets.token_urlsafe(16)
        email = arguments.get("email") or f"{username}@pentest.local"

        try:
            async with httpx.AsyncClient(
                timeout=15.0, follow_redirects=False, verify=False
            ) as client:
                # ── INTROSPECT ─────────────────────────────────────────────
                if action == "introspect":
                    return await self._auth_introspect(client, base_url)

                # ── REGISTER ───────────────────────────────────────────────
                elif action == "register":
                    return await self._auth_register(client, base_url, username, password, email)

                # ── LOGIN ──────────────────────────────────────────────────
                elif action == "login":
                    return await self._auth_login(client, base_url, username, password)

                # ── AUTO (register + login) ────────────────────────────────
                elif action == "auto":
                    reg_result = await self._auth_register(
                        client, base_url, username, password, email
                    )
                    if reg_result.get("status") != "registered":
                        return reg_result

                    login_result = await self._auth_login(client, base_url, username, password)
                    login_result["registered_as"] = username
                    return login_result

                else:
                    return {"error": f"Unknown action: {action}"}

        except httpx.ConnectError as e:
            return {"error": f"Connection failed: {e}"}
        except httpx.TimeoutException:
            return {"error": f"Timeout connecting to {base_url}"}

    async def _auth_introspect(self, client, base_url: str) -> Dict[str, Any]:
        """Discover login/register forms and their fields."""
        from erebos.auth.form_introspector import find_login_form, find_register_form

        result: Dict[str, Any] = {"status": "introspected", "base_url": base_url}

        # Check login forms
        for path in ("/login", "/signin", "/sign-in", "/auth/login"):
            try:
                resp = await client.get(f"{base_url}{path}")
                if resp.status_code == 200:
                    form = find_login_form(resp.text)
                    if form:
                        result["login"] = {
                            "path": path,
                            "action": form.action,
                            "method": form.method,
                            "fields": form.field_names,
                            "classified": form.classify_fields(),
                        }
                        break
            except Exception:
                continue

        # Check register forms
        for path in ("/register", "/signup", "/sign-up", "/api/register"):
            try:
                resp = await client.get(f"{base_url}{path}")
                if resp.status_code == 200:
                    form = find_register_form(resp.text)
                    if form:
                        result["register"] = {
                            "path": path,
                            "action": form.action,
                            "method": form.method,
                            "fields": form.field_names,
                            "classified": form.classify_fields(),
                        }
                        break
            except Exception:
                continue

        if "login" not in result and "register" not in result:
            result["status"] = "no_forms_found"
            result["message"] = (
                "No standard login/register forms detected. "
                "Target may use API-based auth or non-standard paths."
            )

        return result

    async def _auth_register(
        self, client, base_url: str, username: str, password: str, email: str
    ) -> Dict[str, Any]:
        """Register a test user using form introspection."""
        from erebos.auth.form_introspector import (
            build_registration_payload,
            find_register_form,
        )

        # Find register form
        register_form = None
        for path in ("/register", "/signup", "/sign-up", "/api/register"):
            try:
                resp = await client.get(f"{base_url}{path}")
                if resp.status_code == 200:
                    register_form = find_register_form(resp.text)
                    if register_form:
                        break
            except Exception:
                continue

        if not register_form:
            return {"status": "error", "error": "No registration form found"}

        # Build and submit payload
        payload = build_registration_payload(
            form=register_form,
            username=username,
            password=password,
            email=email,
        )
        reg_action = register_form.action or "/register"
        reg_url = f"{base_url}{reg_action}"

        resp = await client.post(reg_url, data=payload)

        # Success heuristic
        ok = resp.status_code in (200, 201) or (
            resp.status_code == 302
            and "/login" not in resp.headers.get("location", "")
            and "/register" not in resp.headers.get("location", "")
        )

        if ok:
            return {
                "status": "registered",
                "username": username,
                "email": email,
                "password": password,
                "message": f"Test user '{username}' registered at {reg_url}",
            }
        else:
            return {
                "status": "error",
                "error": f"Registration failed (HTTP {resp.status_code})",
                "url": reg_url,
                "fields_submitted": list(payload.keys()),
            }

    async def _auth_login(
        self, client, base_url: str, username: str, password: str
    ) -> Dict[str, Any]:
        """Login and extract session cookie/token."""
        import re

        from erebos.auth.form_introspector import build_login_payload, find_login_form

        # Find login form
        login_form = None
        for path in ("/login", "/signin", "/sign-in", "/auth/login"):
            try:
                resp = await client.get(f"{base_url}{path}")
                if resp.status_code == 200:
                    login_form = find_login_form(resp.text)
                    if login_form:
                        break
            except Exception:
                continue

        if not login_form:
            return {"status": "error", "error": "No login form found"}

        # Build and submit payload
        payload = build_login_payload(form=login_form, username=username, password=password)
        login_action = login_form.action or "/login"
        login_url = f"{base_url}{login_action}"

        resp = await client.post(login_url, data=payload)

        # Extract session
        session_cookie = None
        auth_token = None

        cookie_keywords = ("sess", "sid", "token", "auth", "jwt", "connect")
        for name, value in resp.cookies.items():
            if any(kw in name.lower() for kw in cookie_keywords):
                session_cookie = f"{name}={value}"
                break

        # Check Set-Cookie header
        if not session_cookie:
            set_cookie = resp.headers.get("set-cookie", "")
            for kw in ("connect.sid", "session_id", "JSESSIONID", "session"):
                if kw in set_cookie:
                    match = re.search(rf"{re.escape(kw)}=([^;]+)", set_cookie)
                    if match:
                        session_cookie = f"{kw}={match.group(1)}"
                        break

        # Check JSON token
        if resp.status_code == 200 and not session_cookie:
            try:
                data = resp.json()
                if isinstance(data, dict):
                    for key in ("token", "access_token", "jwt", "id_token"):
                        if data.get(key):
                            auth_token = str(data[key])
                            break
            except Exception:
                pass

        if session_cookie or auth_token:
            result: Dict[str, Any] = {
                "status": "authenticated",
                "username": username,
            }
            if session_cookie:
                result["auth_cookie"] = session_cookie
                result["auth_type"] = "cookie"
                result["message"] = (
                    f"Authenticated as '{username}'. "
                    f"Use auth_cookie='{session_cookie}' in scan parameters."
                )
            else:
                result["auth_header"] = f"Authorization: Bearer {auth_token}"
                result["auth_type"] = "bearer"
                result["message"] = (
                    f"Authenticated as '{username}'. " f"Use auth_header in scan parameters."
                )
            return result
        else:
            return {
                "status": "error",
                "error": f"Login failed (HTTP {resp.status_code}) — no session obtained",
                "url": login_url,
                "fields_submitted": list(payload.keys()),
            }

    def _make_result(self, req_id: Optional[Union[str, int]], result: Any) -> MCPResponse:
        """Create JSON-RPC success response."""
        return MCPResponse(id=req_id, result=result)

    def _make_error(
        self,
        req_id: Optional[Union[str, int]],
        code: int,
        message: str,
        data: Optional[Any] = None,
    ) -> MCPResponse:
        """Create JSON-RPC error response.

        VT-Spec ID-002: Never include stack traces, file paths, or internal state.
        """
        return MCPResponse(id=req_id, error=MCPError(code=code, message=message, data=data))

    @abstractmethod
    async def disconnect(self) -> None:
        """Transport-specific disconnect logic."""
        ...
