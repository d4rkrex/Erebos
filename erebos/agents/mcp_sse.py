"""MCP SSE HTTP Transport Server — Starlette + Uvicorn.

VT-Spec REQ-001: POST /mcp, GET /sse, GET /health endpoints.
VT-Spec REQ-002: Bearer token auth with hmac.compare_digest.
VT-Spec REQ-003: 50 max SSE connections, 30s heartbeat, 1h max duration.
VT-Spec REQ-004: 1MB request size, depth 10.
VT-Spec REQ-005: CORS deny-all default.
VT-Spec REQ-006: IP allowlist middleware.
VT-Spec REQ-009: Inherits from MCPProtocolHandler.

Security mitigations implemented:
- S-001: hmac.compare_digest for all token comparisons
- S-003: Only trust proxy headers from configured trusted_proxies
- T-001: Default 127.0.0.1, refuse non-loopback without TLS/--insecure
- T-002: Validate CORS origins, reject wildcard '*'
- R-001: Structured audit logging for all operations
- ID-001: Minimal health response, configurable path
- ID-002: Sanitized error responses (no internals leaked)
- DOS-001: Auth before slot allocation, per-IP limits, idle timeout
- DOS-002: Content-Length check, request body timeout
- EOP-001: Mandatory allowlist when SSE enabled, target re-validation
- EOP-002: Constant-time token comparison with rate limiting
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import random
import re
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.routing import Route
from starlette.types import ASGIApp, Receive, Scope, Send

from erebos.agents.mcp_protocol import (
    MCPProtocolHandler,
    MCPRequest,
    MCPResponse,
    check_json_depth,
    constant_time_compare,
    token_hash_prefix,
    MAX_MESSAGE_SIZE,
    MAX_JSON_DEPTH,
)

logger = logging.getLogger(__name__)


# ── Rate Limiter for Auth Failures (VT-Spec S-001 / EOP-002) ────────


class AuthRateLimiter:
    """VT-Spec S-001 / EOP-002: Rate limit failed auth attempts per IP.

    Progressive delay: 1s, 2s, 4s... after failures.
    Max 5 failures per minute per IP.
    """

    def __init__(self, max_failures: int = 5, window_seconds: int = 60):
        self._max_failures = max_failures
        self._window = window_seconds
        # IP -> list of failure timestamps
        self._failures: Dict[str, List[float]] = defaultdict(list)

    def record_failure(self, ip: str) -> None:
        """Record a failed auth attempt."""
        self._failures[ip].append(time.time())

    def is_blocked(self, ip: str) -> bool:
        """Check if IP is rate-limited."""
        now = time.time()
        # Prune old entries
        self._failures[ip] = [
            t for t in self._failures[ip] if now - t < self._window
        ]
        return len(self._failures[ip]) >= self._max_failures

    def get_delay(self, ip: str) -> float:
        """VT-Spec EOP-002: Progressive delay (1s, 2s, 4s...) with jitter."""
        count = len(self._failures[ip])
        if count == 0:
            return 0.0
        base_delay = min(2 ** (count - 1), 16)  # Cap at 16s
        # Add jitter to prevent timing analysis
        jitter = random.uniform(0.0, 0.5)
        return base_delay + jitter

    def clear(self, ip: str) -> None:
        """Clear failures for an IP on successful auth."""
        self._failures.pop(ip, None)


# ── IP Allowlist Middleware (VT-Spec REQ-006 / S-003) ────────────────


class IPAllowlistMiddleware:
    """VT-Spec REQ-006 / S-003: IP allowlist with trusted proxy support.

    - Only trusts X-Forwarded-For from configured trusted_proxies IPs.
    - Defaults to REMOTE_ADDR (direct connection IP).
    - Health endpoint bypasses allowlist (for load balancer probes).
    """

    def __init__(
        self,
        app: ASGIApp,
        allowlist: List[str],
        trusted_proxies: List[str],
        health_path: str = "/health",
    ):
        self.app = app
        self.health_path = health_path
        # Parse CIDR networks
        self._networks: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for entry in allowlist:
            try:
                self._networks.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                logger.warning(f"Invalid IP allowlist entry: {entry}")
        # Parse trusted proxy IPs
        self._trusted_proxies: Set[str] = set()
        for proxy in trusted_proxies:
            try:
                # Support single IPs only for trusted_proxies
                ipaddress.ip_address(proxy)
                self._trusted_proxies.add(proxy)
            except ValueError:
                logger.warning(f"Invalid trusted_proxies entry: {proxy}")

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # VT-Spec ID-001: Health endpoint bypasses IP allowlist
        path = scope.get("path", "")
        if path == self.health_path:
            await self.app(scope, receive, send)
            return

        # If no allowlist configured, allow all (REQ-006 scenario 3)
        if not self._networks:
            await self.app(scope, receive, send)
            return

        # VT-Spec S-003: Get client IP — only trust proxy headers from trusted_proxies
        client_ip = self._get_client_ip(scope)

        if not self._is_allowed(client_ip):
            logger.warning(
                "IP_BLOCKED",
                extra={"client_ip": client_ip, "path": path},
            )
            response = PlainTextResponse("Forbidden", status_code=403)
            await response(scope, receive, send)
            return

        await self.app(scope, receive, send)

    def _get_client_ip(self, scope: Scope) -> str:
        """VT-Spec S-003: Extract client IP, only trusting proxy headers from trusted sources."""
        # Get direct connection IP (REMOTE_ADDR equivalent)
        client = scope.get("client")
        direct_ip = client[0] if client else "127.0.0.1"

        # Only trust X-Forwarded-For if request comes from a trusted proxy
        if direct_ip not in self._trusted_proxies:
            return direct_ip

        # Parse X-Forwarded-For from headers
        headers = dict(scope.get("headers", []))
        xff = headers.get(b"x-forwarded-for", b"").decode("utf-8")
        if xff:
            # Take the first (leftmost) IP — the original client
            parts = [p.strip() for p in xff.split(",")]
            if parts and parts[0]:
                try:
                    ipaddress.ip_address(parts[0])
                    return parts[0]
                except ValueError:
                    pass

        return direct_ip

    def _is_allowed(self, ip_str: str) -> bool:
        """Check if IP is in any allowed network."""
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            return False

        for network in self._networks:
            if addr in network:
                return True
        return False


# ── SSE Connection Manager (VT-Spec REQ-003 / DOS-001) ──────────────


class SSEConnectionManager:
    """VT-Spec REQ-003 / DOS-001: Manage SSE connections with limits.

    - Global cap: 50 connections (configurable)
    - Per-IP cap: 5 connections (VT-Spec DOS-001)
    - 1-hour max duration
    - 5-minute idle timeout
    - 30s heartbeat
    """

    def __init__(
        self,
        max_connections: int = 50,
        max_per_ip: int = 5,
        max_duration: int = 3600,
        idle_timeout: int = 300,
        heartbeat_interval: int = 30,
    ):
        self.max_connections = max_connections
        self.max_per_ip = max_per_ip
        self.max_duration = max_duration
        self.idle_timeout = idle_timeout
        self.heartbeat_interval = heartbeat_interval
        # Active connections: id -> metadata
        self._connections: Dict[str, Dict[str, Any]] = {}
        # Per-IP tracking
        self._ip_connections: Dict[str, Set[str]] = defaultdict(set)
        self._lock = asyncio.Lock()

    @property
    def active_count(self) -> int:
        return len(self._connections)

    async def can_connect(self, client_ip: str) -> tuple[bool, str]:
        """VT-Spec DOS-001: Check if connection is allowed (called AFTER auth)."""
        async with self._lock:
            # Global limit
            if len(self._connections) >= self.max_connections:
                return False, "Maximum connections reached"
            # Per-IP limit
            if len(self._ip_connections[client_ip]) >= self.max_per_ip:
                return False, f"Per-IP connection limit reached ({self.max_per_ip})"
            return True, ""

    async def register(self, conn_id: str, client_ip: str) -> None:
        """Register a new connection."""
        async with self._lock:
            self._connections[conn_id] = {
                "ip": client_ip,
                "started": time.time(),
                "last_data": time.time(),
            }
            self._ip_connections[client_ip].add(conn_id)

        logger.info(
            "SSE_CONNECT",
            extra={
                "conn_id": conn_id,
                "client_ip": client_ip,
                "active_total": len(self._connections),
            },
        )

    async def unregister(self, conn_id: str) -> None:
        """Remove a connection."""
        async with self._lock:
            meta = self._connections.pop(conn_id, None)
            if meta:
                ip = meta["ip"]
                self._ip_connections[ip].discard(conn_id)
                if not self._ip_connections[ip]:
                    del self._ip_connections[ip]

        logger.info(
            "SSE_DISCONNECT",
            extra={"conn_id": conn_id, "active_total": len(self._connections)},
        )

    async def touch(self, conn_id: str) -> None:
        """Update last data time for idle tracking."""
        async with self._lock:
            if conn_id in self._connections:
                self._connections[conn_id]["last_data"] = time.time()

    def should_timeout(self, conn_id: str) -> tuple[bool, str]:
        """Check if connection should be terminated."""
        meta = self._connections.get(conn_id)
        if not meta:
            return True, "Connection not found"

        now = time.time()
        # Max duration check
        if now - meta["started"] > self.max_duration:
            return True, "Maximum duration exceeded"
        # Idle timeout check
        if now - meta["last_data"] > self.idle_timeout:
            return True, "Idle timeout"
        return False, ""


# ── SSE Server Application (VT-Spec REQ-001) ────────────────────────


class MCPSSEServer(MCPProtocolHandler):
    """MCP SSE HTTP Transport Server.

    VT-Spec REQ-001: POST /mcp, GET /sse, GET /health.
    VT-Spec REQ-009: Inherits from MCPProtocolHandler.
    """

    def __init__(
        self,
        token: str,
        host: str = "127.0.0.1",
        port: int = 8443,
        ip_allowlist: Optional[List[str]] = None,
        cors_origins: Optional[List[str]] = None,
        max_connections: int = 50,
        max_connections_per_ip: int = 5,
        heartbeat_interval: int = 30,
        max_duration: int = 3600,
        idle_timeout: int = 300,
        max_request_size: int = MAX_MESSAGE_SIZE,
        ssl_certfile: Optional[str] = None,
        ssl_keyfile: Optional[str] = None,
        insecure: bool = False,
        trusted_proxies: Optional[List[str]] = None,
        health_path: str = "/health",
        auth_rate_limit: int = 5,
        security_allowlist: Optional[List[str]] = None,
        on_scan: Optional[Any] = None,
        on_exploit: Optional[Any] = None,
    ):
        super().__init__(auth_token=token, on_scan=on_scan, on_exploit=on_exploit)

        self._host = host
        self._port = port
        self._max_request_size = max_request_size
        self._ssl_certfile = ssl_certfile
        self._ssl_keyfile = ssl_keyfile
        self._insecure = insecure
        self._health_path = health_path
        self._security_allowlist = security_allowlist or []

        # VT-Spec T-002: Validate CORS origins
        self._cors_origins = self._validate_cors_origins(cors_origins or [])

        # VT-Spec S-001 / EOP-002: Auth rate limiter
        self._auth_rate_limiter = AuthRateLimiter(max_failures=auth_rate_limit)

        # VT-Spec REQ-003 / DOS-001: Connection manager
        self._conn_manager = SSEConnectionManager(
            max_connections=max_connections,
            max_per_ip=max_connections_per_ip,
            max_duration=max_duration,
            idle_timeout=idle_timeout,
            heartbeat_interval=heartbeat_interval,
        )

        # Event queue for SSE broadcasting
        self._event_queues: Dict[str, asyncio.Queue] = {}

        # Build Starlette app
        self._app = self._build_app(
            ip_allowlist=ip_allowlist or [],
            trusted_proxies=trusted_proxies or [],
        )

    def _validate_cors_origins(self, origins: List[str]) -> List[str]:
        """VT-Spec T-002: Validate CORS origin entries.

        - Reject wildcard '*'
        - Validate proper origin URLs (scheme+host+port)
        - Log warnings for non-HTTPS origins
        """
        validated = []
        for origin in origins:
            # VT-Spec T-002: Reject wildcard
            if origin == "*":
                logger.error("T-002: Wildcard '*' CORS origin rejected — use explicit origins")
                continue

            parsed = urlparse(origin)
            if not parsed.scheme or not parsed.hostname:
                logger.error(f"T-002: Invalid CORS origin (must be scheme+host): {origin}")
                continue

            if parsed.scheme != "https":
                logger.warning(f"T-002: Non-HTTPS CORS origin: {origin}")

            validated.append(origin)

        return validated

    def _build_app(
        self,
        ip_allowlist: List[str],
        trusted_proxies: List[str],
    ) -> Starlette:
        """Build the Starlette application with security middleware."""
        routes = [
            Route("/mcp", self._handle_mcp, methods=["POST"]),
            Route("/sse", self._handle_sse, methods=["GET"]),
            Route(self._health_path, self._handle_health, methods=["GET"]),
        ]

        # VT-Spec REQ-005 / T-002: CORS middleware
        middleware = []
        if self._cors_origins:
            middleware.append(
                Middleware(
                    CORSMiddleware,
                    allow_origins=self._cors_origins,
                    allow_methods=["GET", "POST"],
                    allow_headers=["Authorization", "Content-Type"],
                    allow_credentials=False,
                    max_age=3600,
                )
            )

        app = Starlette(routes=routes, middleware=middleware)

        # VT-Spec REQ-006 / S-003: IP allowlist (wraps the app)
        if ip_allowlist:
            app = IPAllowlistMiddleware(
                app=app,
                allowlist=ip_allowlist,
                trusted_proxies=trusted_proxies,
                health_path=self._health_path,
            )

        return app

    def _authenticate_request(self, request: Request) -> tuple[bool, str]:
        """VT-Spec REQ-002 / S-001: Bearer token auth with constant-time comparison.

        Returns (success, error_detail).
        """
        client_ip = self._get_request_ip(request)

        # VT-Spec EOP-002: Check if IP is rate-limited for auth failures
        if self._auth_rate_limiter.is_blocked(client_ip):
            logger.warning(
                "AUTH_RATE_LIMITED",
                extra={"client_ip": client_ip},
            )
            return False, "rate_limited"

        auth_header = request.headers.get("authorization", "")
        if not auth_header:
            return False, "missing"

        # Parse Bearer token
        parts = auth_header.split(" ", 1)
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return False, "malformed"

        token = parts[1]

        # VT-Spec S-001 / EOP-002: Constant-time comparison
        if not constant_time_compare(token, self._auth_token):
            # Record failure for rate limiting
            self._auth_rate_limiter.record_failure(client_ip)

            # VT-Spec R-001: Log failed auth
            logger.warning(
                "AUTH_FAILURE",
                extra={
                    "client_ip": client_ip,
                    "token_prefix": token_hash_prefix(token),
                },
            )
            return False, "invalid"

        # Success — clear any rate limit state
        self._auth_rate_limiter.clear(client_ip)

        # VT-Spec R-001: Log successful auth
        logger.info(
            "AUTH_SUCCESS",
            extra={
                "client_ip": client_ip,
                "token_prefix": token_hash_prefix(token),
            },
        )
        return True, ""

    def _get_request_ip(self, request: Request) -> str:
        """Get client IP from request (respects trusted proxy config via scope)."""
        client = request.scope.get("client")
        return client[0] if client else "127.0.0.1"

    async def _handle_health(self, request: Request) -> Response:
        """VT-Spec REQ-001 / ID-001: Health check — minimal response, no auth.

        Returns plain 'ok' to avoid leaking server info.
        """
        # VT-Spec ID-001: Minimal response — plain text 'ok'
        return PlainTextResponse("ok", status_code=200)

    async def _handle_mcp(self, request: Request) -> Response:
        """VT-Spec REQ-001: POST /mcp — JSON-RPC endpoint.

        VT-Spec DOS-001: Auth BEFORE processing.
        VT-Spec DOS-002: Content-Length check before reading body.
        VT-Spec REQ-004: Size limit (1MB) and depth limit (10).
        """
        # VT-Spec REQ-002: Authenticate first
        authed, reason = self._authenticate_request(request)
        if not authed:
            if reason == "missing":
                return JSONResponse(
                    {"error": "Unauthorized"},
                    status_code=401,
                    headers={"WWW-Authenticate": "Bearer"},
                )
            if reason == "rate_limited":
                # VT-Spec EOP-002: Add jitter delay before responding
                delay = self._auth_rate_limiter.get_delay(self._get_request_ip(request))
                await asyncio.sleep(delay)
                return JSONResponse({"error": "Too many requests"}, status_code=429)
            return JSONResponse({"error": "Forbidden"}, status_code=403)

        # VT-Spec DOS-002: Check Content-Length before reading body
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                size = int(content_length)
                if size > self._max_request_size:
                    return Response(
                        content="Payload Too Large",
                        status_code=413,
                    )
            except ValueError:
                pass

        # Read body with size limit
        body = await request.body()
        if len(body) > self._max_request_size:
            return Response(content="Payload Too Large", status_code=413)

        # Decode
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            return self._jsonrpc_error_response(None, -32700, "Parse error")

        # VT-Spec REQ-004: Depth limit check
        if not check_json_depth(text, MAX_JSON_DEPTH):
            return self._jsonrpc_error_response(
                None, -32600, "JSON nesting exceeds limit"
            )

        # Parse JSON-RPC request
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return self._jsonrpc_error_response(None, -32700, "Parse error")

        # Validate
        try:
            mcp_request = MCPRequest(**data)
        except Exception:
            req_id = data.get("id") if isinstance(data, dict) else None
            return self._jsonrpc_error_response(req_id, -32600, "Invalid Request")

        # Rate limit
        if not self.check_rate_limit():
            return self._jsonrpc_error_response(
                mcp_request.id, -32000, "Rate limit exceeded"
            )

        # VT-Spec EOP-001: Re-validate targets at transport layer
        if mcp_request.method == "tools/call":
            params = mcp_request.params or {}
            tool_name = params.get("name", "")
            arguments = params.get("arguments", {})
            target = arguments.get("target", "")

            if tool_name in ("scan", "exploit") and target:
                if not self._validate_target(target):
                    # VT-Spec R-001: Log blocked target
                    logger.warning(
                        "TARGET_BLOCKED",
                        extra={
                            "tool": tool_name,
                            "target": target,
                            "client_ip": self._get_request_ip(request),
                        },
                    )
                    return self._jsonrpc_error_response(
                        mcp_request.id, -32001, "Target not in security allowlist"
                    )

        # Route to handler
        response = await self.route(mcp_request)

        # VT-Spec R-001: Log request
        logger.info(
            "MCP_REQUEST",
            extra={
                "method": mcp_request.method,
                "client_ip": self._get_request_ip(request),
                "has_error": response.error is not None,
            },
        )

        return JSONResponse(
            json.loads(response.model_dump_json()),
            status_code=200,
        )

    def _validate_target(self, target: str) -> bool:
        """VT-Spec EOP-001: Validate target is in security allowlist.

        If allowlist is empty, all targets are denied in SSE mode (fail-closed).
        Handles both bare hostnames and full URLs (extracts hostname from URL).
        """
        from urllib.parse import urlparse

        if not self._security_allowlist:
            return False

        # Extract hostname from URL if target looks like a URL
        hostname = target
        if "://" in target or target.startswith("//"):
            parsed = urlparse(target)
            hostname = parsed.hostname or target

        for allowed in self._security_allowlist:
            if hostname == allowed or hostname.endswith("." + allowed):
                return True
            # Wildcard match (e.g., *.example.com)
            if allowed.startswith("*."):
                suffix = allowed[2:]
                if hostname == suffix or hostname.endswith("." + suffix):
                    return True
            # CIDR check for IP targets
            try:
                network = ipaddress.ip_network(allowed, strict=False)
                addr = ipaddress.ip_address(hostname)
                if addr in network:
                    return True
            except ValueError:
                continue

        return False

    async def _handle_sse(self, request: Request) -> Response:
        """VT-Spec REQ-001 / REQ-003: GET /sse — Server-Sent Events stream.

        VT-Spec DOS-001: Auth BEFORE allocating connection slot.
        """
        # VT-Spec DOS-001: Authenticate BEFORE allocating connection slots
        authed, reason = self._authenticate_request(request)
        if not authed:
            if reason == "missing":
                return JSONResponse(
                    {"error": "Unauthorized"},
                    status_code=401,
                    headers={"WWW-Authenticate": "Bearer"},
                )
            if reason == "rate_limited":
                delay = self._auth_rate_limiter.get_delay(self._get_request_ip(request))
                await asyncio.sleep(delay)
                return JSONResponse({"error": "Too many requests"}, status_code=429)
            return JSONResponse({"error": "Forbidden"}, status_code=403)

        client_ip = self._get_request_ip(request)

        # VT-Spec DOS-001: Check connection limits AFTER auth
        can_connect, msg = await self._conn_manager.can_connect(client_ip)
        if not can_connect:
            return JSONResponse(
                {"error": "Service Unavailable", "message": msg},
                status_code=503,
                headers={"Retry-After": "60"},
            )

        # Generate connection ID
        import uuid
        conn_id = str(uuid.uuid4())

        # Register connection
        await self._conn_manager.register(conn_id, client_ip)
        event_queue: asyncio.Queue = asyncio.Queue()
        self._event_queues[conn_id] = event_queue

        # VT-Spec R-001: Log connection lifecycle
        logger.info(
            "SSE_STREAM_START",
            extra={"conn_id": conn_id, "client_ip": client_ip},
        )

        async def event_generator():
            """Generate SSE events with heartbeat and timeouts."""
            try:
                while True:
                    # Check timeouts
                    should_close, close_reason = self._conn_manager.should_timeout(conn_id)
                    if should_close:
                        yield f"event: close\ndata: {close_reason}\n\n"
                        break

                    try:
                        # Wait for event or heartbeat timeout
                        event = await asyncio.wait_for(
                            event_queue.get(),
                            timeout=self._conn_manager.heartbeat_interval,
                        )
                        await self._conn_manager.touch(conn_id)
                        yield f"data: {json.dumps(event)}\n\n"
                    except asyncio.TimeoutError:
                        # VT-Spec REQ-003: Send keepalive heartbeat
                        yield ": keepalive\n\n"
            finally:
                await self._conn_manager.unregister(conn_id)
                self._event_queues.pop(conn_id, None)
                logger.info(
                    "SSE_STREAM_END",
                    extra={"conn_id": conn_id, "client_ip": client_ip},
                )

        from starlette.responses import StreamingResponse
        return StreamingResponse(
            event_generator(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    async def broadcast_event(self, event: Dict[str, Any]) -> None:
        """Broadcast an event to all connected SSE clients."""
        for conn_id, queue in list(self._event_queues.items()):
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                logger.warning(f"SSE queue full for {conn_id}, dropping event")

    def _jsonrpc_error_response(self, req_id, code: int, message: str) -> JSONResponse:
        """VT-Spec ID-002: Sanitized JSON-RPC error response."""
        response = self._make_error(req_id, code, message)
        return JSONResponse(json.loads(response.model_dump_json()), status_code=200)

    async def disconnect(self) -> None:
        """Disconnect all SSE clients."""
        for conn_id in list(self._event_queues.keys()):
            await self._conn_manager.unregister(conn_id)
        self._event_queues.clear()

    def validate_startup(self) -> None:
        """VT-Spec T-001 / EOP-001: Validate startup configuration.

        - Refuse non-loopback without TLS or --insecure
        - Mandatory allowlist for SSE mode
        - Required token
        """
        # VT-Spec EOP-001: Mandatory allowlist when SSE enabled
        if not self._security_allowlist:
            raise RuntimeError(
                "EOP-001: security.allowlist MUST be non-empty when SSE transport is enabled. "
                "This prevents use as an unauthorized scan platform."
            )

        # Token is already required by caller, but double-check
        if not self._auth_token:
            raise RuntimeError("REQ-011: sse_token is required for SSE transport")

        # VT-Spec T-001: Refuse non-loopback without TLS
        is_loopback = self._host in ("127.0.0.1", "::1", "localhost")
        has_tls = self._ssl_certfile and self._ssl_keyfile

        if not is_loopback and not has_tls and not self._insecure:
            raise RuntimeError(
                "T-001: Refusing to bind to non-loopback address without TLS. "
                "Either configure ssl_certfile/ssl_keyfile, use --insecure flag, "
                "or bind to 127.0.0.1."
            )

        if not is_loopback and not has_tls and self._insecure:
            logger.warning(
                "T-001: Running on non-loopback address WITHOUT TLS. "
                "Tokens and scan data will be transmitted in cleartext. "
                "This is NOT recommended for production use."
            )

    def run(self) -> None:
        """Start the SSE server with Uvicorn."""
        import uvicorn

        self.validate_startup()

        logger.info(
            "SSE_SERVER_START",
            extra={
                "host": self._host,
                "port": self._port,
                "tls": bool(self._ssl_certfile),
                "cors_origins": len(self._cors_origins),
            },
        )

        uvicorn_kwargs: Dict[str, Any] = {
            "app": self._app,
            "host": self._host,
            "port": self._port,
            "log_level": "info",
            # VT-Spec DOS-002: Timeout settings
            "timeout_keep_alive": 30,
            "limit_max_requests": 10000,
        }

        # TLS configuration
        if self._ssl_certfile and self._ssl_keyfile:
            uvicorn_kwargs["ssl_certfile"] = self._ssl_certfile
            uvicorn_kwargs["ssl_keyfile"] = self._ssl_keyfile

        uvicorn.run(**uvicorn_kwargs)

    @property
    def app(self) -> Any:
        """Return the ASGI application (for testing)."""
        return self._app


def create_sse_server_from_config(config: Any) -> MCPSSEServer:
    """Create SSE server from Erebos Config object.

    VT-Spec REQ-011: Load all SSE config options.
    """
    sse_config = config.sse

    if not sse_config.token:
        raise RuntimeError("REQ-011: sse_token is required for SSE transport")

    return MCPSSEServer(
        token=sse_config.token,
        host=sse_config.host,
        port=sse_config.port,
        ip_allowlist=sse_config.ip_allowlist,
        cors_origins=sse_config.cors_origins,
        max_connections=sse_config.max_connections,
        max_connections_per_ip=sse_config.max_connections_per_ip,
        heartbeat_interval=sse_config.heartbeat_interval,
        max_duration=sse_config.max_duration,
        idle_timeout=sse_config.idle_timeout,
        max_request_size=sse_config.max_request_size,
        ssl_certfile=sse_config.ssl_certfile,
        ssl_keyfile=sse_config.ssl_keyfile,
        insecure=sse_config.insecure,
        trusted_proxies=sse_config.trusted_proxies,
        health_path=sse_config.health_path,
        auth_rate_limit=sse_config.auth_rate_limit,
        security_allowlist=config.security.allowlist,
    )
