"""Integration tests for MCP SSE HTTP transport (VT-Spec REQ-001..REQ-009).

Tests cover authentication, CORS, rate limiting, request size limits,
target allowlist validation, and connection management.
"""

from __future__ import annotations

import json

import httpx
import pytest

from erebos.agents.mcp_sse import MCPSSEServer, SSEConnectionManager

TEST_TOKEN = "test-token-for-sse-integration"
TEST_ALLOWLIST = ["example.com", "10.0.0.0/8"]


def _build_server(**overrides) -> MCPSSEServer:
    """Create a test MCPSSEServer with sensible defaults."""
    defaults = dict(
        token=TEST_TOKEN,
        host="127.0.0.1",
        port=8443,
        security_allowlist=TEST_ALLOWLIST,
        max_request_size=1024 * 1024,
        insecure=False,
    )
    defaults.update(overrides)
    return MCPSSEServer(**defaults)


def _auth_headers(token: str = TEST_TOKEN) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _jsonrpc_body(method: str, params: dict | None = None, req_id: int = 1) -> str:
    payload: dict = {"jsonrpc": "2.0", "id": req_id, "method": method}
    if params is not None:
        payload["params"] = params
    return json.dumps(payload)


# ── Auth Tests ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_mcp_post_without_token_returns_401():
    """REQ-002: Missing Authorization header → 401."""
    server = _build_server()
    transport = httpx.ASGITransport(app=server.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/mcp", content=_jsonrpc_body("initialize"))
        assert resp.status_code == 401
        assert "WWW-Authenticate" in resp.headers


@pytest.mark.asyncio
async def test_mcp_post_with_invalid_token_returns_403():
    """REQ-002: Invalid Bearer token → 403."""
    server = _build_server()
    transport = httpx.ASGITransport(app=server.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/mcp",
            content=_jsonrpc_body("initialize"),
            headers=_auth_headers("wrong-token"),
        )
        assert resp.status_code == 403


@pytest.mark.asyncio
async def test_mcp_post_with_valid_token_returns_200():
    """REQ-002: Valid Bearer token → 200 with JSON-RPC result."""
    server = _build_server()
    transport = httpx.ASGITransport(app=server.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/mcp",
            content=_jsonrpc_body("initialize"),
            headers=_auth_headers(),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("result") is not None


# ── Health Endpoint ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_health_returns_ok_without_auth():
    """ID-001: GET /health returns plain 'ok' without requiring auth."""
    server = _build_server()
    transport = httpx.ASGITransport(app=server.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/health")
        assert resp.status_code == 200
        assert resp.text == "ok"


# ── CORS Tests ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_no_cors_headers_when_origins_not_configured():
    """T-002: No CORS middleware when cors_origins is empty."""
    server = _build_server(cors_origins=[])
    transport = httpx.ASGITransport(app=server.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/health", headers={"Origin": "https://evil.com"})
        assert "access-control-allow-origin" not in resp.headers


@pytest.mark.asyncio
async def test_cors_rejects_disallowed_origin():
    """T-002: CORS preflight with disallowed origin gets no allow-origin header."""
    server = _build_server(cors_origins=["https://trusted.example.com"])
    transport = httpx.ASGITransport(app=server.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.options(
            "/mcp",
            headers={
                "Origin": "https://evil.com",
                "Access-Control-Request-Method": "POST",
            },
        )
        allow_origin = resp.headers.get("access-control-allow-origin", "")
        assert allow_origin != "https://evil.com"


# ── Rate Limiting ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_rate_limit_returns_429():
    """T-02: Exceeding 30 req/min rate limit returns JSON-RPC error."""
    server = _build_server()
    transport = httpx.ASGITransport(app=server.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # Initialize first
        await client.post(
            "/mcp",
            content=_jsonrpc_body("initialize"),
            headers=_auth_headers(),
        )

        # Exhaust the rate limit (server starts at 1 used from initialize)
        for i in range(30):
            await client.post(
                "/mcp",
                content=_jsonrpc_body("ping", req_id=i + 10),
                headers=_auth_headers(),
            )

        # Next should be rate limited
        resp = await client.post(
            "/mcp",
            content=_jsonrpc_body("ping", req_id=999),
            headers=_auth_headers(),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("error") is not None
        assert "rate limit" in data["error"]["message"].lower()


# ── Request Size ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_oversized_content_length_returns_413():
    """DOS-002: Content-Length exceeding max_request_size → 413."""
    server = _build_server(max_request_size=1024)
    transport = httpx.ASGITransport(app=server.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/mcp",
            content=_jsonrpc_body("initialize"),
            headers={**_auth_headers(), "Content-Length": "9999999"},
        )
        assert resp.status_code == 413


# ── Target Validation (AC-002) ───────────────────────────────────────


@pytest.mark.asyncio
async def test_scan_target_not_in_allowlist_rejected():
    """EOP-001 / AC-002: scan tool with out-of-scope target is rejected."""
    server = _build_server(security_allowlist=["example.com"])
    transport = httpx.ASGITransport(app=server.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # Initialize the MCP session
        await client.post(
            "/mcp",
            content=_jsonrpc_body("initialize"),
            headers=_auth_headers(),
        )

        # Attempt scan with out-of-scope target
        body = _jsonrpc_body(
            "tools/call",
            params={
                "name": "scan",
                "arguments": {"target": "evil.com"},
                "_meta": {"auth_token": TEST_TOKEN},
            },
        )
        resp = await client.post("/mcp", content=body, headers=_auth_headers())
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("error") is not None
        assert "allowlist" in data["error"]["message"].lower()


# ── Connection Limit (AC-003) ────────────────────────────────────────


@pytest.mark.asyncio
async def test_connection_manager_rejects_at_max_capacity():
    """DOS-001 / AC-003: SSEConnectionManager rejects when at max_connections."""
    mgr = SSEConnectionManager(max_connections=2, max_per_ip=10)

    # Register two connections
    await mgr.register("conn-1", "10.0.0.1")
    await mgr.register("conn-2", "10.0.0.2")

    # Third should be rejected
    allowed, reason = await mgr.can_connect("10.0.0.3")
    assert allowed is False
    assert "maximum" in reason.lower()

    # Cleanup
    await mgr.unregister("conn-1")
    await mgr.unregister("conn-2")


@pytest.mark.asyncio
async def test_connection_manager_rejects_per_ip_limit():
    """DOS-001: SSEConnectionManager enforces per-IP limit."""
    mgr = SSEConnectionManager(max_connections=50, max_per_ip=2)

    await mgr.register("conn-1", "10.0.0.1")
    await mgr.register("conn-2", "10.0.0.1")

    allowed, reason = await mgr.can_connect("10.0.0.1")
    assert allowed is False
    assert "per-ip" in reason.lower()

    # Different IP should still work
    allowed, _ = await mgr.can_connect("10.0.0.2")
    assert allowed is True

    # Cleanup
    await mgr.unregister("conn-1")
    await mgr.unregister("conn-2")
