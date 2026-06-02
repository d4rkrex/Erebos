"""Unit tests for ApiSecurityExecutor.

Tests cover:
- IDOR detection (BOLA/API1:2023)
- Mass Assignment via PUT/PATCH (API6:2023)
- Rate Limiting absence detection (API4:2023)
- Auth token propagation in headers
"""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from erebos.executors.api_security import ApiSecurityExecutor


# ============================================================================
# Helpers
# ============================================================================


def _mock_response(status_code: int = 200, json_body: dict | None = None, text: str = "") -> httpx.Response:
    """Create a mock httpx.Response."""
    if json_body is not None:
        content = json.dumps(json_body).encode()
        headers = {"content-type": "application/json"}
    else:
        content = text.encode()
        headers = {"content-type": "text/plain"}
    return httpx.Response(
        status_code=status_code,
        content=content,
        headers=headers,
        request=httpx.Request("GET", "http://test"),
    )


def _patch_client(client_instance):
    """Context manager to patch httpx.AsyncClient with a mock instance."""
    patcher = patch("httpx.AsyncClient")
    mock_cls = patcher.start()
    mock_cls.return_value.__aenter__ = AsyncMock(return_value=client_instance)
    mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
    return patcher


# ============================================================================
# IDOR Tests
# ============================================================================


class TestIDOR:
    """Tests for Insecure Direct Object Reference detection."""

    def test_idor_detected(self):
        """Endpoint returns 200 for both original and alt resource → IDOR finding."""
        executor = ApiSecurityExecutor(auth_token="valid-token")

        async def mock_get(url, **kwargs):
            return _mock_response(200, json_body={"id": 1, "name": "user"})

        client = AsyncMock()
        client.get = AsyncMock(side_effect=mock_get)

        patcher = _patch_client(client)
        try:
            findings = asyncio.run(executor.run(
                target="http://target.local",
                endpoints=["/api/users/1"],
                tests=["idor"],
            ))
        finally:
            patcher.stop()

        assert len(findings) == 1
        assert "IDOR" in findings[0].title
        assert findings[0].severity == "HIGH"

    def test_idor_not_detected(self):
        """Endpoint returns 401 for alt resource → no IDOR finding."""
        executor = ApiSecurityExecutor(auth_token="valid-token")

        call_count = 0

        async def mock_get(url, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return _mock_response(200, json_body={"id": 1})
            else:
                return _mock_response(401, text="Unauthorized")

        client = AsyncMock()
        client.get = AsyncMock(side_effect=mock_get)

        patcher = _patch_client(client)
        try:
            findings = asyncio.run(executor.run(
                target="http://target.local",
                endpoints=["/api/users/1"],
                tests=["idor"],
            ))
        finally:
            patcher.stop()

        assert len(findings) == 0


# ============================================================================
# Mass Assignment Tests
# ============================================================================


class TestMassAssignment:
    """Tests for Mass Assignment (API6:2023) detection."""

    def test_mass_assignment_put(self):
        """PUT with price=-1 returns 200 with price in response → finding."""
        executor = ApiSecurityExecutor(auth_token="tok")

        async def mock_get(url, **kwargs):
            return _mock_response(200, json_body={"id": 1, "name": "Widget", "price": 10})

        async def mock_put(url, **kwargs):
            content = kwargs.get("content", "{}")
            payload = json.loads(content)
            resp_body = {"id": 1, "name": "Widget"}
            resp_body.update(payload)
            return _mock_response(200, json_body=resp_body)

        async def mock_patch(url, **kwargs):
            return _mock_response(403, text="Forbidden")

        client = AsyncMock()
        client.get = AsyncMock(side_effect=mock_get)
        client.put = AsyncMock(side_effect=mock_put)
        client.patch = AsyncMock(side_effect=mock_patch)

        patcher = _patch_client(client)
        try:
            findings = asyncio.run(executor.run(
                target="http://target.local",
                endpoints=["/Products/1"],
                tests=["mass_assignment"],
            ))
        finally:
            patcher.stop()

        assert len(findings) > 0
        price_findings = [f for f in findings if "price" in f.title.lower()]
        assert len(price_findings) >= 1
        assert price_findings[0].severity == "HIGH"

    def test_mass_assignment_patch(self):
        """PATCH with dangerous fields accepted → finding produced.

        Note: The implementation tries PUT first and only falls through to PATCH
        if PUT raises an exception. So we simulate PUT throwing an error.
        """
        executor = ApiSecurityExecutor(auth_token="tok")

        async def mock_get(url, **kwargs):
            return _mock_response(200, json_body={"id": 1, "role": "user"})

        async def mock_put(url, **kwargs):
            # PUT raises exception → implementation continues to PATCH
            raise httpx.ConnectError("Connection refused")

        async def mock_patch(url, **kwargs):
            content = kwargs.get("content", "{}")
            payload = json.loads(content)
            resp_body = {"id": 1}
            resp_body.update(payload)
            return _mock_response(200, json_body=resp_body)

        client = AsyncMock()
        client.get = AsyncMock(side_effect=mock_get)
        client.put = AsyncMock(side_effect=mock_put)
        client.patch = AsyncMock(side_effect=mock_patch)

        patcher = _patch_client(client)
        try:
            findings = asyncio.run(executor.run(
                target="http://target.local",
                endpoints=["/api/users/me"],
                tests=["mass_assignment"],
            ))
        finally:
            patcher.stop()

        assert len(findings) > 0
        assert any("Mass Assignment" in f.title for f in findings)

    def test_mass_assignment_rejected(self):
        """PUT/PATCH return 403 → no mass assignment finding."""
        executor = ApiSecurityExecutor(auth_token="tok")

        async def mock_get(url, **kwargs):
            return _mock_response(200, json_body={"id": 1, "name": "Widget"})

        async def mock_put(url, **kwargs):
            return _mock_response(403, text="Forbidden")

        async def mock_patch(url, **kwargs):
            return _mock_response(403, text="Forbidden")

        client = AsyncMock()
        client.get = AsyncMock(side_effect=mock_get)
        client.put = AsyncMock(side_effect=mock_put)
        client.patch = AsyncMock(side_effect=mock_patch)

        patcher = _patch_client(client)
        try:
            findings = asyncio.run(executor.run(
                target="http://target.local",
                endpoints=["/Products/1"],
                tests=["mass_assignment"],
            ))
        finally:
            patcher.stop()

        assert len(findings) == 0


# ============================================================================
# Rate Limit Tests
# ============================================================================


class TestRateLimit:
    """Tests for rate limiting detection (API4:2023)."""

    def test_rate_limit_detected(self):
        """All 20 requests succeed (no 429) → rate limiting finding produced."""
        executor = ApiSecurityExecutor(auth_token="tok")

        async def mock_post(url, **kwargs):
            return _mock_response(200, json_body={"token": "abc"})

        client = AsyncMock()
        client.post = AsyncMock(side_effect=mock_post)

        patcher = _patch_client(client)
        try:
            findings = asyncio.run(executor.run(
                target="http://target.local",
                endpoints=["/api/login"],
                tests=["rate_limit"],
            ))
        finally:
            patcher.stop()

        assert len(findings) == 1
        assert "Rate Limiting" in findings[0].title
        assert findings[0].severity == "MEDIUM"
        assert "20" in findings[0].description

    def test_rate_limit_not_an_issue(self):
        """Request returns 429 before 20 requests → no finding."""
        executor = ApiSecurityExecutor(auth_token="tok")

        call_count = 0

        async def mock_post(url, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count >= 5:
                return _mock_response(429, text="Too Many Requests")
            return _mock_response(200, json_body={"token": "abc"})

        client = AsyncMock()
        client.post = AsyncMock(side_effect=mock_post)

        patcher = _patch_client(client)
        try:
            findings = asyncio.run(executor.run(
                target="http://target.local",
                endpoints=["/api/login"],
                tests=["rate_limit"],
            ))
        finally:
            patcher.stop()

        assert len(findings) == 0


# ============================================================================
# Auth Token Propagation
# ============================================================================


class TestAuthPropagation:
    """Tests for auth token being included in request headers."""

    def test_auth_token_propagation(self):
        """When auth_token provided, Authorization header is sent in requests."""
        executor = ApiSecurityExecutor(auth_token="my-secret-token")

        captured_headers = []

        async def mock_get(url, **kwargs):
            headers = kwargs.get("headers", {})
            captured_headers.append(dict(headers))
            return _mock_response(200, json_body={"id": 1})

        client = AsyncMock()
        client.get = AsyncMock(side_effect=mock_get)

        patcher = _patch_client(client)
        try:
            asyncio.run(executor.run(
                target="http://target.local",
                endpoints=["/api/users/1"],
                tests=["idor"],
            ))
        finally:
            patcher.stop()

        assert len(captured_headers) > 0
        for headers in captured_headers:
            assert headers.get("Authorization") == "Bearer my-secret-token"
