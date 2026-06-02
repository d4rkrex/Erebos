"""Scoped HTTP client — enforces allowlist on every request including redirects.

VT-Spec T-01: Scope Bypass via Spider Link Following (CRITICAL)
Mitigation: Enforce AllowlistValidator.is_allowed() on EVERY URL before HTTP request.
Implement allowlist check in the HTTP client layer as defense-in-depth.

VT-Spec S-01: Scope Creep via Redirect Following
Mitigation: Validate every redirect target against allowlist; reject cross-domain
redirects; strip auth headers on cross-domain redirect.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx

from erebos.security.rate_limit import SharedRateLimiter
from erebos.security.scope import AllowlistValidator

logger = logging.getLogger(__name__)

MAX_REDIRECTS = 10


class ScopeViolationError(Exception):
    """Raised when a URL is outside the configured allowlist scope."""

    def __init__(self, url: str, reason: str = "URL not in allowlist"):
        self.url = url
        self.reason = reason
        super().__init__(f"Scope violation: {reason} — {url}")


class ScopedHttpClient:
    """HTTP client that enforces scope allowlist on every request and redirect.

    VT-Spec T-01 CRITICAL: This is the primary defense against out-of-scope attacks.
    Every HTTP request in the discovery and auth modules MUST go through this client.

    Features:
    - Validates URL against allowlist BEFORE sending any request
    - Manually follows redirects, validating each hop against allowlist
    - Strips Authorization headers on cross-domain redirects (AC-005 mitigation)
    - Integrates with SharedRateLimiter for rate limiting
    - Raises ScopeViolationError for any out-of-scope URL
    """

    def __init__(
        self,
        allowlist: List[str],
        timeout: float = 15.0,
        rate_limiter: Optional[SharedRateLimiter] = None,
        max_redirects: int = MAX_REDIRECTS,
        user_agent: str = "Erebos/1.0",
        default_headers: Optional[Dict[str, str]] = None,
    ):
        self._validator = AllowlistValidator(allowlist)
        self._timeout = timeout
        self._rate_limiter = rate_limiter
        self._max_redirects = max_redirects
        self._user_agent = user_agent
        self._default_headers = dict(default_headers or {})
        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self) -> "ScopedHttpClient":
        headers = {"User-Agent": self._user_agent, **self._default_headers}
        self._client = httpx.AsyncClient(
            timeout=self._timeout,
            follow_redirects=False,  # VT-Spec T-01: We manually follow + validate each hop
            headers=headers,
        )
        return self

    async def __aexit__(self, *args: Any) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    def _enforce_scope(self, url: str) -> None:
        """VT-Spec T-01: Validate URL against allowlist BEFORE any request.

        Raises ScopeViolationError if URL is not in scope.
        """
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            raise ScopeViolationError(url, "Invalid URL format")

        # VT-Spec T-01: Check scheme is http/https only
        if parsed.scheme not in ("http", "https"):
            raise ScopeViolationError(url, f"Disallowed scheme: {parsed.scheme}")

        # Extract hostname (without port) for allowlist check
        hostname = parsed.hostname or ""
        if not self._validator.is_allowed(hostname):
            # Also try with port (netloc) for compatibility
            if not self._validator.is_allowed(parsed.netloc):
                raise ScopeViolationError(url, f"Host '{hostname}' not in allowlist")

    async def _rate_limit(self, url: str) -> None:
        """Apply rate limiting if a SharedRateLimiter is configured."""
        if self._rate_limiter:
            parsed = urlparse(url)
            target = parsed.hostname or parsed.netloc
            await self._rate_limiter.acquire(target)

    async def _follow_redirects(
        self,
        response: httpx.Response,
        original_headers: dict,
        **kwargs: Any,
    ) -> httpx.Response:
        """VT-Spec S-01: Manually follow redirects, validating each hop.

        Strips Authorization headers on cross-domain redirects (AC-005).
        """
        redirect_count = 0
        current_response = response
        original_host = urlparse(str(current_response.request.url)).hostname

        while current_response.is_redirect and redirect_count < self._max_redirects:
            redirect_count += 1
            location = current_response.headers.get("location", "")

            if not location:
                break

            # Resolve relative URLs
            redirect_url = str(current_response.request.url.join(location))

            # VT-Spec T-01: Validate redirect target against allowlist
            self._enforce_scope(redirect_url)
            logger.debug(
                "Following redirect %d: %s -> %s",
                redirect_count,
                current_response.url,
                redirect_url,
            )

            # VT-Spec AC-005: Strip auth headers on cross-domain redirect
            redirect_host = urlparse(redirect_url).hostname
            headers = dict(original_headers)
            if redirect_host != original_host:
                headers.pop("Authorization", None)
                headers.pop("authorization", None)
                headers.pop("Cookie", None)
                headers.pop("cookie", None)
                logger.warning(
                    "Cross-domain redirect detected: %s -> %s. Stripped auth headers.",
                    original_host,
                    redirect_host,
                )

            await self._rate_limit(redirect_url)
            current_response = await self._client.request(  # type: ignore[union-attr]
                method="GET",
                url=redirect_url,
                headers=headers,
                **kwargs,
            )

        return current_response

    async def request(
        self, method: str, url: str, follow_redirects: bool = True, **kwargs: Any
    ) -> httpx.Response:
        """Generic request proxy — delegates to _request with scope enforcement."""
        return await self._request(method, url, follow_redirects=follow_redirects, **kwargs)

    async def get(self, url: str, follow_redirects: bool = True, **kwargs: Any) -> httpx.Response:
        """Send GET request with scope enforcement.

        VT-Spec T-01: Validates URL against allowlist before sending.
        """
        return await self._request("GET", url, follow_redirects=follow_redirects, **kwargs)

    async def post(self, url: str, follow_redirects: bool = True, **kwargs: Any) -> httpx.Response:
        """Send POST request with scope enforcement."""
        return await self._request("POST", url, follow_redirects=follow_redirects, **kwargs)

    async def head(self, url: str, follow_redirects: bool = True, **kwargs: Any) -> httpx.Response:
        """Send HEAD request with scope enforcement."""
        return await self._request("HEAD", url, follow_redirects=follow_redirects, **kwargs)

    async def put(self, url: str, follow_redirects: bool = True, **kwargs: Any) -> httpx.Response:
        """Send PUT request with scope enforcement."""
        return await self._request("PUT", url, follow_redirects=follow_redirects, **kwargs)

    async def delete(
        self, url: str, follow_redirects: bool = True, **kwargs: Any
    ) -> httpx.Response:
        """Send DELETE request with scope enforcement."""
        return await self._request("DELETE", url, follow_redirects=follow_redirects, **kwargs)

    async def _request(
        self,
        method: str,
        url: str,
        follow_redirects: bool = True,
        **kwargs: Any,
    ) -> httpx.Response:
        """Core request method with scope enforcement and redirect validation.

        VT-Spec T-01: Every request is validated against allowlist.
        VT-Spec S-01: Every redirect hop is validated.
        VT-Spec D-01: Rate limiting applied before each request.
        """
        if not self._client:
            raise RuntimeError("ScopedHttpClient must be used as async context manager")

        # VT-Spec T-01 CRITICAL: Enforce scope BEFORE sending any request
        self._enforce_scope(url)

        # VT-Spec D-01: Rate limit before request
        await self._rate_limit(url)

        # Send request without following redirects
        headers = dict(self._default_headers)
        headers.update(kwargs.pop("headers", {}))
        response = await self._client.request(
            method=method,
            url=url,
            headers=headers,
            **kwargs,
        )

        # VT-Spec S-01: Manually follow redirects with per-hop validation
        if follow_redirects and response.is_redirect:
            response = await self._follow_redirects(response, headers, **kwargs)

        return response
