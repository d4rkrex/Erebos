"""HTTP/HTTPS probing service for any open port."""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import requests

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 5.0
DEFAULT_MAX_CONCURRENT = 20


@dataclass
class HttpProbeResult:
    """Result of probing a port for HTTP/HTTPS."""

    is_http: bool = False
    is_https: bool = False
    status_code: Optional[int] = None
    server_banner: Optional[str] = None
    redirect_url: Optional[str] = None
    content_type: Optional[str] = None
    body: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    final_url: Optional[str] = None
    reason: str = "not_probed"


class HttpProbeService:
    """Universal HTTP probe service for any open port.

    Probes ports for HTTP/HTTPS responses, extracts server banners,
    and handles redirects. Uses a thread pool for parallel execution.
    """

    def __init__(
        self, max_concurrent: int = DEFAULT_MAX_CONCURRENT, timeout: float = DEFAULT_TIMEOUT
    ):
        """Initialize the HTTP probe service.

        Args:
            max_concurrent: Maximum concurrent probes (default 20).
            timeout: Per-probe timeout in seconds (default 5.0).
        """
        self._max_concurrent = max_concurrent
        self._timeout = timeout

    def probe(self, host: str, port: int) -> HttpProbeResult:
        """Probe a single host:port for HTTP/HTTPS.

        Tries HTTPS first, then HTTP. Extracts Server banner and redirect URL.

        Args:
            host: Target IP or hostname.
            port: Port number.

        Returns:
            HttpProbeResult with detection details.
        """
        # Try HTTPS first
        result = self._probe_url(f"https://{host}:{port}/")
        if result.is_http:
            result.is_https = True
            return result

        # Fall back to HTTP
        result = self._probe_url(f"http://{host}:{port}/")
        if result.is_http:
            result.is_https = False
            return result

        return result

    def _probe_url(self, url: str) -> HttpProbeResult:
        """Send a GET request and parse the response."""
        try:
            response = requests.get(
                url,
                timeout=self._timeout,
                allow_redirects=False,
                stream=False,
                verify=False,  # Handle self-signed certs
            )

            status_code = response.status_code

            # Extract Server banner
            server_banner: Optional[str] = None
            if response.headers:
                server_banner = response.headers.get("Server")

            content_type = response.headers.get("Content-Type") if response.headers else None

            headers = self._sanitize_headers(dict(response.headers or {}))

            # Capture redirect URL
            redirect_url: Optional[str] = None
            if status_code in (301, 302, 303, 307, 308):
                redirect_url = response.headers.get("Location")

            # Determine if it's a real HTTP service
            # Anything that responds to HTTP GET is an HTTP service
            reason = "http_response" if status_code else "no_response"

            return HttpProbeResult(
                is_http=True,
                status_code=status_code,
                server_banner=server_banner,
                redirect_url=redirect_url,
                content_type=content_type,
                body=(response.text or "")[:8192],
                headers=headers,
                final_url=response.url,
                reason=reason,
            )

        except requests.exceptions.SSLError:
            # SSL error on HTTPS — try as HTTP
            return HttpProbeResult(is_http=False, reason="ssl_error")
        except requests.exceptions.Timeout:
            return HttpProbeResult(is_http=False, reason="timeout")
        except requests.exceptions.ConnectionError:
            return HttpProbeResult(is_http=False, reason="connection_refused")
        except requests.RequestException as e:
            logger.debug("HTTP probe failed for %s: %s", url, e)
            return HttpProbeResult(is_http=False, reason="request_error")

    def probe_batch(self, targets: List[Tuple[str, int]]) -> Dict[Tuple[str, int], HttpProbeResult]:
        """Probe multiple host:port pairs in parallel.

        Args:
            targets: List of (host, port) tuples.

        Returns:
            Dict mapping (host, port) to HttpProbeResult.
        """
        results: Dict[Tuple[str, int], HttpProbeResult] = {}

        with ThreadPoolExecutor(max_workers=self._max_concurrent) as executor:
            future_to_target = {
                executor.submit(self.probe, host, port): (host, port) for host, port in targets
            }

            for future in as_completed(future_to_target):
                target = future_to_target[future]
                try:
                    results[target] = future.result()
                except Exception as e:
                    logger.error("Probe failed for %s: %s", target, e)
                    results[target] = HttpProbeResult(is_http=False, reason="exception")

        return results

    def _sanitize_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Lowercase and filter sensitive headers before storing them."""
        sanitized: Dict[str, str] = {}
        for key, value in headers.items():
            lowered = key.lower()
            if lowered in {"authorization", "cookie", "set-cookie"}:
                continue
            sanitized[lowered] = value
        return sanitized
