"""Rate limiting for tool execution.

VT-Spec D-01: Discovery Module Rate Limit Exhaustion
Mitigation: Shared RateLimiter instance; global request budget;
circuit-breaker on >50% 429/503 responses with exponential backoff.
"""

import asyncio
import logging
import time
from collections import deque
from threading import Lock
from typing import Dict
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class RateLimiter:
    """Rate limiter using sliding window algorithm (synchronous)."""

    def __init__(self, requests_per_second: int = 10):
        self.requests_per_second = requests_per_second
        self.window_size = 1.0  # 1 second window
        self.requests: deque = deque()
        self.lock = Lock()

    def acquire(self) -> None:
        """Wait until rate limit allows execution."""
        with self.lock:
            now = time.time()

            # Remove requests outside the current window
            while self.requests and self.requests[0] < now - self.window_size:
                self.requests.popleft()

            # Check if we've hit the rate limit
            if len(self.requests) >= self.requests_per_second:
                # Calculate wait time
                oldest_request = self.requests[0]
                wait_time = self.window_size - (now - oldest_request)
                if wait_time > 0:
                    time.sleep(wait_time)
                    # Clean up again after waiting
                    now = time.time()
                    while self.requests and self.requests[0] < now - self.window_size:
                        self.requests.popleft()

            # Add this request
            self.requests.append(now)

    def try_acquire(self) -> bool:
        """Try to acquire without blocking. Returns True if successful."""
        with self.lock:
            now = time.time()

            # Remove requests outside the current window
            while self.requests and self.requests[0] < now - self.window_size:
                self.requests.popleft()

            # Check if we can proceed
            if len(self.requests) < self.requests_per_second:
                self.requests.append(now)
                return True

            return False


class ConcurrencyLimiter:
    """Limit concurrent executions."""

    def __init__(self, max_concurrent: int = 3):
        self.max_concurrent = max_concurrent
        self.current = 0
        self.lock = Lock()

    def acquire(self) -> None:
        """Wait until a slot is available."""
        with self.lock:
            while self.current >= self.max_concurrent:
                self.lock.release()
                time.sleep(0.1)
                self.lock.acquire()
            self.current += 1

    def release(self) -> None:
        """Release a slot."""
        with self.lock:
            self.current -= 1


class SharedRateLimiter:
    """Async token-bucket rate limiter with circuit breaker for shared use.

    VT-Spec D-01: Discovery module MUST use shared RateLimiter instance from runner.
    Implements:
    - Per-target rate limiting (token bucket)
    - Global request counter (max_total_requests)
    - Circuit breaker: pause on >50% 429/503 in last 20 responses with exponential backoff

    This class is designed to be shared across discovery, auth, and exploit modules.
    """

    # VT-Spec D-01: Circuit breaker constants
    CIRCUIT_WINDOW_SIZE = 20  # Track last N responses
    CIRCUIT_THRESHOLD = 0.5  # >50% errors triggers circuit break
    BACKOFF_BASE = 1.0  # Starting backoff in seconds
    BACKOFF_MAX = 30.0  # Maximum backoff in seconds

    def __init__(
        self,
        max_per_second: float = 10.0,
        max_total_requests: int = 1000,
    ):
        self._max_per_second = max_per_second
        self._max_total_requests = max_total_requests
        self._total_requests = 0
        self._tokens: Dict[str, float] = {}
        self._last_refill: Dict[str, float] = {}
        self._locks: Dict[str, asyncio.Lock] = {}
        self._global_lock = asyncio.Lock()

        # VT-Spec D-01: Circuit breaker state
        self._recent_statuses: deque = deque(maxlen=self.CIRCUIT_WINDOW_SIZE)
        self._backoff_seconds = 0.0
        self._circuit_open = False

    @property
    def total_requests(self) -> int:
        """Total requests made across all targets."""
        return self._total_requests

    @property
    def budget_remaining(self) -> int:
        """Remaining request budget."""
        return max(0, self._max_total_requests - self._total_requests)

    @property
    def circuit_open(self) -> bool:
        """Whether circuit breaker is currently tripped."""
        return self._circuit_open

    def _get_lock(self, target: str) -> asyncio.Lock:
        """Get or create a per-target lock."""
        if target not in self._locks:
            self._locks[target] = asyncio.Lock()
        return self._locks[target]

    async def acquire(self, target: str) -> None:
        """Acquire a rate limit token for the given target.

        VT-Spec D-01: Enforces per-target rate limit, global budget,
        and circuit breaker.

        Raises:
            RuntimeError: If global request budget is exhausted.
        """
        # Check global budget
        if self._total_requests >= self._max_total_requests:
            raise RuntimeError(
                f"VT-Spec D-01: Global request budget exhausted "
                f"({self._max_total_requests} requests). Stopping."
            )

        # VT-Spec D-01: Circuit breaker — wait if open
        if self._circuit_open and self._backoff_seconds > 0:
            logger.warning(
                "Circuit breaker OPEN: backing off %.1fs for target %s",
                self._backoff_seconds,
                target,
            )
            await asyncio.sleep(self._backoff_seconds)

        # Per-target token bucket
        lock = self._get_lock(target)
        async with lock:
            while True:
                now = time.monotonic()
                if target not in self._tokens:
                    self._tokens[target] = self._max_per_second
                    self._last_refill[target] = now

                elapsed = now - self._last_refill[target]
                refill = elapsed * self._max_per_second
                if refill > 0:
                    self._tokens[target] = min(
                        self._max_per_second,
                        self._tokens[target] + refill,
                    )
                    self._last_refill[target] = now

                if self._tokens[target] >= 1.0:
                    self._tokens[target] -= 1.0
                    break

                wait_seconds = max(
                    (1.0 - self._tokens[target]) / self._max_per_second, 0.01
                )
                await asyncio.sleep(wait_seconds)

        # Increment global counter
        async with self._global_lock:
            self._total_requests += 1

    def record_response(self, status_code: int) -> None:
        """Record a response status for circuit breaker evaluation.

        VT-Spec D-01: Track last 20 responses; if >50% are 429/503,
        pause with exponential backoff (1s → 2s → 4s → max 30s).
        """
        is_error = status_code in (429, 503)
        self._recent_statuses.append(is_error)

        if len(self._recent_statuses) >= self.CIRCUIT_WINDOW_SIZE:
            error_rate = sum(self._recent_statuses) / len(self._recent_statuses)

            if error_rate > self.CIRCUIT_THRESHOLD:
                # Trip circuit breaker with exponential backoff
                if not self._circuit_open:
                    self._backoff_seconds = self.BACKOFF_BASE
                else:
                    self._backoff_seconds = min(
                        self._backoff_seconds * 2, self.BACKOFF_MAX
                    )
                self._circuit_open = True
                logger.warning(
                    "VT-Spec D-01: Circuit breaker TRIPPED. Error rate: %.0f%%. "
                    "Backoff: %.1fs",
                    error_rate * 100,
                    self._backoff_seconds,
                )
            else:
                # Reset circuit breaker
                if self._circuit_open:
                    logger.info("VT-Spec D-01: Circuit breaker CLOSED. Error rate normalized.")
                self._circuit_open = False
                self._backoff_seconds = 0.0

    def reset(self) -> None:
        """Reset all state (for testing or scan restart)."""
        self._total_requests = 0
        self._tokens.clear()
        self._last_refill.clear()
        self._recent_statuses.clear()
        self._circuit_open = False
        self._backoff_seconds = 0.0
