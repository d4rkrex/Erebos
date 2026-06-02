"""Retry logic with exponential backoff for tool execution."""

import time
import logging
from dataclasses import dataclass
from typing import Callable, Optional, TypeVar, Generic

from erebos.executors.base import ToolResult


logger = logging.getLogger(__name__)

T = TypeVar("T")


@dataclass
class RetryConfig:
    """Configuration for retry behavior."""

    max_retries: int = 3
    initial_delay: float = 1.0  # seconds
    max_delay: float = 30.0  # seconds
    exponential_base: float = 2.0
    jitter: bool = True

    def get_delay(self, attempt: int) -> float:
        """Calculate delay for the given attempt number (0-indexed)."""
        delay = self.initial_delay * (self.exponential_base**attempt)
        delay = min(delay, self.max_delay)

        if self.jitter:
            import random

            # Add random jitter of ±25%
            jitter_range = delay * 0.25
            delay = delay + random.uniform(-jitter_range, jitter_range)

        return max(0, delay)


class RetryableError(Exception):
    """Exception that indicates a transient failure worth retrying."""

    def __init__(self, message: str, is_retryable: bool = True):
        super().__init__(message)
        self.is_retryable = is_retryable


class RetryExhaustedError(Exception):
    """Raised when all retry attempts have been exhausted."""

    def __init__(self, message: str, attempts: int, last_result: Optional[ToolResult] = None):
        super().__init__(message)
        self.attempts = attempts
        self.last_result = last_result


def is_retryable_result(result: ToolResult) -> bool:
    """Determine if a tool result indicates a transient failure."""
    from erebos.core.error_handler import ErrorClassifier, ErrorType

    return ErrorClassifier.classify(result) in {
        ErrorType.TIMEOUT,
        ErrorType.NETWORK_ERROR,
        ErrorType.RATE_LIMIT,
    }


def execute_with_retry(
    func: Callable[[], ToolResult],
    config: Optional[RetryConfig] = None,
    tool_name: str = "tool",
    on_retry: Optional[Callable[[int, ToolResult], None]] = None,
) -> ToolResult:
    """Execute a function with exponential backoff retry.

    Args:
        func: Function that returns a ToolResult
        config: Retry configuration
        tool_name: Name of tool for logging
        on_retry: Callback called before each retry (attempt_number, last_result)

    Returns:
        ToolResult from successful execution

    Raises:
        RetryExhaustedError: If all retries are exhausted
    """
    if config is None:
        config = RetryConfig()

    last_result: Optional[ToolResult] = None

    for attempt in range(config.max_retries + 1):
        try:
            result = func()
            last_result = result

            # Check if successful
            if result.exit_code == 0:
                if attempt > 0:
                    logger.info(f"{tool_name}: succeeded after {attempt} retries")
                return result

            # Check if retryable
            if not is_retryable_result(result):
                logger.debug(f"{tool_name}: non-retryable failure, returning")
                return result

            # Log the failure
            if attempt < config.max_retries:
                delay = config.get_delay(attempt)
                logger.warning(
                    f"{tool_name}: attempt {attempt + 1} failed (exit {result.exit_code}), "
                    f"retrying in {delay:.2f}s..."
                )

                if on_retry:
                    on_retry(attempt, result)

                time.sleep(delay)
            else:
                logger.error(f"{tool_name}: all {config.max_retries + 1} attempts exhausted")
                raise RetryExhaustedError(
                    f"{tool_name} failed after {config.max_retries + 1} attempts",
                    attempts=config.max_retries + 1,
                    last_result=result,
                )

        except RetryExhaustedError:
            raise
        except Exception as e:
            # Retry on any exception during execution
            if attempt < config.max_retries:
                delay = config.get_delay(attempt)
                logger.warning(
                    f"{tool_name}: attempt {attempt + 1} raised {type(e).__name__}: {e}, "
                    f"retrying in {delay:.2f}s..."
                )
                time.sleep(delay)
            else:
                logger.error(
                    f"{tool_name}: all {config.max_retries + 1} attempts exhausted due to exceptions"
                )
                raise RetryExhaustedError(
                    f"{tool_name} failed after {config.max_retries + 1} attempts due to: {e}",
                    attempts=config.max_retries + 1,
                    last_result=last_result,
                )

    # Should not reach here, but just in case
    if last_result:
        return last_result

    raise RetryExhaustedError(
        f"{tool_name} failed unexpectedly",
        attempts=config.max_retries + 1,
    )


class RetryableExecutor:
    """Wrapper that adds retry logic to any executor."""

    def __init__(
        self,
        transport,
        config: Optional[RetryConfig] = None,
        intelligent_handler=None,
        enable_intelligent_error_handler: bool = False,
    ):
        self.transport = transport
        self.config = config or RetryConfig()
        self.intelligent_handler = intelligent_handler
        self.enable_intelligent_error_handler = enable_intelligent_error_handler

    def execute(
        self,
        tool: str,
        args: list,
        env: Optional[dict] = None,
        timeout: Optional[int] = None,
        tool_category: Optional[str] = None,
        scan_id: str = "unknown",
    ) -> ToolResult:
        """Execute a tool with retry logic."""

        if (
            self.enable_intelligent_error_handler
            and self.intelligent_handler is not None
            and tool_category is not None
        ):
            return self.intelligent_handler.execute_with_fallback(
                tool=tool,
                args=args,
                category=tool_category,
                env=env,
                timeout=timeout,
                scan_id=scan_id,
            )

        def do_execute():
            return self.transport.execute(tool, args, env, timeout)

        try:
            return execute_with_retry(
                do_execute,
                self.config,
                tool_name=tool,
            )
        except RetryExhaustedError as e:
            # Return the last result if available
            if e.last_result:
                return e.last_result
            # Otherwise return a failed result
            return ToolResult(
                tool=tool,
                exit_code=1,
                stdout="",
                stderr=str(e),
                duration_seconds=0.0,
            )
