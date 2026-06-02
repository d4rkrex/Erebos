"""Intelligent error handling with fallback chains and graceful degradation."""

from __future__ import annotations

import logging
import random
import shutil
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Callable, Dict, List, Optional

import yaml

from erebos.executors.base import ToolResult, Transport


logger = logging.getLogger(__name__)

PATTERN_PERMISSION = (
    "permission denied",
    "access denied",
    "eacces",
    "eperm",
)
PATTERN_TIMEOUT = (
    "timeout",
    "timed out",
)
PATTERN_NETWORK = (
    "connection refused",
    "connection reset",
    "network unreachable",
    "name or service not known",
    "temporary failure in name resolution",
    "no route to host",
    "dns",
    "socket.timeout",
)
PATTERN_PARSE = (
    "parse error",
    "unexpected format",
    "malformed",
    "invalid json",
    "jsondecodeerror",
    "xmlsyntaxerror",
    "xml parse",
)
PATTERN_TOOL_NOT_FOUND = (
    "command not found",
    "not found",
    "no such file",
    "filenotfounderror",
)
PATTERN_RATE_LIMIT = (
    "429",
    "503",
    "504",
    "rate limit",
    "too many requests",
    "throttl",
)


class ErrorType(str, Enum):
    """Error categories used for recovery decisions."""

    PERMISSION_DENIED = "permission_denied"
    TIMEOUT = "timeout"
    NETWORK_ERROR = "network_error"
    PARSE_FAILURE = "parse_failure"
    TOOL_NOT_FOUND = "tool_not_found"
    RATE_LIMIT = "rate_limit"
    UNKNOWN = "unknown"


class RecoveryStrategy(str, Enum):
    """Recovery actions available to the intelligent error handler."""

    RETRY = "retry"
    FALLBACK = "fallback"
    SKIP = "skip"
    ABORT = "abort"


@dataclass
class FallbackChain:
    """Fallback chain for a tool category."""

    primary: str
    alternatives: List[str] = field(default_factory=list)
    max_retries: int = 3
    retry_delay: float = 1.0

    def ordered_tools(self) -> List[str]:
        """Return the primary tool followed by its alternatives."""
        return [self.primary, *self.alternatives]


@dataclass
class RecoveryAttempt:
    """Execution attempt made during recovery."""

    original_error: Exception
    error_type: ErrorType
    attempted_tool: str
    fallback_tool: Optional[str]
    success: bool
    timestamp: datetime


@dataclass
class ErrorRecoveryContext:
    """Context kept for recovery logging and debugging."""

    scan_id: str = "unknown"
    attempts: List[RecoveryAttempt] = field(default_factory=list)
    metadata: Dict[str, object] = field(default_factory=dict)


@dataclass
class FallbackEvent:
    """Persisted event describing a recovery decision."""

    timestamp: datetime
    tool: str
    category: str
    error_type: ErrorType
    recovery_strategy: RecoveryStrategy
    fallback_tool: Optional[str]
    success: bool
    duration_seconds: float

    def to_dict(self) -> Dict[str, object]:
        """Convert the event to a JSON-serializable dictionary."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "tool": self.tool,
            "category": self.category,
            "error_type": self.error_type.value,
            "recovery_strategy": self.recovery_strategy.value,
            "fallback_tool": self.fallback_tool,
            "success": self.success,
            "duration_seconds": self.duration_seconds,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, object]) -> "FallbackEvent":
        """Create an event from serialized scan-state data."""
        timestamp = str(data.get("timestamp", datetime.now(timezone.utc).isoformat()))
        duration_value = str(data.get("duration_seconds", "0.0"))
        return cls(
            timestamp=datetime.fromisoformat(timestamp),
            tool=str(data.get("tool", "unknown")),
            category=str(data.get("category", "unknown")),
            error_type=ErrorType(str(data.get("error_type", ErrorType.UNKNOWN.value))),
            recovery_strategy=RecoveryStrategy(
                str(data.get("recovery_strategy", RecoveryStrategy.SKIP.value))
            ),
            fallback_tool=(
                str(data["fallback_tool"]) if data.get("fallback_tool") is not None else None
            ),
            success=bool(data.get("success", False)),
            duration_seconds=float(duration_value),
        )


@dataclass
class FallbackStatistics:
    """Aggregated fallback event statistics."""

    total_fallbacks: int
    success_count: int
    error_type_counts: Dict[str, int]
    tools: List[str]


@dataclass
class FallbackChainsConfig:
    """Loaded fallback chain configuration."""

    chains: Dict[str, FallbackChain] = field(default_factory=dict)
    strategies: Dict[str, Dict[ErrorType, RecoveryStrategy]] = field(default_factory=dict)
    tool_strategies: Dict[str, Dict[str, Dict[ErrorType, RecoveryStrategy]]] = field(
        default_factory=dict
    )


def _default_chains_path() -> Path:
    return Path(__file__).resolve().parents[1] / "config" / "fallback_chains.yaml"


DEFAULT_STRATEGIES: Dict[str, Dict[ErrorType, RecoveryStrategy]] = {
    "network_scanning": {
        ErrorType.PERMISSION_DENIED: RecoveryStrategy.FALLBACK,
        ErrorType.TIMEOUT: RecoveryStrategy.RETRY,
        ErrorType.NETWORK_ERROR: RecoveryStrategy.RETRY,
        ErrorType.TOOL_NOT_FOUND: RecoveryStrategy.FALLBACK,
        ErrorType.PARSE_FAILURE: RecoveryStrategy.FALLBACK,
        ErrorType.RATE_LIMIT: RecoveryStrategy.RETRY,
        ErrorType.UNKNOWN: RecoveryStrategy.SKIP,
    },
    "web_enumeration": {
        ErrorType.PERMISSION_DENIED: RecoveryStrategy.SKIP,
        ErrorType.TIMEOUT: RecoveryStrategy.RETRY,
        ErrorType.NETWORK_ERROR: RecoveryStrategy.RETRY,
        ErrorType.TOOL_NOT_FOUND: RecoveryStrategy.FALLBACK,
        ErrorType.PARSE_FAILURE: RecoveryStrategy.FALLBACK,
        ErrorType.RATE_LIMIT: RecoveryStrategy.RETRY,
        ErrorType.UNKNOWN: RecoveryStrategy.SKIP,
    },
    "web_scanning": {
        ErrorType.PERMISSION_DENIED: RecoveryStrategy.SKIP,
        ErrorType.TIMEOUT: RecoveryStrategy.RETRY,
        ErrorType.NETWORK_ERROR: RecoveryStrategy.RETRY,
        ErrorType.TOOL_NOT_FOUND: RecoveryStrategy.SKIP,
        ErrorType.PARSE_FAILURE: RecoveryStrategy.SKIP,
        ErrorType.RATE_LIMIT: RecoveryStrategy.RETRY,
        ErrorType.UNKNOWN: RecoveryStrategy.SKIP,
    },
    "dns_enumeration": {
        ErrorType.PERMISSION_DENIED: RecoveryStrategy.FALLBACK,
        ErrorType.TIMEOUT: RecoveryStrategy.RETRY,
        ErrorType.NETWORK_ERROR: RecoveryStrategy.RETRY,
        ErrorType.TOOL_NOT_FOUND: RecoveryStrategy.FALLBACK,
        ErrorType.PARSE_FAILURE: RecoveryStrategy.SKIP,
        ErrorType.RATE_LIMIT: RecoveryStrategy.RETRY,
        ErrorType.UNKNOWN: RecoveryStrategy.SKIP,
    },
}


DEFAULT_CHAINS: Dict[str, FallbackChain] = {
    "network_scanning": FallbackChain(
        primary="masscan",
        alternatives=["rustscan", "nmap"],
        max_retries=3,
        retry_delay=1.0,
    ),
    "web_enumeration": FallbackChain(
        primary="gobuster",
        alternatives=["ffuf", "dirsearch"],
        max_retries=3,
        retry_delay=1.0,
    ),
    "web_scanning": FallbackChain(
        primary="nikto",
        alternatives=["skip"],
        max_retries=3,
        retry_delay=1.0,
    ),
    "dns_enumeration": FallbackChain(
        primary="nslookup",
        alternatives=["dig", "fierce"],
        max_retries=3,
        retry_delay=1.0,
    ),
}


class ErrorClassifier:
    """Classify tool execution failures into recovery buckets."""

    @staticmethod
    def classify_exception(
        error: Optional[Exception], stdout: str = "", stderr: str = ""
    ) -> ErrorType:
        message = ErrorClassifier._normalize_text(
            str(error) if error is not None else "", stdout, stderr
        )
        error_name = type(error).__name__.lower() if error is not None else ""

        if any(pattern in message for pattern in PATTERN_PERMISSION):
            return ErrorType.PERMISSION_DENIED
        if error_name == "permissionerror":
            return ErrorType.PERMISSION_DENIED

        if error_name in {"timeoutexpired", "timeouterror"} or any(
            pattern in message for pattern in PATTERN_TIMEOUT
        ):
            return ErrorType.TIMEOUT

        if error_name in {"sockettimeout", "socketerror"} or any(
            pattern in message for pattern in PATTERN_NETWORK
        ):
            return ErrorType.NETWORK_ERROR

        if error_name in {"jsondecodeerror", "xmlsyntaxerror"} or any(
            pattern in message for pattern in PATTERN_PARSE
        ):
            return ErrorType.PARSE_FAILURE

        if error_name == "filenotfounderror" or any(
            pattern in message for pattern in PATTERN_TOOL_NOT_FOUND
        ):
            return ErrorType.TOOL_NOT_FOUND

        if any(pattern in message for pattern in PATTERN_RATE_LIMIT):
            return ErrorType.RATE_LIMIT

        return ErrorType.UNKNOWN

    @staticmethod
    def classify(result: ToolResult) -> ErrorType:
        """Classify a normalized tool result into an error category."""
        if result.exit_code == 0:
            return ErrorType.UNKNOWN

        text = ErrorClassifier._normalize_text(result.stdout, result.stderr)

        if result.exit_code == 124:
            return ErrorType.TIMEOUT
        if result.exit_code in {429, 503, 504}:
            return ErrorType.RATE_LIMIT
        if result.exit_code == 126:
            return ErrorType.PERMISSION_DENIED
        if result.exit_code == 127:
            if any(pattern in text for pattern in PATTERN_PERMISSION):
                return ErrorType.PERMISSION_DENIED
            return ErrorType.TOOL_NOT_FOUND

        classified = ErrorClassifier.classify_exception(None, result.stdout, result.stderr)
        return classified

    @staticmethod
    def _normalize_text(*parts: Optional[str]) -> str:
        normalized_parts = [part.lower() for part in parts if part]
        return " ".join(normalized_parts)


class RecoveryStrategyRegistry:
    """Resolve recovery strategy for a category and error type."""

    def __init__(
        self,
        overrides: Optional[Dict[str, Dict[ErrorType, RecoveryStrategy]]] = None,
        tool_overrides: Optional[Dict[str, Dict[str, Dict[ErrorType, RecoveryStrategy]]]] = None,
    ):
        self._strategies = dict(DEFAULT_STRATEGIES)
        self._tool_overrides = tool_overrides or {}
        if overrides:
            for category, category_overrides in overrides.items():
                merged = dict(self._strategies.get(category, {}))
                merged.update(category_overrides)
                self._strategies[category] = merged

    def get_strategy(
        self,
        category: str,
        error_type: ErrorType,
        tool: Optional[str] = None,
        has_fallback: bool = True,
    ) -> RecoveryStrategy:
        if tool:
            strategy = self._tool_overrides.get(category, {}).get(tool, {}).get(error_type)
            if strategy is not None:
                if strategy == RecoveryStrategy.FALLBACK and not has_fallback:
                    return RecoveryStrategy.SKIP
                return strategy
        strategy = self._strategies.get(category, {}).get(error_type, RecoveryStrategy.SKIP)
        if strategy == RecoveryStrategy.FALLBACK and not has_fallback:
            return RecoveryStrategy.SKIP
        return strategy


class FallbackChainManager:
    """Load and validate fallback chains."""

    def __init__(self, config: Optional[FallbackChainsConfig] = None):
        self.config = config or FallbackChainsConfig(
            chains=dict(DEFAULT_CHAINS),
            strategies={category: dict(values) for category, values in DEFAULT_STRATEGIES.items()},
            tool_strategies={},
        )

    @classmethod
    def load(cls, config_path: Optional[str] = None) -> "FallbackChainManager":
        """Load fallback chains from YAML, falling back to embedded defaults."""
        path = Path(config_path) if config_path else _default_chains_path()
        if not path.exists():
            logger.debug("Fallback config not found at %s, using embedded defaults", path)
            return cls()

        with open(path, "r", encoding="utf-8") as handle:
            raw_data = yaml.safe_load(handle) or {}

        chains_block = raw_data.get("fallback_chains", {})
        chains: Dict[str, FallbackChain] = {}
        strategies: Dict[str, Dict[ErrorType, RecoveryStrategy]] = {}
        tool_strategies: Dict[str, Dict[str, Dict[ErrorType, RecoveryStrategy]]] = {}

        for category, payload in chains_block.items():
            alternatives = payload.get("alternatives") or []
            chains[category] = FallbackChain(
                primary=str(payload.get("primary", "")),
                alternatives=[str(tool) for tool in alternatives],
                max_retries=int(payload.get("max_retries", 3)),
                retry_delay=float(payload.get("retry_delay", 1.0)),
            )
            strategies[category] = {
                ErrorType[key]: RecoveryStrategy[value]
                for key, value in (payload.get("strategies") or {}).items()
                if key in ErrorType.__members__ and value in RecoveryStrategy.__members__
            }
            category_tool_strategies: Dict[str, Dict[ErrorType, RecoveryStrategy]] = {}
            for tool_name, strategy_map in (payload.get("tool_strategies") or {}).items():
                category_tool_strategies[str(tool_name)] = {
                    ErrorType[key]: RecoveryStrategy[value]
                    for key, value in (strategy_map or {}).items()
                    if key in ErrorType.__members__ and value in RecoveryStrategy.__members__
                }
            if category_tool_strategies:
                tool_strategies[category] = category_tool_strategies

        manager = cls(
            FallbackChainsConfig(
                chains=chains or dict(DEFAULT_CHAINS),
                strategies=strategies,
                tool_strategies=tool_strategies,
            )
        )
        manager.validate()
        return manager

    def validate(self) -> None:
        """Validate fallback chain structure and log missing tools."""
        for category, chain in self.config.chains.items():
            if not chain.primary:
                raise ValueError(f"Fallback chain '{category}' is missing a primary tool")
            if chain.max_retries < 0:
                raise ValueError(f"Fallback chain '{category}' has invalid max_retries")
            if chain.retry_delay < 0:
                raise ValueError(f"Fallback chain '{category}' has invalid retry_delay")
        unavailable = self.list_unavailable_tools()
        if unavailable:
            logger.debug("Fallback chains reference unavailable tools: %s", ", ".join(unavailable))

    def get_chain(self, category: str) -> Optional[FallbackChain]:
        """Return the configured fallback chain for a category, if any."""
        return self.config.chains.get(category)

    def list_tools(self) -> List[str]:
        """List configured fallback chain categories."""
        return sorted(self.config.chains.keys())

    def list_unavailable_tools(
        self, tool_exists: Optional[Callable[[str], Optional[str]]] = None
    ) -> List[str]:
        """Return referenced tools that are not available on PATH."""
        exists_fn = tool_exists or shutil.which
        unavailable = set()
        for chain in self.config.chains.values():
            for tool in chain.ordered_tools():
                if tool == "skip":
                    continue
                if exists_fn(tool) is None:
                    unavailable.add(tool)
        return sorted(unavailable)


class FallbackStateStore:
    """In-memory fallback event store."""

    def __init__(self):
        self._events: Dict[str, List[FallbackEvent]] = {}

    def record(self, scan_id: str, event: FallbackEvent) -> None:
        """Persist a fallback event for a scan."""
        self._events.setdefault(scan_id, []).append(event)

    def get_events(self, scan_id: str) -> List[FallbackEvent]:
        """Return all recorded fallback events for a scan."""
        return list(self._events.get(scan_id, []))

    def get_statistics(self, scan_id: str) -> FallbackStatistics:
        """Aggregate fallback event statistics for a scan."""
        events = self.get_events(scan_id)
        error_type_counts: Dict[str, int] = {}
        tools = set()
        success_count = 0

        for event in events:
            error_type_counts[event.error_type.value] = (
                error_type_counts.get(event.error_type.value, 0) + 1
            )
            tools.add(event.tool)
            if event.fallback_tool:
                tools.add(event.fallback_tool)
            if event.success:
                success_count += 1

        return FallbackStatistics(
            total_fallbacks=len(events),
            success_count=success_count,
            error_type_counts=error_type_counts,
            tools=sorted(tools),
        )


class ScanStateFallbackStore(FallbackStateStore):
    """Persist fallback events into scan state artifacts for auditability."""

    def __init__(self, scan_state):
        super().__init__()
        self.scan_state = scan_state

    def record(self, scan_id: str, event: FallbackEvent) -> None:
        super().record(scan_id, event)
        self.scan_state.log_fallback_event(event.to_dict())

    def get_events(self, scan_id: str) -> List[FallbackEvent]:
        in_memory = super().get_events(scan_id)
        if in_memory:
            return in_memory
        raw_events = self.scan_state.get_fallback_events()
        return [FallbackEvent.from_dict(event) for event in raw_events]


class IntelligentErrorHandler:
    """Execute tools with error classification, retries, and fallback chains."""

    def __init__(
        self,
        transport: Transport,
        config: Optional[FallbackChainsConfig] = None,
        fallback_state_store: Optional[FallbackStateStore] = None,
        sleep_func: Callable[[float], None] = time.sleep,
    ):
        self.transport = transport
        self.manager = FallbackChainManager(config)
        self.strategy_registry = RecoveryStrategyRegistry(
            self.manager.config.strategies,
            self.manager.config.tool_strategies,
        )
        self.fallback_state_store = fallback_state_store or FallbackStateStore()
        self.sleep_func = sleep_func
        self.recovery_log: List[RecoveryAttempt] = []

    def execute(
        self,
        tool: str,
        args: List[str],
        category: str,
        env: Optional[dict] = None,
        timeout: Optional[int] = None,
        scan_id: str = "unknown",
    ) -> ToolResult:
        """Compatibility wrapper around `execute_with_fallback()`."""
        return self.execute_with_fallback(tool, args, category, env, timeout, scan_id)

    def execute_with_fallback(
        self,
        tool: str,
        args: List[str],
        category: str,
        env: Optional[dict] = None,
        timeout: Optional[int] = None,
        scan_id: str = "unknown",
    ) -> ToolResult:
        """Execute a tool and recover using retry/fallback strategies when configured."""
        chain = self.manager.get_chain(category)
        if chain is None:
            result = self.transport.execute(tool, args, env, timeout)
            return self._decorate_result(
                result,
                degraded=False,
                fallback_source=None,
                attempted_tools=[tool],
                recovery_context={"attempts": [], "statistics": {}},
            )

        ordered_tools = chain.ordered_tools()
        if tool not in ordered_tools:
            ordered_tools = [tool, *ordered_tools]

        attempted_tools: List[str] = []
        current_index = ordered_tools.index(tool)
        current_tool = ordered_tools[current_index]
        last_result = self.transport.execute(current_tool, args, env, timeout)
        attempted_tools.append(current_tool)

        if last_result.exit_code == 0:
            return self._decorate_result(
                last_result,
                degraded=False,
                fallback_source=None,
                attempted_tools=attempted_tools,
                recovery_context=self._build_recovery_context(scan_id),
            )

        while True:
            error_type = ErrorClassifier.classify(last_result)
            next_tool = (
                ordered_tools[current_index + 1] if current_index + 1 < len(ordered_tools) else None
            )
            strategy = self.strategy_registry.get_strategy(
                category,
                error_type,
                tool=current_tool,
                has_fallback=next_tool is not None,
            )

            self._record_event(
                scan_id=scan_id,
                tool=current_tool,
                category=category,
                error_type=error_type,
                strategy=strategy,
                fallback_tool=next_tool,
                result=last_result,
            )

            if strategy == RecoveryStrategy.RETRY:
                retried_result = self.retry_with_backoff(
                    scan_id=scan_id,
                    tool=current_tool,
                    category=category,
                    args=args,
                    env=env,
                    timeout=timeout,
                    chain=chain,
                    attempted_tools=attempted_tools,
                )
                if retried_result.exit_code == 0:
                    degraded = current_tool != tool
                    fallback_source = current_tool if degraded else None
                    return self._decorate_result(
                        retried_result,
                        degraded=degraded,
                        fallback_source=fallback_source,
                        attempted_tools=attempted_tools,
                        recovery_context=self._build_recovery_context(scan_id),
                    )
                last_result = retried_result
                if next_tool is None:
                    return self._decorate_result(
                        last_result,
                        degraded=True,
                        fallback_source=current_tool if current_tool != tool else None,
                        attempted_tools=attempted_tools,
                        recovery_context=self._build_recovery_context(scan_id),
                    )
                current_index += 1
                current_tool = next_tool
                if current_tool == "skip":
                    return self._decorate_result(
                        self._build_skip_result(tool, last_result),
                        degraded=True,
                        fallback_source="skip",
                        attempted_tools=attempted_tools,
                        recovery_context=self._build_recovery_context(scan_id),
                    )
                last_result = self.transport.execute(current_tool, args, env, timeout)
                attempted_tools.append(current_tool)
                continue

            if strategy == RecoveryStrategy.FALLBACK and next_tool is not None:
                fallback_result, fallback_tool = self._try_fallbacks(
                    scan_id=scan_id,
                    category=category,
                    tool=tool,
                    args=args,
                    env=env,
                    timeout=timeout,
                    ordered_tools=ordered_tools,
                    start_index=current_index + 1,
                    attempted_tools=attempted_tools,
                )
                if fallback_result.exit_code == 0:
                    return self._decorate_result(
                        fallback_result,
                        degraded=True,
                        fallback_source=fallback_tool,
                        attempted_tools=attempted_tools,
                        recovery_context=self._build_recovery_context(scan_id),
                    )
                last_result = fallback_result
                if fallback_tool in ordered_tools:
                    current_index = ordered_tools.index(fallback_tool)
                    current_tool = fallback_tool
                continue

            if (
                next_tool is not None
                and current_tool != tool
                and strategy != RecoveryStrategy.ABORT
            ):
                current_index += 1
                current_tool = next_tool
                last_result = self.transport.execute(current_tool, args, env, timeout)
                attempted_tools.append(current_tool)
                if last_result.exit_code == 0:
                    return self._decorate_result(
                        last_result,
                        degraded=True,
                        fallback_source=current_tool,
                        attempted_tools=attempted_tools,
                        recovery_context=self._build_recovery_context(scan_id),
                    )
                continue

            return self._decorate_result(
                last_result,
                degraded=True,
                fallback_source=current_tool if current_tool != tool else None,
                attempted_tools=attempted_tools,
                recovery_context=self._build_recovery_context(scan_id),
            )

    def retry_with_backoff(
        self,
        scan_id: str,
        tool: str,
        category: str,
        args: List[str],
        env: Optional[dict],
        timeout: Optional[int],
        chain: FallbackChain,
        attempted_tools: Optional[List[str]] = None,
    ) -> ToolResult:
        """Retry the same tool with exponential backoff and jitter."""
        last_result = ToolResult(tool=tool, exit_code=1, stdout="", stderr="", duration_seconds=0.0)
        for attempt in range(chain.max_retries):
            delay = min(chain.retry_delay * (2**attempt), 30.0)
            jitter = delay * 0.25
            sleep_for = max(0.0, delay + random.uniform(-jitter, jitter))
            self.sleep_func(sleep_for)
            last_result = self.transport.execute(tool, args, env, timeout)
            if attempted_tools is not None:
                attempted_tools.append(tool)
            if last_result.exit_code != 0:
                self._record_event(
                    scan_id=scan_id,
                    tool=tool,
                    category=category,
                    error_type=ErrorClassifier.classify(last_result),
                    strategy=RecoveryStrategy.RETRY,
                    fallback_tool=None,
                    result=last_result,
                )
            if last_result.exit_code == 0:
                return last_result
        return last_result

    def _try_fallbacks(
        self,
        scan_id: str,
        category: str,
        tool: str,
        args: List[str],
        env: Optional[dict],
        timeout: Optional[int],
        ordered_tools: List[str],
        start_index: int,
        attempted_tools: List[str],
    ) -> tuple[ToolResult, str]:
        """Try alternative tools in order and return the best available result."""
        last_result = ToolResult(tool=tool, exit_code=1, stdout="", stderr="", duration_seconds=0.0)
        fallback_tool = tool
        for fallback_tool in ordered_tools[start_index:]:
            logger.info("Fallback selected for %s -> %s", tool, fallback_tool)
            if fallback_tool == "skip":
                return self._build_skip_result(tool, last_result), fallback_tool
            last_result = self.transport.execute(fallback_tool, args, env, timeout)
            attempted_tools.append(fallback_tool)
            if last_result.exit_code == 0:
                return last_result, fallback_tool
            self._record_event(
                scan_id=scan_id,
                tool=fallback_tool,
                category=category,
                error_type=ErrorClassifier.classify(last_result),
                strategy=RecoveryStrategy.FALLBACK,
                fallback_tool=None,
                result=last_result,
            )
        return last_result, fallback_tool

    def _build_recovery_context(self, scan_id: str) -> Dict[str, object]:
        """Build a serializable recovery context summary for the final result."""
        events = self.fallback_state_store.get_events(scan_id)
        statistics = self.fallback_state_store.get_statistics(scan_id)
        return {
            "attempts": [event.to_dict() for event in events],
            "statistics": {
                "total_fallbacks": statistics.total_fallbacks,
                "success_count": statistics.success_count,
                "error_type_counts": statistics.error_type_counts,
                "tools": statistics.tools,
            },
        }

    def _build_skip_result(self, tool: str, last_result: ToolResult) -> ToolResult:
        """Create a synthetic result representing intentionally skipped coverage."""
        reason = last_result.stderr or last_result.stdout or "Recovery exhausted"
        return ToolResult(
            tool=tool,
            exit_code=75,
            stdout="",
            stderr=f"Coverage skipped after recovery exhaustion: {reason}",
            duration_seconds=last_result.duration_seconds,
            command_string=last_result.command_string,
        )

    def _record_event(
        self,
        scan_id: str,
        tool: str,
        category: str,
        error_type: ErrorType,
        strategy: RecoveryStrategy,
        fallback_tool: Optional[str],
        result: ToolResult,
    ) -> None:
        attempt = RecoveryAttempt(
            original_error=Exception(result.stderr or result.stdout or error_type.value),
            error_type=error_type,
            attempted_tool=tool,
            fallback_tool=fallback_tool,
            success=result.exit_code == 0,
            timestamp=datetime.now(timezone.utc),
        )
        self.recovery_log.append(attempt)
        self.fallback_state_store.record(
            scan_id,
            FallbackEvent(
                timestamp=attempt.timestamp,
                tool=tool,
                category=category,
                error_type=error_type,
                recovery_strategy=strategy,
                fallback_tool=fallback_tool,
                success=result.exit_code == 0,
                duration_seconds=result.duration_seconds,
            ),
        )

    def _decorate_result(
        self,
        result: ToolResult,
        degraded: bool,
        fallback_source: Optional[str],
        attempted_tools: List[str],
        recovery_context: Optional[Dict[str, object]] = None,
    ) -> ToolResult:
        setattr(result, "degraded", degraded)
        setattr(result, "fallback_source", fallback_source)
        setattr(result, "attempted_tools", list(attempted_tools))
        setattr(result, "recovery_context", recovery_context or {"attempts": [], "statistics": {}})
        return result


IntelligentRetryExecutor = IntelligentErrorHandler
