"""Transport abstraction for tool execution."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, Generator, List, Optional


@dataclass
class ToolResult:
    """Result from tool execution."""

    tool: str
    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float
    command_string: str = ""  # Full command executed (for logging)


class Transport(ABC):
    """Abstract transport interface for tool execution."""

    @abstractmethod
    def execute(
        self,
        tool: str,
        args: List[str],
        env: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None,
    ) -> ToolResult:
        """Execute a tool and return normalized result."""
        pass

    @abstractmethod
    def stream(
        self,
        tool: str,
        args: List[str],
        env: Optional[Dict[str, str]] = None,
    ) -> Generator[str, None, None]:
        """Stream output in real-time."""
        pass

    @abstractmethod
    def available(self) -> bool:
        """Check if transport is available."""
        pass
