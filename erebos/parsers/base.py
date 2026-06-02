"""Parser abstraction for tool output normalization."""

from abc import ABC, abstractmethod
from typing import List

from erebos.core.finding import Finding


class Parser(ABC):
    """Abstract parser interface."""

    tool_name: str = ""

    @abstractmethod
    def parse(self, output: str) -> List[Finding]:
        """Parse tool output into canonical Finding model."""
        pass

    @abstractmethod
    def can_parse(self, output: str) -> bool:
        """Check if this parser handles the output format."""
        pass
