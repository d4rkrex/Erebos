"""Abstract base class for findings parsers and shared models."""

from __future__ import annotations

import html
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Optional

from erebos.core.finding import Finding


# VT-Spec INJ-01: Field length limits to prevent resource exhaustion
MAX_TITLE_LENGTH = 200
MAX_DESCRIPTION_LENGTH = 2000
MAX_EVIDENCE_LENGTH = 5000

# Regex patterns for sanitization
_HTML_TAG_RE = re.compile(r"<[^>]+>", re.DOTALL)
_SCRIPT_TAG_RE = re.compile(r"<script[^>]*>.*?</script>", re.DOTALL | re.IGNORECASE)
_EVENT_HANDLER_RE = re.compile(r"\bon\w+\s*=\s*[\"'][^\"']*[\"']", re.IGNORECASE)
_JAVASCRIPT_URI_RE = re.compile(r"javascript\s*:", re.IGNORECASE)
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


@dataclass
class IngestResult:
    """Result of an ingestion operation."""

    total_parsed: int = 0
    accepted: int = 0
    rejected: int = 0
    format_detected: str = ""
    source_tool: str = ""
    findings: List[Finding] = field(default_factory=list)


class FindingsParser(ABC):
    """Base class for external findings parsers.

    VT-Spec R8: Supports multiple ingestion formats.
    """

    @abstractmethod
    def parse(self, content: bytes) -> List[Finding]:
        """Parse raw file content into normalized Findings."""

    @abstractmethod
    def detect(self, content: bytes) -> bool:
        """Return True if this parser can handle the content."""

    @property
    @abstractmethod
    def format_name(self) -> str:
        """Return the format name for this parser."""


def sanitize_text(text: Optional[str], max_length: int = MAX_DESCRIPTION_LENGTH) -> str:
    """Sanitize a text field by stripping dangerous content.

    VT-Spec INJ-01: Mitigate malicious content injection via crafted findings files.
    - Strip ALL HTML tags from descriptions, titles, evidence
    - Remove JavaScript (script tags, event handlers, javascript: URIs)
    - Truncate fields to reasonable limits
    - Replace null bytes and control characters
    """
    if not text:
        return ""

    # Step 1: Remove script tags and their content first
    result = _SCRIPT_TAG_RE.sub("", text)

    # Step 2: Remove event handlers (onclick=, onerror=, etc.)
    result = _EVENT_HANDLER_RE.sub("", result)

    # Step 3: Remove javascript: URIs
    result = _JAVASCRIPT_URI_RE.sub("", result)

    # Step 4: Strip all remaining HTML tags
    result = _HTML_TAG_RE.sub("", result)

    # Step 5: Decode HTML entities that might hide content
    result = html.unescape(result)

    # Step 6: Remove null bytes and control characters
    result = _CONTROL_CHARS_RE.sub("", result)

    # Step 7: Truncate to max length
    if len(result) > max_length:
        result = result[:max_length]

    return result.strip()
