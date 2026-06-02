"""Output Manager for Erebos (REQ-006).

Handles output storage, tiering, and credential scrubbing.

# VT-Spec ID-02 HIGH: Multi-pass credential scrubbing before storage
# VT-Spec T-02: Never use CWD from PS1 in filesystem operations without sanitization
# VT-Spec R-01: Output storage operations logged
"""

from __future__ import annotations

import hashlib
import logging
import math
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Output size thresholds
INLINE_THRESHOLD = 15 * 1024  # 15KB — inline preview
FILE_THRESHOLD = 5 * 1024 * 1024  # 5MB — truncation point

# VT-Spec ID-02: Known credential patterns (Pass 1)
CREDENTIAL_PATTERNS = [
    # Passwords and tokens
    re.compile(r"(?i)(password|passwd|pwd)\s*[=:]\s*\S+"),
    re.compile(r"(?i)(token|api[_-]?key|secret[_-]?key|access[_-]?key)\s*[=:]\s*\S+"),
    re.compile(r"(?i)Authorization:\s*(Bearer|Basic|Token)\s+\S+"),
    re.compile(r"(?i)(auth[_-]?token|session[_-]?id|csrf[_-]?token)\s*[=:]\s*\S+"),
    # SSH/PGP private keys
    re.compile(r"-----BEGIN\s+(RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END\s+(RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----"),
    # AWS credentials
    re.compile(r"(?i)(aws[_-]?access[_-]?key[_-]?id|aws[_-]?secret[_-]?access[_-]?key)\s*[=:]\s*\S+"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    # Database connection strings
    re.compile(r"(?i)(mysql|postgres|mongodb|redis)://[^\s]+:[^\s]+@"),
    # JWT tokens
    re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    # NTLM hashes
    re.compile(r"[a-fA-F0-9]{32}:[a-fA-F0-9]{32}"),
    # Kerberos tickets (base64 blobs in expected context)
    re.compile(r"(?i)ticket\s*[=:]\s*[A-Za-z0-9+/=]{40,}"),
    # msfrpcd auth format
    re.compile(r"(?i)(msf|metasploit|rpc)[_-]?(password|token|auth)\s*[=:]\s*\S+"),
    # Generic secrets
    re.compile(r"(?i)(private[_-]?key|client[_-]?secret|signing[_-]?key)\s*[=:]\s*\S+"),
]

# VT-Spec ID-02: Redaction placeholder
REDACTED = "[REDACTED]"


@dataclass
class OutputReference:
    """Reference to stored output with tiering metadata.

    Attributes:
        inline_preview: First 15KB of scrubbed output (always present).
        file_path: Path to full output file (if output > 15KB).
        truncated: True if output was truncated (> 5MB).
        original_size: Original output size in bytes.
        scrubbed: True if credential scrubbing was applied.
    """

    inline_preview: str
    file_path: Optional[Path] = None
    truncated: bool = False
    original_size: int = 0
    scrubbed: bool = False


class OutputManager:
    """Manages output storage with tiering and credential scrubbing.

    # VT-Spec ID-02 HIGH: Multi-pass credential scrubbing:
    #   Pass 1: Known patterns (password=, token=, Authorization:, private keys)
    #   Pass 2: High-entropy string detection (base64 blobs >40 chars)
    #   Pass 3: Configurable custom patterns from engagement config
    # VT-Spec R-01: Storage operations logged
    """

    def __init__(
        self,
        storage_dir: Path,
        custom_patterns: Optional[list[re.Pattern]] = None,
        entropy_threshold: float = 4.5,
        entropy_min_length: int = 40,
    ):
        self._storage_dir = storage_dir
        self._custom_patterns = custom_patterns or []
        self._entropy_threshold = entropy_threshold
        self._entropy_min_length = entropy_min_length
        self._audit_log: list[dict] = []

    def store(
        self,
        raw_output: str,
        engagement_id: str,
        phase: str,
        tool: str,
    ) -> OutputReference:
        """Store output with tiering and credential scrubbing.

        # VT-Spec ID-02: Multi-pass scrubbing applied at ALL tiers.

        Tiering:
          - <15KB: inline only
          - 15KB-5MB: file with inline preview
          - >5MB: truncated to 5MB + warning

        Args:
            raw_output: Raw tool output string.
            engagement_id: Engagement ID.
            phase: Current engagement phase.
            tool: Tool that produced the output.

        Returns:
            OutputReference with appropriate tier data.
        """
        original_size = len(raw_output.encode("utf-8"))

        # VT-Spec ID-02: Apply multi-pass credential scrubbing BEFORE storage
        scrubbed_output = self.scrub_credentials(raw_output)
        scrubbed = scrubbed_output != raw_output

        # Determine tier and handle accordingly
        output_bytes = len(scrubbed_output.encode("utf-8"))
        truncated = False

        if output_bytes > FILE_THRESHOLD:
            # >5MB: Truncate to 5MB + warning
            scrubbed_output = scrubbed_output[:FILE_THRESHOLD]
            scrubbed_output += "\n\n[VT-Spec: Output truncated at 5MB]"
            truncated = True

        # Generate inline preview (always ≤15KB)
        if output_bytes <= INLINE_THRESHOLD:
            inline_preview = scrubbed_output
            file_path = None
        else:
            # 15KB-5MB: Store to file, provide inline preview
            inline_preview = scrubbed_output[:INLINE_THRESHOLD]
            if len(scrubbed_output) > INLINE_THRESHOLD:
                inline_preview += "\n\n[... truncated for inline, see file ...]"

            # Write to file
            file_path = self._write_output_file(
                scrubbed_output, engagement_id, phase, tool
            )

        # VT-Spec R-01: Log storage operation
        self._audit_log.append({
            "action": "store_output",
            "engagement_id": engagement_id,
            "phase": phase,
            "tool": tool,
            "original_size": original_size,
            "scrubbed": scrubbed,
            "truncated": truncated,
            "timestamp": time.time(),
        })

        return OutputReference(
            inline_preview=inline_preview,
            file_path=file_path,
            truncated=truncated,
            original_size=original_size,
            scrubbed=scrubbed,
        )

    def scrub_credentials(self, text: str) -> str:
        """VT-Spec ID-02 HIGH: Multi-pass credential scrubbing.

        Pass 1: Known credential patterns (regex).
        Pass 2: High-entropy string detection.
        Pass 3: Custom patterns from engagement config.
        """
        result = text

        # Pass 1: Known patterns
        result = self._scrub_known_patterns(result)

        # Pass 2: High-entropy string detection
        result = self._scrub_high_entropy(result)

        # Pass 3: Custom patterns
        result = self._scrub_custom_patterns(result)

        return result

    def _scrub_known_patterns(self, text: str) -> str:
        """VT-Spec ID-02 Pass 1: Scrub known credential patterns."""
        result = text
        for pattern in CREDENTIAL_PATTERNS:
            result = pattern.sub(REDACTED, result)
        return result

    def _scrub_high_entropy(self, text: str) -> str:
        """VT-Spec ID-02 Pass 2: Detect and scrub high-entropy strings.

        Identifies base64-like blobs > entropy_min_length chars with
        Shannon entropy > entropy_threshold.
        """
        # Match potential high-entropy strings (base64-like, hex-like)
        high_entropy_pattern = re.compile(r"[A-Za-z0-9+/=_\-]{" + str(self._entropy_min_length) + r",}")

        def _check_and_redact(match: re.Match) -> str:
            value = match.group(0)
            entropy = self._shannon_entropy(value)
            if entropy >= self._entropy_threshold:
                return REDACTED
            return value

        return high_entropy_pattern.sub(_check_and_redact, text)

    def _scrub_custom_patterns(self, text: str) -> str:
        """VT-Spec ID-02 Pass 3: Apply custom patterns from engagement config."""
        result = text
        for pattern in self._custom_patterns:
            result = pattern.sub(REDACTED, result)
        return result

    @staticmethod
    def _shannon_entropy(data: str) -> float:
        """Calculate Shannon entropy of a string.

        Higher entropy indicates more randomness (likely a credential/token).
        """
        if not data:
            return 0.0

        freq: dict[str, int] = {}
        for char in data:
            freq[char] = freq.get(char, 0) + 1

        length = len(data)
        entropy = 0.0
        for count in freq.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return entropy

    def _write_output_file(
        self,
        content: str,
        engagement_id: str,
        phase: str,
        tool: str,
    ) -> Path:
        """Write output to file in storage hierarchy.

        Storage path: {storage_dir}/{engagement_id}/{phase}/{tool}_{timestamp}.out

        # VT-Spec T-02: Path components sanitized to prevent traversal.
        """
        # VT-Spec T-02: Sanitize path components (no traversal)
        safe_engagement = self._sanitize_path_component(engagement_id)
        safe_phase = self._sanitize_path_component(phase)
        safe_tool = self._sanitize_path_component(tool)

        timestamp = str(int(time.time()))
        filename = f"{safe_tool}_{timestamp}.out"

        output_dir = self._storage_dir / safe_engagement / safe_phase
        output_dir.mkdir(parents=True, exist_ok=True)

        file_path = output_dir / filename
        file_path.write_text(content, encoding="utf-8")

        return file_path

    @staticmethod
    def _sanitize_path_component(component: str) -> str:
        """VT-Spec T-02: Sanitize path component to prevent directory traversal.

        Removes .., /, and other dangerous characters.
        """
        # Remove path separators and traversal patterns
        sanitized = re.sub(r"[/\\]", "_", component)
        sanitized = re.sub(r"\.\.", "_", sanitized)
        # Only allow alphanumeric, dash, underscore
        sanitized = re.sub(r"[^a-zA-Z0-9_\-]", "_", sanitized)
        return sanitized or "unknown"
