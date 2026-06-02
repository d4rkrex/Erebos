"""HMAC log integrity — tamper-evident audit logging.

VT-Spec I-01: Secret isolation, minimum length, env clearing.
VT-Spec AC-004: Constant-time comparison via hmac.compare_digest.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
from pathlib import Path
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)

# VT-Spec I-01: Minimum secret length
MIN_SECRET_LENGTH = 32
HMAC_SEGMENT_MARKER = "--- HMAC-SHA256:"
DEFAULT_SEGMENT_SIZE = 100  # entries per HMAC segment


class HMACIntegrityError(Exception):
    """Raised when log integrity verification fails."""


class LogIntegrity:
    """HMAC-SHA256 log integrity system.

    VT-Spec I-01: Loads secret once, clears from env, never passes to subprocess.
    VT-Spec AC-004: Uses hmac.compare_digest for constant-time verification.
    """

    def __init__(
        self,
        secret: Optional[bytes] = None,
        env_var: str = "EREBOS_LOG_SECRET",
        segment_size: int = DEFAULT_SEGMENT_SIZE,
    ):
        # VT-Spec I-01: Load secret and clear from environment
        if secret:
            self._secret = secret
        else:
            raw = os.environ.get(env_var, "")
            if raw:
                self._secret = raw.encode("utf-8")
                # I-01: Clear from env after loading
                os.environ.pop(env_var, None)
            else:
                self._secret = b""

        # I-01: Validate minimum length
        if self._secret and len(self._secret) < MIN_SECRET_LENGTH:
            logger.warning(
                f"I-01: HMAC secret is only {len(self._secret)} bytes "
                f"(minimum: {MIN_SECRET_LENGTH}). Log integrity may be weak."
            )

        self._segment_size = segment_size
        self._current_entries: List[str] = []

    @property
    def is_configured(self) -> bool:
        """Return True if a valid secret is loaded."""
        return len(self._secret) >= MIN_SECRET_LENGTH

    def append_entry(self, entry: str, log_path: Path) -> None:
        """Append a log entry and sign segment when full."""
        self._current_entries.append(entry)

        with open(log_path, "a") as f:
            f.write(entry + "\n")

            # Sign segment when reaching configured size
            if len(self._current_entries) >= self._segment_size:
                signature = self._sign_segment(self._current_entries)
                marker = (
                    f"{HMAC_SEGMENT_MARKER}{signature} "
                    f"entries:{len(self._current_entries)}"
                )
                f.write(marker + "\n")
                self._current_entries = []

    def flush(self, log_path: Path) -> None:
        """Force-sign remaining entries (e.g., on shutdown)."""
        if not self._current_entries:
            return

        signature = self._sign_segment(self._current_entries)
        marker = (
            f"{HMAC_SEGMENT_MARKER}{signature} "
            f"entries:{len(self._current_entries)}"
        )

        with open(log_path, "a") as f:
            f.write(marker + "\n")

        self._current_entries = []

    def verify_log_integrity(self, log_path: Path) -> Tuple[bool, str]:
        """Verify entire log file integrity.

        VT-Spec AC-004: Uses hmac.compare_digest for constant-time comparison.

        Returns:
            (is_valid, message) tuple.
        """
        if not log_path.exists():
            return False, "Log file does not exist"

        if not self.is_configured:
            return False, "HMAC secret not configured"

        with open(log_path, "r") as f:
            lines = f.readlines()

        current_segment: List[str] = []
        segments_verified = 0

        for line in lines:
            line = line.rstrip("\n")

            if line.startswith(HMAC_SEGMENT_MARKER):
                # Extract expected signature and count
                try:
                    parts = line[len(HMAC_SEGMENT_MARKER):].split(" ")
                    expected_sig = parts[0]
                    expected_count = int(parts[1].split(":")[1])
                except (IndexError, ValueError):
                    return False, f"Malformed HMAC marker at segment {segments_verified + 1}"

                # Verify entry count
                if len(current_segment) != expected_count:
                    return False, (
                        f"Segment {segments_verified + 1}: expected {expected_count} "
                        f"entries, found {len(current_segment)}"
                    )

                # Verify HMAC signature (AC-004: constant-time)
                actual_sig = self._sign_segment(current_segment)
                if not hmac.compare_digest(actual_sig, expected_sig):
                    return False, (
                        f"Segment {segments_verified + 1}: HMAC mismatch — "
                        "log has been tampered with"
                    )

                segments_verified += 1
                current_segment = []
            else:
                current_segment.append(line)

        # Unsigned trailing entries are acceptable (not yet flushed)
        message = f"Verified {segments_verified} segments"
        if current_segment:
            message += f" ({len(current_segment)} unsigned trailing entries)"

        return True, message

    def _sign_segment(self, entries: List[str]) -> str:
        """Compute HMAC-SHA256 for a segment of log entries."""
        content = "\n".join(entries).encode("utf-8")
        return hmac.new(self._secret, content, hashlib.sha256).hexdigest()
