"""Scope enforcement for Erebos control plane (REQ-006).

Per-command scope validation with IP normalization and command blocklist.

# VT-Spec E-01: Normalize all IP formats before scope check (CRITICAL)
# VT-Spec S-02: Validate CIDR, IP ranges, hostnames uniformly
"""

from __future__ import annotations

import ipaddress
import logging
import re
import shlex
import struct
import socket
from typing import List, Optional, Set

logger = logging.getLogger(__name__)

# VT-Spec E-01: Command blocklist — dangerous commands never allowed
COMMAND_BLOCKLIST = frozenset(
    [
        "rm",
        "dd",
        "mkfs",
        "reboot",
        "shutdown",
        "halt",
        "poweroff",
        "init",
        "systemctl",
        "format",
        "fdisk",
        "parted",
        "wipefs",
    ]
)

# Regex patterns for IP extraction from command arguments
# VT-Spec E-01: Extract hex (0x7f000001), octal (0177.0.0.1), decimal (2130706433)
IP_DOTTED_PATTERN = re.compile(
    r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
)
IP_HEX_PATTERN = re.compile(r"\b0x([0-9a-fA-F]{1,8})\b")
IP_OCTAL_PATTERN = re.compile(r"\b(0[0-7]{1,3}(?:\.0?[0-7]{1,3}){3})\b")
IP_DECIMAL_PATTERN = re.compile(r"\b([0-9]{8,10})\b")  # Large integers that could be IPs
CIDR_PATTERN = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})\b")
HOSTNAME_PATTERN = re.compile(
    r"\b([a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,})\b"
)


class ScopeValidator:
    """Validates commands and targets against engagement scope.

    # VT-Spec E-01: IP normalization (hex/octal/decimal) before scope check
    # VT-Spec S-02: CIDR matching with ipaddress module
    """

    def __init__(
        self,
        allowed_targets: List[str],
        excluded_targets: Optional[List[str]] = None,
        max_depth: int = 3,
        allowed_action_classes: Optional[List[str]] = None,
    ):
        self._allowed_targets = allowed_targets
        self._excluded_targets = excluded_targets or []
        self._max_depth = max_depth
        self._allowed_action_classes = allowed_action_classes or ["scan", "enumerate"]
        self._depth_tracker: dict[str, int] = {}  # host -> current depth

        # Parse CIDR networks for efficient matching
        self._allowed_networks: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._excluded_networks: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._parse_networks()

    def _parse_networks(self) -> None:
        """Parse CIDR networks from target lists."""
        for target in self._allowed_targets:
            if "/" in target:
                try:
                    self._allowed_networks.append(
                        ipaddress.ip_network(target, strict=False)
                    )
                except ValueError:
                    pass
        for target in self._excluded_targets:
            if "/" in target:
                try:
                    self._excluded_networks.append(
                        ipaddress.ip_network(target, strict=False)
                    )
                except ValueError:
                    pass

    @staticmethod
    def normalize_ip(raw: str) -> Optional[str]:
        """Normalize IP from various encodings to standard dotted notation.

        # VT-Spec E-01: CRITICAL — Convert hex/octal/decimal encodings
        Handles:
          - 0x7f000001 → 127.0.0.1
          - 0177.0.0.1 → 127.0.0.1
          - 2130706433 → 127.0.0.1
          - Standard dotted: 127.0.0.1 → 127.0.0.1
        """
        raw = raw.strip()

        # Hex format: 0x7f000001
        if raw.startswith("0x") or raw.startswith("0X"):
            try:
                ip_int = int(raw, 16)
                if 0 <= ip_int <= 0xFFFFFFFF:
                    return socket.inet_ntoa(struct.pack("!I", ip_int))
            except (ValueError, struct.error, OSError):
                pass
            return None

        # Check for octal dotted notation: 0177.0.0.1
        if "." in raw:
            parts = raw.split(".")
            if len(parts) == 4:
                try:
                    octets = []
                    for part in parts:
                        if part.startswith("0") and len(part) > 1 and part.isdigit():
                            # Octal notation
                            octets.append(int(part, 8))
                        else:
                            octets.append(int(part))
                    if all(0 <= o <= 255 for o in octets):
                        return f"{octets[0]}.{octets[1]}.{octets[2]}.{octets[3]}"
                except ValueError:
                    pass

            # Standard dotted notation
            try:
                addr = ipaddress.ip_address(raw)
                return str(addr)
            except ValueError:
                pass
            return None

        # Pure decimal integer format: 2130706433
        try:
            ip_int = int(raw)
            if 0 <= ip_int <= 0xFFFFFFFF:
                return socket.inet_ntoa(struct.pack("!I", ip_int))
        except (ValueError, struct.error, OSError):
            pass

        return None

    def extract_targets_from_command(self, command: str) -> Set[str]:
        """Extract all target IPs/hostnames from a command string.

        # VT-Spec E-01: Parse args with shlex.split, extract all IP-like patterns
        """
        targets = set()

        try:
            args = shlex.split(command)
        except ValueError:
            args = command.split()

        full_text = " ".join(args)

        # Extract standard dotted IPs
        for match in IP_DOTTED_PATTERN.finditer(full_text):
            ip = self.normalize_ip(match.group(1))
            if ip:
                targets.add(ip)

        # VT-Spec E-01: Extract hex IPs (0x7f000001)
        for match in IP_HEX_PATTERN.finditer(full_text):
            ip = self.normalize_ip("0x" + match.group(1))
            if ip:
                targets.add(ip)

        # VT-Spec E-01: Extract octal IPs (0177.0.0.1)
        for match in IP_OCTAL_PATTERN.finditer(full_text):
            ip = self.normalize_ip(match.group(1))
            if ip:
                targets.add(ip)

        # VT-Spec E-01: Extract decimal IPs (2130706433)
        for match in IP_DECIMAL_PATTERN.finditer(full_text):
            raw = match.group(1)
            try:
                val = int(raw)
                if val > 255 and val <= 0xFFFFFFFF:
                    ip = self.normalize_ip(raw)
                    if ip:
                        targets.add(ip)
            except ValueError:
                pass

        # Extract CIDR ranges
        for match in CIDR_PATTERN.finditer(full_text):
            targets.add(match.group(1))

        # Extract hostnames
        for match in HOSTNAME_PATTERN.finditer(full_text):
            hostname = match.group(1)
            # Skip common non-target patterns
            if not hostname.startswith("-") and "." in hostname:
                targets.add(hostname)

        return targets

    def is_target_allowed(self, target: str) -> bool:
        """Check if a target is within scope.

        # VT-Spec E-01: Normalize IP before checking
        # VT-Spec S-02: CIDR matching
        """
        # Normalize IP if possible
        normalized = self.normalize_ip(target)
        check_target = normalized if normalized else target

        # Check exclusions first (deny takes precedence)
        if self._is_excluded(check_target):
            return False

        # Check against allowed targets
        return self._is_included(check_target)

    def _is_excluded(self, target: str) -> bool:
        """Check if target is in exclusion list."""
        for excluded in self._excluded_targets:
            if target == excluded:
                return True

        # Check CIDR exclusions
        try:
            addr = ipaddress.ip_address(target)
            for network in self._excluded_networks:
                if addr in network:
                    return True
        except ValueError:
            pass

        return False

    def _is_included(self, target: str) -> bool:
        """Check if target is in allowed list."""
        for allowed in self._allowed_targets:
            # Exact match
            if target == allowed:
                return True

            # Wildcard domain match
            if allowed.startswith("*."):
                suffix = allowed[2:]
                if target == suffix or target.endswith("." + suffix):
                    return True

        # Check CIDR inclusions
        try:
            addr = ipaddress.ip_address(target)
            for network in self._allowed_networks:
                if addr in network:
                    return True
        except ValueError:
            pass

        return False

    def validate_command(self, command: str) -> tuple[bool, str]:
        """Validate a command against scope and blocklist.

        Returns (allowed, reason).
        """
        # Check command blocklist
        try:
            args = shlex.split(command)
        except ValueError:
            args = command.split()

        if not args:
            return False, "Empty command"

        base_cmd = args[0].split("/")[-1]  # Handle full paths

        # VT-Spec: Command blocklist enforcement
        if base_cmd in COMMAND_BLOCKLIST:
            return False, f"Command '{base_cmd}' is in blocklist (dangerous operation)"

        # Also check for blocklisted commands with flags (e.g., "rm -rf")
        for i, arg in enumerate(args):
            cmd_part = arg.split("/")[-1]
            if cmd_part in COMMAND_BLOCKLIST:
                return False, f"Blocklisted command '{cmd_part}' found in arguments"

        # Extract and validate targets
        targets = self.extract_targets_from_command(command)
        for target in targets:
            if not self.is_target_allowed(target):
                return False, f"Target '{target}' is out of scope"

        return True, "Command is within scope"

    def track_depth(self, host: str) -> bool:
        """Track and enforce depth limit per host.

        Returns True if depth is within limit.
        """
        current = self._depth_tracker.get(host, 0)
        if current >= self._max_depth:
            return False
        self._depth_tracker[host] = current + 1
        return True

    def get_depth(self, host: str) -> int:
        """Get current depth for a host."""
        return self._depth_tracker.get(host, 0)

    def reset_depth(self, host: Optional[str] = None) -> None:
        """Reset depth tracking."""
        if host:
            self._depth_tracker.pop(host, None)
        else:
            self._depth_tracker.clear()
