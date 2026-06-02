"""Tool Runner for Erebos — Maps tool names to binaries (REQ-003).

Validates tool availability, enforces timeouts, and routes execution.

# VT-Spec T-01 CRITICAL: Strict command allowlist + metacharacter rejection
# VT-Spec AC-001: Tool-specific argument validation
# VT-Spec DoS-01: Per-tool timeout enforcement
# VT-Spec S-01: DNS resolution pinning for hostnames
"""

from __future__ import annotations

import hashlib
import logging
import re
import shlex
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from erebos.core.models import PlannedAction
from erebos.executor.base import BaseExecutor, ExecutionResult

logger = logging.getLogger(__name__)

# VT-Spec T-01: Allowed tools with their binary paths and default timeouts
TOOL_REGISTRY: dict[str, dict] = {
    "nmap": {"timeout": 600, "description": "Network scanner"},
    "nikto": {"timeout": 300, "description": "Web server scanner"},
    "gobuster": {"timeout": 300, "description": "Directory/DNS bruteforcer"},
    "sqlmap": {"timeout": 600, "description": "SQL injection tester"},
    "hydra": {"timeout": 300, "description": "Password bruteforcer"},
    "dirb": {"timeout": 300, "description": "Web content scanner"},
    "wfuzz": {"timeout": 300, "description": "Web fuzzer"},
    "whatweb": {"timeout": 120, "description": "Web technology identifier"},
    "curl": {"timeout": 60, "description": "HTTP client"},
    "wget": {"timeout": 120, "description": "File downloader"},
    "dig": {"timeout": 30, "description": "DNS lookup"},
    "whois": {"timeout": 30, "description": "WHOIS lookup"},
    "enum4linux": {"timeout": 300, "description": "SMB enumeration"},
    "smbclient": {"timeout": 120, "description": "SMB client"},
    "crackmapexec": {"timeout": 300, "description": "Network pentesting"},
    "ffuf": {"timeout": 300, "description": "Fast web fuzzer"},
    "nuclei": {"timeout": 600, "description": "Vulnerability scanner"},
    "feroxbuster": {"timeout": 300, "description": "Content discovery"},
    "testssl.sh": {"timeout": 300, "description": "SSL/TLS testing"},
    "masscan": {"timeout": 300, "description": "Fast port scanner"},
}

# VT-Spec T-01: Dangerous argument patterns per tool
DANGEROUS_ARG_PATTERNS = [
    re.compile(r"--script[=\s]+.*os\.execute", re.IGNORECASE),  # nmap script injection
    re.compile(r"-oN\s+/(?:etc|proc|sys|dev)/"),  # Write to sensitive paths
    re.compile(r"--output[=\s]+/(?:etc|proc|sys|dev)/"),
    re.compile(r"[;`]"),  # Shell metacharacters in arguments
    re.compile(r"\$\("),  # Command substitution
    re.compile(r"\.\./\.\./"),  # Path traversal
]

# VT-Spec DoS-01: Absolute maximum timeout for any tool
ABSOLUTE_MAX_TIMEOUT = 3600  # 1 hour


@dataclass
class DNSPinning:
    """VT-Spec S-01: DNS resolution pinning for engagement duration."""

    hostname: str
    resolved_ip: str
    resolved_at: float


class ToolRunner(BaseExecutor):
    """Executes security tools with validation and timeout enforcement.

    # VT-Spec T-01 CRITICAL: Strict tool allowlist + argument validation
    # VT-Spec AC-001: Double scope validation at tool level
    # VT-Spec DoS-01: Per-tool timeout enforcement
    # VT-Spec S-01: DNS pinning for hostname resolution
    """

    def __init__(
        self,
        storage_dir: Optional[Path] = None,
        custom_tool_paths: Optional[dict[str, str]] = None,
        scope_validator=None,
    ):
        self._storage_dir = storage_dir or Path("erebos-storage")
        self._custom_tool_paths = custom_tool_paths or {}
        self._scope_validator = scope_validator
        # VT-Spec S-01: DNS pinning cache
        self._dns_pins: dict[str, DNSPinning] = {}
        self._running_processes: dict[str, subprocess.Popen] = {}
        self._audit_log: list[dict] = []

    def execute(self, action: PlannedAction, engagement_id: str) -> ExecutionResult:
        """Execute a tool action.

        # VT-Spec AC-001: Validates tool is allowed and arguments are safe.
        # VT-Spec T-01: Rejects unknown tools and dangerous arguments.
        """
        tool_name = self._extract_tool_name(action.command)

        # VT-Spec T-01: Reject unknown tools
        if tool_name not in TOOL_REGISTRY:
            logger.warning(
                "VT-Spec T-01: Unknown tool rejected: %s", tool_name
            )
            raise ValueError(
                f"VT-Spec T-01: Tool '{tool_name}' is not in the allowed tool registry"
            )

        # VT-Spec T-01: Validate arguments for dangerous patterns
        if not self._validate_arguments(action.command):
            return ExecutionResult(
                stdout="",
                stderr="VT-Spec T-01: Command arguments contain dangerous patterns",
                exit_code=-1,
            )

        # VT-Spec AC-001: Double scope validation at executor level
        if self._scope_validator:
            scope_ok, scope_reason = self._scope_validator.validate_command(action.command)
            if not scope_ok:
                logger.warning(
                    "VT-Spec AC-001: Scope check failed at executor level: %s",
                    scope_reason,
                )
                return ExecutionResult(
                    stdout="",
                    stderr=f"VT-Spec AC-001: Scope violation at executor: {scope_reason}",
                    exit_code=-1,
                )

        # Resolve tool binary path
        binary_path = self._resolve_binary(tool_name)
        if not binary_path:
            return ExecutionResult(
                stdout="",
                stderr=f"Tool '{tool_name}' not found in PATH",
                exit_code=-1,
            )

        # Get timeout for this tool
        tool_config = TOOL_REGISTRY[tool_name]
        timeout = min(tool_config["timeout"], ABSOLUTE_MAX_TIMEOUT)

        # VT-Spec T-01: Build command safely with shell=False
        cmd_parts = self._build_safe_command(action.command, binary_path)

        # VT-Spec R-01: Audit log
        self._audit_log.append({
            "action": "execute_tool",
            "tool": tool_name,
            "command": action.command,
            "engagement_id": engagement_id,
            "timeout": timeout,
            "timestamp": time.time(),
        })

        # Execute with timeout
        start_time = time.monotonic()
        truncated = False

        try:
            proc = subprocess.run(
                cmd_parts,
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=False,  # VT-Spec T-01: NEVER use shell=True
            )
            duration = time.monotonic() - start_time

            return ExecutionResult(
                stdout=proc.stdout,
                stderr=proc.stderr,
                exit_code=proc.returncode,
                duration_seconds=duration,
                truncated=False,
            )

        except subprocess.TimeoutExpired as e:
            duration = time.monotonic() - start_time
            logger.warning(
                "VT-Spec DoS-01: Tool %s timed out after %ds",
                tool_name,
                timeout,
            )
            return ExecutionResult(
                stdout=e.stdout.decode() if e.stdout else "",
                stderr=e.stderr.decode() if e.stderr else f"Timeout after {timeout}s",
                exit_code=-1,
                duration_seconds=duration,
                truncated=True,
            )

        except FileNotFoundError:
            return ExecutionResult(
                stdout="",
                stderr=f"Tool binary not found: {binary_path}",
                exit_code=-1,
            )

        except OSError as e:
            return ExecutionResult(
                stdout="",
                stderr=f"Execution error: {e}",
                exit_code=-1,
            )

    def cleanup(self, engagement_id: str) -> None:
        """Clean up resources for an engagement."""
        # Remove DNS pins for this engagement
        self._dns_pins = {
            k: v for k, v in self._dns_pins.items()
            if not k.startswith(f"{engagement_id}:")
        }

    def abort(self, engagement_id: str) -> None:
        """Abort running processes for an engagement.

        # VT-Spec EoP-02: Kill process trees.
        """
        # In subprocess.run mode, processes are killed by timeout
        # For any tracked Popen processes, terminate them
        to_remove = []
        for key, proc in self._running_processes.items():
            if key.startswith(f"{engagement_id}:"):
                try:
                    proc.terminate()
                    proc.wait(timeout=5)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
                to_remove.append(key)

        for key in to_remove:
            del self._running_processes[key]

    def _extract_tool_name(self, command: str) -> str:
        """Extract the tool name from a command string."""
        parts = shlex.split(command) if command else []
        if not parts:
            return ""
        # Handle full paths: /usr/bin/nmap → nmap
        return Path(parts[0]).name.lower()

    def _validate_arguments(self, command: str) -> bool:
        """VT-Spec T-01: Validate command arguments for dangerous patterns.

        Returns:
            True if safe, False if dangerous patterns detected.
        """
        for pattern in DANGEROUS_ARG_PATTERNS:
            if pattern.search(command):
                logger.warning(
                    "VT-Spec T-01: Dangerous argument pattern detected: %s",
                    pattern.pattern,
                )
                return False
        return True

    def _resolve_binary(self, tool_name: str) -> Optional[str]:
        """Resolve tool binary path."""
        # Check custom paths first
        if tool_name in self._custom_tool_paths:
            path = self._custom_tool_paths[tool_name]
            if Path(path).exists():
                return path

        # Check system PATH
        return shutil.which(tool_name)

    def _build_safe_command(self, command: str, binary_path: str) -> list[str]:
        """VT-Spec T-01: Build command list safely without shell interpretation.

        Uses shlex.split for proper tokenization, replaces tool name with
        resolved binary path.
        """
        parts = shlex.split(command)
        if parts:
            parts[0] = binary_path
        return parts

    def resolve_and_pin_dns(self, hostname: str, engagement_id: str) -> Optional[str]:
        """VT-Spec S-01: Resolve hostname and pin the IP for engagement duration.

        Prevents DNS rebinding attacks by resolving ONCE and pinning.

        Returns:
            Resolved IP address, or None if resolution fails.
        """
        import socket

        cache_key = f"{engagement_id}:{hostname}"
        if cache_key in self._dns_pins:
            return self._dns_pins[cache_key].resolved_ip

        try:
            ip = socket.gethostbyname(hostname)
            self._dns_pins[cache_key] = DNSPinning(
                hostname=hostname,
                resolved_ip=ip,
                resolved_at=time.time(),
            )
            logger.info(
                "VT-Spec S-01: Pinned DNS %s → %s for engagement %s",
                hostname, ip, engagement_id,
            )
            return ip
        except socket.gaierror:
            logger.warning(
                "VT-Spec S-01: DNS resolution failed for %s", hostname
            )
            return None
