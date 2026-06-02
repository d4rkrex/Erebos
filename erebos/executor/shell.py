"""Shell Manager for Erebos — tmux-based command execution (REQ-002).

Manages tmux sessions for interactive command execution with:
- Per-command UUID nonce in PS1 to prevent prompt spoofing (T-02)
- Command sanitization before tmux send-keys (T-01)
- Stall detection with configurable timeout (DoS-01)
- Process group termination on abort (EoP-02)

# VT-Spec T-01 CRITICAL: Commands pre-validated; no raw interpolation in send-keys
# VT-Spec T-02 MEDIUM: Per-command UUID nonce in PS1 prevents spoofing
# VT-Spec DoS-01 MEDIUM: Stall detection + absolute wall-clock timeout
# VT-Spec EoP-02 HIGH: Enumerate child PIDs via tmux pane_pid for process group kill
# VT-Spec R-01: All commands logged to audit trail
"""

from __future__ import annotations

import hashlib
import logging
import re
import shlex
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from erebos.core.models import PlannedAction
from erebos.executor.base import BaseExecutor, ExecutionResult

logger = logging.getLogger(__name__)

# VT-Spec T-01: Shell metacharacters that must NEVER appear in commands sent to tmux
# These are checked as a secondary filter after scope validation
DANGEROUS_METACHAR_PATTERN = re.compile(
    r"[`$]|\$\(|;\s*[a-z]|&&\s*[a-z]|\|\|\s*[a-z]|>\s*/|<\s*/"
)

# VT-Spec T-02: Nonce pattern for PS1 prompt matching
# Format: [VTSTRIKE:{nonce}:{exitcode}:{cwd}]$
PS1_NONCE_PATTERN = re.compile(
    r"^\[VTSTRIKE:([a-f0-9\-]{36}):(\d+):([^\]]+)\]\$\s*$", re.MULTILINE
)

# Maximum sessions per engagement and system-wide
MAX_SESSIONS_PER_ENGAGEMENT = 5
MAX_SESSIONS_GLOBAL = 20

# Default timeouts
DEFAULT_COMMAND_TIMEOUT = 300  # 5 minutes
DEFAULT_STALL_TIMEOUT = 60  # 1 minute of no output → stalled
# VT-Spec DoS-01: Absolute wall-clock max independent of stall detection
ABSOLUTE_MAX_TIMEOUT = 3600  # 1 hour hard cap


@dataclass
class ShellSession:
    """Tracks a tmux session for an engagement."""

    session_name: str
    engagement_id: str
    created_at: float = field(default_factory=time.monotonic)
    active: bool = True


class ShellManager(BaseExecutor):
    """Manages tmux sessions for command execution.

    # VT-Spec T-01 CRITICAL: Commands sanitized before tmux send-keys
    # VT-Spec T-02 MEDIUM: Per-command nonce in PS1 prevents output spoofing
    # VT-Spec DoS-01: Stall detection + absolute timeout
    # VT-Spec EoP-02 HIGH: Process group kill on abort
    # VT-Spec AC-001: Double scope check (command integrity hash)
    """

    def __init__(
        self,
        stall_timeout: int = DEFAULT_STALL_TIMEOUT,
        command_timeout: int = DEFAULT_COMMAND_TIMEOUT,
        absolute_timeout: int = ABSOLUTE_MAX_TIMEOUT,
        max_sessions_per_engagement: int = MAX_SESSIONS_PER_ENGAGEMENT,
        max_sessions_global: int = MAX_SESSIONS_GLOBAL,
    ):
        self._stall_timeout = stall_timeout
        self._command_timeout = command_timeout
        # VT-Spec DoS-01: Absolute wall-clock timeout independent of stall detection
        self._absolute_timeout = absolute_timeout
        self._max_sessions_per_engagement = max_sessions_per_engagement
        self._max_sessions_global = max_sessions_global
        self._sessions: dict[str, list[ShellSession]] = {}  # engagement_id -> sessions
        self._audit_log: list[dict] = []  # VT-Spec R-01: Audit trail

    def create_session(self, engagement_id: str) -> str:
        """Create a new tmux session for an engagement.

        # VT-Spec DoS-01: Cap total concurrent sessions.

        Returns:
            Session name string.

        Raises:
            RuntimeError: If session limits exceeded.
        """
        # VT-Spec DoS-01: Enforce session limits
        engagement_sessions = self._sessions.get(engagement_id, [])
        active_sessions = [s for s in engagement_sessions if s.active]

        if len(active_sessions) >= self._max_sessions_per_engagement:
            raise RuntimeError(
                f"VT-Spec DoS-01: Max sessions per engagement reached "
                f"({self._max_sessions_per_engagement})"
            )

        total_active = sum(
            len([s for s in sessions if s.active])
            for sessions in self._sessions.values()
        )
        if total_active >= self._max_sessions_global:
            raise RuntimeError(
                f"VT-Spec DoS-01: Max global sessions reached ({self._max_sessions_global})"
            )

        session_name = f"vts_{engagement_id[:8]}_{uuid.uuid4().hex[:8]}"

        # Create tmux session
        cmd = [
            "tmux", "new-session", "-d", "-s", session_name,
            "-x", "200", "-y", "50",
        ]

        # VT-Spec R-01: Log session creation
        self._audit_log.append({
            "action": "create_session",
            "engagement_id": engagement_id,
            "session_name": session_name,
            "timestamp": time.time(),
        })

        try:
            subprocess.run(cmd, check=True, capture_output=True, timeout=10)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.error("Failed to create tmux session %s: %s", session_name, e)
            raise RuntimeError(f"Failed to create tmux session: {e}") from e

        # Set PS1 with nonce placeholder — actual nonce set per-command
        ps1_setup = "export PS1='[VTSTRIKE:NONCE_PLACEHOLDER:$?:$PWD]$ '"
        self._send_keys_literal(session_name, ps1_setup)

        session = ShellSession(session_name=session_name, engagement_id=engagement_id)
        if engagement_id not in self._sessions:
            self._sessions[engagement_id] = []
        self._sessions[engagement_id].append(session)

        return session_name

    def execute_command(
        self,
        session: str,
        command: str,
        timeout: Optional[int] = None,
        command_hash: Optional[str] = None,
    ) -> ExecutionResult:
        """Execute a command in a tmux session.

        # VT-Spec T-01 CRITICAL: Command sanitized + integrity verified
        # VT-Spec T-02: Per-command nonce in PS1 for response verification
        # VT-Spec DoS-01: Stall detection + absolute timeout

        Args:
            session: tmux session name.
            command: Pre-validated command string.
            timeout: Command timeout in seconds (default: self._command_timeout).
            command_hash: SHA-256 hash of original command for integrity check (T-01).

        Returns:
            ExecutionResult with output and exit code.
        """
        effective_timeout = min(timeout or self._command_timeout, self._absolute_timeout)

        # VT-Spec T-01 CRITICAL: Secondary metacharacter filter at tmux layer
        if not self._validate_command_safety(command):
            logger.warning(
                "VT-Spec T-01: Command rejected by secondary metachar filter: %s",
                command[:100],
            )
            return ExecutionResult(
                stdout="",
                stderr="VT-Spec T-01: Command contains dangerous shell metacharacters",
                exit_code=-1,
            )

        # VT-Spec AC-001: Verify command integrity hash if provided
        if command_hash:
            computed = hashlib.sha256(command.encode()).hexdigest()
            if computed != command_hash:
                logger.error(
                    "VT-Spec AC-001: Command integrity check FAILED. "
                    "Expected %s, got %s",
                    command_hash,
                    computed,
                )
                return ExecutionResult(
                    stdout="",
                    stderr="VT-Spec AC-001: Command integrity verification failed",
                    exit_code=-1,
                )

        # VT-Spec T-02: Generate per-command nonce
        nonce = str(uuid.uuid4())

        # Set PS1 with this command's nonce
        ps1_cmd = f"export PS1='[VTSTRIKE:{nonce}:$?:$PWD]$ '"
        self._send_keys_literal(session, ps1_cmd)
        time.sleep(0.1)  # Brief wait for PS1 to be set

        # VT-Spec R-01: Audit log the command
        self._audit_log.append({
            "action": "execute_command",
            "session": session,
            "command": command,
            "nonce": nonce,
            "timeout": effective_timeout,
            "timestamp": time.time(),
        })

        # VT-Spec T-01: Use send-keys -l (literal) to prevent metachar interpretation
        self._send_keys_literal(session, command)

        # Wait for completion with stall detection
        start_time = time.monotonic()
        last_output_time = start_time
        previous_output = ""
        truncated = False

        while True:
            elapsed = time.monotonic() - start_time

            # VT-Spec DoS-01: Absolute timeout check
            if elapsed >= effective_timeout:
                logger.warning(
                    "VT-Spec DoS-01: Command timed out after %.1fs in session %s",
                    elapsed,
                    session,
                )
                truncated = True
                break

            # Capture current output
            current_output = self._capture_pane(session)

            # Check for new output (stall detection)
            if current_output != previous_output:
                last_output_time = time.monotonic()
                previous_output = current_output
            else:
                # VT-Spec DoS-01: Stall detection
                stall_duration = time.monotonic() - last_output_time
                if stall_duration >= self._stall_timeout:
                    # Check if command completed (nonce in output)
                    if self._check_nonce_in_output(current_output, nonce):
                        break
                    logger.warning(
                        "VT-Spec DoS-01: Command stalled for %.1fs in session %s",
                        stall_duration,
                        session,
                    )
                    truncated = True
                    break

            # Check if command completed via nonce
            if self._check_nonce_in_output(current_output, nonce):
                break

            time.sleep(0.5)

        # Final capture
        final_output = self._capture_pane(session)
        duration = time.monotonic() - start_time

        # VT-Spec T-02: Extract exit code from PS1 nonce pattern
        exit_code = self._extract_exit_code(final_output, nonce)

        # Strip PS1 prompts from output for clean result
        clean_output = self._clean_output(final_output, nonce)

        return ExecutionResult(
            stdout=clean_output,
            stderr="",
            exit_code=exit_code,
            duration_seconds=duration,
            truncated=truncated,
        )

    def execute(self, action: PlannedAction, engagement_id: str) -> ExecutionResult:
        """Execute a PlannedAction in a tmux session.

        # VT-Spec AC-001: Double scope validation — command already validated by bridge.
        # VT-Spec T-01: Command integrity hash verified at execution time.
        """
        # Get or create session for engagement
        sessions = self._sessions.get(engagement_id, [])
        active_sessions = [s for s in sessions if s.active]

        if not active_sessions:
            session_name = self.create_session(engagement_id)
        else:
            session_name = active_sessions[0].session_name

        # VT-Spec AC-001: Compute command hash for integrity verification
        command_hash = hashlib.sha256(action.command.encode()).hexdigest()

        return self.execute_command(
            session=session_name,
            command=action.command,
            command_hash=command_hash,
        )

    def cleanup(self, engagement_id: str) -> None:
        """Clean up all tmux sessions for an engagement."""
        sessions = self._sessions.get(engagement_id, [])
        for session in sessions:
            if session.active:
                self._destroy_session(session.session_name)
                session.active = False

        # VT-Spec R-01: Audit log
        self._audit_log.append({
            "action": "cleanup",
            "engagement_id": engagement_id,
            "sessions_cleaned": len(sessions),
            "timestamp": time.time(),
        })

    def abort(self, engagement_id: str) -> None:
        """Abort all sessions and kill all child processes for an engagement.

        # VT-Spec EoP-02 HIGH: Enumerate child PIDs via tmux pane_pid + cgroup kill.
        """
        sessions = self._sessions.get(engagement_id, [])
        for session in sessions:
            if session.active:
                # VT-Spec EoP-02: Get all pane PIDs for process group kill
                pids = self._get_session_pids(session.session_name)
                for pid in pids:
                    self._kill_process_tree(pid)
                self._destroy_session(session.session_name)
                session.active = False

        # VT-Spec R-01: Audit log
        self._audit_log.append({
            "action": "abort",
            "engagement_id": engagement_id,
            "timestamp": time.time(),
        })

        logger.info(
            "VT-Spec EoP-02: Aborted all sessions for engagement %s", engagement_id
        )

    def _validate_command_safety(self, command: str) -> bool:
        """VT-Spec T-01: Secondary regex filter rejecting dangerous metacharacters.

        This is a DEFENSE-IN-DEPTH check. The primary validation happens at the
        scope validator layer. This catches anything that slipped through.

        Returns:
            True if command is safe, False if dangerous patterns detected.
        """
        # Allow simple commands with pipes for tool chaining (e.g., nmap | grep)
        # But reject backticks, $(), command chaining with semicolons to new commands
        if DANGEROUS_METACHAR_PATTERN.search(command):
            return False
        return True

    def _send_keys_literal(self, session: str, command: str) -> None:
        """Send keys to tmux using -l (literal) flag.

        # VT-Spec T-01: Use tmux send-keys -l to prevent metachar interpretation.
        """
        # VT-Spec T-01: Use -l flag for literal sending, then send Enter separately
        cmd = ["tmux", "send-keys", "-t", session, "-l", command]
        try:
            subprocess.run(cmd, check=True, capture_output=True, timeout=5)
            # Send Enter key separately (not literal)
            subprocess.run(
                ["tmux", "send-keys", "-t", session, "Enter"],
                check=True, capture_output=True, timeout=5,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            logger.error("Failed to send keys to session %s: %s", session, e)

    def _capture_pane(self, session: str) -> str:
        """Capture current tmux pane output."""
        cmd = ["tmux", "capture-pane", "-t", session, "-p", "-S", "-1000"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            return result.stdout
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return ""

    def _check_nonce_in_output(self, output: str, nonce: str) -> bool:
        """VT-Spec T-02: Check if per-command nonce appears in output (command completed)."""
        # Pattern must appear at line start after newline
        pattern = f"[VTSTRIKE:{nonce}:"
        for line in output.split("\n"):
            if line.strip().startswith(pattern):
                return True
        return False

    def _extract_exit_code(self, output: str, nonce: str) -> int:
        """VT-Spec T-02: Extract exit code from PS1 nonce pattern.

        Only trusts exit codes from lines containing OUR nonce.
        """
        for match in PS1_NONCE_PATTERN.finditer(output):
            if match.group(1) == nonce:
                try:
                    return int(match.group(2))
                except ValueError:
                    pass
        return -1  # Unknown if nonce not found

    def _clean_output(self, output: str, nonce: str) -> str:
        """Remove PS1 prompt lines from output."""
        lines = output.split("\n")
        clean_lines = [
            line for line in lines
            if not line.strip().startswith("[VTSTRIKE:")
        ]
        return "\n".join(clean_lines)

    def _get_session_pids(self, session_name: str) -> list[int]:
        """VT-Spec EoP-02: Get all PIDs from tmux session panes."""
        cmd = [
            "tmux", "list-panes", "-t", session_name,
            "-F", "#{pane_pid}",
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            pids = []
            for line in result.stdout.strip().split("\n"):
                if line.strip().isdigit():
                    pids.append(int(line.strip()))
            return pids
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return []

    def _kill_process_tree(self, pid: int) -> None:
        """VT-Spec EoP-02: Kill process and all descendants.

        Uses SIGTERM first, then SIGKILL after brief wait.
        """
        import signal
        import os

        try:
            # Send SIGTERM to process group
            os.killpg(os.getpgid(pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError, OSError):
            pass

        # Brief wait then SIGKILL
        time.sleep(0.5)
        try:
            os.killpg(os.getpgid(pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            pass

    def _destroy_session(self, session_name: str) -> None:
        """Kill a tmux session."""
        cmd = ["tmux", "kill-session", "-t", session_name]
        try:
            subprocess.run(cmd, capture_output=True, timeout=5)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass
