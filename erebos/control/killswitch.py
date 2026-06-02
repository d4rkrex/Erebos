"""Kill switch for Erebos control plane (REQ-005).

Emergency abort mechanism for autonomous engagements.

# VT-Spec D-01: Process group kill + tmux destroy + verify termination
"""

from __future__ import annotations

import logging
import os
import signal
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Set

from erebos.core.models import Engagement, EngagementStatus, Session

logger = logging.getLogger(__name__)


class KillSwitch:
    """Emergency kill switch for engagement abort.

    # VT-Spec D-01: Actually terminate ALL processes
    Idempotent — safe to call multiple times.
    """

    def __init__(self, state_dir: Path):
        self._state_dir = state_dir
        self._state_dir.mkdir(parents=True, exist_ok=True)

    def _kill_file(self, engagement_id: str) -> Path:
        """Path to the kill switch state file for an engagement."""
        return self._state_dir / f"{engagement_id}.killed"

    def is_killed(self, engagement_id: str) -> bool:
        """Check if an engagement has been killed (for polling by workers)."""
        return self._kill_file(engagement_id).exists()

    def activate(
        self,
        engagement: Engagement,
        reason: str = "Manual abort",
        operator: str = "operator",
    ) -> dict:
        """Activate kill switch for an engagement.

        # VT-Spec D-01: Process group kill + tmux destroy + verify termination
        Idempotent — safe to call multiple times.
        """
        result = {
            "engagement_id": engagement.id,
            "reason": reason,
            "operator": operator,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "processes_killed": [],
            "tmux_sessions_destroyed": [],
            "errors": [],
            "verified": False,
        }

        # 1. Write kill state file (atomic) for worker polling
        kill_file = self._kill_file(engagement.id)
        try:
            tmp_path = kill_file.with_suffix(".tmp")
            with open(tmp_path, "w") as f:
                f.write(f"{reason}\n{operator}\n{datetime.now(timezone.utc).isoformat()}")
                f.flush()
                os.fsync(f.fileno())
            os.rename(str(tmp_path), str(kill_file))
        except OSError as e:
            # Idempotent — file may already exist
            if not kill_file.exists():
                result["errors"].append(f"Failed to write kill file: {e}")

        # 2. Kill all session processes
        # VT-Spec D-01: Process group-based termination
        for session in engagement.sessions:
            if session.pid:
                killed = self._kill_process_group(session.pid)
                if killed:
                    result["processes_killed"].append(session.pid)

            # 3. Destroy tmux sessions
            if session.tmux_session:
                destroyed = self._destroy_tmux_session(session.tmux_session)
                if destroyed:
                    result["tmux_sessions_destroyed"].append(session.tmux_session)

        # 4. Verify termination
        # VT-Spec D-01: Post-abort verification step
        time.sleep(0.5)  # Brief pause for process cleanup
        all_dead = True
        for session in engagement.sessions:
            if session.pid and self._is_process_alive(session.pid):
                # Escalate to SIGKILL
                self._force_kill(session.pid)
                if self._is_process_alive(session.pid):
                    all_dead = False
                    result["errors"].append(
                        f"Process {session.pid} still alive after SIGKILL"
                    )

        result["verified"] = all_dead
        return result

    def _kill_process_group(self, pid: int) -> bool:
        """Kill a process group with SIGTERM.

        # VT-Spec D-01: SIGTERM followed by SIGKILL with timeout
        """
        try:
            # Send SIGTERM to entire process group
            os.killpg(os.getpgid(pid), signal.SIGTERM)
            logger.info(f"Sent SIGTERM to process group of PID {pid}")
            return True
        except (ProcessLookupError, PermissionError, OSError) as e:
            logger.debug(f"Process group kill for PID {pid}: {e}")
            # Try killing just the process
            try:
                os.kill(pid, signal.SIGTERM)
                return True
            except (ProcessLookupError, PermissionError, OSError):
                return False

    def _force_kill(self, pid: int) -> bool:
        """Force kill with SIGKILL after SIGTERM timeout."""
        try:
            os.killpg(os.getpgid(pid), signal.SIGKILL)
            return True
        except (ProcessLookupError, PermissionError, OSError):
            try:
                os.kill(pid, signal.SIGKILL)
                return True
            except (ProcessLookupError, PermissionError, OSError):
                return False

    def _destroy_tmux_session(self, session_name: str) -> bool:
        """Destroy a tmux session.

        # VT-Spec D-01: tmux session discovery and kill
        """
        try:
            subprocess.run(
                ["tmux", "kill-session", "-t", session_name],
                capture_output=True,
                timeout=5,
            )
            logger.info(f"Destroyed tmux session: {session_name}")
            return True
        except (subprocess.SubprocessError, FileNotFoundError) as e:
            logger.debug(f"tmux session destroy failed: {e}")
            return False

    def _is_process_alive(self, pid: int) -> bool:
        """Check if a process is still running."""
        try:
            os.kill(pid, 0)  # Signal 0 just checks existence
            return True
        except (ProcessLookupError, PermissionError, OSError):
            return False

    def generate_partial_report(self, engagement: Engagement) -> dict:
        """Generate a partial report for an aborted engagement."""
        return {
            "engagement_id": engagement.id,
            "status": "aborted",
            "phase_at_abort": engagement.phase.value,
            "targets": [t.model_dump(mode="json") for t in engagement.targets],
            "aborted_at": datetime.now(timezone.utc).isoformat(),
            "abort_reason": engagement.abort_reason or "Kill switch activated",
            "note": "Partial report — engagement was aborted before completion",
        }
