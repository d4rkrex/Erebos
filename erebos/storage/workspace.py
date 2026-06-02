"""Workspace management with named workspaces and intelligent resume.

Provides workspace lifecycle (create, load, resume, list) with:
- Named workspaces via -w flag or auto-generated names
- Intelligent resume that skips completed phases/tools
- Append-only audit trail for non-repudiation
- Atomic session persistence (write-temp + rename)

VT-Spec SPOOF-001: Workspace names include UUID suffix for unpredictability.
VT-Spec INFO-001: Sensitive files written with 0o600 permissions.
VT-Spec REPU-001: All actions logged to append-only audit trail.
"""

import json
import logging
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from uuid import uuid4

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class AuditEntry(BaseModel):
    """Single entry in the workspace audit log.

    VT-Spec REPU-001: Provides non-repudiation via structured logging.
    """

    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    event_type: str  # phase_start, phase_end, tool_start, tool_end, error, resume, abort
    phase: Optional[str] = None
    tool: Optional[str] = None
    message: str

    def to_log_line(self) -> str:
        """Format as append-only log line."""
        parts = [self.timestamp.isoformat(), self.event_type]
        if self.phase:
            parts.append(self.phase)
        if self.tool:
            parts.append(self.tool)
        parts.append(self.message)
        return " | ".join(parts)


class WorkspaceSession(BaseModel):
    """Workspace session metadata with completion tracking."""

    name: str
    target: str
    scan_id: str = Field(default_factory=lambda: str(uuid4()))
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_phases: List[str] = Field(default_factory=list)
    completed_tools: Dict[str, List[str]] = Field(default_factory=dict)
    status: str = "active"  # active | paused | complete | aborted


class WorkspaceManager:
    """Manages workspace lifecycle with security controls.

    VT-Spec SPOOF-001: Names include random suffix to prevent prediction.
    VT-Spec INFO-001: Files written with restricted permissions.
    VT-Spec REPU-001: All significant actions logged to audit trail.
    """

    SESSION_FILE = "session.json"
    AUDIT_FILE = "audit.log"
    FINDINGS_FILE = "findings.json"
    QUEUE_FILE = "exploitation-queue.json"

    def __init__(self, base_dir: Path):
        self._base_dir = base_dir
        self._base_dir.mkdir(parents=True, exist_ok=True)

    @property
    def base_dir(self) -> Path:
        return self._base_dir

    def create(self, name: Optional[str], target: str) -> WorkspaceSession:
        """Create a new workspace.

        VT-Spec SPOOF-001: Auto-generated names include UUID suffix.
        """
        if name is None:
            # Auto-generate: target_timestamp_shortuuid
            safe_target = target.replace("://", "_").replace("/", "_").replace(".", "_")
            ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            suffix = uuid4().hex[:8]
            name = f"{safe_target}_{ts}_{suffix}"
        else:
            # VT-Spec SPOOF-001: Even user-named workspaces get a short random suffix
            # to prevent workspace name prediction attacks
            suffix = uuid4().hex[:6]
            name = f"{name}_{suffix}"

        workspace_dir = self._base_dir / name
        if workspace_dir.exists():
            raise ValueError(f"Workspace already exists: {name}")

        workspace_dir.mkdir(parents=True)
        # VT-Spec INFO-001: Restrict directory access
        workspace_dir.chmod(0o700)

        session = WorkspaceSession(name=name, target=target)
        self._save_session(session)
        self._log_audit(
            name,
            AuditEntry(event_type="workspace_create", message=f"Created workspace for {target}"),
        )
        return session

    def load(self, name: str) -> WorkspaceSession:
        """Load an existing workspace session."""
        session_path = self._session_path(name)
        if not session_path.exists():
            raise FileNotFoundError(f"Workspace not found: {name}")
        data = json.loads(session_path.read_text())
        return WorkspaceSession.model_validate(data)

    def find_by_prefix(self, prefix: str) -> Optional[str]:
        """Find workspace by name prefix (user may omit the random suffix)."""
        if not self._base_dir.exists():
            return None
        for entry in sorted(self._base_dir.iterdir()):
            if entry.is_dir() and entry.name.startswith(prefix):
                session_path = entry / self.SESSION_FILE
                if session_path.exists():
                    return entry.name
        return None

    def can_resume(self, name: str) -> Tuple[bool, List[str]]:
        """Check if workspace can be resumed, validating deliverables.

        VT-Spec SC-06: Validates that previously completed deliverables
        still exist on disk; if missing, marks phase as incomplete.

        Returns:
            Tuple of (can_resume, list_of_invalidated_phases).
        """
        try:
            session = self.load(name)
        except FileNotFoundError:
            return False, []

        if session.status in ("complete", "aborted"):
            return False, []

        invalidated: List[str] = []
        workspace_dir = self._base_dir / name

        # Validate that findings exist if any phase beyond recon is "complete"
        for phase in list(session.completed_phases):
            # Check phase-specific deliverables
            if phase in ("recon", "discovery", "vuln-scan"):
                findings_path = workspace_dir / self.FINDINGS_FILE
                if not findings_path.exists():
                    invalidated.append(phase)
                    session.completed_phases.remove(phase)

        if invalidated:
            self._save_session(session)
            self._log_audit(
                name,
                AuditEntry(
                    event_type="resume_invalidation",
                    message=f"Invalidated phases (missing deliverables): {invalidated}",
                ),
            )

        return True, invalidated

    def mark_phase_complete(self, name: str, phase: str) -> None:
        """Mark a phase as completed in the workspace session."""
        session = self.load(name)
        if phase not in session.completed_phases:
            session.completed_phases.append(phase)
        session.updated_at = datetime.now(timezone.utc)
        self._save_session(session)
        self._log_audit(
            name,
            AuditEntry(
                event_type="phase_end",
                phase=phase,
                message=f"Phase {phase} completed",
            ),
        )

    def mark_tool_complete(self, name: str, phase: str, tool: str) -> None:
        """Mark a specific tool as completed within a phase."""
        session = self.load(name)
        if phase not in session.completed_tools:
            session.completed_tools[phase] = []
        if tool not in session.completed_tools[phase]:
            session.completed_tools[phase].append(tool)
        session.updated_at = datetime.now(timezone.utc)
        self._save_session(session)

    def set_status(self, name: str, status: str) -> None:
        """Update workspace status."""
        session = self.load(name)
        session.status = status
        session.updated_at = datetime.now(timezone.utc)
        self._save_session(session)
        self._log_audit(
            name,
            AuditEntry(event_type="status_change", message=f"Status → {status}"),
        )

    def list_all(self) -> List[WorkspaceSession]:
        """List all workspaces with their session data."""
        sessions: List[WorkspaceSession] = []
        if not self._base_dir.exists():
            return sessions
        for entry in sorted(self._base_dir.iterdir()):
            if entry.is_dir():
                session_path = entry / self.SESSION_FILE
                if session_path.exists():
                    try:
                        data = json.loads(session_path.read_text())
                        sessions.append(WorkspaceSession.model_validate(data))
                    except (json.JSONDecodeError, Exception) as e:
                        logger.warning(f"Skipping corrupt workspace {entry.name}: {e}")
        return sessions

    def workspace_dir(self, name: str) -> Path:
        """Get the directory path for a workspace."""
        return self._base_dir / name

    def log_event(self, name: str, entry: AuditEntry) -> None:
        """Log an event to the workspace audit trail."""
        self._log_audit(name, entry)

    def _session_path(self, name: str) -> Path:
        return self._base_dir / name / self.SESSION_FILE

    def _save_session(self, session: WorkspaceSession) -> None:
        """Atomically save session (write-to-temp + rename).

        VT-Spec INFO-001: Session file written with 0o600 permissions.
        """
        session_path = self._session_path(session.name)
        session_path.parent.mkdir(parents=True, exist_ok=True)

        data = session.model_dump(mode="json")
        # Atomic write: temp file + rename
        fd, tmp_path = tempfile.mkstemp(
            dir=str(session_path.parent), suffix=".tmp"
        )
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(data, f, indent=2)
            os.chmod(tmp_path, 0o600)
            os.rename(tmp_path, str(session_path))
        except Exception:
            # Cleanup temp file on error
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            raise

    def _log_audit(self, name: str, entry: AuditEntry) -> None:
        """Append entry to audit log (append-only, no read-modify-write).

        VT-Spec REPU-001: Non-repudiable audit trail.
        VT-Spec INFO-001: Audit file has restricted permissions.
        """
        audit_path = self._base_dir / name / self.AUDIT_FILE
        audit_path.parent.mkdir(parents=True, exist_ok=True)

        line = entry.to_log_line() + "\n"
        # Append-only pattern — safe for concurrent access
        with open(audit_path, "a") as f:
            f.write(line)

        # Ensure restricted permissions on first write
        if audit_path.stat().st_size == len(line.encode()):
            audit_path.chmod(0o600)
