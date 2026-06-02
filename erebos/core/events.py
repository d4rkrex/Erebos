"""Event sourcing for Erebos control plane (REQ-002).

Append-only event log with hash chain integrity and HMAC signing.
"""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import logging
import os
import tempfile
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field
from ulid import ULID

logger = logging.getLogger(__name__)


class EventType(str, Enum):
    """Types of events in the control plane."""

    ENGAGEMENT_CREATED = "engagement_created"
    ENGAGEMENT_STARTED = "engagement_started"
    PHASE_CHANGED = "phase_changed"
    ACTION_PLANNED = "action_planned"
    POLICY_EVALUATED = "policy_evaluated"
    ACTION_APPROVED = "action_approved"
    ACTION_REJECTED = "action_rejected"
    ACTION_EXECUTED = "action_executed"
    OBSERVATION_ADDED = "observation_added"
    KILL_SWITCH_ACTIVATED = "kill_switch_activated"
    ENGAGEMENT_COMPLETED = "engagement_completed"
    ENGAGEMENT_ABORTED = "engagement_aborted"
    APPROVAL_REQUESTED = "approval_requested"
    APPROVAL_TIMEOUT = "approval_timeout"


class Event(BaseModel):
    """An immutable event in the engagement event log."""

    id: str = Field(default_factory=lambda: str(ULID()))
    engagement_id: str
    event_type: EventType
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    data: Dict[str, Any] = Field(default_factory=dict)
    actor: str = "system"
    previous_hash: str = ""
    hash: str = ""

    def compute_hash(self) -> str:
        """Compute SHA-256 hash of event content."""
        content = (
            f"{self.id}|{self.engagement_id}|{self.event_type.value}|"
            f"{self.timestamp.isoformat()}|{json.dumps(self.data, sort_keys=True, default=str)}|"
            f"{self.actor}|{self.previous_hash}"
        )
        return hashlib.sha256(content.encode()).hexdigest()

    def compute_hmac(self, secret: str) -> str:
        """Compute HMAC-SHA256 signature for this event.

        # VT-Spec R-01: Mandatory HMAC signing for all events
        """
        content = f"{self.hash}|{self.id}"
        return hmac.new(
            secret.encode(), content.encode(), hashlib.sha256
        ).hexdigest()


class EventLog:
    """Append-only event log with hash chain integrity.

    # VT-Spec T-01: File locking on all append operations
    # VT-Spec T-02: HMAC secret must not be empty
    # VT-Spec R-01: Mandatory HMAC signing
    """

    def __init__(self, log_path: Path, hmac_secret: str):
        # VT-Spec T-02: Reject empty/whitespace HMAC secrets
        if not hmac_secret or not hmac_secret.strip():
            raise ValueError(
                "HMAC secret must not be empty or whitespace. "
                "Configure a strong secret before starting engagement."
            )
        self._log_path = log_path
        # VT-Spec I-01: Mask HMAC secret in all log output
        self._hmac_secret = hmac_secret
        self._last_hash = ""
        # Load existing chain hash if log exists
        if log_path.exists():
            self._last_hash = self._load_last_hash()

    @property
    def log_path(self) -> Path:
        return self._log_path

    def _load_last_hash(self) -> str:
        """Load the last hash from existing log file."""
        last_hash = ""
        if not self._log_path.exists():
            return last_hash
        # VT-Spec T-01: File locking for reads
        with open(self._log_path, "r") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_SH)
            try:
                for line in f:
                    line = line.strip()
                    if line:
                        event_data = json.loads(line)
                        last_hash = event_data.get("hash", "")
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        return last_hash

    def append(self, event: Event) -> Event:
        """Append an event to the log with hash chain integrity.

        # VT-Spec T-01: fcntl.flock on event log file operations
        # VT-Spec R-01: Mandatory HMAC signing for all events
        """
        # Set hash chain
        event.previous_hash = self._last_hash
        event.hash = event.compute_hash()

        # Compute HMAC signature
        event_hmac = hmac.new(
            self._hmac_secret.encode(),
            f"{event.hash}|{event.id}".encode(),
            hashlib.sha256,
        ).hexdigest()

        # Serialize event with HMAC
        event_dict = event.model_dump(mode="json")
        event_dict["_hmac"] = event_hmac

        line = json.dumps(event_dict, default=str) + "\n"

        # VT-Spec T-01: Atomic write with file locking
        # Write to temp file, fsync, then append under lock
        self._log_path.parent.mkdir(parents=True, exist_ok=True)

        with open(self._log_path, "a") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                f.write(line)
                f.flush()
                os.fsync(f.fileno())
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)

        self._last_hash = event.hash
        return event

    def read_all(self) -> List[Event]:
        """Read all events from the log."""
        if not self._log_path.exists():
            return []

        events = []
        # VT-Spec T-01: Shared lock for reads
        with open(self._log_path, "r") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_SH)
            try:
                for line in f:
                    line = line.strip()
                    if line:
                        data = json.loads(line)
                        # Remove HMAC before constructing Event
                        data.pop("_hmac", None)
                        events.append(Event(**data))
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        return events

    def verify_integrity(self) -> bool:
        """Verify hash chain and HMAC integrity of the log.

        # VT-Spec T-01: Verify hash chain under lock
        """
        if not self._log_path.exists():
            return True

        previous_hash = ""
        with open(self._log_path, "r") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_SH)
            try:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    data = json.loads(line)
                    stored_hmac = data.pop("_hmac", None)

                    event = Event(**data)

                    # Verify hash chain
                    if event.previous_hash != previous_hash:
                        logger.error(
                            f"Hash chain broken at line {line_num}: "
                            f"expected previous_hash={previous_hash!r}, "
                            f"got {event.previous_hash!r}"
                        )
                        return False

                    # Verify event hash
                    computed_hash = event.compute_hash()
                    if event.hash != computed_hash:
                        logger.error(
                            f"Event hash mismatch at line {line_num}: "
                            f"stored={event.hash!r}, computed={computed_hash!r}"
                        )
                        return False

                    # Verify HMAC if present
                    if stored_hmac:
                        expected_hmac = hmac.new(
                            self._hmac_secret.encode(),
                            f"{event.hash}|{event.id}".encode(),
                            hashlib.sha256,
                        ).hexdigest()
                        if not hmac.compare_digest(stored_hmac, expected_hmac):
                            logger.error(f"HMAC verification failed at line {line_num}")
                            return False

                    previous_hash = event.hash
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)

        return True

    def query(
        self,
        engagement_id: Optional[str] = None,
        event_type: Optional[EventType] = None,
    ) -> List[Event]:
        """Query events with optional filters."""
        events = self.read_all()
        if engagement_id:
            events = [e for e in events if e.engagement_id == engagement_id]
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        return events
