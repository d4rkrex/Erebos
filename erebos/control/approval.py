"""Approval gates for Erebos control plane (REQ-004).

Human-in-the-loop approval for high-impact actions.

# VT-Spec T-03: Atomic file operations with exclusive locks
# VT-Spec E-02: Approval enforcement at execution layer
"""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import logging
import os
import tempfile
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import List, Optional

from pydantic import BaseModel, Field
from ulid import ULID

logger = logging.getLogger(__name__)


class ApprovalStatus(str, Enum):
    """Status of an approval request."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    TIMEOUT = "timeout"


class ApprovalRequest(BaseModel):
    """A request for human approval of an action."""

    id: str = Field(default_factory=lambda: str(ULID()))
    action_id: str
    engagement_id: str
    summary: str
    risk_level: str = "medium"
    requested_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    timeout_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc) + timedelta(minutes=30)
    )
    status: ApprovalStatus = ApprovalStatus.PENDING
    decided_at: Optional[datetime] = None
    decided_by: Optional[str] = None
    rejection_reason: Optional[str] = None


class ApprovalGate:
    """Manages approval workflow for high-impact actions.

    # VT-Spec T-03: Atomic file operations with exclusive locks
    # VT-Spec E-02: Enforcement at execution layer, not just function call
    """

    def __init__(self, queue_dir: Path, hmac_secret: str):
        if not hmac_secret or not hmac_secret.strip():
            raise ValueError("HMAC secret required for approval gate integrity")
        self._queue_dir = queue_dir
        self._hmac_secret = hmac_secret
        self._queue_dir.mkdir(parents=True, exist_ok=True)

    def _compute_signature(self, request: ApprovalRequest) -> str:
        """Compute HMAC signature for an approval request.

        # VT-Spec T-03: HMAC signature tied to request ID
        """
        content = f"{request.id}|{request.action_id}|{request.engagement_id}|{request.status.value}"
        return hmac.new(
            self._hmac_secret.encode(), content.encode(), hashlib.sha256
        ).hexdigest()

    def _request_path(self, request_id: str) -> Path:
        """Get file path for a request."""
        return self._queue_dir / f"{request_id}.json"

    def _write_atomic(self, path: Path, data: dict) -> None:
        """Write data atomically with fsync and rename.

        # VT-Spec T-03: Atomic file writes (write to .tmp, fsync, rename)
        """
        tmp_path = path.with_suffix(".tmp")
        content = json.dumps(data, default=str)

        # VT-Spec T-03: Open with exclusive creation for new files
        fd = os.open(
            str(tmp_path),
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
            0o600,
        )
        try:
            os.write(fd, content.encode())
            os.fsync(fd)
        finally:
            os.close(fd)

        # Atomic rename
        os.rename(str(tmp_path), str(path))

    def _read_request(self, path: Path) -> Optional[dict]:
        """Read request file with shared lock."""
        if not path.exists():
            return None
        with open(path, "r") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_SH)
            try:
                return json.load(f)
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)

    def request_approval(self, request: ApprovalRequest) -> ApprovalRequest:
        """Submit an action for approval.

        # VT-Spec T-03: Atomic file operations
        """
        signature = self._compute_signature(request)
        data = request.model_dump(mode="json")
        data["_signature"] = signature

        self._write_atomic(self._request_path(request.id), data)
        logger.info(f"Approval requested: {request.id} for action {request.action_id}")
        return request

    def approve(self, request_id: str, approved_by: str = "operator") -> ApprovalRequest:
        """Approve a pending request."""
        path = self._request_path(request_id)
        data = self._read_request(path)
        if data is None:
            raise ValueError(f"Approval request not found: {request_id}")

        data.pop("_signature", None)
        request = ApprovalRequest(**data)

        if request.status != ApprovalStatus.PENDING:
            raise ValueError(
                f"Request {request_id} is not pending (status: {request.status.value})"
            )

        request.status = ApprovalStatus.APPROVED
        request.decided_at = datetime.now(timezone.utc)
        request.decided_by = approved_by

        # Re-sign with new status
        signature = self._compute_signature(request)
        updated_data = request.model_dump(mode="json")
        updated_data["_signature"] = signature

        self._write_atomic(path, updated_data)
        logger.info(f"Approval granted: {request_id} by {approved_by}")
        return request

    def reject(
        self, request_id: str, reason: str = "", rejected_by: str = "operator"
    ) -> ApprovalRequest:
        """Reject a pending request."""
        path = self._request_path(request_id)
        data = self._read_request(path)
        if data is None:
            raise ValueError(f"Approval request not found: {request_id}")

        data.pop("_signature", None)
        request = ApprovalRequest(**data)

        if request.status != ApprovalStatus.PENDING:
            raise ValueError(
                f"Request {request_id} is not pending (status: {request.status.value})"
            )

        request.status = ApprovalStatus.REJECTED
        request.decided_at = datetime.now(timezone.utc)
        request.decided_by = rejected_by
        request.rejection_reason = reason

        signature = self._compute_signature(request)
        updated_data = request.model_dump(mode="json")
        updated_data["_signature"] = signature

        self._write_atomic(path, updated_data)
        logger.info(f"Approval rejected: {request_id} by {rejected_by} - {reason}")
        return request

    def check_timeout(self, request_id: str) -> ApprovalRequest:
        """Check if a pending request has timed out."""
        path = self._request_path(request_id)
        data = self._read_request(path)
        if data is None:
            raise ValueError(f"Approval request not found: {request_id}")

        data.pop("_signature", None)
        request = ApprovalRequest(**data)

        if request.status != ApprovalStatus.PENDING:
            return request

        now = datetime.now(timezone.utc)
        if now >= request.timeout_at:
            request.status = ApprovalStatus.TIMEOUT
            request.decided_at = now
            signature = self._compute_signature(request)
            updated_data = request.model_dump(mode="json")
            updated_data["_signature"] = signature
            self._write_atomic(path, updated_data)
            logger.warning(f"Approval request timed out: {request_id}")

        return request

    def list_pending(self, engagement_id: Optional[str] = None) -> List[ApprovalRequest]:
        """List all pending approval requests."""
        pending = []
        for path in self._queue_dir.glob("*.json"):
            data = self._read_request(path)
            if data is None:
                continue
            data.pop("_signature", None)
            request = ApprovalRequest(**data)
            if request.status == ApprovalStatus.PENDING:
                if engagement_id is None or request.engagement_id == engagement_id:
                    pending.append(request)
        return pending

    def verify_approval(self, request_id: str) -> bool:
        """Verify approval signature integrity at execution time.

        # VT-Spec E-02: Enforcement at execution dispatcher
        # VT-Spec T-03: Verify HMAC signature at execution time
        """
        path = self._request_path(request_id)
        data = self._read_request(path)
        if data is None:
            return False

        stored_signature = data.pop("_signature", None)
        if not stored_signature:
            return False

        request = ApprovalRequest(**data)

        # Must be approved
        if request.status != ApprovalStatus.APPROVED:
            return False

        # Verify HMAC signature
        expected_signature = self._compute_signature(request)
        return hmac.compare_digest(stored_signature, expected_signature)
