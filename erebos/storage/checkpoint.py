"""Checkpoint integrity for Erebos engagement state (REQ-001).

HMAC-signed checkpoint files for safe engagement resume.

# VT-Spec R-001 MEDIUM: Sign checkpoint files with HMAC
# VT-Spec R-001: Verify signature before state restore
# VT-Spec R-001: Re-validate RoE scope on resume
# VT-Spec R-001: Log resume events with checkpoint hash
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class CheckpointIntegrityError(Exception):
    """Raised when checkpoint integrity verification fails."""

    pass


class CheckpointManager:
    """Manages HMAC-signed engagement checkpoints.

    # VT-Spec R-001 MEDIUM: Sign checkpoint files with HMAC (same pattern as ApprovalGate)
    # VT-Spec R-001: Verify signature before state restore
    """

    def __init__(self, checkpoint_dir: Path, hmac_secret: str):
        """Initialize checkpoint manager.

        Args:
            checkpoint_dir: Directory for checkpoint files.
            hmac_secret: HMAC secret for signing (must not be empty).

        Raises:
            ValueError: If hmac_secret is empty.
        """
        # VT-Spec R-001: Require non-empty HMAC secret
        if not hmac_secret or not hmac_secret.strip():
            raise ValueError(
                "VT-Spec R-001: HMAC secret required for checkpoint integrity"
            )
        self._checkpoint_dir = checkpoint_dir
        self._hmac_secret = hmac_secret
        self._checkpoint_dir.mkdir(parents=True, exist_ok=True)

    def _compute_hmac(self, data: bytes) -> str:
        """Compute HMAC-SHA256 for checkpoint data."""
        return hmac.new(
            self._hmac_secret.encode(),
            data,
            hashlib.sha256,
        ).hexdigest()

    def _checkpoint_path(self, engagement_id: str) -> Path:
        """Get path for engagement checkpoint file."""
        # Sanitize engagement_id to prevent path traversal
        safe_id = "".join(c for c in engagement_id if c.isalnum() or c in "-_")
        return self._checkpoint_dir / f"{safe_id}.checkpoint.json"

    def save_checkpoint(
        self,
        engagement_id: str,
        state: Dict[str, Any],
    ) -> Path:
        """Save HMAC-signed checkpoint.

        # VT-Spec R-001: Sign checkpoint files with HMAC.

        Args:
            engagement_id: Engagement identifier.
            state: State data to checkpoint.

        Returns:
            Path to saved checkpoint file.
        """
        checkpoint_data = {
            "engagement_id": engagement_id,
            "timestamp": time.time(),
            "state": state,
        }

        # Serialize state (deterministic JSON)
        payload = json.dumps(checkpoint_data, sort_keys=True, default=str).encode()

        # VT-Spec R-001: Compute content hash
        content_hash = hashlib.sha256(payload).hexdigest()

        # VT-Spec R-001: Compute HMAC signature
        signature = self._compute_hmac(payload)

        # Write checkpoint with signature
        signed_checkpoint = {
            "data": checkpoint_data,
            "content_hash": content_hash,
            "hmac_signature": signature,
        }

        filepath = self._checkpoint_path(engagement_id)
        filepath.write_text(
            json.dumps(signed_checkpoint, indent=2, default=str),
            encoding="utf-8",
        )

        logger.info(
            "VT-Spec R-001: Checkpoint saved",
            extra={
                "engagement_id": engagement_id,
                "content_hash": content_hash,
                "path": str(filepath),
            },
        )

        return filepath

    def load_checkpoint(self, engagement_id: str) -> Dict[str, Any]:
        """Load and verify checkpoint.

        # VT-Spec R-001: Verify signature before state restore.

        Args:
            engagement_id: Engagement identifier.

        Returns:
            Verified checkpoint state data.

        Raises:
            CheckpointIntegrityError: If signature verification fails.
            FileNotFoundError: If checkpoint doesn't exist.
        """
        filepath = self._checkpoint_path(engagement_id)
        if not filepath.exists():
            raise FileNotFoundError(
                f"No checkpoint found for engagement: {engagement_id}"
            )

        # Load signed checkpoint
        raw = filepath.read_text(encoding="utf-8")
        signed_checkpoint = json.loads(raw)

        # Extract components
        checkpoint_data = signed_checkpoint.get("data")
        stored_hash = signed_checkpoint.get("content_hash")
        stored_signature = signed_checkpoint.get("hmac_signature")

        if not checkpoint_data or not stored_hash or not stored_signature:
            raise CheckpointIntegrityError(
                "VT-Spec R-001: Checkpoint file missing required integrity fields"
            )

        # VT-Spec R-001: Recompute and verify content hash
        payload = json.dumps(checkpoint_data, sort_keys=True, default=str).encode()
        computed_hash = hashlib.sha256(payload).hexdigest()

        if not hmac.compare_digest(stored_hash, computed_hash):
            raise CheckpointIntegrityError(
                "VT-Spec R-001: Checkpoint content hash mismatch — data may be tampered"
            )

        # VT-Spec R-001: Verify HMAC signature
        computed_signature = self._compute_hmac(payload)
        if not hmac.compare_digest(stored_signature, computed_signature):
            raise CheckpointIntegrityError(
                "VT-Spec R-001: Checkpoint HMAC verification failed — data tampered or wrong key"
            )

        logger.info(
            "VT-Spec R-001: Checkpoint integrity verified",
            extra={
                "engagement_id": engagement_id,
                "content_hash": computed_hash,
            },
        )

        return checkpoint_data.get("state", {})

    def checkpoint_exists(self, engagement_id: str) -> bool:
        """Check if a checkpoint exists for an engagement."""
        return self._checkpoint_path(engagement_id).exists()

    def delete_checkpoint(self, engagement_id: str) -> None:
        """Delete checkpoint file after successful completion."""
        filepath = self._checkpoint_path(engagement_id)
        if filepath.exists():
            filepath.unlink()
            logger.info(f"Checkpoint deleted: {engagement_id}")
