"""Artifact Store for Erebos (REQ-006).

Persists engagement artifacts with integrity verification.

# VT-Spec T-SKG-04 MEDIUM: Atomic write (tmp → hash → rename), verify on retrieve
"""

from __future__ import annotations

import hashlib
import logging
import os
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from pydantic import BaseModel, Field

from erebos.knowledge.graph import _validate_engagement_id

logger = logging.getLogger(__name__)


class ArtifactRef(BaseModel):
    """Reference to a stored artifact."""

    path: str
    sha256_hash: str
    size: int
    stored_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    engagement_id: str = ""
    phase: str = ""
    tool: str = ""
    filename: str = ""


class ArtifactIntegrityError(Exception):
    """Raised when artifact integrity check fails."""

    pass


class ArtifactStore:
    """Persists engagement artifacts with atomic writes and integrity verification.

    # VT-Spec T-SKG-04 MEDIUM: Atomic write + SHA-256 hash, verify on retrieve
    """

    def __init__(self, data_dir: Path) -> None:
        self._data_dir = data_dir
        self._data_dir.mkdir(parents=True, exist_ok=True)

    def store(
        self,
        data: bytes,
        engagement_id: str,
        phase: str,
        tool: str,
        filename: str,
    ) -> ArtifactRef:
        """Store artifact data with atomic write and integrity hash.

        # VT-Spec T-SKG-04: Write tmp → hash → rename (atomic)
        """
        # VT-Spec T-SKG-03: Validate engagement_id
        _validate_engagement_id(engagement_id)

        # Build storage path
        timestamp = int(time.time())
        artifact_dir = self._data_dir / "artifacts" / engagement_id / phase
        artifact_dir.mkdir(parents=True, exist_ok=True)

        final_filename = f"{tool}_{timestamp}_{filename}"
        final_path = artifact_dir / final_filename

        # VT-Spec T-SKG-04: Compute hash first
        sha256_hash = hashlib.sha256(data).hexdigest()

        # VT-Spec T-SKG-04: Atomic write — write to temp, then rename
        tmp_fd, tmp_path = tempfile.mkstemp(dir=str(artifact_dir), prefix=".tmp_")
        try:
            os.write(tmp_fd, data)
            os.fsync(tmp_fd)
            os.close(tmp_fd)
            os.rename(tmp_path, str(final_path))
        except Exception:
            os.close(tmp_fd) if not os.get_inheritable(tmp_fd) else None
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            raise

        ref = ArtifactRef(
            path=str(final_path),
            sha256_hash=sha256_hash,
            size=len(data),
            engagement_id=engagement_id,
            phase=phase,
            tool=tool,
            filename=filename,
        )

        logger.debug(
            "Artifact stored: %s (hash: %s, size: %d)",
            final_path,
            sha256_hash[:16],
            len(data),
        )

        return ref

    def retrieve(self, ref: ArtifactRef) -> bytes:
        """Retrieve artifact data with integrity verification.

        # VT-Spec T-SKG-04: Verify hash on retrieve
        """
        path = Path(ref.path)
        if not path.exists():
            raise FileNotFoundError(f"Artifact not found: {ref.path}")

        data = path.read_bytes()

        # VT-Spec T-SKG-04: Verify integrity on read
        actual_hash = hashlib.sha256(data).hexdigest()
        if actual_hash != ref.sha256_hash:
            raise ArtifactIntegrityError(
                f"VT-Spec T-SKG-04: Artifact integrity failed. "
                f"Expected {ref.sha256_hash}, got {actual_hash}"
            )

        return data

    def verify_integrity(self, ref: ArtifactRef) -> bool:
        """Verify artifact integrity without returning data."""
        try:
            self.retrieve(ref)
            return True
        except (FileNotFoundError, ArtifactIntegrityError):
            return False

    def list_artifacts(self, engagement_id: str) -> List[ArtifactRef]:
        """List all artifacts for an engagement."""
        _validate_engagement_id(engagement_id)

        artifact_dir = self._data_dir / "artifacts" / engagement_id
        if not artifact_dir.exists():
            return []

        refs: List[ArtifactRef] = []
        for file_path in sorted(artifact_dir.rglob("*")):
            if file_path.is_file() and not file_path.name.startswith("."):
                data = file_path.read_bytes()
                sha256_hash = hashlib.sha256(data).hexdigest()

                # Parse phase from path
                rel = file_path.relative_to(artifact_dir)
                parts = rel.parts
                phase = parts[0] if len(parts) > 1 else ""

                refs.append(
                    ArtifactRef(
                        path=str(file_path),
                        sha256_hash=sha256_hash,
                        size=len(data),
                        engagement_id=engagement_id,
                        phase=phase,
                    )
                )

        return refs
