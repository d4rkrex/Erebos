"""Observation Store for Erebos (REQ-005).

JSONL-based observation persistence with deduplication and engagement isolation.

# VT-Spec T-SKG-03 HIGH: Engagement isolation via separate files and validated IDs
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from erebos.core.models import EngagementPhase, Observation, ObservationType
from erebos.knowledge.graph import _validate_engagement_id

logger = logging.getLogger(__name__)


def _compute_content_hash(obs: Observation) -> str:
    """Compute content hash for deduplication, ignoring volatile fields."""
    stable = {
        "observation_type": obs.observation_type.value,
        "target_id": obs.target_id or "",
        "data": json.dumps(
            {k: v for k, v in sorted(obs.data.items()) if k not in ("timestamp", "nonce")},
            sort_keys=True,
        ),
    }
    content = json.dumps(stable, sort_keys=True)
    return hashlib.sha256(content.encode()).hexdigest()


class ObservationStore:
    """JSONL-based observation persistence with deduplication.

    # VT-Spec T-SKG-03: Engagement isolation (separate files, validated engagement_id)
    """

    def __init__(self, data_dir: Path) -> None:
        self._data_dir = data_dir
        self._data_dir.mkdir(parents=True, exist_ok=True)
        # In-memory hash sets per engagement for dedup
        self._hashes: Dict[str, set] = {}

    def _get_file(self, engagement_id: str) -> Path:
        """Get JSONL file path for an engagement.

        # VT-Spec T-SKG-03: Validate engagement_id
        """
        _validate_engagement_id(engagement_id)
        return self._data_dir / f"{engagement_id}.jsonl"

    def store(self, observation: Observation, engagement_id: str) -> bool:
        """Store an observation, returns False if duplicate.

        # VT-Spec T-SKG-03: Engagement isolation
        """
        _validate_engagement_id(engagement_id)

        content_hash = _compute_content_hash(observation)

        # Dedup check
        if engagement_id not in self._hashes:
            self._hashes[engagement_id] = set()
            # Load existing hashes from file
            obs_file = self._get_file(engagement_id)
            if obs_file.exists():
                for line in obs_file.read_text().splitlines():
                    if line.strip():
                        try:
                            data = json.loads(line)
                            self._hashes[engagement_id].add(data.get("_hash", ""))
                        except json.JSONDecodeError:
                            pass

        if content_hash in self._hashes[engagement_id]:
            return False

        self._hashes[engagement_id].add(content_hash)

        # Serialize and append
        record = {
            "_hash": content_hash,
            "id": observation.id,
            "engagement_id": engagement_id,
            "target_id": observation.target_id,
            "observation_type": observation.observation_type.value,
            "data": observation.data,
            "phase": observation.phase.value,
            "timestamp": observation.timestamp.isoformat(),
        }

        obs_file = self._get_file(engagement_id)
        with obs_file.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")

        return True

    def query(
        self,
        engagement_id: str,
        obs_type: Optional[str] = None,
        target: Optional[str] = None,
    ) -> List[Observation]:
        """Query observations for an engagement.

        # VT-Spec T-SKG-03: Engagement isolation
        """
        _validate_engagement_id(engagement_id)

        obs_file = self._get_file(engagement_id)
        if not obs_file.exists():
            return []

        results: List[Observation] = []
        for line in obs_file.read_text().splitlines():
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            # Filter by type
            if obs_type and record.get("observation_type") != obs_type:
                continue
            # Filter by target
            if target and record.get("target_id") != target:
                continue

            obs = Observation(
                id=record["id"],
                engagement_id=record["engagement_id"],
                target_id=record.get("target_id"),
                observation_type=ObservationType(record["observation_type"]),
                data=record.get("data", {}),
                phase=EngagementPhase(record["phase"]),
            )
            results.append(obs)

        return results

    def deduplicate(self, observations: List[Observation]) -> List[Observation]:
        """Deduplicate a list of observations by content hash."""
        seen: set = set()
        unique: List[Observation] = []
        for obs in observations:
            h = _compute_content_hash(obs)
            if h not in seen:
                seen.add(h)
                unique.append(obs)
        return unique

    def count(self, engagement_id: str) -> int:
        """Count observations for an engagement."""
        _validate_engagement_id(engagement_id)
        obs_file = self._get_file(engagement_id)
        if not obs_file.exists():
            return 0
        return sum(1 for line in obs_file.read_text().splitlines() if line.strip())
