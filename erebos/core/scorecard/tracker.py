"""ModelScorecard — tracks LLM decision reliability per (model, CWE) pair.

Persistence: JSON file at `{storage_dir}/scorecard.json`.
Thread-safe via file locking on write.

Wilson CI formula: determines when a model's miss-rate for a specific
decision class is low enough to trust for short-circuit decisions.
"""

from __future__ import annotations

import fcntl
import json
import logging
import math
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class DecisionEvent:
    """A single decision event to record."""

    model: str
    cwe_class: str  # e.g., "CWE-89" or "generic"
    decision: str  # "true_positive" | "false_positive" | "uncertain"
    correct: bool  # Whether the decision matched ground truth
    timestamp: Optional[str] = None
    reasoning: Optional[str] = None


@dataclass
class ScorecardEntry:
    """Per-(model, cwe) reliability cell."""

    model: str
    cwe_class: str
    correct: int = 0
    incorrect: int = 0
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None

    @property
    def total(self) -> int:
        return self.correct + self.incorrect

    @property
    def accuracy(self) -> float:
        """Raw accuracy."""
        if self.total == 0:
            return 0.0
        return self.correct / self.total

    @property
    def miss_rate(self) -> float:
        """Miss rate (1 - accuracy)."""
        return 1.0 - self.accuracy

    def wilson_upper_bound(self, confidence: float = 0.95) -> float:
        """Wilson score interval upper bound on miss rate.

        Returns the upper bound of the confidence interval for the
        proportion of incorrect decisions. When this falls below the
        threshold (e.g., 0.05), the model is "trusted" for this class.
        """
        n = self.total
        if n == 0:
            return 1.0

        # z-score for confidence level
        z = 1.96 if confidence == 0.95 else 1.645  # 95% or 90%
        p_hat = self.incorrect / n  # Observed miss rate

        # Wilson interval upper bound
        numerator = (
            p_hat + (z * z) / (2 * n) + z * math.sqrt((p_hat * (1 - p_hat) + (z * z) / (4 * n)) / n)
        )
        denominator = 1 + (z * z) / n

        return numerator / denominator

    def is_trusted(self, max_miss_rate: float = 0.05, min_samples: int = 20) -> bool:
        """Whether this (model, cwe) cell is trusted for short-circuit.

        Trusted when:
        1. At least min_samples decisions recorded
        2. Wilson 95% upper bound on miss-rate ≤ max_miss_rate
        """
        if self.total < min_samples:
            return False
        return self.wilson_upper_bound() <= max_miss_rate


class ModelScorecard:
    """Persistent scorecard tracking LLM reliability per decision class.

    Thread-safe file operations with flock.
    """

    def __init__(self, storage_path: Optional[Path] = None):
        """Initialize scorecard.

        Args:
            storage_path: Path to scorecard JSON file.
                          Defaults to ./erebos-storage/scorecard.json
        """
        if storage_path is None:
            storage_path = Path("./erebos-storage/scorecard.json")
        self._path = storage_path
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, event: DecisionEvent) -> ScorecardEntry:
        """Record a decision event and return the updated entry."""
        now = datetime.now(timezone.utc).isoformat()
        if not event.timestamp:
            event.timestamp = now

        data = self._load()
        key = f"{event.model}:{event.cwe_class}"

        if key not in data:
            data[key] = {
                "model": event.model,
                "cwe_class": event.cwe_class,
                "correct": 0,
                "incorrect": 0,
                "first_seen": now,
                "last_seen": now,
            }

        entry_data = data[key]
        if event.correct:
            entry_data["correct"] += 1
        else:
            entry_data["incorrect"] += 1
        entry_data["last_seen"] = now

        self._save(data)

        return ScorecardEntry(
            model=entry_data["model"],
            cwe_class=entry_data["cwe_class"],
            correct=entry_data["correct"],
            incorrect=entry_data["incorrect"],
            first_seen=entry_data["first_seen"],
            last_seen=entry_data["last_seen"],
        )

    def get_entry(self, model: str, cwe_class: str) -> Optional[ScorecardEntry]:
        """Get scorecard entry for a specific (model, cwe) pair."""
        data = self._load()
        key = f"{model}:{cwe_class}"
        if key not in data:
            return None
        d = data[key]
        return ScorecardEntry(
            model=d["model"],
            cwe_class=d["cwe_class"],
            correct=d["correct"],
            incorrect=d["incorrect"],
            first_seen=d.get("first_seen"),
            last_seen=d.get("last_seen"),
        )

    def should_short_circuit(
        self,
        model: str,
        cwe_class: str,
        max_miss_rate: float = 0.05,
        min_samples: int = 20,
    ) -> bool:
        """Check if a model is trusted enough to short-circuit for a CWE class."""
        entry = self.get_entry(model, cwe_class)
        if entry is None:
            return False
        return entry.is_trusted(max_miss_rate=max_miss_rate, min_samples=min_samples)

    def get_all_entries(self) -> List[ScorecardEntry]:
        """Get all scorecard entries."""
        data = self._load()
        entries = []
        for d in data.values():
            entries.append(
                ScorecardEntry(
                    model=d["model"],
                    cwe_class=d["cwe_class"],
                    correct=d["correct"],
                    incorrect=d["incorrect"],
                    first_seen=d.get("first_seen"),
                    last_seen=d.get("last_seen"),
                )
            )
        return entries

    def get_model_summary(self, model: str) -> Dict[str, Any]:
        """Get summary statistics for a specific model."""
        entries = [e for e in self.get_all_entries() if e.model == model]
        if not entries:
            return {"model": model, "total_decisions": 0, "classes": 0}

        total_correct = sum(e.correct for e in entries)
        total_incorrect = sum(e.incorrect for e in entries)
        total = total_correct + total_incorrect
        trusted = [e for e in entries if e.is_trusted()]

        return {
            "model": model,
            "total_decisions": total,
            "accuracy": total_correct / total if total > 0 else 0.0,
            "classes": len(entries),
            "trusted_classes": len(trusted),
            "entries": entries,
        }

    def _load(self) -> Dict[str, Any]:
        """Load scorecard from disk."""
        if not self._path.exists():
            return {}
        try:
            with open(self._path, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"Failed to load scorecard: {e}")
            return {}

    def _save(self, data: Dict[str, Any]) -> None:
        """Save scorecard to disk with file locking."""
        try:
            with open(self._path, "w") as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                try:
                    json.dump(data, f, indent=2)
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        except OSError as e:
            logger.error(f"Failed to save scorecard: {e}")
