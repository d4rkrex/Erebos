"""Project-specific learning — persists per-project FP patterns and safe constructs.

Stored in `.erebos/project-learned.json` at the project root.
Learns from validated findings: when a finding is consistently marked FP in a project,
the system learns the pattern and auto-suppresses future occurrences.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class LearnedPattern:
    """A pattern learned from project scan history."""

    pattern_id: str
    pattern_type: str  # "sanitizer" | "safe_file" | "framework_safe" | "suppressed_rule"
    description: str
    cwe_covered: List[str] = field(default_factory=list)
    file_patterns: List[str] = field(default_factory=list)  # glob patterns
    rule_ids: List[str] = field(default_factory=list)  # semgrep/nuclei rule IDs
    confidence: float = 0.5
    occurrences: int = 1
    last_seen: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def matches_finding(self, title: str, cwe: Optional[str], file_path: Optional[str]) -> bool:
        """Check if this pattern matches a finding."""
        # Rule ID match
        if self.rule_ids and any(rid in title for rid in self.rule_ids):
            return True

        # CWE match + file pattern match
        if cwe and cwe in self.cwe_covered:
            if not self.file_patterns:
                return True
            if file_path:
                from fnmatch import fnmatch

                return any(fnmatch(file_path, pat) for pat in self.file_patterns)
        return False


@dataclass
class ProjectInsight:
    """High-level insight about a project's security posture."""

    stack: str  # "express" | "django" | "spring" | etc.
    sanitizers: List[str] = field(default_factory=list)
    safe_patterns: List[str] = field(default_factory=list)
    common_fps: List[str] = field(default_factory=list)
    scan_count: int = 0
    last_scan: str = ""


class ProjectLearning:
    """Per-project learning system.

    Persists learned patterns in `.erebos/project-learned.json`.
    Patterns accumulate confidence with repeated consistent validations.
    """

    CONFIDENCE_THRESHOLD = 0.7
    MIN_OCCURRENCES = 3

    def __init__(self, project_path: Optional[Path] = None):
        """Initialize learning for a project.

        Args:
            project_path: Root of the project. Default: CWD.
        """
        self._project_path = project_path or Path.cwd()
        self._storage_path = self._project_path / ".erebos" / "project-learned.json"
        self._patterns: List[LearnedPattern] = []
        self._insight: ProjectInsight = ProjectInsight(stack="unknown")
        self._load()

    def learn_from_validation(
        self,
        title: str,
        tool: str,
        cwe: Optional[str],
        file_path: Optional[str],
        decision: str,
        reason: Optional[str] = None,
    ) -> Optional[LearnedPattern]:
        """Learn from a validation decision.

        Args:
            title: Finding title/rule_id.
            tool: Tool that produced the finding.
            cwe: CWE identifier.
            file_path: Source file path.
            decision: 'false_positive' | 'confirmed' | 'uncertain'
            reason: Why this decision was made (e.g., "sanitized by escapeHtml()")

        Returns:
            The learned pattern if threshold reached, None otherwise.
        """
        pattern_id = self._compute_pattern_id(title, tool, cwe)
        existing = self._find_pattern(pattern_id)

        now = datetime.now(timezone.utc).isoformat()

        if existing:
            existing.occurrences += 1
            existing.last_seen = now
            if decision == "false_positive":
                # Increase confidence toward FP
                existing.confidence = min(1.0, existing.confidence + 0.1)
            elif decision == "confirmed":
                # Decrease FP confidence
                existing.confidence = max(0.0, existing.confidence - 0.2)

            if reason and reason not in existing.metadata.get("reasons", []):
                existing.metadata.setdefault("reasons", []).append(reason)

            self._save()
            return existing if existing.confidence >= self.CONFIDENCE_THRESHOLD else None
        else:
            # Create new pattern
            pattern = LearnedPattern(
                pattern_id=pattern_id,
                pattern_type="suppressed_rule" if decision == "false_positive" else "observed",
                description=f"{tool}: {title}",
                cwe_covered=[cwe] if cwe else [],
                rule_ids=[title] if "/" in title or "." in title else [],
                file_patterns=[self._generalize_path(file_path)] if file_path else [],
                confidence=0.3 if decision == "false_positive" else 0.1,
                occurrences=1,
                last_seen=now,
                metadata={"tool": tool, "reasons": [reason] if reason else []},
            )
            self._patterns.append(pattern)
            self._save()
            return None  # Not yet at threshold

    def learn_sanitizer(
        self,
        name: str,
        cwes_covered: List[str],
        file_patterns: Optional[List[str]] = None,
    ) -> LearnedPattern:
        """Explicitly register a project sanitizer.

        Args:
            name: Sanitizer function name (e.g., "escapeHtml", "sanitize_input").
            cwes_covered: CWEs this sanitizer handles (e.g., ["CWE-79"]).
            file_patterns: File patterns where this sanitizer is used.
        """
        pattern_id = hashlib.sha256(f"sanitizer:{name}".encode()).hexdigest()[:16]
        existing = self._find_pattern(pattern_id)

        if existing:
            existing.cwe_covered = list(set(existing.cwe_covered + cwes_covered))
            existing.confidence = min(1.0, existing.confidence + 0.1)
            self._save()
            return existing

        pattern = LearnedPattern(
            pattern_id=pattern_id,
            pattern_type="sanitizer",
            description=f"Sanitizer: {name} covers {', '.join(cwes_covered)}",
            cwe_covered=cwes_covered,
            file_patterns=file_patterns or [],
            confidence=0.8,
            occurrences=1,
            last_seen=datetime.now(timezone.utc).isoformat(),
            metadata={"sanitizer_name": name},
        )
        self._patterns.append(pattern)
        self._save()
        return pattern

    def should_suppress(
        self, title: str, cwe: Optional[str], file_path: Optional[str]
    ) -> Tuple[bool, Optional[LearnedPattern]]:
        """Check if a finding should be suppressed based on learned patterns.

        Returns:
            (should_suppress, matching_pattern)
        """
        for pattern in self._patterns:
            if (
                pattern.confidence >= self.CONFIDENCE_THRESHOLD
                and pattern.occurrences >= self.MIN_OCCURRENCES
                and pattern.matches_finding(title, cwe, file_path)
            ):
                return True, pattern
        return False, None

    def get_patterns(self, pattern_type: Optional[str] = None) -> List[LearnedPattern]:
        """Get all learned patterns, optionally filtered by type."""
        if pattern_type:
            return [p for p in self._patterns if p.pattern_type == pattern_type]
        return list(self._patterns)

    def get_insight(self) -> ProjectInsight:
        """Get high-level project insight."""
        return self._insight

    def update_insight(self, stack: Optional[str] = None, **kwargs: Any) -> None:
        """Update project insight."""
        if stack:
            self._insight.stack = stack
        for key, value in kwargs.items():
            if hasattr(self._insight, key):
                setattr(self._insight, key, value)
        self._insight.scan_count += 1
        self._insight.last_scan = datetime.now(timezone.utc).isoformat()
        self._save()

    def prune_low_confidence(self, min_confidence: float = 0.3) -> int:
        """Remove patterns below confidence threshold. Returns count removed."""
        before = len(self._patterns)
        self._patterns = [p for p in self._patterns if p.confidence >= min_confidence]
        removed = before - len(self._patterns)
        if removed:
            self._save()
        return removed

    def export_summary(self) -> Dict[str, Any]:
        """Export learning summary for display."""
        by_type: Dict[str, int] = {}
        for p in self._patterns:
            by_type[p.pattern_type] = by_type.get(p.pattern_type, 0) + 1

        suppressible = [p for p in self._patterns if p.confidence >= self.CONFIDENCE_THRESHOLD]
        return {
            "project_path": str(self._project_path),
            "stack": self._insight.stack,
            "total_patterns": len(self._patterns),
            "by_type": by_type,
            "suppressible": len(suppressible),
            "scan_count": self._insight.scan_count,
            "top_fps": [
                {"rule": p.description, "confidence": p.confidence, "occurrences": p.occurrences}
                for p in sorted(suppressible, key=lambda x: -x.occurrences)[:10]
            ],
        }

    # --- Private ---

    def _compute_pattern_id(self, title: str, tool: str, cwe: Optional[str]) -> str:
        """Compute stable pattern ID from finding attributes."""
        normalized = f"{tool}:{self._normalize_title(title)}:{cwe or 'none'}"
        return hashlib.sha256(normalized.encode()).hexdigest()[:16]

    def _normalize_title(self, title: str) -> str:
        """Normalize title: lowercase, strip dynamic parts."""
        import re

        t = title.lower().strip()
        # Strip UUIDs
        t = re.sub(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "", t)
        # Strip IP addresses
        t = re.sub(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "", t)
        # Strip port numbers
        t = re.sub(r":\d{2,5}", "", t)
        # Collapse whitespace
        t = re.sub(r"\s+", " ", t).strip()
        return t

    def _generalize_path(self, file_path: str) -> str:
        """Generalize a file path to a pattern."""
        parts = Path(file_path).parts
        if len(parts) > 2:
            # Keep directory structure, wildcard the filename
            return str(Path(*parts[:-1]) / "*")
        return file_path

    def _find_pattern(self, pattern_id: str) -> Optional[LearnedPattern]:
        """Find pattern by ID."""
        for p in self._patterns:
            if p.pattern_id == pattern_id:
                return p
        return None

    def _load(self) -> None:
        """Load from JSON file."""
        if not self._storage_path.exists():
            return
        try:
            data = json.loads(self._storage_path.read_text())
            self._patterns = [LearnedPattern(**p) for p in data.get("patterns", [])]
            if data.get("insight"):
                self._insight = ProjectInsight(**data["insight"])
        except Exception as e:
            logger.warning(f"Failed to load project learning: {e}")

    def _save(self) -> None:
        """Save to JSON file."""
        try:
            self._storage_path.parent.mkdir(parents=True, exist_ok=True)
            data = {
                "patterns": [asdict(p) for p in self._patterns],
                "insight": asdict(self._insight),
            }
            self._storage_path.write_text(json.dumps(data, indent=2))
        except Exception as e:
            logger.warning(f"Failed to save project learning: {e}")
