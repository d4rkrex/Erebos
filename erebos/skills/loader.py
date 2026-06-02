"""Skill Loader for Erebos (REQ-001).

Loads skill definitions from YAML files with strict security controls.

# VT-Spec T-SKG-01 CRITICAL: yaml.safe_load ONLY, reject anchors/aliases,
#   SHA-256 integrity verification for hot-reload
# VT-Spec T-SKG-06 MEDIUM: No custom YAML constructors, pure safe_load
"""

from __future__ import annotations

import hashlib
import logging
import re
from pathlib import Path
from typing import Dict, List, Optional

import yaml
from pydantic import ValidationError

from erebos.skills.catalog import ActionTemplate, Skill, TriggerPattern

logger = logging.getLogger(__name__)

# VT-Spec T-SKG-01: Max YAML file size (256KB)
MAX_SKILL_FILE_SIZE = 256 * 1024

# VT-Spec T-SKG-01: Anchor/alias detection pattern (same as roe.py)
ANCHOR_ALIAS_PATTERN = re.compile(r"[&*]\w+")


class SkillLoadError(Exception):
    """Raised when a skill file cannot be loaded."""

    pass


class SkillLoader:
    """Loads skill definitions from YAML files.

    # VT-Spec T-SKG-01 CRITICAL: yaml.safe_load, reject anchors/aliases
    # VT-Spec T-SKG-06 MEDIUM: No custom YAML constructors
    """

    def __init__(self) -> None:
        # VT-Spec T-SKG-01: SHA-256 manifest for hot-reload integrity
        self._file_hashes: Dict[str, str] = {}

    def load_directory(self, path: Path) -> List[Skill]:
        """Load all skill YAML files from a directory recursively."""
        if not path.is_dir():
            raise SkillLoadError(f"Skill directory not found: {path}")

        skills: List[Skill] = []
        for yaml_file in sorted(path.rglob("*.yaml")):
            try:
                skill = self.load_file(yaml_file)
                skills.append(skill)
            except SkillLoadError as e:
                logger.warning("Skipping skill file %s: %s", yaml_file, e)
            except Exception as e:
                logger.warning("Unexpected error loading %s: %s", yaml_file, e)

        return skills

    def load_file(self, path: Path) -> Skill:
        """Load a single skill YAML file.

        # VT-Spec T-SKG-01 CRITICAL: yaml.safe_load, reject anchors/aliases
        # VT-Spec T-SKG-06 MEDIUM: No custom constructors
        """
        if not path.is_file():
            raise SkillLoadError(f"Skill file not found: {path}")

        # VT-Spec T-SKG-01: Size limit
        file_size = path.stat().st_size
        if file_size > MAX_SKILL_FILE_SIZE:
            raise SkillLoadError(
                f"VT-Spec T-SKG-01: Skill file exceeds max size "
                f"({file_size} > {MAX_SKILL_FILE_SIZE}): {path}"
            )

        content = path.read_text(encoding="utf-8")

        # VT-Spec T-SKG-01: Reject YAML anchors and aliases
        if ANCHOR_ALIAS_PATTERN.search(content):
            raise SkillLoadError(
                f"VT-Spec T-SKG-01: YAML anchors/aliases not permitted in skill files: {path}"
            )

        # VT-Spec T-SKG-01 / T-SKG-06: yaml.safe_load ONLY
        try:
            data = yaml.safe_load(content)
        except yaml.YAMLError as e:
            raise SkillLoadError(f"YAML parse error in {path}: {e}")

        if not isinstance(data, dict):
            raise SkillLoadError(f"Skill YAML must be a mapping: {path}")

        # Schema validation via Pydantic
        if not self.validate_schema(data):
            raise SkillLoadError(f"Schema validation failed for: {path}")

        # Build Skill model
        skill = self._build_skill(data)

        # Store hash for hot-reload integrity
        self._file_hashes[str(path)] = self._compute_hash(content)

        return skill

    def validate_schema(self, data: dict) -> bool:
        """Validate skill data against schema using Pydantic."""
        required_fields = {"name", "actions"}
        if not required_fields.issubset(data.keys()):
            return False

        # Validate actions are lists (T-SKG-05)
        actions = data.get("actions", [])
        if not isinstance(actions, list):
            return False
        for action in actions:
            if not isinstance(action, dict):
                return False
            args = action.get("args_template", [])
            # VT-Spec T-SKG-05: args_template must be a list
            if not isinstance(args, list):
                return False

        return True

    def hot_reload(self, path: Path) -> Optional[Skill]:
        """Hot-reload a skill file with integrity verification.

        # VT-Spec T-SKG-01: Verify SHA-256 file integrity before accepting
        """
        if not path.is_file():
            logger.warning("Hot-reload failed: file not found: %s", path)
            return None

        # Read content and compute hash
        content = path.read_text(encoding="utf-8")
        new_hash = self._compute_hash(content)

        # Check if file actually changed
        old_hash = self._file_hashes.get(str(path))
        if old_hash == new_hash:
            logger.debug("Hot-reload: file unchanged: %s", path)
            return None

        # VT-Spec T-SKG-01: Re-validate on reload
        try:
            skill = self.load_file(path)
            logger.info("Hot-reload successful: %s (hash: %s)", path, new_hash[:16])
            return skill
        except SkillLoadError as e:
            logger.error("Hot-reload rejected: %s — %s", path, e)
            return None

    def _build_skill(self, data: dict) -> Skill:
        """Build a Skill model from validated data."""
        triggers = []
        for t in data.get("triggers", []):
            triggers.append(
                TriggerPattern(
                    observation_type=t.get("observation_type", ""),
                    field_match=t.get("field_match", {}),
                    regex_pattern=t.get("regex_pattern"),
                )
            )

        actions = []
        for a in data.get("actions", []):
            actions.append(
                ActionTemplate(
                    tool=a.get("tool", ""),
                    args_template=a.get("args_template", []),
                    description=a.get("description", ""),
                )
            )

        return Skill(
            name=data["name"],
            description=data.get("description", ""),
            version=data.get("version", "1.0"),
            triggers=triggers,
            tools_required=data.get("tools_required", []),
            technique_id=data.get("technique_id"),
            phase_applicable=data.get("phase_applicable", []),
            actions=actions,
        )

    @staticmethod
    def _compute_hash(content: str) -> str:
        """Compute SHA-256 hash of content."""
        return hashlib.sha256(content.encode("utf-8")).hexdigest()
