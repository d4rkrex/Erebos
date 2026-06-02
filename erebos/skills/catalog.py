"""Skill Catalog for Erebos (REQ-002).

Manages skill registration, trigger matching, and progressive disclosure.

# VT-Spec T-SKG-02 HIGH: Regex timeout 100ms via signal, reject nested quantifiers
# VT-Spec T-SKG-05 CRITICAL: ActionTemplate.args_template is LIST, safe allowlist substitution
"""

from __future__ import annotations

import logging
import re
import signal
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator

from erebos.core.models import Observation

logger = logging.getLogger(__name__)

# VT-Spec T-SKG-02: Maximum regex execution time in seconds
REGEX_TIMEOUT_SECONDS = 0.1  # 100ms

# VT-Spec T-SKG-02: Patterns that indicate catastrophic backtracking
CATASTROPHIC_BACKTRACKING_PATTERNS = [
    re.compile(r"\([^)]*[+*][^)]*\)[+*]"),  # Nested quantifiers like (a+)+, (a*)*
    re.compile(r"\(.+\)\{.+\}\{"),  # Nested repetitions
    re.compile(r"\(\.\*\)[+*]"),  # (.*)+, (.*)*
    re.compile(r"\(\.\+\)[+*]"),  # (.+)+, (.+)*
    re.compile(r"\(\[.*\][+*]\)[+*]"),  # ([...]+)+
]

# VT-Spec T-SKG-05: Safe variable allowlist for template substitution
SAFE_TEMPLATE_VARIABLES = frozenset(["target", "port", "service", "url", "hostname", "protocol"])


class _RegexTimeoutError(Exception):
    """Raised when regex evaluation exceeds timeout."""

    pass


def _regex_timeout_handler(signum: int, frame: Any) -> None:
    """Signal handler for regex timeout."""
    raise _RegexTimeoutError("Regex evaluation exceeded timeout")


# ─── Models ─────────────────────────────────────────────────────────────────


class TriggerPattern(BaseModel):
    """Pattern that triggers a skill based on observations."""

    observation_type: str
    field_match: Dict[str, Any] = Field(default_factory=dict)
    regex_pattern: Optional[str] = None

    @field_validator("regex_pattern")
    @classmethod
    def validate_regex_pattern(cls, v: Optional[str]) -> Optional[str]:
        """VT-Spec T-SKG-02: Reject patterns with catastrophic backtracking indicators."""
        if v is None:
            return v
        for dangerous in CATASTROPHIC_BACKTRACKING_PATTERNS:
            if dangerous.search(v):
                raise ValueError(
                    f"VT-Spec T-SKG-02: Regex pattern rejected — "
                    f"contains catastrophic backtracking indicator: {v!r}"
                )
        # Validate regex compiles
        try:
            re.compile(v)
        except re.error as e:
            raise ValueError(f"Invalid regex pattern: {e}")
        return v


class ActionTemplate(BaseModel):
    """Action template for a skill.

    # VT-Spec T-SKG-05 CRITICAL: args_template is a LIST, never a string.
    """

    tool: str
    args_template: List[str]  # VT-Spec T-SKG-05: MUST be list, never string
    description: str = ""

    @field_validator("args_template")
    @classmethod
    def validate_args_template(cls, v: List[str]) -> List[str]:
        """VT-Spec T-SKG-05: Ensure args_template is a list of strings."""
        if not isinstance(v, list):
            raise ValueError("VT-Spec T-SKG-05: args_template MUST be a list, never a string")
        for item in v:
            if not isinstance(item, str):
                raise ValueError(
                    f"VT-Spec T-SKG-05: Each arg in args_template must be a string, got {type(item)}"
                )
        return v


class Skill(BaseModel):
    """A skill definition with triggers, tools, and action templates."""

    name: str
    description: str = ""
    version: str = "1.0"
    triggers: List[TriggerPattern] = Field(default_factory=list)
    tools_required: List[str] = Field(default_factory=list)
    technique_id: Optional[str] = None
    phase_applicable: List[str] = Field(default_factory=list)
    actions: List[ActionTemplate] = Field(default_factory=list)


class SkillSummary(BaseModel):
    """Lightweight skill summary for listing."""

    name: str
    description: str
    version: str
    technique_id: Optional[str]
    phase_applicable: List[str]


# ─── Catalog ────────────────────────────────────────────────────────────────


class SkillCatalog:
    """Manages skill registration and trigger matching.

    # VT-Spec T-SKG-02 HIGH: Regex matching uses signal-based timeout (100ms)
    # VT-Spec T-SKG-05 CRITICAL: Template variables via safe allowlist only
    """

    def __init__(self) -> None:
        self._skills: Dict[str, Skill] = {}

    def register(self, skill: Skill) -> None:
        """Register a skill in the catalog."""
        self._skills[skill.name] = skill
        logger.debug("Skill registered: %s (v%s)", skill.name, skill.version)

    def unregister(self, name: str) -> None:
        """Remove a skill from the catalog."""
        if name in self._skills:
            del self._skills[name]
            logger.debug("Skill unregistered: %s", name)

    def get_skill(self, name: str) -> Optional[Skill]:
        """Get a skill by name."""
        return self._skills.get(name)

    def list_skills(self, phase: Optional[str] = None) -> List[SkillSummary]:
        """List skills, optionally filtered by phase."""
        results = []
        for skill in self._skills.values():
            if phase and phase not in skill.phase_applicable:
                continue
            results.append(
                SkillSummary(
                    name=skill.name,
                    description=skill.description,
                    version=skill.version,
                    technique_id=skill.technique_id,
                    phase_applicable=skill.phase_applicable,
                )
            )
        return results

    def match_triggers(
        self, observations: List[Observation], phase: str
    ) -> List[Skill]:
        """Match observations against skill triggers for the given phase.

        # VT-Spec T-SKG-02 HIGH: Regex matching uses signal-based timeout
        """
        matched: List[Skill] = []

        for skill in self._skills.values():
            # Phase filtering
            if phase not in skill.phase_applicable:
                continue

            for trigger in skill.triggers:
                if self._trigger_matches(trigger, observations):
                    matched.append(skill)
                    break  # One match per skill is enough

        return matched

    def _trigger_matches(
        self, trigger: TriggerPattern, observations: List[Observation]
    ) -> bool:
        """Check if any observation matches the trigger pattern."""
        for obs in observations:
            if obs.observation_type.value != trigger.observation_type:
                continue

            # Check field_match
            if trigger.field_match:
                if not self._fields_match(trigger.field_match, obs.data):
                    continue

            # Check regex_pattern against observation data
            if trigger.regex_pattern:
                if not self._regex_match_safe(trigger.regex_pattern, obs.data):
                    continue

            return True

        return False

    def _fields_match(self, field_match: Dict[str, Any], data: Dict[str, Any]) -> bool:
        """Check if all field_match criteria are satisfied by data."""
        for key, expected in field_match.items():
            actual = data.get(key)
            if actual is None:
                return False
            if isinstance(expected, list):
                if actual not in expected:
                    return False
            elif actual != expected:
                return False
        return True

    def _regex_match_safe(self, pattern: str, data: Dict[str, Any]) -> bool:
        """Match regex against observation data with timeout protection.

        # VT-Spec T-SKG-02 HIGH: Signal-based timeout (100ms max)
        """
        # Combine data values into a single string for matching
        text = " ".join(str(v) for v in data.values() if isinstance(v, str))

        try:
            compiled = re.compile(pattern)
        except re.error:
            logger.warning("VT-Spec T-SKG-02: Invalid regex pattern: %s", pattern)
            return False

        # VT-Spec T-SKG-02: Signal-based timeout for regex evaluation
        old_handler = signal.signal(signal.SIGALRM, _regex_timeout_handler)
        try:
            # Set alarm for 100ms (signal.alarm only supports integer seconds,
            # so we use setitimer for sub-second precision)
            signal.setitimer(signal.ITIMER_REAL, REGEX_TIMEOUT_SECONDS)
            result = compiled.search(text)
            signal.setitimer(signal.ITIMER_REAL, 0)  # Cancel timer
            return result is not None
        except _RegexTimeoutError:
            logger.warning(
                "VT-Spec T-SKG-02: Regex timeout exceeded for pattern: %s", pattern
            )
            return False
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)  # Ensure timer cancelled
            signal.signal(signal.SIGALRM, old_handler)
