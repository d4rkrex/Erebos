"""Configuration profiles for Erebos engagement modes (REQ-005).

Predefined profiles control engagement behavior, tool selection, timing,
and approval requirements.

# VT-Spec EOP-001 HIGH: CTF profile MUST require explicit target allowlist
# VT-Spec EOP-001: Profile-level scope validation cross-referencing RoE
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class ApprovalMode(str, Enum):
    """Approval mode for engagement actions."""

    MANUAL = "manual"  # All high-risk require approval
    AUTO = "auto"  # Auto-approve within scope
    DISABLED = "disabled"  # No approval required (CTF only)


class EvasionLevel(str, Enum):
    """Evasion level for stealth operations."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class CleanupMode(str, Enum):
    """Post-engagement cleanup behavior."""

    FULL = "full"  # Clean all artifacts
    MINIMAL = "minimal"  # Clean sensitive only
    NONE = "none"  # No cleanup (CTF)


class EngagementProfile(BaseModel):
    """Engagement profile defining behavior constraints.

    # VT-Spec EOP-001: CTF profile requires non-production declaration
    """

    name: str
    description: str
    phases_enabled: List[str] = Field(
        default_factory=lambda: ["recon", "enumeration", "exploitation", "post_exploit", "reporting"]
    )
    approval_mode: ApprovalMode = ApprovalMode.MANUAL
    timing_min_delay_ms: int = 0
    timing_max_delay_ms: int = 0
    parallel_scanning: bool = True
    evasion_level: EvasionLevel = EvasionLevel.NONE
    cleanup_mode: CleanupMode = CleanupMode.FULL
    max_iterations: int = 100
    wall_clock_budget_seconds: int = 3600
    aggressive_techniques: bool = False
    # VT-Spec EOP-001: CTF-specific fields
    requires_non_production_declaration: bool = False
    ctf_target_allowlist: List[str] = Field(default_factory=list)

    def is_ctf(self) -> bool:
        """Check if this is the CTF profile."""
        return self.name == "ctf"


# ── Preset Profiles ──────────────────────────────────────────────────────────


QUICK_SCAN = EngagementProfile(
    name="quick-scan",
    description="Fast reconnaissance and enumeration only. No exploitation.",
    phases_enabled=["recon", "enumeration", "reporting"],
    approval_mode=ApprovalMode.AUTO,
    timing_min_delay_ms=0,
    timing_max_delay_ms=100,
    parallel_scanning=True,
    evasion_level=EvasionLevel.NONE,
    cleanup_mode=CleanupMode.FULL,
    max_iterations=30,
    wall_clock_budget_seconds=900,  # 15 min
    aggressive_techniques=False,
)

FULL_PENTEST = EngagementProfile(
    name="full-pentest",
    description="Complete pentest lifecycle with human approval for critical actions.",
    phases_enabled=["recon", "enumeration", "exploitation", "post_exploit", "reporting"],
    approval_mode=ApprovalMode.MANUAL,
    timing_min_delay_ms=100,
    timing_max_delay_ms=1000,
    parallel_scanning=True,
    evasion_level=EvasionLevel.LOW,
    cleanup_mode=CleanupMode.FULL,
    max_iterations=100,
    wall_clock_budget_seconds=3600,
    aggressive_techniques=False,
)

STEALTH = EngagementProfile(
    name="stealth",
    description="Low-and-slow engagement with maximum evasion. No parallel scanning.",
    phases_enabled=["recon", "enumeration", "exploitation", "reporting"],
    approval_mode=ApprovalMode.MANUAL,
    timing_min_delay_ms=2000,
    timing_max_delay_ms=10000,
    parallel_scanning=False,
    evasion_level=EvasionLevel.HIGH,
    cleanup_mode=CleanupMode.FULL,
    max_iterations=50,
    wall_clock_budget_seconds=7200,  # 2 hours
    aggressive_techniques=False,
)

# VT-Spec EOP-001 HIGH: CTF profile with scope boundary enforcement
CTF = EngagementProfile(
    name="ctf",
    description="CTF mode: auto-approve all, no cleanup, aggressive techniques. REQUIRES non-production target declaration.",
    phases_enabled=["recon", "enumeration", "exploitation", "post_exploit", "reporting"],
    approval_mode=ApprovalMode.DISABLED,
    timing_min_delay_ms=0,
    timing_max_delay_ms=0,
    parallel_scanning=True,
    evasion_level=EvasionLevel.NONE,
    cleanup_mode=CleanupMode.NONE,
    max_iterations=200,
    wall_clock_budget_seconds=14400,  # 4 hours
    aggressive_techniques=True,
    # VT-Spec EOP-001: Mandatory non-production declaration
    requires_non_production_declaration=True,
)


# Profile registry
ENGAGEMENT_PROFILES: Dict[str, EngagementProfile] = {
    "quick-scan": QUICK_SCAN,
    "full-pentest": FULL_PENTEST,
    "stealth": STEALTH,
    "ctf": CTF,
}


def get_profile(name: str) -> EngagementProfile:
    """Get a profile by name.

    Raises ValueError if profile not found.
    """
    if name not in ENGAGEMENT_PROFILES:
        available = ", ".join(sorted(ENGAGEMENT_PROFILES.keys()))
        raise ValueError(f"Unknown profile '{name}'. Available: {available}")
    return ENGAGEMENT_PROFILES[name]


def validate_ctf_profile(
    profile: EngagementProfile,
    targets: List[str],
    roe_environment: Optional[str] = None,
    confirm_callback=None,
) -> bool:
    """VT-Spec EOP-001 HIGH: Validate CTF profile usage.

    1. CTF profile MUST require explicit target allowlist
    2. Cross-reference with RoE environment classification
    3. Confirmation prompt for non-production
    4. Log CTF profile selection as audit event

    Returns True if validation passes, raises ValueError otherwise.
    """
    if not profile.is_ctf():
        return True

    # VT-Spec EOP-001: Require explicit target allowlist
    if not profile.ctf_target_allowlist:
        raise ValueError(
            "VT-Spec EOP-001: CTF profile requires explicit ctf_target_allowlist. "
            "Set allowed CTF platform IPs/hostnames."
        )

    # VT-Spec EOP-001: All targets must be within CTF allowlist
    for target in targets:
        if target not in profile.ctf_target_allowlist:
            raise ValueError(
                f"VT-Spec EOP-001: Target '{target}' not in CTF allowlist. "
                f"Allowed: {profile.ctf_target_allowlist}"
            )

    # VT-Spec EOP-001: Cross-reference RoE environment classification
    if roe_environment and roe_environment.lower() in ("production", "prod", "live"):
        raise ValueError(
            "VT-Spec EOP-001: CTF profile CANNOT be used against production environments. "
            f"RoE environment classified as: {roe_environment}"
        )

    # VT-Spec EOP-001: Confirmation prompt
    if confirm_callback is not None:
        confirmed = confirm_callback(
            "CTF mode disables all safety gates. Confirm non-production [y/N]"
        )
        if not confirmed:
            raise ValueError("VT-Spec EOP-001: CTF profile usage not confirmed by operator.")

    # VT-Spec EOP-001: Log as audit event
    logger.warning(
        "VT-Spec EOP-001: CTF profile selected",
        extra={
            "profile": "ctf",
            "targets": targets,
            "ctf_allowlist": profile.ctf_target_allowlist,
            "roe_environment": roe_environment,
        },
    )

    return True
