"""Policy engine for Erebos control plane (REQ-003).

Evaluates actions against engagement policy derived from Rules of Engagement.
Deny-by-default — actions must be explicitly permitted.

# VT-Spec S-01: yaml.safe_load only, reject anchors/aliases
# VT-Spec S-02: Validate CIDR, IP ranges, hostnames uniformly
"""

from __future__ import annotations

import ipaddress
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from pydantic import BaseModel, Field

from erebos.core.models import (
    ActionType,
    EngagementPhase,
    ImpactLevel,
    PlannedAction,
    PolicyDecision,
)

logger = logging.getLogger(__name__)

# VT-Spec S-01: Maximum YAML file size to prevent resource exhaustion
MAX_YAML_SIZE_BYTES = 1_048_576  # 1MB


class RateLimitConfig(BaseModel):
    """Rate limit configuration per action class."""

    requests_per_minute: int = 10
    burst_max: int = 20


class Policy(BaseModel):
    """Engagement policy defining allowed actions and constraints."""

    # Scope
    scope_targets: List[str] = Field(default_factory=list)
    scope_excluded: List[str] = Field(default_factory=list)

    # Depth and limits
    max_depth: int = 3
    max_actions_per_phase: int = 100
    time_budget_minutes: int = 60

    # Allowed action classes
    allowed_action_classes: List[str] = Field(
        default_factory=lambda: ["scan", "enumerate"]
    )

    # Approval thresholds by impact level
    approval_thresholds: Dict[str, bool] = Field(
        default_factory=lambda: {
            "none": False,
            "low": False,
            "medium": True,
            "high": True,
            "critical": True,
        }
    )

    # Rate limits per action type
    rate_limits: Dict[str, RateLimitConfig] = Field(default_factory=dict)

    # Version tracking
    version: str = "1.0"


class PolicyEngine:
    """Evaluates actions against engagement policy.

    # VT-Spec S-01: YAML safe_load, reject anchors
    # VT-Spec S-02: CIDR/IP/hostname validation
    """

    def __init__(self, policy: Policy):
        self._policy = policy
        self._parsed_networks: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._parse_scope_networks()

    @property
    def policy(self) -> Policy:
        return self._policy

    def _parse_scope_networks(self) -> None:
        """Parse CIDR notation targets into network objects.

        # VT-Spec S-02: Proper CIDR matching using ipaddress.ip_network
        """
        for target in self._policy.scope_targets:
            try:
                if "/" in target:
                    network = ipaddress.ip_network(target, strict=False)
                    self._parsed_networks.append(network)
            except ValueError as e:
                logger.warning(f"Invalid CIDR in policy scope: {target} - {e}")

    @classmethod
    def load_from_yaml(cls, yaml_path: Path) -> PolicyEngine:
        """Load policy from YAML file.

        # VT-Spec S-01: yaml.safe_load only, no aliases, size limits
        """
        if not yaml_path.exists():
            raise FileNotFoundError(f"Policy file not found: {yaml_path}")

        file_size = yaml_path.stat().st_size
        if file_size > MAX_YAML_SIZE_BYTES:
            raise ValueError(
                f"Policy file exceeds maximum size ({file_size} > {MAX_YAML_SIZE_BYTES} bytes)"
            )

        content = yaml_path.read_text()

        # VT-Spec S-01: Reject YAML anchors and aliases
        if "&" in content or "*" in content:
            # Check for actual YAML anchor/alias patterns
            anchor_pattern = re.compile(r"[&*]\w+")
            if anchor_pattern.search(content):
                raise ValueError(
                    "YAML anchors/aliases are not permitted in policy files (S-01 mitigation)"
                )

        data = yaml.safe_load(content)
        if not isinstance(data, dict):
            raise ValueError("Policy YAML must be a mapping")

        policy = Policy(**data)
        return cls(policy)

    @classmethod
    def derive_from_roe(cls, roe_data: Dict[str, Any]) -> PolicyEngine:
        """Derive a policy from Rules of Engagement.

        Conservative derivation — deny-by-default.
        """
        policy = Policy(
            scope_targets=roe_data.get("targets", []),
            scope_excluded=roe_data.get("excluded", []),
            max_depth=roe_data.get("max_depth", 3),
            allowed_action_classes=roe_data.get(
                "allowed_action_classes", ["scan", "enumerate"]
            ),
            time_budget_minutes=roe_data.get("time_budget_minutes", 60),
        )

        # VT-Spec S-02: Validate all targets
        for target in policy.scope_targets:
            cls._validate_target_format(target)

        return cls(policy)

    @staticmethod
    def _validate_target_format(target: str) -> None:
        """Validate target format (IP, CIDR, hostname).

        # VT-Spec S-02: Validate CIDR, IP ranges, hostnames uniformly
        """
        # Try as IP address
        try:
            ipaddress.ip_address(target)
            return
        except ValueError:
            pass

        # Try as CIDR network
        try:
            if "/" in target:
                ipaddress.ip_network(target, strict=False)
                return
        except ValueError:
            raise ValueError(f"Invalid CIDR notation: {target}")

        # Validate as hostname
        hostname_pattern = re.compile(
            r"^(\*\.)?[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$"
        )
        if not hostname_pattern.match(target):
            raise ValueError(f"Invalid target format: {target}")

    def evaluate(self, action: PlannedAction) -> PolicyDecision:
        """Evaluate an action against the policy.

        Deny-by-default: action must be explicitly allowed.
        """
        # Check if action class is allowed
        action_class = action.action_type.value
        if action_class not in self._policy.allowed_action_classes:
            return PolicyDecision(
                allowed=False,
                reason=f"Action class '{action_class}' not in allowed classes: "
                f"{self._policy.allowed_action_classes}",
                action_id=action.id,
                policy_version=self._policy.version,
            )

        # Check depth limit
        if self._policy.max_depth <= 0:
            return PolicyDecision(
                allowed=False,
                reason="Depth limit reached",
                action_id=action.id,
                policy_version=self._policy.version,
            )

        # Determine if approval is required
        impact = action.impact_level.value
        requires_approval = self._policy.approval_thresholds.get(impact, True)

        return PolicyDecision(
            allowed=True,
            reason="Action permitted by policy",
            requires_approval=requires_approval,
            action_id=action.id,
            policy_version=self._policy.version,
        )

    def is_target_in_scope(self, target: str) -> bool:
        """Check if a target is within policy scope.

        # VT-Spec S-02: CIDR matching with ipaddress module
        """
        # Check exclusions first
        for excluded in self._policy.scope_excluded:
            if target == excluded:
                return False
            try:
                if "/" in excluded:
                    network = ipaddress.ip_network(excluded, strict=False)
                    try:
                        if ipaddress.ip_address(target) in network:
                            return False
                    except ValueError:
                        pass
            except ValueError:
                pass

        # Check inclusions
        for scope_target in self._policy.scope_targets:
            # Exact match
            if target == scope_target:
                return True

            # Wildcard domain match
            if scope_target.startswith("*."):
                suffix = scope_target[2:]
                if target == suffix or target.endswith("." + suffix):
                    return True

            # CIDR match
            try:
                if "/" in scope_target:
                    network = ipaddress.ip_network(scope_target, strict=False)
                    try:
                        if ipaddress.ip_address(target) in network:
                            return True
                    except ValueError:
                        pass
            except ValueError:
                pass

        return False
