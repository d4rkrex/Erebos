"""Rules of Engagement parser for Erebos control plane (REQ-007).

Parses and validates RoE YAML files, derives policy from RoE.

# VT-Spec S-01: yaml.safe_load only, reject anchors/aliases in RoE files
"""

from __future__ import annotations

import ipaddress
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from pydantic import BaseModel, Field, field_validator

from erebos.control.policy import MAX_YAML_SIZE_BYTES, Policy, PolicyEngine
from erebos.core.models import RulesOfEngagement

logger = logging.getLogger(__name__)

# Required top-level keys in a valid RoE file
ROE_REQUIRED_KEYS = {"targets", "operator"}

ROE_TEMPLATE = """\
# Erebos Rules of Engagement Template
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Fill in all required fields before starting an engagement.
# YAML anchors/aliases are NOT permitted.

# Required: Targets in scope (IPs, CIDRs, hostnames)
targets:
  - "192.168.1.0/24"
  - "example.com"

# Optional: Explicitly excluded targets
excluded:
  - "192.168.1.1"  # Gateway - do not touch

# Allowed techniques/action classes
techniques:
  - "scan"
  - "enumerate"
  # - "exploit"  # Uncomment if exploitation is authorized

# Time window for engagement (ISO 8601)
time_window:
  start: "2024-01-01T09:00:00Z"
  end: "2024-01-01T17:00:00Z"

# Emergency contact information
emergency_contact: "security-team@example.com"

# Data handling policy: no_exfil | encrypt_at_rest | allowed
data_handling: "no_exfil"

# Operator name (required)
operator: "Your Name"

# Maximum engagement depth per host
max_depth: 3

# Allowed action classes
allowed_action_classes:
  - "scan"
  - "enumerate"
"""


def parse_roe(roe_path: Path) -> RulesOfEngagement:
    """Parse a Rules of Engagement YAML file.

    # VT-Spec S-01: yaml.safe_load, reject anchors/aliases, size limits
    # VT-Spec S-02: Validate all target formats
    """
    if not roe_path.exists():
        raise FileNotFoundError(f"RoE file not found: {roe_path}")

    # VT-Spec S-01: Size limit
    file_size = roe_path.stat().st_size
    if file_size > MAX_YAML_SIZE_BYTES:
        raise ValueError(
            f"RoE file exceeds maximum size ({file_size} > {MAX_YAML_SIZE_BYTES} bytes)"
        )

    content = roe_path.read_text()

    # VT-Spec S-01: Reject YAML anchors and aliases
    anchor_pattern = re.compile(r"[&*]\w+")
    if anchor_pattern.search(content):
        raise ValueError(
            "YAML anchors/aliases are not permitted in RoE files (S-01 mitigation). "
            "All values must be explicitly defined."
        )

    # VT-Spec S-01: yaml.safe_load only
    data = yaml.safe_load(content)
    if not isinstance(data, dict):
        raise ValueError("RoE YAML must be a mapping/dictionary")

    # Validate required keys
    missing = ROE_REQUIRED_KEYS - set(data.keys())
    if missing:
        raise ValueError(f"RoE file missing required keys: {missing}")

    # VT-Spec S-02: Validate all target formats
    targets = data.get("targets", [])
    if not isinstance(targets, list) or not targets:
        raise ValueError("RoE must contain at least one target")

    for target in targets:
        _validate_target(target)

    excluded = data.get("excluded", [])
    for target in excluded:
        _validate_target(target)

    # Build RulesOfEngagement model
    roe = RulesOfEngagement(
        targets=targets,
        excluded=excluded,
        techniques=data.get("techniques", []),
        time_window=data.get("time_window"),
        emergency_contact=data.get("emergency_contact"),
        data_handling=data.get("data_handling", "no_exfil"),
        operator=data.get("operator", "unknown"),
        max_depth=data.get("max_depth", 3),
        allowed_action_classes=data.get("allowed_action_classes", ["scan", "enumerate"]),
    )

    return roe


def _validate_target(target: str) -> None:
    """Validate a target string format.

    # VT-Spec S-02: Validate CIDR, IP ranges, hostnames uniformly
    """
    if not isinstance(target, str) or not target.strip():
        raise ValueError(f"Invalid target (empty or non-string): {target!r}")

    target = target.strip()

    # Try as IP address
    try:
        ipaddress.ip_address(target)
        return
    except ValueError:
        pass

    # Try as CIDR network
    if "/" in target:
        try:
            ipaddress.ip_network(target, strict=False)
            return
        except ValueError:
            raise ValueError(f"Invalid CIDR notation in RoE: {target}")

    # Validate as hostname (relaxed pattern)
    hostname_pattern = re.compile(
        r"^(\*\.)?[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$"
    )
    if not hostname_pattern.match(target):
        raise ValueError(f"Invalid target format in RoE: {target}")


def derive_policy(roe: RulesOfEngagement) -> Policy:
    """Derive a security policy from Rules of Engagement.

    Conservative derivation — deny-by-default for anything not explicitly permitted.
    """
    # Map techniques to action classes
    allowed_classes = []
    for technique in roe.techniques:
        if technique in ("scan", "enumerate", "exploit", "pivot", "exfiltrate", "persist", "cleanup"):
            allowed_classes.append(technique)

    # If no techniques specified, use RoE allowed_action_classes
    if not allowed_classes:
        allowed_classes = roe.allowed_action_classes

    # Conservative approval thresholds
    approval_thresholds = {
        "none": False,
        "low": False,
        "medium": True,
        "high": True,
        "critical": True,
    }

    # If exploitation is not in allowed classes, require approval for everything
    if "exploit" not in allowed_classes:
        approval_thresholds["low"] = True

    policy = Policy(
        scope_targets=roe.targets,
        scope_excluded=roe.excluded,
        max_depth=roe.max_depth,
        allowed_action_classes=allowed_classes,
        approval_thresholds=approval_thresholds,
    )

    return policy


def generate_template(output_path: Path) -> Path:
    """Generate a RoE template YAML file.

    # VT-Spec E-03: Mandatory --dry-run showing fully resolved policy
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(ROE_TEMPLATE)
    logger.info(f"RoE template written to: {output_path}")
    return output_path
