"""Control plane package for Erebos autonomous engagement management."""

from erebos.control.approval import ApprovalGate, ApprovalRequest
from erebos.control.killswitch import KillSwitch
from erebos.control.policy import Policy, PolicyEngine
from erebos.control.roe import parse_roe, derive_policy, generate_template
from erebos.control.scope import ScopeValidator

__all__ = [
    "ApprovalGate",
    "ApprovalRequest",
    "KillSwitch",
    "Policy",
    "PolicyEngine",
    "ScopeValidator",
    "parse_roe",
    "derive_policy",
    "generate_template",
]
