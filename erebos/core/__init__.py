"""Core module exports.

Uses lazy imports to avoid circular dependency chains between core and parsers.
"""

from __future__ import annotations


def __getattr__(name: str):
    """Lazy module attribute access to break circular imports."""
    _exports = {
        "Finding": ("erebos.core.finding", "Finding"),
        "FindingEvidence": ("erebos.core.finding", "FindingEvidence"),
        "Phase": ("erebos.core.finding", "Phase"),
        "ScanMode": ("erebos.core.finding", "ScanMode"),
        "Severity": ("erebos.core.finding", "Severity"),
        "DecisionContext": ("erebos.core.decision_engine", "DecisionContext"),
        "DecisionResult": ("erebos.core.decision_engine", "DecisionResult"),
        "IntelligentDecisionEngine": ("erebos.core.decision_engine", "IntelligentDecisionEngine"),
        "Orchestrator": ("erebos.core.orchestrator", "Orchestrator"),
        "PhaseStateMachine": ("erebos.core.orchestrator", "PhaseStateMachine"),
        "KillSwitch": ("erebos.core.orchestrator", "KillSwitch"),
        "AbortException": ("erebos.core.orchestrator", "AbortException"),
        "PauseException": ("erebos.core.orchestrator", "PauseException"),
        "get_kill_switch": ("erebos.core.orchestrator", "get_kill_switch"),
        "PhaseAgent": ("erebos.core.phase_agent", "PhaseAgent"),
        "ReconAgent": ("erebos.core.phase_agent", "ReconAgent"),
        "DiscoveryAgent": ("erebos.core.phase_agent", "DiscoveryAgent"),
        "VulnScanAgent": ("erebos.core.phase_agent", "VulnScanAgent"),
        "ValidationAgent": ("erebos.core.phase_agent", "ValidationAgent"),
        "ReportingAgent": ("erebos.core.phase_agent", "ReportingAgent"),
        "get_agent_for_phase": ("erebos.core.phase_agent", "get_agent_for_phase"),
    }

    if name in _exports:
        module_path, attr = _exports[name]
        import importlib

        module = importlib.import_module(module_path)
        return getattr(module, attr)
    raise AttributeError(f"module 'erebos.core' has no attribute {name!r}")


__all__ = [
    "Finding",
    "FindingEvidence",
    "Phase",
    "ScanMode",
    "Severity",
    "DecisionContext",
    "DecisionResult",
    "IntelligentDecisionEngine",
    "Orchestrator",
    "PhaseStateMachine",
    "KillSwitch",
    "AbortException",
    "PauseException",
    "get_kill_switch",
    "PhaseAgent",
    "ReconAgent",
    "DiscoveryAgent",
    "VulnScanAgent",
    "ValidationAgent",
    "ReportingAgent",
    "get_agent_for_phase",
]
