"""Agent roles for fleet execution."""

from erebos.agents.roles.exploit import ExploitRole
from erebos.agents.roles.recon import ReconRole
from erebos.agents.roles.reporter import ReporterRole
from erebos.agents.roles.vuln_scan import VulnScanRole
from erebos.agents.roles.web_discovery import WebDiscoveryRole

__all__ = [
    "ExploitRole",
    "ReconRole",
    "ReporterRole",
    "VulnScanRole",
    "WebDiscoveryRole",
]
