"""Attack domain classification for security tools.

Maps tools to their primary attack domains, inspired by Shannon's
parallel agent architecture where each domain runs independently.
"""

from enum import Enum
from typing import Dict, List


class AttackDomain(str, Enum):
    """Attack domain categories for tool classification."""

    INJECTION = "injection"
    XSS = "xss"
    AUTH = "auth"
    AUTHZ = "authz"
    SSRF = "ssrf"
    RECON = "recon"
    DISCOVERY = "discovery"
    GENERIC = "generic"


# VT-Spec EOP-001: Strict tool-to-domain mapping validated at config load time.
# Only registered tools can execute; prevents arbitrary tool injection.
DEFAULT_TOOL_DOMAIN_MAPPING: Dict[str, List[AttackDomain]] = {
    "nuclei": [
        AttackDomain.INJECTION,
        AttackDomain.XSS,
        AttackDomain.AUTH,
        AttackDomain.SSRF,
    ],
    "nikto": [AttackDomain.GENERIC],
    "sqlmap": [AttackDomain.INJECTION],
    "nmap": [AttackDomain.DISCOVERY],
    "masscan": [AttackDomain.DISCOVERY],
    "katana": [AttackDomain.RECON],
    "subfinder": [AttackDomain.RECON],
    "amass": [AttackDomain.RECON],
    "ffuf": [AttackDomain.DISCOVERY],
    "gobuster": [AttackDomain.DISCOVERY],
    "dirb": [AttackDomain.DISCOVERY],
}


def get_tool_domains(tool: str, custom_mapping: Dict[str, List[str]] | None = None) -> List[AttackDomain]:
    """Get attack domains for a given tool.

    Args:
        tool: Tool name (e.g., "nuclei", "sqlmap").
        custom_mapping: Optional override from config.yaml tools.domain_mapping.

    Returns:
        List of attack domains the tool covers.
    """
    if custom_mapping and tool in custom_mapping:
        return [AttackDomain(d) for d in custom_mapping[tool]]
    return DEFAULT_TOOL_DOMAIN_MAPPING.get(tool, [AttackDomain.GENERIC])


def get_tools_for_domain(
    domain: AttackDomain,
    custom_mapping: Dict[str, List[str]] | None = None,
) -> List[str]:
    """Get all tools that cover a specific attack domain."""
    mapping = DEFAULT_TOOL_DOMAIN_MAPPING
    if custom_mapping:
        mapping = {
            k: [AttackDomain(d) for d in v] for k, v in custom_mapping.items()
        }
    return [tool for tool, domains in mapping.items() if domain in domains]
