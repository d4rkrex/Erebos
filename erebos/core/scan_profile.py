"""Scan profile definitions."""

from typing import Dict, List, Literal
from pydantic import BaseModel


class ProfileTools(BaseModel):
    """Tools to run for each phase in a profile."""

    recon: List[str] = []
    discovery: List[str] = []
    vuln_scan: List[str] = []
    # Enrichment tools for smart recon
    enrichment: List[str] = []


class ScanProfile(BaseModel):
    """Scan profile configuration."""

    name: str
    description: str
    tools: ProfileTools
    inference_engine: bool = True
    nmap_strategy: Literal["fast", "dual"] = "fast"  # fast = -F only, dual = -F then -p-


# Predefined profiles inspired by SN1PER modes
PROFILES: Dict[str, ScanProfile] = {
    "minimal": ScanProfile(
        name="minimal",
        description="Stealthy scan with minimal footprint",
        tools=ProfileTools(
            recon=["katana"],
            discovery=[],
            vuln_scan=["nuclei-basic"],
            enrichment=[],
        ),
        inference_engine=False,
    ),
    "standard": ScanProfile(
        name="standard",
        description="Standard scan with common tools",
        tools=ProfileTools(
            recon=["katana", "nmap", "nikto"],
            discovery=[],
            vuln_scan=["nuclei-medium"],
            enrichment=["cve_service", "exploit_db", "http_probe"],
        ),
        inference_engine=True,
        nmap_strategy="dual",  # Use dual strategy for comprehensive port scanning
    ),
    "comprehensive": ScanProfile(
        name="comprehensive",
        description="Full scan with all available tools",
        tools=ProfileTools(
            recon=["katana", "nmap", "nikto"],
            discovery=[],
            vuln_scan=["nuclei-full"],
            enrichment=["cve_service", "exploit_db", "http_probe"],
        ),
        inference_engine=True,
        nmap_strategy="dual",  # Use dual strategy for comprehensive scanning
    ),
    "web-only": ScanProfile(
        name="web-only",
        description="Web-focused assessment only",
        tools=ProfileTools(
            recon=["katana"],
            discovery=[],
            vuln_scan=["nuclei-web"],
            enrichment=["cve_service", "http_probe"],
        ),
        inference_engine=True,
    ),
    "vuln-focused": ScanProfile(
        name="vuln-focused",
        description="Only vulnerability scanning",
        tools=ProfileTools(
            recon=[],
            discovery=[],
            vuln_scan=["nuclei"],
            enrichment=[],
        ),
        inference_engine=False,
    ),
}


def get_profile(name: str) -> ScanProfile:
    """Get a scan profile by name."""
    return PROFILES.get(name, PROFILES["standard"])
