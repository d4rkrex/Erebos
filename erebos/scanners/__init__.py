"""Infrastructure scanning module for Erebos.

Provides network template-based vulnerability scanning, service matching,
and CVE enrichment for detected infrastructure services.
"""

from erebos.scanners.cve_enricher import CVEEnricher, CVEInfo
from erebos.scanners.infra_scanner import InfraScanner
from erebos.scanners.network_template import (
    NetworkInput,
    NetworkMatcher,
    NetworkTemplate,
    NetworkTemplateParser,
)
from erebos.scanners.service_matcher import ServiceInfo, ServiceMatcher

__all__ = [
    "CVEEnricher",
    "CVEInfo",
    "InfraScanner",
    "NetworkInput",
    "NetworkMatcher",
    "NetworkTemplate",
    "NetworkTemplateParser",
    "ServiceInfo",
    "ServiceMatcher",
]
