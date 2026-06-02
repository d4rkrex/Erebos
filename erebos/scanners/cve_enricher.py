"""CVE enrichment for detected services.

Queries vulnx (if available) or falls back to built-in CVE database
for common services. Enriches detected services with known vulnerability data.
"""

import json
import logging
import subprocess
from typing import List, Optional

from packaging.version import InvalidVersion, Version
from pydantic import BaseModel, Field

from erebos.scanners.service_matcher import ServiceInfo

logger = logging.getLogger(__name__)


class CVEInfo(BaseModel):
    """Known CVE information for a service."""

    cve_id: str  # e.g., CVE-2021-44228
    severity: str  # critical, high, medium, low
    cvss_score: float = 0.0
    description: str
    affected_product: str
    affected_versions: str = ""
    exploit_available: bool = False
    references: List[str] = Field(default_factory=list)


class _KnownCVEEntry(BaseModel):
    """Internal model for built-in CVE database entries."""

    versions_before: str
    cves: List[CVEInfo]


# Built-in CVE database for common services (fallback when vulnx unavailable)
KNOWN_CVES: dict = {
    "redis": _KnownCVEEntry(
        versions_before="6.2.7",
        cves=[
            CVEInfo(
                cve_id="CVE-2022-0543",
                severity="critical",
                cvss_score=10.0,
                description="Redis Lua sandbox escape - Remote Code Execution",
                affected_product="redis",
                affected_versions="< 6.2.7",
                exploit_available=True,
                references=["https://nvd.nist.gov/vuln/detail/CVE-2022-0543"],
            ),
            CVEInfo(
                cve_id="CVE-2021-32762",
                severity="high",
                cvss_score=8.8,
                description="Redis integer overflow on 32-bit systems via BITFIELD command",
                affected_product="redis",
                affected_versions="< 6.2.5",
                exploit_available=False,
                references=["https://nvd.nist.gov/vuln/detail/CVE-2021-32762"],
            ),
        ],
    ),
    "openssh": _KnownCVEEntry(
        versions_before="8.8",
        cves=[
            CVEInfo(
                cve_id="CVE-2021-41617",
                severity="high",
                cvss_score=7.0,
                description="OpenSSH privilege escalation via AuthorizedKeysCommand/AuthorizedPrincipalsCommand",
                affected_product="openssh",
                affected_versions="< 8.8",
                exploit_available=False,
                references=["https://nvd.nist.gov/vuln/detail/CVE-2021-41617"],
            ),
        ],
    ),
    "apache": _KnownCVEEntry(
        versions_before="2.4.52",
        cves=[
            CVEInfo(
                cve_id="CVE-2021-44790",
                severity="critical",
                cvss_score=9.8,
                description="Apache HTTP Server mod_lua buffer overflow",
                affected_product="apache",
                affected_versions="< 2.4.52",
                exploit_available=True,
                references=["https://nvd.nist.gov/vuln/detail/CVE-2021-44790"],
            ),
            CVEInfo(
                cve_id="CVE-2021-41773",
                severity="critical",
                cvss_score=9.8,
                description="Apache HTTP Server 2.4.49 path traversal and RCE",
                affected_product="apache",
                affected_versions="= 2.4.49",
                exploit_available=True,
                references=["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"],
            ),
        ],
    ),
    "nginx": _KnownCVEEntry(
        versions_before="1.21.4",
        cves=[
            CVEInfo(
                cve_id="CVE-2021-23017",
                severity="high",
                cvss_score=7.7,
                description="Nginx DNS resolver off-by-one heap write vulnerability",
                affected_product="nginx",
                affected_versions="< 1.21.0",
                exploit_available=True,
                references=["https://nvd.nist.gov/vuln/detail/CVE-2021-23017"],
            ),
        ],
    ),
    "mysql": _KnownCVEEntry(
        versions_before="8.0.28",
        cves=[
            CVEInfo(
                cve_id="CVE-2022-21270",
                severity="high",
                cvss_score=6.5,
                description="MySQL Server optimizer denial of service",
                affected_product="mysql",
                affected_versions="< 8.0.28",
                exploit_available=False,
                references=["https://nvd.nist.gov/vuln/detail/CVE-2022-21270"],
            ),
        ],
    ),
    "postgresql": _KnownCVEEntry(
        versions_before="14.1",
        cves=[
            CVEInfo(
                cve_id="CVE-2021-23214",
                severity="high",
                cvss_score=8.1,
                description="PostgreSQL man-in-the-middle attack via initial packet injection",
                affected_product="postgresql",
                affected_versions="< 14.1",
                exploit_available=False,
                references=["https://nvd.nist.gov/vuln/detail/CVE-2021-23214"],
            ),
        ],
    ),
    "vsftpd": _KnownCVEEntry(
        versions_before="3.0.4",
        cves=[
            CVEInfo(
                cve_id="CVE-2011-2523",
                severity="critical",
                cvss_score=10.0,
                description="vsftpd 2.3.4 backdoor command execution",
                affected_product="vsftpd",
                affected_versions="= 2.3.4",
                exploit_available=True,
                references=["https://nvd.nist.gov/vuln/detail/CVE-2011-2523"],
            ),
        ],
    ),
    "proftpd": _KnownCVEEntry(
        versions_before="1.3.7",
        cves=[
            CVEInfo(
                cve_id="CVE-2019-12815",
                severity="critical",
                cvss_score=9.8,
                description="ProFTPD arbitrary file copy via mod_copy without authentication",
                affected_product="proftpd",
                affected_versions="< 1.3.6",
                exploit_available=True,
                references=["https://nvd.nist.gov/vuln/detail/CVE-2019-12815"],
            ),
        ],
    ),
    "samba": _KnownCVEEntry(
        versions_before="4.15.2",
        cves=[
            CVEInfo(
                cve_id="CVE-2021-44142",
                severity="critical",
                cvss_score=9.9,
                description="Samba vfs_fruit out-of-bounds heap read/write via file metadata",
                affected_product="samba",
                affected_versions="< 4.15.5",
                exploit_available=True,
                references=["https://nvd.nist.gov/vuln/detail/CVE-2021-44142"],
            ),
        ],
    ),
    "elasticsearch": _KnownCVEEntry(
        versions_before="7.16.1",
        cves=[
            CVEInfo(
                cve_id="CVE-2021-44228",
                severity="critical",
                cvss_score=10.0,
                description="Log4Shell - Elasticsearch uses Log4j vulnerable to RCE",
                affected_product="elasticsearch",
                affected_versions="< 7.16.1",
                exploit_available=True,
                references=["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
            ),
        ],
    ),
    "mongodb": _KnownCVEEntry(
        versions_before="5.0.6",
        cves=[
            CVEInfo(
                cve_id="CVE-2021-32040",
                severity="high",
                cvss_score=7.5,
                description="MongoDB Server denial of service via crafted request",
                affected_product="mongodb",
                affected_versions="< 5.0.6",
                exploit_available=False,
                references=["https://nvd.nist.gov/vuln/detail/CVE-2021-32040"],
            ),
        ],
    ),
    "memcached": _KnownCVEEntry(
        versions_before="1.6.12",
        cves=[
            CVEInfo(
                cve_id="CVE-2021-37519",
                severity="high",
                cvss_score=7.5,
                description="Memcached buffer overflow on UDP amplification",
                affected_product="memcached",
                affected_versions="< 1.6.12",
                exploit_available=True,
                references=["https://nvd.nist.gov/vuln/detail/CVE-2021-37519"],
            ),
        ],
    ),
    "tomcat": _KnownCVEEntry(
        versions_before="9.0.56",
        cves=[
            CVEInfo(
                cve_id="CVE-2022-22965",
                severity="critical",
                cvss_score=9.8,
                description="Spring4Shell - RCE via data binding on Tomcat",
                affected_product="tomcat",
                affected_versions="< 9.0.62",
                exploit_available=True,
                references=["https://nvd.nist.gov/vuln/detail/CVE-2022-22965"],
            ),
        ],
    ),
    "iis": _KnownCVEEntry(
        versions_before="10.0",
        cves=[
            CVEInfo(
                cve_id="CVE-2021-31166",
                severity="critical",
                cvss_score=9.8,
                description="IIS HTTP Protocol Stack Remote Code Execution",
                affected_product="iis",
                affected_versions="< 10.0.20348",
                exploit_available=True,
                references=["https://nvd.nist.gov/vuln/detail/CVE-2021-31166"],
            ),
        ],
    ),
    "rabbitmq": _KnownCVEEntry(
        versions_before="3.9.11",
        cves=[
            CVEInfo(
                cve_id="CVE-2021-32718",
                severity="medium",
                cvss_score=5.4,
                description="RabbitMQ stored XSS in management UI",
                affected_product="rabbitmq",
                affected_versions="< 3.8.18",
                exploit_available=False,
                references=["https://nvd.nist.gov/vuln/detail/CVE-2021-32718"],
            ),
        ],
    ),
}

# Product name normalization for CVE lookup
_PRODUCT_ALIASES: dict = {
    "openss": "openssh",
    "apache httpd": "apache",
    "apache http server": "apache",
    "httpd": "apache",
    "microsoft iis": "iis",
    "mysql server": "mysql",
    "mariadb": "mysql",
    "redis server": "redis",
    "nginx": "nginx",
    "postgresql": "postgresql",
    "postgres": "postgresql",
    "apache tomcat": "tomcat",
    "elasticsearch": "elasticsearch",
    "elastic": "elasticsearch",
}


class CVEEnricher:
    """Enrich detected services with known CVE data via vulnx or built-in DB."""

    def __init__(self) -> None:
        self._vulnx_available: Optional[bool] = None

    @property
    def vulnx_available(self) -> bool:
        """Check if vulnx CLI is installed (cached)."""
        if self._vulnx_available is None:
            self._vulnx_available = self._check_vulnx()
        return self._vulnx_available

    def enrich(self, services: List[ServiceInfo]) -> List[CVEInfo]:
        """Query for known CVEs matching detected services.

        For each service with product+version:
        1. Try vulnx if available
        2. Fall back to built-in CVE database
        3. Filter: severity critical or high only
        """
        results: List[CVEInfo] = []

        for service in services:
            if not service.product:
                continue

            cves = self._lookup_cves(service)
            results.extend(cves)

        return results

    def enrich_single(self, service: ServiceInfo) -> List[CVEInfo]:
        """Enrich a single service with CVE data."""
        if not service.product:
            return []
        return self._lookup_cves(service)

    def _lookup_cves(self, service: ServiceInfo) -> List[CVEInfo]:
        """Look up CVEs for a service, trying vulnx first then built-in DB."""
        # Try vulnx if available
        if self.vulnx_available:
            vulnx_results = self._query_vulnx(service)
            if vulnx_results:
                return vulnx_results

        # Fallback to built-in database
        return self._query_builtin(service)

    def _query_builtin(self, service: ServiceInfo) -> List[CVEInfo]:
        """Query built-in CVE database for matching vulnerabilities."""
        product_key = self._normalize_product(service.product)
        if not product_key or product_key not in KNOWN_CVES:
            return []

        entry = KNOWN_CVES[product_key]

        # If we have version info, filter by affected versions
        if service.version:
            if self._is_version_affected(service.version, entry.versions_before):
                # Return only critical/high CVEs
                return [
                    cve for cve in entry.cves if cve.severity in ("critical", "high")
                ]
        else:
            # No version info — return all CVEs as potential matches
            return [cve for cve in entry.cves if cve.severity in ("critical", "high")]

        return []

    def _query_vulnx(self, service: ServiceInfo) -> List[CVEInfo]:
        """Query vulnx CLI for CVEs matching a service."""
        query = f"{service.product} {service.version}".strip()
        try:
            result = subprocess.run(
                ["vulnx", "search", query, "--json", "--limit", "10"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if result.returncode != 0:
                return []

            data = json.loads(result.stdout)
            cves: List[CVEInfo] = []
            if isinstance(data, list):
                for item in data:
                    severity = item.get("severity", "").lower()
                    if severity not in ("critical", "high"):
                        continue
                    cves.append(
                        CVEInfo(
                            cve_id=item.get("cve_id", ""),
                            severity=severity,
                            cvss_score=float(item.get("cvss_score", 0.0)),
                            description=item.get("description", ""),
                            affected_product=service.product,
                            affected_versions=item.get("affected_versions", ""),
                            exploit_available=item.get("exploit_available", False),
                            references=item.get("references", []),
                        )
                    )
            return cves
        except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
            return []

    def _check_vulnx(self) -> bool:
        """Check if vulnx CLI is installed."""
        try:
            subprocess.run(
                ["vulnx", "version"],
                capture_output=True,
                timeout=5,
            )
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return False

    def _normalize_product(self, product: str) -> Optional[str]:
        """Normalize product name to match built-in CVE database keys."""
        product_lower = product.lower().strip()

        # Direct match
        if product_lower in KNOWN_CVES:
            return product_lower

        # Check aliases
        for alias, canonical in _PRODUCT_ALIASES.items():
            if alias in product_lower:
                return canonical

        return None

    def _is_version_affected(self, detected_version: str, max_version: str) -> bool:
        """Check if detected version is below the patched version.

        Uses packaging.version for comparison with fallback to string comparison.
        """
        try:
            # Clean version string (remove suffixes like "p1", "-ubuntu")
            clean_detected = self._clean_version(detected_version)
            clean_max = self._clean_version(max_version)

            detected_v = Version(clean_detected)
            max_v = Version(clean_max)
            return detected_v < max_v
        except InvalidVersion:
            # Fallback: simple string comparison
            return detected_version < max_version

    def _clean_version(self, version: str) -> str:
        """Clean version string for comparison.

        Removes common suffixes like 'p1', '-ubuntu', '+deb10u4', etc.
        """
        import re

        # Extract numeric version (e.g., "8.2p1" -> "8.2", "1.18.0-2ubuntu1" -> "1.18.0")
        match = re.match(r"(\d+(?:\.\d+)*)", version)
        if match:
            return match.group(1)
        return version
