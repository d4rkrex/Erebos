"""Match network templates to detected services.

Maps nuclei network templates to services discovered via nmap based on
port number, service name tags, and product identification.
"""

from typing import List, Optional, Tuple

from pydantic import BaseModel, Field, field_validator

from erebos.scanners.network_template import NetworkTemplate


class ServiceInfo(BaseModel):
    """Detected network service from nmap/recon."""

    host: str
    port: int
    protocol: str = "tcp"  # tcp, udp
    service: str = ""  # e.g., "ftp", "ssh", "redis"
    product: str = ""  # e.g., "OpenSSH", "vsftpd"
    version: str = ""  # e.g., "8.2p1"
    banner: str = ""

    @field_validator("host")
    @classmethod
    def validate_host(cls, v: str) -> str:
        """Basic host validation — not empty."""
        if not v or not v.strip():
            raise ValueError("Host cannot be empty")
        return v.strip()

    @field_validator("port")
    @classmethod
    def validate_port(cls, v: int) -> int:
        """Port must be valid."""
        if v < 1 or v > 65535:
            raise ValueError(f"Port must be 1-65535, got {v}")
        return v

    @field_validator("protocol")
    @classmethod
    def validate_protocol(cls, v: str) -> str:
        """Only tcp/udp allowed."""
        if v.lower() not in ("tcp", "udp"):
            raise ValueError(f"Protocol must be tcp or udp, got {v}")
        return v.lower()


class ServiceMatcher:
    """Match network templates to detected services."""

    # Port to service mapping for inference
    PORT_SERVICE_MAP = {
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        53: "dns",
        80: "http",
        110: "pop3",
        143: "imap",
        443: "https",
        445: "smb",
        993: "imaps",
        995: "pop3s",
        1433: "mssql",
        1521: "oracle",
        3306: "mysql",
        3389: "rdp",
        5432: "postgresql",
        5900: "vnc",
        6379: "redis",
        6556: "checkmk",
        8080: "http-proxy",
        8443: "https-alt",
        9200: "elasticsearch",
        11211: "memcached",
        27017: "mongodb",
    }

    # Service name aliases for fuzzy matching
    SERVICE_ALIASES = {
        "http-proxy": "http",
        "https-alt": "https",
        "https": "http",
        "imaps": "imap",
        "pop3s": "pop3",
        "ms-sql-s": "mssql",
        "microsoft-ds": "smb",
        "netbios-ssn": "smb",
    }

    def match(
        self,
        templates: List[NetworkTemplate],
        services: List[ServiceInfo],
    ) -> List[Tuple[NetworkTemplate, ServiceInfo]]:
        """Match templates to services by port, tags, and product name.

        Returns list of (template, service) pairs where the template applies
        to the detected service.
        """
        matches: List[Tuple[NetworkTemplate, ServiceInfo]] = []

        for service in services:
            for template in templates:
                if self._is_match(template, service):
                    matches.append((template, service))

        return matches

    def _is_match(self, template: NetworkTemplate, service: ServiceInfo) -> bool:
        """Check if a template matches a service."""
        # Protocol must match
        if template.protocol != service.protocol:
            return False

        # Port-based matching (strongest signal)
        if template.port is not None and template.port == service.port:
            return True

        # Tag-based matching against service name
        service_name = self._normalize_service(service.service, service.port)
        if service_name and template.target_service:
            if self._services_match(template.target_service, service_name):
                return True

        # Product-based matching against template name/tags
        if service.product:
            product_lower = service.product.lower()
            # Check if product name appears in template tags
            for tag in template.tags:
                if tag.lower() in product_lower or product_lower in tag.lower():
                    return True
            # Check template name
            if product_lower in template.name.lower():
                return True

        return False

    def _normalize_service(self, service: str, port: int) -> Optional[str]:
        """Normalize a service name using aliases and port mapping."""
        if service:
            service_lower = service.lower()
            # Check aliases first
            if service_lower in self.SERVICE_ALIASES:
                return self.SERVICE_ALIASES[service_lower]
            return service_lower

        # Fallback to port-based inference
        return self.PORT_SERVICE_MAP.get(port)

    def _services_match(self, template_service: str, detected_service: str) -> bool:
        """Check if two service names refer to the same service."""
        if template_service == detected_service:
            return True

        # Normalize both through aliases
        ts = self.SERVICE_ALIASES.get(template_service, template_service)
        ds = self.SERVICE_ALIASES.get(detected_service, detected_service)
        return ts == ds
