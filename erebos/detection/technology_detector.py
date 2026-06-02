"""Technology detector plugins used by TargetProfiler."""

from __future__ import annotations

from abc import ABC, abstractmethod
import re
from typing import TYPE_CHECKING, Dict, Iterable, List, Tuple

from erebos.enrichment.http_probe import HttpProbeResult
from erebos.parsers.nmap import NmapScanResult

if TYPE_CHECKING:
    from erebos.core.target_profile import Technology


class TechnologyDetector(ABC):
    """Abstract base for technology detection plugins."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable detector name."""

    @abstractmethod
    def detect_from_nmap(self, nmap_result: NmapScanResult) -> List[Technology]:
        """Detect technologies from nmap output."""

    @abstractmethod
    def detect_from_http(self, http_result: HttpProbeResult) -> List[Technology]:
        """Detect technologies from HTTP probe data."""


class HttpHeaderDetector(TechnologyDetector):
    """Detect technologies from HTTP headers."""

    SERVER_PATTERNS: Tuple[Tuple[str, str, str], ...] = (
        (r"apache/?([\d.]+)?", "Apache", "web_server"),
        (r"nginx/?([\d.]+)?", "nginx", "web_server"),
        (r"microsoft-iis/?([\d.]+)?", "IIS", "web_server"),
        (r"awselb/?([\d.]+)?", "AWS ELB", "cloud"),
    )
    POWERED_BY_PATTERNS: Tuple[Tuple[str, str, str], ...] = (
        (r"php/?([\d.]+)?", "PHP", "language"),
        (r"asp\.net", "ASP.NET", "framework"),
        (r"express", "Node.js", "runtime"),
    )

    @property
    def name(self) -> str:
        return "http_header"

    def detect_from_nmap(self, nmap_result: NmapScanResult) -> List[Technology]:
        return []

    def detect_from_http(self, http_result: HttpProbeResult) -> List[Technology]:
        from erebos.core.target_profile import Technology

        technologies: List[Technology] = []
        headers = http_result.headers
        server = headers.get("server", http_result.server_banner or "")
        powered_by = headers.get("x-powered-by", "")
        generator = headers.get("x-generator", "")

        technologies.extend(self._match_patterns(server, self.SERVER_PATTERNS, 0.8, "http_header"))
        technologies.extend(
            self._match_patterns(powered_by, self.POWERED_BY_PATTERNS, 0.7, "http_header")
        )
        if generator:
            technologies.append(
                Technology(
                    name=generator.split("/")[0].strip(),
                    version=_extract_version(generator),
                    confidence=0.6,
                    source="http_header",
                    category="cms",
                )
            )
        if "cf-ray" in headers:
            technologies.append(
                Technology(
                    name="Cloudflare",
                    confidence=0.9,
                    source="http_header",
                    category="cdn",
                )
            )
        if any(key.startswith("x-akamai") for key in headers):
            technologies.append(
                Technology(name="Akamai", confidence=0.9, source="http_header", category="cdn")
            )
        return technologies

    def _match_patterns(
        self,
        value: str,
        patterns: Iterable[Tuple[str, str, str]],
        confidence: float,
        source: str,
    ) -> List[Technology]:
        from erebos.core.target_profile import Technology

        technologies: List[Technology] = []
        lowered = value.lower()
        for pattern, name, category in patterns:
            match = re.search(pattern, lowered)
            if match:
                version = match.group(1) if match.lastindex else None
                technologies.append(
                    Technology(
                        name=name,
                        version=version,
                        confidence=confidence,
                        source=source,
                        category=category,
                    )
                )
        return technologies


class ContentPatternDetector(TechnologyDetector):
    """Detect technologies from HTTP content patterns."""

    PATTERNS: Tuple[Tuple[str, str, float, str], ...] = (
        (r"wp-content|wp-includes|wp-admin", "WordPress", 0.9, "cms"),
        (r"drupal\.settings|sites/default|/modules/", "Drupal", 0.9, "cms"),
        (r"joomla", "Joomla", 0.8, "cms"),
        (r"__react_devtools_global_hook__|react(?:\.min)?\.js", "React", 0.8, "frontend"),
        (r"__vue__|vue(?:\.min)?\.js|_nuxt/", "Vue.js", 0.8, "frontend"),
        (r"ng-app|angular(?:\.min)?\.js", "Angular", 0.8, "frontend"),
        (r"__next_data__", "Next.js", 0.9, "frontend"),
        (r"jquery(?:\.min)?\.js", "jQuery", 0.8, "frontend"),
    )

    @property
    def name(self) -> str:
        return "content_pattern"

    def detect_from_nmap(self, nmap_result: NmapScanResult) -> List[Technology]:
        return []

    def detect_from_http(self, http_result: HttpProbeResult) -> List[Technology]:
        from erebos.core.target_profile import Technology

        content = (http_result.body or "").lower()
        technologies: List[Technology] = []
        for pattern, name, confidence, category in self.PATTERNS:
            if re.search(pattern, content):
                technologies.append(
                    Technology(
                        name=name,
                        confidence=confidence,
                        source="content",
                        category=category,
                    )
                )
        return technologies


class NmapBannerDetector(TechnologyDetector):
    """Detect technologies from nmap products and CPEs."""

    CPE_MAP: Dict[str, Tuple[str, str]] = {
        "apache:http_server": ("Apache", "web_server"),
        "nginx:nginx": ("nginx", "web_server"),
        "oracle:mysql": ("MySQL", "database"),
        "redis:redis": ("Redis", "database"),
        "postgresql:postgresql": ("PostgreSQL", "database"),
        "mongodb:mongodb": ("MongoDB", "database"),
    }

    @property
    def name(self) -> str:
        return "nmap_banner"

    def detect_from_nmap(self, nmap_result: NmapScanResult) -> List[Technology]:
        from erebos.core.target_profile import Technology

        technologies: List[Technology] = []
        for port in nmap_result.ports:
            if port.cpe:
                lowered = port.cpe.lower()
                for fragment, (name, category) in self.CPE_MAP.items():
                    if fragment in lowered:
                        technologies.append(
                            Technology(
                                name=name,
                                version=port.version or _extract_version(port.cpe),
                                confidence=0.9,
                                source="nmap",
                                category=category,
                            )
                        )
                        break
            elif port.product:
                technologies.append(
                    Technology(
                        name=port.product,
                        version=port.version or None,
                        confidence=0.75,
                        source="nmap",
                        category="service",
                    )
                )
        return technologies

    def detect_from_http(self, http_result: HttpProbeResult) -> List[Technology]:
        return []


class PortBasedDetector(TechnologyDetector):
    """Infer technologies from open ports."""

    PORT_MAP: Dict[int, Tuple[str, float, str]] = {
        21: ("FTP", 0.7, "file_transfer"),
        22: ("SSH", 0.7, "auth"),
        25: ("SMTP", 0.7, "mail"),
        80: ("HTTP", 0.5, "web"),
        443: ("HTTPS", 0.5, "web"),
        3306: ("MySQL", 0.7, "database"),
        5432: ("PostgreSQL", 0.7, "database"),
        6379: ("Redis", 0.7, "database"),
        27017: ("MongoDB", 0.7, "database"),
        8080: ("HTTP Alt", 0.4, "web"),
        2375: ("Docker", 0.8, "container"),
        6443: ("Kubernetes API", 0.8, "container"),
    }

    @property
    def name(self) -> str:
        return "port_based"

    def detect_from_nmap(self, nmap_result: NmapScanResult) -> List[Technology]:
        from erebos.core.target_profile import Technology

        technologies: List[Technology] = []
        for port in nmap_result.ports:
            mapping = self.PORT_MAP.get(int(port.port))
            if mapping and port.state != "closed":
                name, confidence, category = mapping
                technologies.append(
                    Technology(name=name, confidence=confidence, source="port", category=category)
                )
        return technologies

    def detect_from_http(self, http_result: HttpProbeResult) -> List[Technology]:
        return []


def _extract_version(value: str) -> str | None:
    match = re.search(r"(\d+(?:\.\d+)+)", value)
    return match.group(1) if match else None
