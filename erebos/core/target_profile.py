"""Target profiling models and builder service."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
import json
from importlib import metadata
from typing import TYPE_CHECKING, Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlparse
import ipaddress
import re

from erebos.enrichment.http_probe import HttpProbeResult

if TYPE_CHECKING:
    from erebos.detection.attack_surface import AttackSurfaceScorer
    from erebos.detection.technology_detector import TechnologyDetector
    from erebos.parsers.nmap import NmapScanResult, PortInfo


class TargetType(str, Enum):
    """Classification of target type."""

    WEB_APPLICATION = "web_application"
    NETWORK_HOST = "network_host"
    API_ENDPOINT = "api_endpoint"
    CLOUD_SERVICE = "cloud_service"
    CONTAINER = "container"
    UNKNOWN = "unknown"


class RiskLevel(str, Enum):
    """Risk level classification."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


@dataclass(frozen=True)
class Technology:
    """Detected technology component."""

    name: str
    version: Optional[str] = None
    confidence: float = 0.0
    source: str = ""
    category: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the technology to a dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Technology":
        """Deserialize a technology from a dictionary."""
        return cls(
            name=str(data.get("name", "")),
            version=data.get("version"),
            confidence=float(data.get("confidence", 0.0)),
            source=str(data.get("source", "")),
            category=data.get("category"),
        )


@dataclass(frozen=True)
class Service:
    """Network service information."""

    port: int
    protocol: str = "tcp"
    service: str = ""
    version: Optional[str] = None
    state: str = "open"
    confidence: float = 0.0
    cpe: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the service to a dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Service":
        """Deserialize a service from a dictionary."""
        return cls(
            port=int(data.get("port", 0)),
            protocol=str(data.get("protocol", "tcp")),
            service=str(data.get("service", "")),
            version=data.get("version"),
            state=str(data.get("state", "open")),
            confidence=float(data.get("confidence", 0.0)),
            cpe=data.get("cpe"),
        )


@dataclass
class TargetProfile:
    """Complete target intelligence profile."""

    target: str
    host: str
    port: Optional[int] = None
    scheme: Optional[str] = None
    target_type: TargetType = TargetType.UNKNOWN
    target_type_confidence: float = 0.0
    technologies: List[Technology] = field(default_factory=list)
    services: List[Service] = field(default_factory=list)
    attack_surface_score: float = 0.0
    risk_level: RiskLevel = RiskLevel.INFORMATIONAL
    confidence: float = 0.0
    fingerprints: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the profile to a JSON-safe dictionary."""
        return {
            "target": self.target,
            "host": self.host,
            "port": self.port,
            "scheme": self.scheme,
            "target_type": self.target_type.value,
            "target_type_confidence": self.target_type_confidence,
            "technologies": [tech.to_dict() for tech in self.technologies],
            "services": [service.to_dict() for service in self.services],
            "attack_surface_score": self.attack_surface_score,
            "risk_level": self.risk_level.value,
            "confidence": self.confidence,
            "fingerprints": list(self.fingerprints),
            "metadata": dict(self.metadata),
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }

    def model_dump_json(self) -> str:
        """Provide a Pydantic-like JSON serialization API for compatibility."""
        return json.dumps(self.to_dict(), default=str)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TargetProfile":
        """Deserialize a profile from a dictionary."""
        return cls(
            target=str(data.get("target", "")),
            host=str(data.get("host", "")),
            port=int(data["port"]) if data.get("port") is not None else None,
            scheme=data.get("scheme"),
            target_type=TargetType(data.get("target_type", TargetType.UNKNOWN.value)),
            target_type_confidence=float(data.get("target_type_confidence", 0.0)),
            technologies=[
                Technology.from_dict(item) for item in data.get("technologies", []) if item
            ],
            services=[Service.from_dict(item) for item in data.get("services", []) if item],
            attack_surface_score=float(data.get("attack_surface_score", 0.0)),
            risk_level=RiskLevel(data.get("risk_level", RiskLevel.INFORMATIONAL.value)),
            confidence=float(data.get("confidence", 0.0)),
            fingerprints=[str(item) for item in data.get("fingerprints", [])],
            metadata=dict(data.get("metadata", {})),
            created_at=_parse_datetime(data.get("created_at")),
            updated_at=_parse_datetime(data.get("updated_at")),
        )

    @classmethod
    def model_validate_json(cls, payload: str) -> "TargetProfile":
        """Provide a Pydantic-like JSON deserialization API for compatibility."""
        return cls.from_dict(json.loads(payload))


def _parse_datetime(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str) and value:
        return datetime.fromisoformat(value)
    return datetime.now(timezone.utc)


class TargetProfiler:
    """Build target profiles from scan artifacts.

    Example:
        profiler = TargetProfiler(enable_profile=True)
        profile = profiler.create_profile("https://example.com", nmap_result, http_results)
    """

    def __init__(
        self,
        enable_profile: bool = True,
        detectors: Optional[Sequence[TechnologyDetector]] = None,
    ):
        from erebos.detection.attack_surface import AttackSurfaceScorer

        self._enable_profile = enable_profile
        self._detectors: List[TechnologyDetector] = list(detectors or self._default_detectors())
        self._detectors.extend(self._load_plugin_detectors())
        self._scorer = AttackSurfaceScorer()

    def create_profile(
        self,
        target: str,
        nmap_result: Optional[NmapScanResult] = None,
        http_results: Optional[Dict[Tuple[str, int], HttpProbeResult]] = None,
        scan_id: Optional[str] = None,
        completed_phases: Optional[Iterable[str]] = None,
    ) -> Optional[TargetProfile]:
        """Create a target profile from nmap and HTTP probe results."""
        if not self._enable_profile:
            return None

        host, port, scheme = self._parse_target(target)
        http_results = http_results or {}
        if nmap_result is None:
            from erebos.parsers.nmap import NmapScanResult as _NmapScanResult

            nmap_result = _NmapScanResult()
        services = self._services_from_nmap(nmap_result)
        technologies = self._detect_technologies(nmap_result, http_results)
        target_type, target_type_confidence = self._classify_target_type(
            target=target,
            host=host,
            port=port,
            technologies=technologies,
            services=services,
            http_results=http_results,
        )

        profile = TargetProfile(
            target=target,
            host=host,
            port=port,
            scheme=scheme,
            target_type=target_type,
            target_type_confidence=target_type_confidence,
            technologies=technologies,
            services=services,
            metadata={
                "scan_id": scan_id,
                "enrichment_sources": self._collect_sources(nmap_result, http_results),
                "scan_phases_completed": list(completed_phases or []),
                "exposure_level": self._determine_exposure_level(host, http_results),
                "security_headers": self._collect_security_headers(http_results),
            },
        )
        profile.fingerprints = self._collect_fingerprints(
            nmap_result, http_results, profile.technologies
        )
        profile.attack_surface_score = self._scorer.calculate_score(profile)
        profile.risk_level = self._scorer.classify_risk(profile.attack_surface_score)
        profile.confidence = self._calculate_confidence(profile, nmap_result, http_results)
        return profile

    def update_profile(
        self,
        profile: TargetProfile,
        nmap_result: Optional[NmapScanResult] = None,
        http_results: Optional[Dict[Tuple[str, int], HttpProbeResult]] = None,
        completed_phase: Optional[str] = None,
    ) -> TargetProfile:
        """Incrementally enrich an existing profile."""
        updated = self.create_profile(
            target=profile.target,
            nmap_result=nmap_result,
            http_results=http_results,
            scan_id=str(profile.metadata.get("scan_id", "")) or None,
            completed_phases=(profile.metadata.get("scan_phases_completed", []) or []),
        )
        if updated is None:
            return profile
        updated.created_at = profile.created_at
        updated.updated_at = datetime.now(timezone.utc)
        phases = list(profile.metadata.get("scan_phases_completed", []) or [])
        if completed_phase and completed_phase not in phases:
            phases.append(completed_phase)
        updated.metadata["scan_phases_completed"] = phases
        return updated

    def _default_detectors(self) -> List[TechnologyDetector]:
        from erebos.detection.technology_detector import (
            ContentPatternDetector,
            HttpHeaderDetector,
            NmapBannerDetector,
            PortBasedDetector,
        )

        return [
            HttpHeaderDetector(),
            ContentPatternDetector(),
            NmapBannerDetector(),
            PortBasedDetector(),
        ]

    def _load_plugin_detectors(self) -> List[TechnologyDetector]:
        """Load detector plugins registered via Python entry points."""
        try:
            entry_points = metadata.entry_points()
            group = entry_points.select(group="erebos.technology_detectors")
        except Exception:
            return []

        detectors: List[TechnologyDetector] = []
        for entry_point in group:
            try:
                loaded = entry_point.load()
                detector = loaded() if isinstance(loaded, type) else loaded
                if hasattr(detector, "detect_from_nmap") and hasattr(detector, "detect_from_http"):
                    detectors.append(detector)
            except Exception:
                continue
        return detectors

    def _parse_target(self, target: str) -> Tuple[str, Optional[int], Optional[str]]:
        if not target:
            raise ValueError("Target cannot be empty")

        if "://" in target:
            parsed = urlparse(target)
            if not parsed.hostname:
                raise ValueError(f"Invalid target format: {target}")
            default_port = (
                443 if parsed.scheme == "https" else 80 if parsed.scheme == "http" else None
            )
            return parsed.hostname, parsed.port or default_port, parsed.scheme or None

        if re.match(r"^[A-Za-z0-9.-]+:\d+$", target):
            host, port_str = target.rsplit(":", 1)
            return host, int(port_str), None

        return target, None, None

    def _services_from_nmap(self, nmap_result: NmapScanResult) -> List[Service]:
        services: List[Service] = []
        for port in nmap_result.ports:
            if port.state == "closed":
                continue
            services.append(
                Service(
                    port=int(port.port),
                    protocol=port.protocol,
                    service=port.service or port.product.lower() or "unknown",
                    version=port.version or None,
                    state=port.state,
                    confidence=self._service_confidence(port),
                    cpe=port.cpe or None,
                )
            )
        return services

    def _service_confidence(self, port: PortInfo) -> float:
        if port.cpe:
            return 0.95
        if port.product and port.version:
            return 0.9
        if port.service:
            return 0.75
        return 0.4

    def _detect_technologies(
        self,
        nmap_result: NmapScanResult,
        http_results: Dict[Tuple[str, int], HttpProbeResult],
    ) -> List[Technology]:
        detected: Dict[Tuple[str, str, Optional[str]], Technology] = {}

        for detector in self._detectors:
            for technology in detector.detect_from_nmap(nmap_result):
                self._merge_technology(detected, technology)
            for http_result in http_results.values():
                for technology in detector.detect_from_http(http_result):
                    self._merge_technology(detected, technology)

        return sorted(detected.values(), key=lambda item: (-item.confidence, item.name.lower()))

    def _merge_technology(
        self,
        detected: Dict[Tuple[str, str, Optional[str]], Technology],
        technology: Technology,
    ) -> None:
        key = (technology.name.lower(), technology.source, technology.version)
        existing = detected.get(key)
        if existing is None or technology.confidence > existing.confidence:
            detected[key] = technology

    def _classify_target_type(
        self,
        target: str,
        host: str,
        port: Optional[int],
        technologies: List[Technology],
        services: List[Service],
        http_results: Dict[Tuple[str, int], HttpProbeResult],
    ) -> Tuple[TargetType, float]:
        tech_names = {tech.name.lower() for tech in technologies}
        service_names = {service.service.lower() for service in services}
        ports = {service.port for service in services}
        http_samples = list(http_results.values())

        if 2375 in ports or 2376 in ports or 6443 in ports:
            return TargetType.CONTAINER, 0.85

        if any(result.is_http and self._looks_like_api(result) for result in http_samples):
            return TargetType.API_ENDPOINT, 0.8

        if any(result.is_http and self._looks_like_web(result) for result in http_samples):
            return TargetType.WEB_APPLICATION, 0.85

        if {"wordpress", "drupal", "joomla"} & tech_names:
            return TargetType.WEB_APPLICATION, 0.9

        if any(name in tech_names for name in {"react", "vue.js", "angular", "nginx", "apache"}):
            return TargetType.WEB_APPLICATION, 0.8

        if any(name in service_names for name in {"http", "https"}) or (
            port in {80, 443, 8080, 8443}
        ):
            return TargetType.WEB_APPLICATION, 0.7

        if self._is_cloud_target(target, host, tech_names):
            return TargetType.CLOUD_SERVICE, 0.65

        if service_names:
            return TargetType.NETWORK_HOST, 0.75

        return TargetType.UNKNOWN, 0.2

    def _is_cloud_target(self, target: str, host: str, tech_names: set[str]) -> bool:
        lowered = f"{target} {host}".lower()
        cloud_markers = ["amazonaws.com", "azure", "cloudapp", "googleusercontent.com", "gcp"]
        return any(marker in lowered for marker in cloud_markers) or bool(
            {"cloudflare", "aws elb", "akamai"} & tech_names
        )

    def _looks_like_api(self, result: HttpProbeResult) -> bool:
        body = (result.body or "").lower()
        content_type = (result.content_type or "").lower()
        return (
            "application/json" in content_type
            or "application/xml" in content_type
            or body.startswith("{")
            or body.startswith("[")
            or "/api/" in body
            or "graphql" in body
        ) and "<html" not in body

    def _looks_like_web(self, result: HttpProbeResult) -> bool:
        body = (result.body or "").lower()
        content_type = (result.content_type or "").lower()
        return "text/html" in content_type or "<html" in body or "<!doctype html" in body

    def _determine_exposure_level(
        self,
        host: str,
        http_results: Dict[Tuple[str, int], HttpProbeResult],
    ) -> str:
        is_public = self._is_public_host(host)
        missing_headers = any(
            not result.headers.get("strict-transport-security")
            and not result.headers.get("content-security-policy")
            for result in http_results.values()
            if result.is_http
        )
        has_cdn = any(
            header in result.headers
            for result in http_results.values()
            for header in ("cf-ray", "x-akamai-request-id")
        )
        if not is_public:
            return "internal"
        if has_cdn and missing_headers:
            return "highly_exposed"
        return "internet_facing"

    def _collect_security_headers(
        self,
        http_results: Dict[Tuple[str, int], HttpProbeResult],
    ) -> Dict[str, bool]:
        flags = {
            "hsts": False,
            "csp": False,
            "x_frame_options": False,
            "x_content_type_options": False,
        }
        for result in http_results.values():
            headers = result.headers
            if not headers:
                continue
            flags["hsts"] = flags["hsts"] or bool(headers.get("strict-transport-security"))
            flags["csp"] = flags["csp"] or bool(headers.get("content-security-policy"))
            flags["x_frame_options"] = flags["x_frame_options"] or bool(
                headers.get("x-frame-options")
            )
            flags["x_content_type_options"] = flags["x_content_type_options"] or bool(
                headers.get("x-content-type-options")
            )
        return flags

    def _collect_sources(
        self,
        nmap_result: NmapScanResult,
        http_results: Dict[Tuple[str, int], HttpProbeResult],
    ) -> List[str]:
        sources: List[str] = []
        if nmap_result.ports or nmap_result.os_matches:
            sources.append("nmap")
        if http_results:
            sources.append("http_probe")
        return sources

    def _collect_fingerprints(
        self,
        nmap_result: NmapScanResult,
        http_results: Dict[Tuple[str, int], HttpProbeResult],
        technologies: List[Technology],
    ) -> List[str]:
        fingerprints: List[str] = []
        for port in nmap_result.ports:
            if port.cpe:
                fingerprints.append(port.cpe)
            if port.product:
                fingerprints.append(f"service:{port.product.lower()}")
        for result in http_results.values():
            for key, value in result.headers.items():
                fingerprints.append(f"{key}: {value}")
            body = (result.body or "").lower()
            for marker in ["wp-content", "drupal.settings", "__next_data__", "graphql", "ng-app"]:
                if marker in body:
                    fingerprints.append(marker)
        for technology in technologies:
            fingerprints.append(f"tech:{technology.name.lower()}")
        return sorted(set(fingerprints))

    def _calculate_confidence(
        self,
        profile: TargetProfile,
        nmap_result: NmapScanResult,
        http_results: Dict[Tuple[str, int], HttpProbeResult],
    ) -> float:
        tech_confidence = (
            sum(tech.confidence for tech in profile.technologies) / len(profile.technologies)
            if profile.technologies
            else 0.0
        )
        if any(port.cpe or (port.product and port.version) for port in nmap_result.ports):
            port_confidence = 0.9
        elif profile.services:
            port_confidence = 0.6
        else:
            port_confidence = 0.3

        exposure_level = str(profile.metadata.get("exposure_level", "unknown"))
        exposure_confidence = {
            "highly_exposed": 0.9,
            "internet_facing": 0.8,
            "internal": 0.5,
        }.get(exposure_level, 0.2)
        if not http_results and not profile.services:
            exposure_confidence = min(exposure_confidence, 0.2)

        return min(1.0, tech_confidence * 0.4 + port_confidence * 0.3 + exposure_confidence * 0.3)

    def _is_public_host(self, host: str) -> bool:
        try:
            return not ipaddress.ip_address(host).is_private
        except ValueError:
            return host not in {"localhost", "127.0.0.1"}
