"""Attack surface scoring for target profiles."""

from __future__ import annotations

from typing import TYPE_CHECKING

from erebos.core.target_profile import RiskLevel

if TYPE_CHECKING:
    from erebos.core.target_profile import TargetProfile


class AttackSurfaceScorer:
    """Calculate attack surface score and risk class."""

    def calculate_score(self, profile: TargetProfile) -> float:
        """Calculate attack surface score in the 0.0-10.0 range."""
        open_ports_count = len(
            [service for service in profile.services if service.state != "closed"]
        )
        base_score = 1.0 if (profile.services or profile.technologies) else 0.0
        port_score = min(3.0, open_ports_count * 0.15)
        tech_score = min(3.0, self._technology_risk(profile))
        exposure_score = self._exposure_score(profile)
        return round(min(10.0, base_score + port_score + tech_score + exposure_score), 2)

    def classify_risk(self, score: float) -> RiskLevel:
        """Map score to risk level."""
        if score >= 8.0:
            return RiskLevel.CRITICAL
        if score >= 6.0:
            return RiskLevel.HIGH
        if score >= 4.0:
            return RiskLevel.MEDIUM
        if score >= 2.0:
            return RiskLevel.LOW
        return RiskLevel.INFORMATIONAL

    def _technology_risk(self, profile: TargetProfile) -> float:
        tech_names = {technology.name.lower() for technology in profile.technologies}
        service_ports = {service.port for service in profile.services if service.state != "closed"}
        score = 0.0

        if {3306, 5432, 27017, 6379} & service_ports:
            score += 2.0
        if {22, 3389} & service_ports:
            score += 1.5
        if {21, 69} & service_ports:
            score += 1.0
        if 2375 in service_ports or 6443 in service_ports:
            score += 2.5
        if {"wordpress", "drupal", "joomla"} & tech_names:
            score += 1.5
        if {"wordpress", "drupal", "joomla"} & tech_names and any(
            marker in profile.fingerprints for marker in ["wp-admin", "administrator", "/admin"]
        ):
            score += 2.0
        if any(
            technology.version
            for technology in profile.technologies
            if technology.category == "web_server"
        ):
            score += 1.0
        return score

    def _exposure_score(self, profile: TargetProfile) -> float:
        level = str(profile.metadata.get("exposure_level", "internal"))
        score = {
            "internal": 0.0,
            "partner": 0.5,
            "internet_facing": 1.5,
            "highly_exposed": 3.0,
        }.get(level, 0.0)
        security_headers = profile.metadata.get("security_headers", {})
        if level in {"internet_facing", "highly_exposed"} and security_headers:
            if security_headers.get("hsts") and security_headers.get("csp"):
                score = max(0.0, score - 1.0)
        return score
