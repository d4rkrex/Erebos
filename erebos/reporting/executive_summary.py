"""Executive summary generation with risk scoring.

VT-Spec R6: Professional Reporting — executive summary with risk score.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from erebos.core.finding import Finding, Severity
from erebos.reporting.models import (
    ExecSummaryData,
    RiskLevel,
    RiskScore,
    ScanMetadata,
)


class ExecutiveSummary:
    """Generate executive summary with risk scoring.

    VT-Spec R6: Returns overall risk level, numeric score, findings breakdown,
    top findings, attack surface metrics, exploitation rate, timeline, and
    key remediation recommendations.
    """

    def generate(
        self,
        findings: List[Finding],
        scan_meta: ScanMetadata,
    ) -> ExecSummaryData:
        """Generate executive summary data from findings and scan metadata.

        Returns:
            ExecSummaryData with:
            - overall_risk: CRITICAL/HIGH/MEDIUM/LOW based on worst finding
            - risk_score: 0-100 numeric score
            - findings_by_severity: Counter
            - top_findings: Top 5 by severity
            - attack_surface: # endpoints, # services
            - exploitation_rate: confirmed/attempted ratio
            - timeline: scan duration, phases completed
            - key_recommendations: Top 3 remediation priorities
        """
        counts = self._count_by_severity(findings)
        risk_score = RiskScore.calculate(
            critical=counts.get("CRITICAL", 0),
            high=counts.get("HIGH", 0),
            medium=counts.get("MEDIUM", 0),
            low=counts.get("LOW", 0),
            info=counts.get("INFO", 0),
        )

        # Top findings sorted by severity
        sorted_findings = sorted(findings, key=lambda f: self._severity_rank(f.severity))
        top_findings = [f.title for f in sorted_findings[:5]]

        # Exploitation rate
        exploitation_rate = self._calc_exploitation_rate(findings)

        # Timeline
        timeline = {
            "duration": f"{scan_meta.duration_seconds:.1f}s",
            "phases_completed": ", ".join(scan_meta.phases_completed) if scan_meta.phases_completed else "N/A",
        }
        if scan_meta.start_time:
            timeline["start"] = scan_meta.start_time.isoformat()
        if scan_meta.end_time:
            timeline["end"] = scan_meta.end_time.isoformat()

        # Attack surface
        attack_surface = {
            "endpoints": scan_meta.endpoints_discovered,
            "services": scan_meta.services_discovered,
        }

        # Key recommendations
        key_recommendations = self._generate_recommendations(sorted_findings)

        return ExecSummaryData(
            overall_risk=risk_score.level,
            risk_score=risk_score,
            findings_by_severity=counts,
            top_findings=top_findings,
            attack_surface=attack_surface,
            exploitation_rate=exploitation_rate,
            timeline=timeline,
            key_recommendations=key_recommendations,
        )

    def _count_by_severity(self, findings: List[Finding]) -> Dict[str, int]:
        """Count findings by severity level."""
        counts: Dict[str, int] = {}
        for f in findings:
            sev = f.severity if isinstance(f.severity, str) else f.severity.value
            sev_upper = sev.upper()
            counts[sev_upper] = counts.get(sev_upper, 0) + 1
        return counts

    def _severity_rank(self, severity) -> int:
        """Return sort rank (lower = more severe)."""
        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        sev = severity if isinstance(severity, str) else severity.value
        try:
            return order.index(sev.upper())
        except ValueError:
            return 99

    def _calc_exploitation_rate(self, findings: List[Finding]) -> float:
        """Calculate ratio of confirmed exploits to total attempted."""
        if not findings:
            return 0.0
        exploited = sum(
            1 for f in findings
            if getattr(f, "exploitation_status", None) == "exploited"
        )
        attempted = sum(
            1 for f in findings
            if getattr(f, "exploitation_status", None) in ("exploited", "potential", "pending")
        )
        if attempted == 0:
            return 0.0
        return exploited / attempted

    def _generate_recommendations(self, sorted_findings: List[Finding]) -> List[str]:
        """Generate top 3 remediation recommendations based on findings."""
        recommendations: List[str] = []
        seen_cwes: set = set()

        for f in sorted_findings:
            if len(recommendations) >= 3:
                break
            if f.suggested_fix and f.cwe not in seen_cwes:
                recommendations.append(f.suggested_fix[:200])
                if f.cwe:
                    seen_cwes.add(f.cwe)

        # Default recommendations if not enough from findings
        if not recommendations:
            recommendations = [
                "Review and patch all critical/high severity vulnerabilities immediately.",
                "Implement input validation on all user-facing endpoints.",
                "Enable security headers (CSP, HSTS, X-Frame-Options).",
            ]

        return recommendations[:3]
