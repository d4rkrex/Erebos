"""Markdown report generation.

# VT-Spec ID-001 HIGH: All evidence fields scrubbed via scrub_credentials() before output.
"""

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from erebos.core.finding import Finding, Severity
from erebos.core.target_profile import TargetProfile
from erebos.executor.output import OutputManager
from erebos.reporting.models import sanitize_report_path

# DAST tool identifiers used to route findings to the DAST section
DAST_TOOLS = {"dast-injection", "api-security", "nuclei-dast"}

# Mapping from DAST tool names to pipeline stage labels
_DAST_TOOL_TO_STAGE: Dict[str, str] = {
    "dast-injection": "Fast Scan",
    "api-security": "API Security",
    "nuclei-dast": "Nuclei Deep Scan",
}

# Severity badge mapping
_SEVERITY_BADGE: Dict[str, str] = {
    "CRITICAL": "🔴 CRITICAL",
    "HIGH": "🟠 HIGH",
    "MEDIUM": "🟡 MEDIUM",
    "LOW": "🔵 LOW",
    "INFO": "ℹ️ INFO",
}

# Regex to detect JWT-like tokens (header.payload.signature base64 segments)
_JWT_PATTERN = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")


class MarkdownReportBuilder:
    """Builds Markdown reports from findings."""

    SEVERITY_ORDER = [
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
    ]

    def __init__(
        self,
        target: str,
        scan_id: str,
        target_profile: TargetProfile | None = None,
        phase_artifacts: Optional[Dict] = None,
    ):
        self.target = target
        self.scan_id = scan_id
        self.target_profile = target_profile
        self.phase_artifacts = phase_artifacts or {}

    def build(self, findings: List[Finding], output_dir: str = "./erebos-reports") -> Path:
        """Build a markdown report and save to file."""
        # Separate DAST findings from standard findings
        dast_findings: List[Finding] = []
        standard_findings: List[Finding] = []
        for f in findings:
            if f.tool in DAST_TOOLS:
                dast_findings.append(f)
            else:
                standard_findings.append(f)

        # Sort standard findings by severity
        sorted_findings = sorted(
            standard_findings, key=lambda f: self.SEVERITY_ORDER.index(f.severity)
        )

        # Group by severity
        by_severity: Dict[Severity, List[Finding]] = {}
        for finding in sorted_findings:
            severity = finding.severity
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(finding)

        # Build markdown
        markdown = self._build_markdown(by_severity, dast_findings)

        # Save to file
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        # VT-Spec R7: Sanitize target for filesystem-safe filename
        safe_target = sanitize_report_path(self.target)
        filename = f"{self.scan_id}_{safe_target}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.md"
        filepath = output_path / filename

        with open(filepath, "w") as f:
            f.write(markdown)

        return filepath

    def _build_markdown(self, by_severity: dict, dast_findings: List[Finding] | None = None) -> str:
        """Build the markdown content."""
        lines = []

        # Title
        lines.append(f"# Erebos Pentest Report")
        lines.append("")
        lines.append(f"**Target:** {self.target}")
        lines.append(f"**Scan ID:** {self.scan_id}")
        lines.append(f"**Generated:** {datetime.now(timezone.utc).isoformat()}")
        lines.append("")

        if self.target_profile is not None:
            lines.append("## Target Profile")
            lines.append("")
            lines.append(f"- **Type:** {self.target_profile.target_type.value}")
            lines.append(
                f"- **Attack Surface Score:** {self.target_profile.attack_surface_score:.2f}"
            )
            lines.append(f"- **Risk Level:** {self.target_profile.risk_level.value}")
            techs = ", ".join(tech.name for tech in self.target_profile.technologies[:8]) or "None"
            services = (
                ", ".join(
                    f"{service.port}/{service.protocol} {service.service}"
                    for service in self.target_profile.services[:8]
                )
                or "None"
            )
            lines.append(f"- **Technologies:** {techs}")
            lines.append(f"- **Services:** {services}")
            lines.append("")

        # Executive Summary
        lines.append("## Executive Summary")
        lines.append("")
        total = sum(len(findings) for findings in by_severity.values()) + len(dast_findings or [])
        all_findings = [finding for findings in by_severity.values() for finding in findings]
        all_findings.extend(dast_findings or [])
        critical = len(by_severity.get(Severity.CRITICAL, []))
        high = len(by_severity.get(Severity.HIGH, []))
        medium = len(by_severity.get(Severity.MEDIUM, []))
        low = len(by_severity.get(Severity.LOW, []))
        info = len(by_severity.get(Severity.INFO, []))
        # Include DAST findings in severity counts
        for df in (dast_findings or []):
            sev = df.severity if isinstance(df.severity, Severity) else Severity(df.severity)
            if sev == Severity.CRITICAL:
                critical += 1
            elif sev == Severity.HIGH:
                high += 1
            elif sev == Severity.MEDIUM:
                medium += 1
            elif sev == Severity.LOW:
                low += 1
            elif sev == Severity.INFO:
                info += 1
        degraded_findings = len([finding for finding in all_findings if finding.degraded])
        fallback_events = self.phase_artifacts.get("fallback_events", [])
        tool_status = self.phase_artifacts.get("tool_status", [])
        vuln_tool_status = [item for item in tool_status if item.get("phase") == "vuln-scan"]
        vuln_coverage_issues = len(
            [
                item
                for item in vuln_tool_status
                if item.get("status") in {"degraded", "skipped", "failed"}
            ]
        )

        lines.append(f"- **Total Findings:** {total}")
        lines.append(f"- **Critical:** {critical}")
        lines.append(f"- **High:** {high}")
        lines.append(f"- **Medium:** {medium}")
        lines.append(f"- **Low:** {low}")
        lines.append(f"- **Info:** {info}")
        lines.append(f"- **Degraded Findings:** {degraded_findings}")
        lines.append(f"- **Recovery Events:** {len(fallback_events)}")
        lines.append(f"- **Vuln Tool Coverage Issues:** {vuln_coverage_issues}")
        lines.append("")

        if vuln_tool_status:
            lines.append("## Vulnerability Scan Coverage")
            lines.append("")
            for item in vuln_tool_status:
                tool = item.get("tool", "unknown")
                status = item.get("status", "unknown")
                exit_code = item.get("exit_code", "-")
                fallback_source = item.get("fallback_source") or "-"
                error_types = ", ".join(item.get("error_types", [])) or "-"
                message = item.get("message") or ""
                lines.append(
                    f"- `{tool}` status=`{status}` exit=`{exit_code}` fallback=`{fallback_source}` errors=`{error_types}`"
                )
                if message:
                    lines.append(f"  - note: {message}")
            lines.append("")

        if fallback_events:
            lines.append("## Recovery Summary")
            lines.append("")
            for event in fallback_events:
                tool = event.get("tool", "unknown")
                error_type = event.get("error_type", "unknown")
                strategy = event.get("recovery_strategy", "unknown")
                fallback_tool = event.get("fallback_tool") or "-"
                success = "success" if event.get("success") else "failed"
                lines.append(
                    f"- `{tool}` -> `{fallback_tool}` | error=`{error_type}` strategy=`{strategy}` outcome={success}"
                )
            lines.append("")

        # Findings by severity
        for severity in self.SEVERITY_ORDER:
            findings = by_severity.get(severity, [])
            if not findings:
                continue

            lines.append(f"## {severity.value} Findings ({len(findings)})")
            lines.append("")

            for i, finding in enumerate(findings, 1):
                lines.append(f"### {i}. {finding.title}")
                lines.append("")
                lines.append(f"**Tool:** {finding.tool}")
                lines.append(f"**Phase:** {finding.phase_found}")
                if finding.degraded:
                    lines.append("**Degraded Execution:** Yes")
                if finding.fallback_source:
                    lines.append(f"**Fallback Source:** {finding.fallback_source}")
                if finding.cve:
                    lines.append(f"**CVE:** {finding.cve}")
                if finding.cwe:
                    lines.append(f"**CWE:** {finding.cwe}")
                lines.append("")
                lines.append("**Description**")
                lines.append(finding.description)
                lines.append("")

                # VT-Spec ID-001 HIGH: Scrub credentials from all evidence fields
                _scrubber = OutputManager(storage_dir=Path("/dev/null"))
                if finding.evidence.url:
                    lines.append("**Evidence (URL)**")
                    lines.append(f"`{_scrubber.scrub_credentials(finding.evidence.url)}`")
                    lines.append("")

                if finding.evidence.payload:
                    lines.append("**Payload**")
                    scrubbed_payload = _scrubber.scrub_credentials(finding.evidence.payload)
                    lines.append(f"```\n{scrubbed_payload}\n```")
                    lines.append("")

                if finding.evidence.output:
                    lines.append("**Output**")
                    scrubbed_output = _scrubber.scrub_credentials(finding.evidence.output[:500])
                    lines.append(f"```\n{scrubbed_output}\n```")
                    lines.append("")

                if finding.suggested_fix:
                    lines.append("**Suggested Fix**")
                    lines.append(finding.suggested_fix)
                    lines.append("")

                lines.append("---")
                lines.append("")

        # DAST Findings section
        if dast_findings:
            lines.extend(self._build_dast_section(dast_findings))

        # Recommendations
        lines.append("## Recommendations")
        lines.append("")
        if critical > 0:
            lines.append("⚠️ **Critical:** Address critical vulnerabilities immediately.")
        if high > 0:
            lines.append("🔴 **High:** Schedule remediation for high-severity findings.")
        if medium > 0:
            lines.append("🟡 **Medium:** Plan remediation in next sprint.")
        lines.append("")

        # Manual validation notes
        lines.append("## Manual Validation Recommended")
        lines.append("")
        lines.append("The following findings should be manually validated:")
        for finding in all_findings:
            if not finding.validated_manually:
                lines.append(f"- {finding.title}")
        lines.append("")

        return "\n".join(lines)

    @staticmethod
    def _redact_tokens(text: str) -> str:
        """Redact JWT-like tokens from evidence text to avoid credential leakage."""
        return _JWT_PATTERN.sub("[REDACTED]", text)

    def _build_dast_section(self, dast_findings: List[Finding]) -> List[str]:
        """Build the DAST Findings markdown section.

        Groups findings by pipeline stage, shows severity badges, evidence,
        and attack chain context when tokens were extracted.
        """
        lines: List[str] = []
        lines.append(f"## DAST Findings ({len(dast_findings)} total)")
        lines.append("")

        # Detect attack chain context from phase_artifacts
        attack_chains = self.phase_artifacts.get("dast_attack_chains", [])
        # Also infer chains from findings descriptions mentioning token extraction
        token_findings: List[Finding] = []
        for f in dast_findings:
            desc_lower = (f.description or "").lower()
            if "token" in desc_lower or "jwt" in desc_lower or "auth bypass" in desc_lower:
                token_findings.append(f)

        if attack_chains or token_findings:
            lines.append("### Attack Chain")
            for chain in attack_chains:
                source = chain.get("source", "unknown")
                usage = chain.get("usage", "authenticated API testing")
                count = chain.get("finding_count", len(token_findings))
                lines.append(f"- 🔗 {source} → used for {usage} ({count} findings)")
            # Fallback: if no explicit chains in artifacts but token findings exist
            if not attack_chains and token_findings:
                lines.append(
                    f"- 🔗 Token extracted from auth bypass → "
                    f"used for authenticated API testing ({len(token_findings)} findings)"
                )
            lines.append("")

        # Group findings by stage (tool → stage label)
        by_stage: Dict[str, List[Finding]] = {}
        for f in dast_findings:
            stage = _DAST_TOOL_TO_STAGE.get(f.tool, f.tool)
            by_stage.setdefault(stage, []).append(f)

        # Sort each stage's findings by severity
        _scrubber = OutputManager(storage_dir=Path("/dev/null"))

        for stage_name, findings in by_stage.items():
            findings_sorted = sorted(
                findings, key=lambda f: self.SEVERITY_ORDER.index(f.severity)
            )
            lines.append(f"### Stage: {stage_name} ({len(findings_sorted)} findings)")
            lines.append("")
            lines.append("| Severity | Finding | Target |")
            lines.append("|----------|---------|--------|")

            for finding in findings_sorted:
                sev_str = finding.severity if isinstance(finding.severity, str) else finding.severity.value
                badge = _SEVERITY_BADGE.get(sev_str, sev_str)
                target = finding.target or finding.evidence.url or "-"
                # Sanitize target (redact tokens, scrub creds)
                target = self._redact_tokens(_scrubber.scrub_credentials(target))
                lines.append(f"| {badge} | {finding.title} | {target} |")

            lines.append("")

            # Evidence details per finding
            for finding in findings_sorted:
                lines.append(f"<details><summary>📋 {finding.title}</summary>")
                lines.append("")
                if finding.evidence.url:
                    url = self._redact_tokens(_scrubber.scrub_credentials(finding.evidence.url))
                    lines.append(f"**URL:** `{url}`")
                if finding.evidence.payload:
                    payload = self._redact_tokens(
                        _scrubber.scrub_credentials(finding.evidence.payload)
                    )
                    # Truncate to 200 chars
                    if len(payload) > 200:
                        payload = payload[:200] + "…"
                    lines.append(f"**Payload:** `{payload}`")
                if finding.evidence.output:
                    output = self._redact_tokens(
                        _scrubber.scrub_credentials(finding.evidence.output)
                    )
                    # Truncate to 200 chars
                    if len(output) > 200:
                        output = output[:200] + "…"
                    lines.append(f"**Response:** `{output}`")
                if finding.evidence.http_banner:
                    method = self._redact_tokens(
                        _scrubber.scrub_credentials(finding.evidence.http_banner)
                    )
                    lines.append(f"**HTTP Method:** `{method}`")
                lines.append("")
                lines.append("</details>")
                lines.append("")

        return lines
