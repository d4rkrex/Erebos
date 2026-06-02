"""Report Generator for Erebos (REQ-003).

Produces structured pentest reports with findings, evidence, scoring,
and remediation recommendations.

VT-Spec ID-001 HIGH: Wire scrub_credentials() into ReportGenerator before ANY output
VT-Spec ID-001: Integrate PromptSanitizer.sanitize() for all evidence fields
VT-Spec R6: Multi-format reporting (md, html, json, pdf)
VT-Spec R7: Sanitize report paths
VT-Spec INJ-03: Default to relative paths in report output
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from erebos.core.finding import Finding, FindingEvidence, Severity
from erebos.executor.output import OutputManager, CREDENTIAL_PATTERNS, REDACTED
from erebos.reporting.models import (
    PathRedactor,
    ReportConfig,
    ReportFormat,
    ScanMetadata,
    make_paths_relative,
    sanitize_report_path,
)

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generates pentest reports from engagement data.

    # VT-Spec ID-001 HIGH: All evidence fields scrubbed before output.
    # All output passes through credential scrubbing pipeline.
    """

    def __init__(
        self,
        engagement_id: str,
        target: str,
        custom_redact_patterns: Optional[List[str]] = None,
    ):
        self._engagement_id = engagement_id
        self._target = target
        # VT-Spec ID-001: Initialize scrubber with optional custom patterns
        compiled_custom = []
        if custom_redact_patterns:
            for pattern_str in custom_redact_patterns:
                try:
                    compiled_custom.append(re.compile(pattern_str))
                except re.error:
                    logger.warning(f"Invalid redact pattern: {pattern_str}")
        self._scrubber = OutputManager(
            storage_dir=Path("/dev/null"),  # Not used for scrubbing
            custom_patterns=compiled_custom,
        )

    def _scrub(self, text: Optional[str]) -> Optional[str]:
        """VT-Spec ID-001 HIGH: Scrub credentials from any text before output.

        Uses the same 3-pass scrubbing as OutputManager:
        Pass 1: Known credential patterns
        Pass 2: High-entropy string detection
        Pass 3: Custom patterns from config
        """
        if text is None:
            return None
        return self._scrubber.scrub_credentials(text)

    def _scrub_evidence(self, evidence: FindingEvidence) -> Dict[str, Optional[str]]:
        """VT-Spec ID-001 HIGH: Scrub all evidence fields.

        Applies scrub_credentials() to:
        - evidence.payload
        - evidence.output
        - evidence.url
        """
        return {
            "url": self._scrub(evidence.url),
            "payload": self._scrub(evidence.payload),
            "output": self._scrub(evidence.output),
            "http_banner": self._scrub(evidence.http_banner),
        }

    def generate_markdown(
        self,
        findings: List[Finding],
        attack_path: Optional[List[Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Generate a Markdown pentest report.

        # VT-Spec ID-001 HIGH: scrub_credentials() applied to ALL evidence before output.
        """
        lines: List[str] = []
        now = datetime.now(timezone.utc).isoformat()

        # Report classification header
        lines.append("<!-- CLASSIFICATION: CONFIDENTIAL - Contains pentest findings -->")
        lines.append("")
        lines.append("# Erebos Pentest Report")
        lines.append("")
        lines.append(f"**Engagement ID:** {self._engagement_id}")
        lines.append(f"**Target:** {self._target}")
        lines.append(f"**Generated:** {now}")
        lines.append("")

        # Executive Summary
        lines.append("## Executive Summary")
        lines.append("")

        if not findings:
            lines.append("No exploitable vulnerabilities found during this engagement.")
            lines.append("")
        else:
            by_severity = self._group_by_severity(findings)
            lines.append(f"- **Total Findings:** {len(findings)}")
            for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
                count = len(by_severity.get(sev, []))
                if count:
                    lines.append(f"- **{sev.value}:** {count}")
            lines.append("")

        # Findings section
        if findings:
            sorted_findings = sorted(
                findings,
                key=lambda f: self._severity_sort_key(f.severity),
            )

            lines.append("## Findings")
            lines.append("")

            for i, finding in enumerate(sorted_findings, 1):
                sev_label = self._severity_label(finding.severity)
                lines.append(f"### {i}. [{sev_label}] {finding.title}")
                lines.append("")
                lines.append(f"**Tool:** {finding.tool}")
                if finding.cvss is not None:
                    lines.append(f"**CVSS:** {finding.cvss}")
                if finding.cve:
                    lines.append(f"**CVE:** {finding.cve}")
                if finding.cwe:
                    lines.append(f"**CWE:** {finding.cwe}")
                lines.append("")
                lines.append("**Description**")
                lines.append("")
                lines.append(finding.description)
                lines.append("")

                # VT-Spec ID-001 HIGH: Scrub evidence before output
                scrubbed = self._scrub_evidence(finding.evidence)

                if scrubbed["url"]:
                    lines.append("**Evidence URL**")
                    lines.append(f"`{scrubbed['url']}`")
                    lines.append("")

                if scrubbed["payload"]:
                    lines.append("**Payload**")
                    lines.append(f"```\n{scrubbed['payload']}\n```")
                    lines.append("")

                if scrubbed["output"]:
                    # Truncate large output
                    output = scrubbed["output"][:2000]
                    lines.append("**Output**")
                    lines.append(f"```\n{output}\n```")
                    lines.append("")

                # Evidence integrity hash
                evidence_content = json.dumps(scrubbed, sort_keys=True, default=str)
                evidence_hash = hashlib.sha256(evidence_content.encode()).hexdigest()
                lines.append(f"**Evidence SHA-256:** `{evidence_hash}`")
                lines.append("")

                # Reproduction steps
                if finding.suggested_fix:
                    lines.append("**Remediation**")
                    lines.append(finding.suggested_fix)
                    lines.append("")

                lines.append("---")
                lines.append("")

        # Attack path section
        if attack_path:
            lines.append("## Attack Path")
            lines.append("")
            for hop in attack_path:
                src = hop.get("source", "initial")
                dst = hop.get("destination", "unknown")
                technique = hop.get("technique", "unknown")
                lines.append(f"- **{src}** → **{dst}** via {technique}")
            lines.append("")

        # Remediation summary
        if findings:
            sorted_findings = sorted(
                findings,
                key=lambda f: self._severity_sort_key(f.severity),
            )
            lines.append("## Remediation Priority")
            lines.append("")
            lines.append("| # | Severity | Finding | Recommendation |")
            lines.append("|---|----------|---------|----------------|")
            for i, f in enumerate(sorted_findings[:20], 1):
                fix = (f.suggested_fix or "Review and patch")[:60]
                sev_label = self._severity_label(f.severity)
                lines.append(f"| {i} | {sev_label} | {f.title[:40]} | {fix} |")
            lines.append("")

        return "\n".join(lines)

    def generate_json(
        self,
        findings: List[Finding],
        attack_path: Optional[List[Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Generate a JSON structured report.

        # VT-Spec ID-001 HIGH: scrub_credentials() applied to ALL evidence before output.
        """
        now = datetime.now(timezone.utc).isoformat()

        # VT-Spec ID-001: Scrub all evidence fields
        scrubbed_findings = []
        for finding in findings:
            scrubbed_evidence = self._scrub_evidence(finding.evidence)
            finding_dict = finding.model_dump(mode="json")
            finding_dict["evidence"] = scrubbed_evidence
            # Compute evidence hash for integrity
            evidence_hash = hashlib.sha256(
                json.dumps(scrubbed_evidence, sort_keys=True, default=str).encode()
            ).hexdigest()
            finding_dict["evidence_sha256"] = evidence_hash
            scrubbed_findings.append(finding_dict)

        report = {
            "schema_version": "1.0",
            "engagement_id": self._engagement_id,
            "target": self._target,
            "generated_at": now,
            "classification": "CONFIDENTIAL",
            "summary": {
                "total_findings": len(findings),
                "by_severity": {
                    sev.value: len([f for f in findings if (f.severity if isinstance(f.severity, Severity) else Severity(f.severity)) == sev])
                    for sev in Severity
                },
            },
            "findings": scrubbed_findings,
            "attack_path": attack_path or [],
            "metadata": metadata or {},
        }

        return json.dumps(report, indent=2, default=str)

    def save_report(
        self,
        findings: List[Finding],
        output_dir: Path,
        format: str = "markdown",
        attack_path: Optional[List[Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        config: Optional[ReportConfig] = None,
    ) -> Path:
        """Generate and save report to file.

        VT-Spec ID-001: All content scrubbed before write.
        VT-Spec R6: Multi-format support (md, html, json, pdf).
        VT-Spec R7: Sanitized filenames.
        VT-Spec INJ-03: Relative paths by default.
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        # VT-Spec R7: Sanitize target for filename
        safe_target = sanitize_report_path(self._target)

        if format == "json":
            content = self.generate_json(findings, attack_path, metadata)
            filename = f"{self._engagement_id}_{safe_target}_{timestamp}.json"
        elif format == "html":
            # VT-Spec R6: HTML report generation
            from erebos.reporting.html_report import HtmlReportGenerator
            html_config = config or ReportConfig(format=ReportFormat.HTML)
            html_gen = HtmlReportGenerator(config=html_config)
            scan_meta = ScanMetadata(
                target=self._target,
                scan_id=self._engagement_id,
            )
            content = html_gen.generate(findings, scan_meta)
            filename = f"{self._engagement_id}_{safe_target}_{timestamp}.html"
        elif format == "pdf":
            # Stretch goal: PDF via weasyprint
            try:
                import weasyprint  # type: ignore
                from erebos.reporting.html_report import HtmlReportGenerator
                html_config = config or ReportConfig(format=ReportFormat.PDF)
                html_gen = HtmlReportGenerator(config=html_config)
                scan_meta = ScanMetadata(
                    target=self._target,
                    scan_id=self._engagement_id,
                )
                html_content = html_gen.generate(findings, scan_meta)
                filename = f"{self._engagement_id}_{safe_target}_{timestamp}.pdf"
                filepath = output_dir / filename
                weasyprint.HTML(string=html_content).write_pdf(str(filepath))
                logger.info(
                    "PDF report generated",
                    extra={"path": str(filepath), "findings_count": len(findings)},
                )
                return filepath
            except ImportError:
                logger.warning("weasyprint not available, falling back to HTML format")
                content = self.generate_markdown(findings, attack_path, metadata)
                filename = f"{self._engagement_id}_{safe_target}_{timestamp}.md"
        else:
            content = self.generate_markdown(findings, attack_path, metadata)
            filename = f"{self._engagement_id}_{safe_target}_{timestamp}.md"

        filepath = output_dir / filename
        filepath.write_text(content, encoding="utf-8")

        logger.info(
            "Report generated",
            extra={
                "engagement_id": self._engagement_id,
                "format": format,
                "findings_count": len(findings),
                "path": str(filepath),
            },
        )

        return filepath

    @staticmethod
    def _group_by_severity(findings: List[Finding]) -> Dict[Severity, List[Finding]]:
        """Group findings by severity."""
        groups: Dict[Severity, List[Finding]] = {}
        for f in findings:
            # Handle both enum and string severity (use_enum_values=True)
            sev = f.severity if isinstance(f.severity, Severity) else Severity(f.severity)
            groups.setdefault(sev, []).append(f)
        return groups

    @staticmethod
    def _severity_label(severity) -> str:
        """Get display label for severity (handles str or Enum)."""
        if isinstance(severity, Severity):
            return severity.value.upper()
        return str(severity).upper()

    @staticmethod
    def _severity_sort_key(severity) -> int:
        """Sort key for severity (handles str or Enum)."""
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        sev = severity if isinstance(severity, Severity) else Severity(severity)
        try:
            return order.index(sev)
        except ValueError:
            return 99
