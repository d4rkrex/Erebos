"""MCP Reporting Tool — auto-generates pentest reports from scan findings.

Inspired by VulnForce's MCP-driven report generation pattern.
Generates structured reports enriched with vulnerability library data.

Security: Per-engagement access control via engagement_id validation.
Mitigation: EoP-01 (RBAC on report operations).
"""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

from erebos.core.finding import Finding
from erebos.reporting.vuln_library import enrich_finding


class ReportAccess:
    """Simple engagement-based access control for reports."""

    def __init__(self, engagement_id: str, owner: str):
        self.engagement_id = engagement_id
        self.owner = owner
        self.readers: set = {owner}
        self.writers: set = {owner}

    def can_read(self, user: str) -> bool:
        return user in self.readers

    def can_write(self, user: str) -> bool:
        return user in self.writers

    def grant_read(self, user: str) -> None:
        self.readers.add(user)

    def grant_write(self, user: str) -> None:
        self.writers.add(user)
        self.readers.add(user)


class PentestReport:
    """A structured pentest report that can be incrementally built."""

    def __init__(
        self,
        engagement_id: str,
        target: str,
        title: Optional[str] = None,
        owner: str = "system",
    ):
        self.id = str(uuid4())
        self.engagement_id = engagement_id
        self.target = target
        self.title = title or f"Security Assessment — {target}"
        self.created_at = datetime.now(timezone.utc)
        self.updated_at = self.created_at
        self.findings: List[Finding] = []
        self.access = ReportAccess(engagement_id, owner)
        self.metadata: Dict[str, Any] = {}

    def add_findings(self, findings: List[Finding], max_findings: int = 500) -> int:
        """Add findings to the report with enrichment. Returns count added."""
        added = 0
        for f in findings:
            if len(self.findings) >= max_findings:
                break
            enriched = enrich_finding(f)
            self.findings.append(enriched)
            added += 1
        self.updated_at = datetime.now(timezone.utc)
        return added

    @property
    def severity_counts(self) -> Dict[str, int]:
        """Count findings by severity."""
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            sev = f.severity if isinstance(f.severity, str) else f.severity.value
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    @property
    def risk_score(self) -> float:
        """Calculate weighted risk score (0-100)."""
        weights = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 10, "LOW": 3, "INFO": 1}
        total = sum(
            weights.get(f.severity if isinstance(f.severity, str) else f.severity.value, 0)
            for f in self.findings
        )
        return min(total, 100.0)

    def to_markdown(self) -> str:
        """Render report as Markdown."""
        lines = [
            f"# {self.title}",
            "",
            f"**Engagement:** {self.engagement_id}  ",
            f"**Target:** {self.target}  ",
            f"**Date:** {self.created_at.strftime('%Y-%m-%d %H:%M UTC')}  ",
            f"**Findings:** {len(self.findings)}  ",
            f"**Risk Score:** {self.risk_score:.0f}/100  ",
            "",
            "## Executive Summary",
            "",
            "| Severity | Count |",
            "|----------|-------|",
        ]
        for sev, count in self.severity_counts.items():
            if count > 0:
                lines.append(f"| {sev} | {count} |")

        lines.extend(["", "## Findings", ""])

        for i, f in enumerate(self.findings, 1):
            sev = f.severity if isinstance(f.severity, str) else f.severity.value
            lines.append(f"### {i}. [{sev}] {f.title}")
            lines.append("")
            lines.append(f"**CWE:** {f.cwe or 'N/A'}  ")
            lines.append(f"**CVSS:** {f.cvss or 'N/A'}  ")
            lines.append(f"**Target:** {f.target or self.target}  ")
            lines.append("")
            lines.append(f.description)
            lines.append("")

            if f.evidence and f.evidence.payload:
                lines.append("**Evidence:**")
                lines.append("```")
                lines.append(f.evidence.payload[:500])
                lines.append("```")
                lines.append("")

            if f.suggested_fix:
                lines.append("**Remediation:**")
                lines.append(f.suggested_fix)
                lines.append("")

            lines.append("---")
            lines.append("")

        return "\n".join(lines)

    def to_html(self) -> str:
        """Render report as HTML with hardened evidence rendering (T-01 mitigation)."""
        esc = html.escape  # All dynamic content MUST go through this

        findings_html = ""
        for i, f in enumerate(self.findings, 1):
            sev = f.severity if isinstance(f.severity, str) else f.severity.value
            sev_class = sev.lower()

            evidence_block = ""
            if f.evidence:
                if f.evidence.url:
                    evidence_block += f'<p><strong>URL:</strong> <code>{esc(f.evidence.url)}</code></p>'
                if f.evidence.payload:
                    evidence_block += f'<p><strong>Payload:</strong></p><pre><code>{esc(f.evidence.payload[:500])}</code></pre>'
                if f.evidence.output:
                    evidence_block += f'<p><strong>Output:</strong></p><pre><code>{esc(f.evidence.output[:500])}</code></pre>'

            remediation_block = ""
            if f.suggested_fix:
                remediation_block = f'<div class="remediation"><h4>Remediation</h4><pre>{esc(f.suggested_fix)}</pre></div>'

            findings_html += f"""
            <div class="finding {sev_class}">
                <h3>{i}. <span class="severity-badge {sev_class}">{esc(sev)}</span> {esc(f.title)}</h3>
                <p><strong>CWE:</strong> {esc(f.cwe or 'N/A')} | <strong>CVSS:</strong> {f.cvss or 'N/A'}</p>
                <p>{esc(f.description)}</p>
                {evidence_block}
                {remediation_block}
            </div>
            """

        return f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline';">
    <title>{esc(self.title)}</title>
    <style>
        body {{ font-family: -apple-system, sans-serif; max-width: 900px; margin: 0 auto; padding: 2rem; background: #1a1a2e; color: #e6e6e6; }}
        .finding {{ border: 1px solid #2a2a4a; border-radius: 8px; padding: 1.5rem; margin: 1rem 0; }}
        .finding.critical {{ border-left: 4px solid #e94560; }}
        .finding.high {{ border-left: 4px solid #ff6b35; }}
        .finding.medium {{ border-left: 4px solid #f0c040; }}
        .finding.low {{ border-left: 4px solid #4a9eff; }}
        .severity-badge {{ padding: 2px 8px; border-radius: 4px; font-size: 0.8em; font-weight: bold; }}
        .severity-badge.critical {{ background: #e94560; color: white; }}
        .severity-badge.high {{ background: #ff6b35; color: white; }}
        .severity-badge.medium {{ background: #f0c040; color: black; }}
        .severity-badge.low {{ background: #4a9eff; color: white; }}
        pre {{ background: #0f3460; padding: 1rem; border-radius: 4px; overflow-x: auto; }}
        code {{ font-family: 'Fira Code', monospace; font-size: 0.9em; }}
        .remediation {{ background: #16213e; padding: 1rem; border-radius: 4px; margin-top: 1rem; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #2a2a4a; padding: 0.5rem; text-align: left; }}
    </style>
</head>
<body>
    <h1>{esc(self.title)}</h1>
    <p><strong>Engagement:</strong> {esc(self.engagement_id)}</p>
    <p><strong>Target:</strong> {esc(self.target)}</p>
    <p><strong>Date:</strong> {esc(self.created_at.strftime('%Y-%m-%d %H:%M UTC'))}</p>
    <p><strong>Risk Score:</strong> {self.risk_score:.0f}/100</p>
    <h2>Summary</h2>
    <table>
        <tr><th>Severity</th><th>Count</th></tr>
        {''.join(f"<tr><td>{s}</td><td>{c}</td></tr>" for s, c in self.severity_counts.items() if c > 0)}
    </table>
    <h2>Findings</h2>
    {findings_html}
</body>
</html>"""

    def to_json(self) -> str:
        """Serialize report to JSON."""
        return json.dumps({
            "id": self.id,
            "engagement_id": self.engagement_id,
            "target": self.target,
            "title": self.title,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "risk_score": self.risk_score,
            "severity_counts": self.severity_counts,
            "findings_count": len(self.findings),
            "findings": [f.model_dump(mode="json") for f in self.findings],
        }, indent=2, default=str)


class McpReporter:
    """MCP-compatible reporter that manages reports per engagement.

    Designed to be exposed as MCP tools for AI agents to generate
    and update pentest reports programmatically.
    """

    def __init__(self):
        self._reports: Dict[str, PentestReport] = {}

    def create_report(
        self,
        engagement_id: str,
        target: str,
        title: Optional[str] = None,
        owner: str = "system",
    ) -> PentestReport:
        """Create a new pentest report for an engagement."""
        report = PentestReport(
            engagement_id=engagement_id,
            target=target,
            title=title,
            owner=owner,
        )
        self._reports[report.id] = report
        return report

    def get_report(self, report_id: str, user: str = "system") -> Optional[PentestReport]:
        """Get a report by ID with access control."""
        report = self._reports.get(report_id)
        if report and report.access.can_read(user):
            return report
        return None

    def add_findings_to_report(
        self,
        report_id: str,
        findings: List[Finding],
        user: str = "system",
        max_findings: int = 500,
    ) -> int:
        """Add findings to an existing report. Returns count added."""
        report = self._reports.get(report_id)
        if not report:
            raise ValueError(f"Report {report_id} not found")
        if not report.access.can_write(user):
            raise PermissionError(f"User {user} cannot write to report {report_id}")
        return report.add_findings(findings, max_findings=max_findings)

    def generate(
        self,
        report_id: str,
        format: str = "markdown",
        user: str = "system",
    ) -> str:
        """Generate report output in specified format."""
        report = self.get_report(report_id, user)
        if not report:
            raise ValueError(f"Report {report_id} not found or access denied")

        if format == "html":
            return report.to_html()
        elif format == "json":
            return report.to_json()
        else:
            return report.to_markdown()

    def list_reports(self, user: str = "system") -> List[Dict[str, Any]]:
        """List all reports accessible to user."""
        results = []
        for report in self._reports.values():
            if report.access.can_read(user):
                results.append({
                    "id": report.id,
                    "engagement_id": report.engagement_id,
                    "target": report.target,
                    "title": report.title,
                    "findings_count": len(report.findings),
                    "risk_score": report.risk_score,
                    "created_at": report.created_at.isoformat(),
                })
        return results
