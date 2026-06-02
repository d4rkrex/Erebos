"""Fleet pentest report generator.

Produces structured markdown reports from fleet scan results
with executive summary, prioritized findings, evidence, and remediation.

VT-Spec ID-01: Warning header about sensitive content.
VT-Spec AC-01: Cap at MAX_REPORT_FINDINGS to prevent OOM.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from erebos.agents.correlation import CorrelatedFinding

# AC-01: Maximum findings included in full report
MAX_REPORT_FINDINGS = 200

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🔵",
    "INFO": "⚪",
}


class FleetReportBuilder:
    """Generates structured pentest reports from fleet correlation results.

    Output is Markdown. Caller is responsible for saving to disk.
    """

    def __init__(
        self,
        target: str,
        fleet_id: str,
        duration_ms: float = 0.0,
        agents_completed: int = 0,
        agents_failed: int = 0,
    ):
        self._target = target
        self._fleet_id = fleet_id
        self._duration_ms = duration_ms
        self._agents_completed = agents_completed
        self._agents_failed = agents_failed

    def build(
        self,
        correlated_findings: List[CorrelatedFinding],
        raw_findings: Optional[List[Dict[str, Any]]] = None,
    ) -> str:
        """Generate full markdown report.

        Args:
            correlated_findings: Priority-scored, correlated findings.
            raw_findings: Optional raw bus findings for evidence detail.

        Returns:
            Complete markdown report string.
        """
        # AC-01: Cap findings to prevent OOM
        capped = correlated_findings[:MAX_REPORT_FINDINGS]
        omitted = len(correlated_findings) - len(capped)
        raw = raw_findings or []

        sections = [
            self._header(),
            self._executive_summary(capped, omitted, raw_total=len(raw)),
            self._severity_distribution(capped),
            self._findings_table(capped),
            self._detailed_findings(capped, raw),
            self._raw_findings_appendix(raw),
            self._remediation_summary(capped),
            self._footer(omitted),
        ]

        return "\n\n".join(sections)

    def _header(self) -> str:
        """Report header with ID-01 warning."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        return (
            f"# 🔒 Penetration Test Report\n\n"
            f"> ⚠️ **CONFIDENTIAL** — This report may contain sensitive information "
            f"including credentials, tokens, and vulnerability details. "
            f"Handle according to your organization's security policy.\n\n"
            f"| Field | Value |\n"
            f"|-------|-------|\n"
            f"| **Target** | `{self._target}` |\n"
            f"| **Fleet ID** | `{self._fleet_id}` |\n"
            f"| **Date** | {now} |\n"
            f"| **Duration** | {self._duration_ms / 1000:.1f}s |\n"
            f"| **Agents** | {self._agents_completed} completed, "
            f"{self._agents_failed} failed |"
        )

    def _executive_summary(
        self, findings: List[CorrelatedFinding], omitted: int,
        raw_total: int = 0,
    ) -> str:
        """Executive summary with risk overview."""
        counts = self._severity_counts(findings)
        total = len(findings)
        top_risk = findings[0] if findings else None

        risk_level = "LOW"
        if counts.get("CRITICAL", 0) > 0:
            risk_level = "CRITICAL"
        elif counts.get("HIGH", 0) > 0:
            risk_level = "HIGH"
        elif counts.get("MEDIUM", 0) > 0:
            risk_level = "MEDIUM"

        lines = [
            "## Executive Summary\n",
            f"**Overall Risk**: {SEVERITY_EMOJI.get(risk_level, '')} **{risk_level}**\n",
            f"- **Total raw findings**: {raw_total}",
            f"- **Unique correlated findings**: {total}"
            + (f" (+{omitted} omitted)" if omitted else ""),
            f"- **Critical**: {counts.get('CRITICAL', 0)}",
            f"- **High**: {counts.get('HIGH', 0)}",
            f"- **Medium**: {counts.get('MEDIUM', 0)}",
            f"- **Low**: {counts.get('LOW', 0)}",
            f"- **Info**: {counts.get('INFO', 0)}",
        ]

        if top_risk:
            lines.append(
                f"\n**Highest priority finding**: {top_risk.title} "
                f"(score: {top_risk.priority_score}/100)"
            )
            if top_risk.signal_count > 1:
                lines.append(
                    f"  - 🔗 Corroborated by {top_risk.signal_count} independent sources"
                )

        return "\n".join(lines)

    def _severity_distribution(self, findings: List[CorrelatedFinding]) -> str:
        """Visual severity distribution."""
        counts = self._severity_counts(findings)
        total = max(len(findings), 1)

        lines = ["## Severity Distribution\n"]
        for sev in SEVERITY_ORDER:
            count = counts.get(sev, 0)
            bar_len = int((count / total) * 30)
            bar = "█" * bar_len + "░" * (30 - bar_len)
            emoji = SEVERITY_EMOJI.get(sev, "")
            lines.append(f"{emoji} {sev:<9} |{bar}| {count}")

        return "\n".join(lines)

    def _findings_table(self, findings: List[CorrelatedFinding]) -> str:
        """Priority-sorted findings table."""
        lines = [
            "## Findings\n",
            "| # | Priority | Severity | Title | CVE/CWE | Signals |",
            "|---|----------|----------|-------|---------|---------|",
        ]

        for i, f in enumerate(findings[:50], 1):  # Show top 50 in table
            badge = f"🔗×{f.signal_count}" if f.signal_count > 1 else ""
            cve_cwe = f.cve or f.cwe or ""
            sev_emoji = SEVERITY_EMOJI.get(f.severity, "")
            lines.append(
                f"| {i} | {f.priority_score} | {sev_emoji} {f.severity} | "
                f"{f.title[:60]} | {cve_cwe} | {badge} |"
            )

        if len(findings) > 50:
            lines.append(f"\n*... and {len(findings) - 50} more findings (see details below)*")

        return "\n".join(lines)

    def _detailed_findings(
        self, findings: List[CorrelatedFinding], raw: List[Dict[str, Any]]
    ) -> str:
        """Detailed findings with evidence and remediation."""
        if not findings:
            return "## Detailed Findings\n\nNo findings to report."

        lines = ["## Detailed Findings\n"]

        # Build raw finding lookup by title for evidence
        raw_by_title: Dict[str, Dict[str, Any]] = {}
        for r in raw:
            payload = r.get("payload", {})
            title = payload.get("title", "")
            if title and title not in raw_by_title:
                raw_by_title[title] = payload

        for i, f in enumerate(findings[:MAX_REPORT_FINDINGS], 1):
            raw_detail = raw_by_title.get(f.title, {})
            evidence = raw_detail.get("evidence", {})

            lines.append(f"### {i}. {f.title}\n")
            lines.append(f"- **Severity**: {SEVERITY_EMOJI.get(f.severity, '')} {f.severity}")
            lines.append(f"- **Priority Score**: {f.priority_score}/100")
            if f.signal_count > 1:
                lines.append(f"- **Correlation**: 🔗 {f.signal_count} independent signals")
            if f.cve:
                lines.append(f"- **CVE**: {f.cve}")
            if f.cwe:
                lines.append(f"- **CWE**: {f.cwe}")

            # Evidence
            if evidence:
                url = evidence.get("url", "")
                output = evidence.get("output", "")
                if url:
                    lines.append(f"- **Evidence URL**: `{url}`")
                if output:
                    # Truncate evidence output for safety
                    safe_output = output[:500]
                    lines.append(f"\n```\n{safe_output}\n```")

            # Remediation
            suggested_fix = raw_detail.get("suggested_fix", "")
            if suggested_fix:
                lines.append(f"\n**Remediation**: {suggested_fix}")

            lines.append("")  # Blank line between findings

        return "\n".join(lines)

    def _remediation_summary(self, findings: List[CorrelatedFinding]) -> str:
        """Aggregated remediation priorities."""
        lines = ["## Remediation Priorities\n"]

        crit_high = [f for f in findings if f.severity in ("CRITICAL", "HIGH")]
        if crit_high:
            lines.append("### Immediate Action Required\n")
            for f in crit_high[:10]:
                badge = f" (🔗×{f.signal_count})" if f.signal_count > 1 else ""
                lines.append(f"1. **{f.title}**{badge}")
                if f.cve:
                    lines.append(f"   - Patch: {f.cve}")
                if f.cwe:
                    lines.append(f"   - Fix pattern: {f.cwe}")
        else:
            lines.append("No critical or high severity findings requiring immediate action.")

        return "\n".join(lines)

    def _raw_findings_appendix(self, raw: List[Dict[str, Any]]) -> str:
        """Appendix with all raw findings for full traceability."""
        if not raw:
            return ""

        lines = ["## Appendix: All Raw Findings\n"]
        lines.append(f"Total: {len(raw)} findings from all agents.\n")
        lines.append("| # | Agent | Severity | Title | Target |")
        lines.append("|---|-------|----------|-------|--------|")

        for i, r in enumerate(raw[:MAX_REPORT_FINDINGS], 1):
            payload = r.get("payload", {})
            role = r.get("role", "unknown")
            sev = payload.get("severity", "INFO")
            title = (payload.get("title") or "—")[:60]
            target = (payload.get("target") or "—")[:50]
            emoji = SEVERITY_EMOJI.get(sev.upper(), "")
            lines.append(f"| {i} | {role} | {emoji} {sev} | {title} | {target} |")

        if len(raw) > MAX_REPORT_FINDINGS:
            lines.append(f"\n*... {len(raw) - MAX_REPORT_FINDINGS} additional findings omitted*")

        return "\n".join(lines)

    def _footer(self, omitted: int) -> str:
        """Report footer."""
        lines = ["---\n", "*Generated by Erebos-Lite Fleet Scanner*"]
        if omitted:
            lines.append(
                f"\n*Note: {omitted} lower-priority findings omitted. "
                f"Run with `--report-all` for complete output.*"
            )
        return "\n".join(lines)

    def _severity_counts(self, findings: List[CorrelatedFinding]) -> Dict[str, int]:
        """Count findings by severity."""
        counts: Dict[str, int] = {}
        for f in findings:
            sev = f.severity.upper() if f.severity else "INFO"
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    @staticmethod
    def save_report(content: str, output_dir: str, filename: str) -> Path:
        """Save report to disk with ID-01 restricted permissions."""
        path = Path(output_dir)
        path.mkdir(parents=True, exist_ok=True)
        filepath = path / filename
        filepath.write_text(content)
        # ID-01: Restrict file permissions to owner-only
        os.chmod(filepath, 0o600)
        return filepath
