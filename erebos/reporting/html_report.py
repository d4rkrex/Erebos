"""HTML report generation with embedded CSS.

VT-Spec R6: Professional Reporting — self-contained HTML report.
VT-Spec INJ-03: Relative paths in report output by default.
"""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from typing import Dict, List, Optional

from erebos.core.finding import Finding, Severity
from erebos.reporting.executive_summary import ExecutiveSummary
from erebos.reporting.models import (
    ExecSummaryData,
    PathRedactor,
    ReportConfig,
    RiskScore,
    ScanMetadata,
    make_paths_relative,
    sanitize_report_path,
)
from erebos.reporting.remediation import get_remediation, get_remediation_grouped


# VT-Spec INJ-03: All user-provided text is HTML-escaped before embedding
_esc = html.escape


CSS_STYLES = """
:root {
    --bg-primary: #1a1a2e;
    --bg-secondary: #16213e;
    --bg-card: #0f3460;
    --text-primary: #e6e6e6;
    --text-secondary: #a0a0a0;
    --accent: #e94560;
    --accent-green: #4ecca3;
    --accent-yellow: #f0c040;
    --accent-orange: #ff8c00;
    --accent-blue: #4a9eff;
    --border: #2a2a4a;
    --critical: #e94560;
    --high: #ff6b35;
    --medium: #f0c040;
    --low: #4a9eff;
    --info: #a0a0a0;
}

* { box-sizing: border-box; margin: 0; padding: 0; }

body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace;
    background: var(--bg-primary);
    color: var(--text-primary);
    line-height: 1.6;
    padding: 2rem;
}

.container { max-width: 1200px; margin: 0 auto; }

.header {
    border-bottom: 2px solid var(--accent);
    padding-bottom: 1.5rem;
    margin-bottom: 2rem;
}

.header h1 {
    font-size: 2rem;
    color: var(--accent);
    margin-bottom: 0.5rem;
}

.header .meta {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 0.5rem;
    color: var(--text-secondary);
    font-size: 0.9rem;
}

.meta-item { padding: 0.3rem 0; }
.meta-label { font-weight: bold; color: var(--text-primary); }

.section {
    background: var(--bg-secondary);
    border-radius: 8px;
    padding: 1.5rem;
    margin-bottom: 1.5rem;
    border: 1px solid var(--border);
}

.section h2 {
    color: var(--accent-green);
    margin-bottom: 1rem;
    font-size: 1.4rem;
    border-bottom: 1px solid var(--border);
    padding-bottom: 0.5rem;
}

.risk-gauge {
    display: flex;
    align-items: center;
    gap: 1.5rem;
    margin: 1rem 0;
}

.risk-score-circle {
    width: 100px;
    height: 100px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 2rem;
    font-weight: bold;
    border: 4px solid;
}

.risk-CRITICAL { border-color: var(--critical); color: var(--critical); }
.risk-HIGH { border-color: var(--high); color: var(--high); }
.risk-MEDIUM { border-color: var(--medium); color: var(--medium); }
.risk-LOW { border-color: var(--low); color: var(--low); }
.risk-INFO { border-color: var(--info); color: var(--info); }

.severity-bar {
    display: flex;
    gap: 1rem;
    flex-wrap: wrap;
    margin: 1rem 0;
}

.severity-badge {
    padding: 0.3rem 0.8rem;
    border-radius: 4px;
    font-weight: bold;
    font-size: 0.85rem;
}

.sev-CRITICAL { background: var(--critical); color: white; }
.sev-HIGH { background: var(--high); color: white; }
.sev-MEDIUM { background: var(--medium); color: black; }
.sev-LOW { background: var(--low); color: white; }
.sev-INFO { background: var(--info); color: white; }

table {
    width: 100%;
    border-collapse: collapse;
    margin: 1rem 0;
    font-size: 0.9rem;
}

th, td {
    padding: 0.6rem 0.8rem;
    text-align: left;
    border-bottom: 1px solid var(--border);
}

th {
    background: var(--bg-card);
    color: var(--accent-green);
    font-weight: 600;
    cursor: pointer;
}

th:hover { color: var(--accent); }

tr:hover { background: rgba(78, 204, 163, 0.05); }

.finding-card {
    background: var(--bg-card);
    border-radius: 6px;
    padding: 1.2rem;
    margin-bottom: 1rem;
    border-left: 4px solid;
}

.finding-card.sev-CRITICAL { border-left-color: var(--critical); }
.finding-card.sev-HIGH { border-left-color: var(--high); }
.finding-card.sev-MEDIUM { border-left-color: var(--medium); }
.finding-card.sev-LOW { border-left-color: var(--low); }
.finding-card.sev-INFO { border-left-color: var(--info); }

.finding-title {
    font-size: 1.1rem;
    font-weight: bold;
    margin-bottom: 0.5rem;
}

.finding-meta {
    display: flex;
    gap: 1rem;
    flex-wrap: wrap;
    color: var(--text-secondary);
    font-size: 0.85rem;
    margin-bottom: 0.8rem;
}

pre {
    background: #0d1117;
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 1rem;
    overflow-x: auto;
    font-size: 0.85rem;
    margin: 0.5rem 0;
    color: #c9d1d9;
}

.remediation-group {
    margin-bottom: 1.5rem;
    padding: 1rem;
    background: var(--bg-card);
    border-radius: 6px;
}

.remediation-group h3 {
    color: var(--accent-yellow);
    margin-bottom: 0.5rem;
}

.footer {
    text-align: center;
    color: var(--text-secondary);
    font-size: 0.8rem;
    padding-top: 2rem;
    border-top: 1px solid var(--border);
    margin-top: 2rem;
}

.confidential-banner {
    background: var(--accent);
    color: white;
    text-align: center;
    padding: 0.5rem;
    font-weight: bold;
    border-radius: 4px;
    margin-bottom: 1.5rem;
}
"""

SORT_SCRIPT = """
<script>
function sortTable(table, col, reverse) {
    var tb = table.tBodies[0];
    var tr = Array.prototype.slice.call(tb.rows, 0);
    reverse = -(+reverse) || -1;
    tr = tr.sort(function(a, b) {
        var aText = a.cells[col].textContent.trim();
        var bText = b.cells[col].textContent.trim();
        var aNum = parseFloat(aText);
        var bNum = parseFloat(bText);
        if (!isNaN(aNum) && !isNaN(bNum)) return reverse * (aNum - bNum);
        return reverse * aText.localeCompare(bText);
    });
    for(var i = 0; i < tr.length; ++i) tb.appendChild(tr[i]);
}
document.addEventListener('DOMContentLoaded', function() {
    var tables = document.querySelectorAll('table.sortable');
    tables.forEach(function(table) {
        var headers = table.querySelectorAll('th');
        headers.forEach(function(th, i) {
            th.addEventListener('click', function() {
                var reverse = th.dataset.sort === 'asc';
                th.dataset.sort = reverse ? 'desc' : 'asc';
                sortTable(table, i, reverse);
            });
        });
    });
});
</script>
"""


class HtmlReportGenerator:
    """Generate self-contained HTML pentest reports.

    VT-Spec R6: Professional HTML report with embedded CSS, dark theme.
    VT-Spec INJ-03: Paths converted to relative by default.
    """

    def __init__(self, config: Optional[ReportConfig] = None):
        self._config = config or ReportConfig()
        self._path_redactor = PathRedactor() if self._config.redact_paths else None

    def generate(
        self,
        findings: List[Finding],
        scan_meta: ScanMetadata,
        tool_version: str = "Erebos",
    ) -> str:
        """Generate complete self-contained HTML report.

        Args:
            findings: List of findings from the scan.
            scan_meta: Scan metadata for the header.
            tool_version: Tool version string.

        Returns:
            Complete HTML string (self-contained, no external deps).
        """
        # Generate executive summary data
        exec_gen = ExecutiveSummary()
        exec_data = exec_gen.generate(findings, scan_meta)

        # Sort findings by severity
        sorted_findings = sorted(findings, key=lambda f: self._severity_rank(f.severity))

        # Build HTML sections
        sections = [
            self._html_head(scan_meta, tool_version),
            '<body><div class="container">',
            self._confidential_banner(),
            self._header_section(scan_meta),
            self._exec_summary_section(exec_data),
            self._findings_table_section(sorted_findings),
            self._detailed_findings_section(sorted_findings),
            self._remediation_section(sorted_findings),
            self._footer_section(tool_version),
            "</div>",
            SORT_SCRIPT,
            "</body></html>",
        ]

        return "\n".join(sections)

    def _html_head(self, scan_meta: ScanMetadata, tool_version: str) -> str:
        """HTML head with embedded CSS."""
        title = f"Pentest Report - {_esc(scan_meta.target)}"
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title}</title>
<style>{CSS_STYLES}</style>
</head>"""

    def _confidential_banner(self) -> str:
        return '<div class="confidential-banner">⚠️ CONFIDENTIAL — Contains sensitive vulnerability information</div>'

    def _header_section(self, scan_meta: ScanMetadata) -> str:
        """Report header with metadata."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        return f"""
<div class="header">
    <h1>🔒 Penetration Test Report</h1>
    <div class="meta">
        <div class="meta-item"><span class="meta-label">Target:</span> {_esc(scan_meta.target)}</div>
        <div class="meta-item"><span class="meta-label">Scan ID:</span> {_esc(scan_meta.scan_id)}</div>
        <div class="meta-item"><span class="meta-label">Date:</span> {now}</div>
        <div class="meta-item"><span class="meta-label">Duration:</span> {scan_meta.duration_seconds:.1f}s</div>
        <div class="meta-item"><span class="meta-label">Tool:</span> {_esc(scan_meta.tool_version)}</div>
    </div>
</div>"""

    def _exec_summary_section(self, data: ExecSummaryData) -> str:
        """Executive summary with risk gauge."""
        risk_level = data.overall_risk.value
        score = data.risk_score.score

        severity_badges = ""
        for sev, count in sorted(data.findings_by_severity.items()):
            if count > 0:
                severity_badges += f'<span class="severity-badge sev-{_esc(sev)}">{_esc(sev)}: {count}</span>\n'

        top_findings_html = ""
        for title in data.top_findings:
            top_findings_html += f"<li>{_esc(title)}</li>\n"

        recommendations_html = ""
        for rec in data.key_recommendations:
            recommendations_html += f"<li>{_esc(rec)}</li>\n"

        return f"""
<div class="section">
    <h2>Executive Summary</h2>
    <div class="risk-gauge">
        <div class="risk-score-circle risk-{_esc(risk_level)}">{score}</div>
        <div>
            <div style="font-size:1.2rem;font-weight:bold;">Overall Risk: {_esc(risk_level)}</div>
            <div style="color:var(--text-secondary);">Score: {score}/100</div>
            <div style="margin-top:0.5rem;">
                Exploitation Rate: {data.exploitation_rate:.0%}
            </div>
        </div>
    </div>
    <div class="severity-bar">{severity_badges}</div>
    <h3 style="color:var(--text-primary);margin-top:1rem;">Top Findings</h3>
    <ol>{top_findings_html}</ol>
    <h3 style="color:var(--text-primary);margin-top:1rem;">Key Recommendations</h3>
    <ol>{recommendations_html}</ol>
</div>"""

    def _findings_table_section(self, findings: List[Finding]) -> str:
        """Sortable findings table."""
        rows = ""
        for i, f in enumerate(findings[:50], 1):
            sev = f.severity if isinstance(f.severity, str) else f.severity.value
            cve_cwe = f.cve or f.cwe or ""
            rows += f"""<tr>
<td>{i}</td>
<td><span class="severity-badge sev-{_esc(sev)}">{_esc(sev)}</span></td>
<td>{_esc(f.title[:80])}</td>
<td>{_esc(cve_cwe)}</td>
<td>{_esc(f.tool)}</td>
</tr>\n"""

        more = ""
        if len(findings) > 50:
            more = f'<p style="color:var(--text-secondary);">...and {len(findings) - 50} more findings below</p>'

        return f"""
<div class="section">
    <h2>Findings Overview</h2>
    <table class="sortable">
        <thead><tr>
            <th>#</th><th>Severity</th><th>Title</th><th>CVE/CWE</th><th>Tool</th>
        </tr></thead>
        <tbody>{rows}</tbody>
    </table>
    {more}
</div>"""

    def _detailed_findings_section(self, findings: List[Finding]) -> str:
        """Detailed finding cards with evidence."""
        if not findings:
            return '<div class="section"><h2>Detailed Findings</h2><p>No findings.</p></div>'

        cards = ""
        for i, f in enumerate(findings[: self._config.max_findings], 1):
            sev = f.severity if isinstance(f.severity, str) else f.severity.value
            meta_parts = [f"Tool: {_esc(f.tool)}"]
            if f.cve:
                meta_parts.append(f"CVE: {_esc(f.cve)}")
            if f.cwe:
                meta_parts.append(f"CWE: {_esc(f.cwe)}")
            if f.cvss is not None:
                meta_parts.append(f"CVSS: {f.cvss}")

            meta_html = " | ".join(meta_parts)

            evidence_html = ""
            if self._config.include_evidence and f.evidence:
                if f.evidence.url:
                    evidence_html += f"<p><strong>URL:</strong> <code>{_esc(f.evidence.url)}</code></p>"
                if f.evidence.payload:
                    # VT-Spec INJ-03: Process paths in evidence
                    payload = self._process_path(f.evidence.payload)
                    evidence_html += f"<p><strong>Payload:</strong></p><pre>{_esc(payload[:500])}</pre>"
                if f.evidence.output:
                    output = self._process_path(f.evidence.output[:500])
                    evidence_html += f"<p><strong>Output:</strong></p><pre>{_esc(output)}</pre>"

            remediation_html = ""
            if f.suggested_fix:
                remediation_html = f"<p><strong>Remediation:</strong> {_esc(f.suggested_fix)}</p>"

            cards += f"""
<div class="finding-card sev-{_esc(sev)}">
    <div class="finding-title">{i}. {_esc(f.title)}</div>
    <div class="finding-meta">{meta_html}</div>
    <p>{_esc(f.description[:300])}</p>
    {evidence_html}
    {remediation_html}
</div>"""

        return f"""
<div class="section">
    <h2>Detailed Findings</h2>
    {cards}
</div>"""

    def _remediation_section(self, findings: List[Finding]) -> str:
        """Remediation section grouped by CWE."""
        cwes = [f.cwe for f in findings if f.cwe]
        grouped = get_remediation_grouped(cwes)

        if not grouped:
            return ""

        groups_html = ""
        for cwe_id, remediation in sorted(grouped.items()):
            title = remediation.get("title", "Unknown")
            short = remediation.get("short", "")
            detailed = remediation.get("detailed", "")
            refs = remediation.get("references", [])

            refs_html = ""
            for ref in refs:  # type: ignore
                refs_html += f'<li><a href="{_esc(str(ref))}" style="color:var(--accent-blue);">{_esc(str(ref))}</a></li>'

            groups_html += f"""
<div class="remediation-group">
    <h3>{_esc(cwe_id)}: {_esc(str(title))}</h3>
    <p><strong>{_esc(str(short))}</strong></p>
    <p style="color:var(--text-secondary);margin-top:0.5rem;">{_esc(str(detailed))}</p>
    {"<ul>" + refs_html + "</ul>" if refs_html else ""}
</div>"""

        return f"""
<div class="section">
    <h2>Remediation Playbook</h2>
    {groups_html}
</div>"""

    def _footer_section(self, tool_version: str) -> str:
        """Report footer with timestamp."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        return f"""
<div class="footer">
    <p>Generated by {_esc(tool_version)} | {now}</p>
    <p>This report is confidential and intended for authorized recipients only.</p>
</div>"""

    def _process_path(self, text: str) -> str:
        """VT-Spec INJ-03: Process file paths according to config.

        - relative_paths=True (default): convert absolute to relative
        - redact_paths=True: replace with opaque identifiers
        """
        if self._path_redactor:
            # Redact mode: replace paths with [FILE-NNN]
            import re
            path_pattern = re.compile(r"(/[a-zA-Z0-9_./\-]+)")
            return path_pattern.sub(lambda m: self._path_redactor.redact(m.group(1)), text)
        elif self._config.relative_paths:
            # Relative mode: strip absolute path prefixes
            import re
            path_pattern = re.compile(r"(/[a-zA-Z0-9_./\-]+)")
            return path_pattern.sub(lambda m: make_paths_relative(m.group(1)), text)
        return text

    def _severity_rank(self, severity) -> int:
        """Return sort rank (lower = more severe)."""
        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        sev = severity if isinstance(severity, str) else severity.value
        try:
            return order.index(sev.upper())
        except ValueError:
            return 99
