"""Reporter agent role — aggregates findings into structured report.

VT-Spec R6: Professional reporting in multiple formats.
VT-Spec R7: Sanitize report filenames.
VT-Spec INJ-03: Default relative paths, --redact-paths flag.
"""

from __future__ import annotations

import json
import logging
import os
from collections import Counter
from typing import Any, Dict, List, Optional

from erebos.agents.base import AgentMessage, AgentRole, FindingsBus
from erebos.agents.correlation import CorrelatedFinding
from erebos.reporting.models import make_paths_relative, sanitize_report_path

logger = logging.getLogger(__name__)


class ReporterRole:
    """Reporter agent — aggregates all findings from bus into final report.

    Reads ALL agent findings, runs correlation, and produces a structured
    report in the requested format.

    VT-Spec R6: Support md, html, json output formats.
    VT-Spec INJ-03: Relative paths by default, --redact-paths for full redaction.
    """

    def __init__(
        self,
        bus: FindingsBus,
        agent_id: str,
        target: str = "",
        fleet_id: str = "",
        output_dir: Optional[str] = None,
        report_format: str = "md",
        redact_paths: bool = False,
        fleet_metadata: Optional[Dict[str, Any]] = None,
    ):
        self._bus = bus
        self._agent_id = agent_id
        self._target = target
        self._fleet_id = fleet_id
        self._output_dir = output_dir or "./erebos-reports"
        # VT-Spec R6: Report format (md, html, json)
        self._report_format = report_format
        # VT-Spec INJ-03: Redact file paths in reports
        self._redact_paths = redact_paths
        # Fleet metadata for report header (agents status, timing)
        self._fleet_metadata = fleet_metadata or {}

    async def execute(
        self,
        correlated: Optional[List[CorrelatedFinding]] = None,
    ) -> Dict[str, Any]:
        """Aggregate findings and generate report.

        Args:
            correlated: Pre-computed correlation results. If None, returns
                        basic summary without full report.
        """
        findings: List[Dict[str, Any]] = []
        severity_counts: Counter = Counter()
        role_counts: Counter = Counter()

        for msg in self._bus.subscribe(message_types=["finding"]):
            # Filter findings to only those matching the requested target.
            # Code-audit findings use file paths as target — skip host filter for them.
            if self._target and not self._finding_matches_target(msg.payload, msg.role.value):
                continue
            findings.append({"payload": msg.payload, "role": msg.role.value})
            severity_counts[msg.payload.get("severity", "UNKNOWN")] += 1
            role_counts[msg.role.value] += 1

        report: Dict[str, Any] = {
            "role": "reporter",
            "total_findings": len(findings),
            "by_severity": dict(severity_counts),
            "by_role": dict(role_counts),
            "report_format": self._report_format,
        }

        # VT-Spec INJ-03: Apply path redaction/relativization to findings
        if self._redact_paths:
            findings = self._apply_path_redaction(findings)

        # Generate full report if correlation data available
        if correlated:
            from erebos.reporting.fleet_report import FleetReportBuilder

            builder = FleetReportBuilder(
                target=self._target,
                fleet_id=self._fleet_id,
                duration_ms=self._fleet_metadata.get("duration_ms", 0.0),
                agents_completed=self._fleet_metadata.get("agents_completed", 0),
                agents_failed=self._fleet_metadata.get("agents_failed", 0),
            )
            markdown = builder.build(
                correlated_findings=correlated,
                raw_findings=findings,
            )

            # VT-Spec R6: Output in requested format
            if self._report_format == "json":
                report["report_content"] = json.dumps({
                    "target": self._target,
                    "fleet_id": self._fleet_id,
                    "total_findings": len(findings),
                    "by_severity": dict(severity_counts),
                    "findings": findings,
                }, default=str)
            elif self._report_format == "html":
                report["report_content"] = self._markdown_to_html(markdown)
            else:
                report["report_content"] = markdown

            report["report_markdown"] = markdown

            # Save to disk
            try:
                # VT-Spec R7: Sanitize target URL for filesystem-safe filename
                safe_target = sanitize_report_path(self._target)
                ext = self._report_format if self._report_format != "md" else "md"
                filename = f"fleet-{self._fleet_id[:8]}-{safe_target}.{ext}"

                # VT-Spec: Create reports directory before writing
                os.makedirs(self._output_dir, exist_ok=True)

                report_path = FleetReportBuilder.save_report(
                    report.get("report_content", markdown), self._output_dir, filename
                )
                report["report_path"] = str(report_path)
                logger.info(f"Fleet report saved: {report_path}")
            except OSError as e:
                logger.warning(f"Could not save report: {e}")

        # Publish summary to bus
        self._bus.publish(AgentMessage(
            id=f"{self._agent_id}-report",
            role=AgentRole.REPORTER,
            message_type="result",
            payload={
                "total_findings": report["total_findings"],
                "by_severity": report["by_severity"],
                "report_path": report.get("report_path", ""),
                "report_format": self._report_format,
            },
        ))

        return report

    def _apply_path_redaction(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """VT-Spec INJ-03: Redact file paths in report output.

        When --redact-paths is set, replace absolute paths with [REDACTED].
        Otherwise, convert to relative paths (default behavior per INJ-03).
        """
        redacted: List[Dict[str, Any]] = []
        for finding in findings:
            payload = dict(finding.get("payload", {}))

            # Redact or relativize file_path fields
            for key in ("file_path", "source_file", "path"):
                if key in payload and payload[key]:
                    path_val = str(payload[key])
                    if self._redact_paths and path_val.startswith("/"):
                        payload[key] = "[REDACTED]"
                    else:
                        # VT-Spec INJ-03: Default to relative paths
                        payload[key] = make_paths_relative(path_val)

            redacted.append({"payload": payload, "role": finding.get("role", "")})
        return redacted

    def _finding_matches_target(self, payload: Dict[str, Any], role: str = "") -> bool:
        """Check if a finding belongs to the requested target.

        Matches if the target domain appears in any target-related field.
        Code-audit findings use file paths as target — always include them.
        """
        from urllib.parse import urlparse

        # Code-audit findings are scoped to the repo, not a network host — always include
        if role == "code-audit":
            return True

        # Extract base domain from configured target
        target_host = self._target.lower().strip()
        if "://" in target_host:
            target_host = urlparse(target_host).hostname or target_host
        if ":" in target_host and not target_host.startswith("["):
            target_host = target_host.rsplit(":", 1)[0]

        # Check all fields that may contain target info
        fields_to_check = ["target", "raw_target", "host", "url", "injectable_url"]
        for field in fields_to_check:
            value = str(payload.get(field, "")).lower()
            if target_host in value:
                return True

        # If no target field present (e.g. code-audit finding), include it
        has_any_target_field = any(payload.get(f) for f in fields_to_check)
        return not has_any_target_field

    def _markdown_to_html(self, markdown: str) -> str:
        """Convert markdown report to basic HTML format."""
        # Simple conversion — wrap in HTML structure
        lines = markdown.split("\n")
        html_lines = [
            "<!DOCTYPE html><html><head><meta charset='utf-8'>",
            "<title>Erebos Report</title>",
            "<style>body{font-family:sans-serif;max-width:900px;margin:0 auto;padding:20px;}"
            "table{border-collapse:collapse;width:100%;}td,th{border:1px solid #ddd;padding:8px;}"
            "pre{background:#f4f4f4;padding:10px;overflow:auto;}"
            ".critical{color:#d32f2f;}.high{color:#f57c00;}.medium{color:#fbc02d;}.low{color:#388e3c;}"
            "</style></head><body>",
        ]
        for line in lines:
            if line.startswith("# "):
                html_lines.append(f"<h1>{line[2:]}</h1>")
            elif line.startswith("## "):
                html_lines.append(f"<h2>{line[3:]}</h2>")
            elif line.startswith("### "):
                html_lines.append(f"<h3>{line[4:]}</h3>")
            elif line.startswith("| "):
                html_lines.append(f"<tr>{''.join(f'<td>{c.strip()}</td>' for c in line.split('|')[1:-1])}</tr>")
            elif line.startswith("- "):
                html_lines.append(f"<li>{line[2:]}</li>")
            elif line.strip():
                html_lines.append(f"<p>{line}</p>")
        html_lines.append("</body></html>")
        return "\n".join(html_lines)
