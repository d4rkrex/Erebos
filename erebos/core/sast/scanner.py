"""SAST Scanner — Semgrep-based static analysis.

Runs semgrep against target source code and produces findings compatible
with the Erebos Finding model. Extracts source context for the
validation pipeline.
"""

from __future__ import annotations

import json
import logging
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from erebos.core.finding import Finding, Phase, Severity
from erebos.core.validation.stages import SourceContext

logger = logging.getLogger(__name__)


# Semgrep severity → Erebos Severity mapping
_SEVERITY_MAP = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}

# CWE mapping for common semgrep rule IDs
_RULE_CWE_MAP = {
    "sql-injection": "CWE-89",
    "command-injection": "CWE-78",
    "code-injection": "CWE-94",
    "xss": "CWE-79",
    "ssrf": "CWE-918",
    "path-traversal": "CWE-22",
    "xxe": "CWE-611",
    "deserialization": "CWE-502",
    "open-redirect": "CWE-601",
    "hardcoded-secret": "CWE-798",
    "insecure-crypto": "CWE-327",
    "weak-random": "CWE-330",
    "csrf": "CWE-352",
    "nosql-injection": "CWE-943",
}


@dataclass
class SastFinding:
    """Raw SAST finding from semgrep."""

    rule_id: str
    severity: str
    message: str
    file_path: str
    line_start: int
    line_end: int
    col_start: int
    col_end: int
    code_snippet: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    dataflow_trace: Optional[List[Dict[str, Any]]] = None


@dataclass
class SastResult:
    """Aggregate result from a SAST scan."""

    findings: List[SastFinding]
    files_scanned: int
    rules_run: int
    scan_time_ms: int
    errors: List[str] = field(default_factory=list)
    target_path: str = ""

    @property
    def finding_count(self) -> int:
        return len(self.findings)


class SastScanner:
    """Semgrep-based SAST scanner.

    Wraps semgrep CLI and parses JSON output into SastFinding objects.
    Provides conversion to Erebos Finding model with SourceContext.
    """

    def __init__(
        self,
        rules: Optional[List[str]] = None,
        severity_filter: Optional[List[str]] = None,
        exclude_patterns: Optional[List[str]] = None,
        timeout: int = 300,
    ):
        """Initialize scanner.

        Args:
            rules: Semgrep rule sets to use. Defaults to security-focused rules.
            severity_filter: Only include these severities (ERROR, WARNING, INFO).
            exclude_patterns: Glob patterns to exclude from scanning.
            timeout: Max scan time in seconds.
        """
        default_rules_dir = Path(__file__).resolve().with_name("rules")
        self._rules = rules or [
            "p/security-audit",
            "p/owasp-top-ten",
            "p/command-injection",
            "p/sql-injection",
            "p/xss",
            str(default_rules_dir / "express-security.yaml"),
            str(default_rules_dir / "python-security.yaml"),
            str(default_rules_dir / "general-security.yaml"),
        ]
        self._severity_filter = severity_filter
        self._exclude_patterns = exclude_patterns or [
            "node_modules",
            "vendor",
            ".git",
            "dist",
            "build",
            "__pycache__",
            "*.min.js",
            "*.bundle.js",
        ]
        self._timeout = timeout

    def scan(self, target_path: str) -> SastResult:
        """Run semgrep scan on target path.

        Args:
            target_path: Path to directory or file to scan.

        Returns:
            SastResult with all findings.
        """
        target = Path(target_path)
        if not target.exists():
            return SastResult(
                findings=[],
                files_scanned=0,
                rules_run=0,
                scan_time_ms=0,
                errors=[f"Target path does not exist: {target_path}"],
                target_path=target_path,
            )

        cmd = self._build_command(target_path)
        logger.info(f"Running SAST scan: {' '.join(cmd[:6])}...")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self._timeout,
                cwd=target_path if target.is_dir() else str(target.parent),
            )
        except subprocess.TimeoutExpired:
            return SastResult(
                findings=[],
                files_scanned=0,
                rules_run=0,
                scan_time_ms=self._timeout * 1000,
                errors=[f"Scan timed out after {self._timeout}s"],
                target_path=target_path,
            )
        except FileNotFoundError:
            return SastResult(
                findings=[],
                files_scanned=0,
                rules_run=0,
                scan_time_ms=0,
                errors=["semgrep not found. Install with: pip install semgrep"],
                target_path=target_path,
            )

        return self._parse_output(result.stdout, result.stderr, target_path)

    def scan_to_findings(self, target_path: str) -> List[Finding]:
        """Scan and convert directly to Erebos Finding objects."""
        sast_result = self.scan(target_path)
        return self.result_to_findings(sast_result, target_path)

    def result_to_findings(
        self,
        sast_result: SastResult,
        target_path: Optional[str] = None,
    ) -> List[Finding]:
        """Convert an existing SAST result into Erebos Finding objects."""
        scan_target = target_path or sast_result.target_path
        return [self._to_finding(sf, scan_target) for sf in sast_result.findings]

    def extract_source_context(self, sast_finding: SastFinding) -> SourceContext:
        """Extract SourceContext from a SAST finding for validation pipeline."""
        # Parse dataflow trace if available
        data_flow = []
        sanitizers = []
        if sast_finding.dataflow_trace:
            for step in sast_finding.dataflow_trace:
                location = step.get("location", {})
                content = step.get("content", "")
                data_flow.append(
                    f"{location.get('path', '?')}:{location.get('start', {}).get('line', '?')} → {content[:60]}"
                )

        # Detect common sanitizer patterns in code
        code = sast_finding.code_snippet.lower()
        sanitizer_patterns = [
            "escape",
            "sanitize",
            "encode",
            "validate",
            "filter",
            "htmlspecialchars",
            "parameterized",
            "prepared",
            "dompurify",
            "xss",
            "clean",
        ]
        for pattern in sanitizer_patterns:
            if pattern in code:
                sanitizers.append(pattern)

        # Detect entry points from metadata
        entry_points = []
        metadata = sast_finding.metadata
        if "route" in str(metadata).lower():
            entry_points.append("HTTP route")
        if "export" in code or "module.exports" in code:
            entry_points.append("exported module")
        if "app.get" in code or "app.post" in code or "router." in code:
            entry_points.append("express route handler")

        # Detect language from file extension
        ext = Path(sast_finding.file_path).suffix.lower()
        lang_map = {
            ".js": "javascript",
            ".ts": "typescript",
            ".py": "python",
            ".java": "java",
            ".go": "go",
            ".rb": "ruby",
            ".php": "php",
        }

        return SourceContext(
            file_path=sast_finding.file_path,
            line_number=sast_finding.line_start,
            code_snippet=sast_finding.code_snippet,
            function_name=None,  # Would need AST parsing
            entry_points=entry_points,
            data_flow=data_flow,
            sanitizers=sanitizers,
            language=lang_map.get(ext),
        )

    def _build_command(self, target_path: str) -> List[str]:
        """Build semgrep command line."""
        cmd = [
            "semgrep",
            "scan",
            "--json",
            "--metrics=off",
        ]

        # Add rule configs
        for rule in self._rules:
            cmd.extend(["--config", rule])

        # Add exclusions
        for pattern in self._exclude_patterns:
            cmd.extend(["--exclude", pattern])

        # Add severity filter
        if self._severity_filter:
            for sev in self._severity_filter:
                cmd.extend(["--severity", sev])

        cmd.append(target_path)
        return cmd

    def _parse_output(self, stdout: str, stderr: str, target_path: str) -> SastResult:
        """Parse semgrep JSON output."""
        if not stdout.strip():
            errors = []
            if stderr:
                errors = [line for line in stderr.split("\n") if line.strip()][:5]
            return SastResult(
                findings=[],
                files_scanned=0,
                rules_run=0,
                scan_time_ms=0,
                errors=errors or ["No output from semgrep"],
                target_path=target_path,
            )

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError as e:
            return SastResult(
                findings=[],
                files_scanned=0,
                rules_run=0,
                scan_time_ms=0,
                errors=[f"Failed to parse semgrep JSON: {e}"],
                target_path=target_path,
            )

        findings = []
        for result in data.get("results", []):
            extra = result.get("extra", {})
            metadata = extra.get("metadata", {})

            # Extract CWE from metadata
            cwe = None
            cwe_list = metadata.get("cwe", [])
            if cwe_list:
                raw_cwe = cwe_list[0] if isinstance(cwe_list, list) else str(cwe_list)
                # Semgrep CWE format: "CWE-89: Improper Neutralization..." — extract ID
                if ":" in raw_cwe:
                    cwe = raw_cwe.split(":")[0].strip()
                else:
                    cwe = raw_cwe
            else:
                # Try to infer from rule ID
                rule_id = result.get("check_id", "")
                for key, cwe_val in _RULE_CWE_MAP.items():
                    if key in rule_id.lower():
                        cwe = cwe_val
                        break

            # Extract dataflow trace if present
            dataflow_trace = extra.get("dataflow_trace")

            sf = SastFinding(
                rule_id=result.get("check_id", "unknown"),
                severity=extra.get("severity", "WARNING"),
                message=extra.get("message", result.get("check_id", "")),
                file_path=result.get("path", ""),
                line_start=result.get("start", {}).get("line", 0),
                line_end=result.get("end", {}).get("line", 0),
                col_start=result.get("start", {}).get("col", 0),
                col_end=result.get("end", {}).get("col", 0),
                code_snippet=extra.get("lines", ""),
                metadata=metadata,
                cwe=cwe,
                owasp=metadata.get("owasp"),
                dataflow_trace=dataflow_trace.get("taint_source", []) if dataflow_trace else None,
            )
            findings.append(sf)

        # Parse stats — semgrep JSON uses paths.scanned and time at top level
        paths_data = data.get("paths", {})
        scanned_files = paths_data.get("scanned", [])
        time_data = data.get("time", {})

        # Fallback to legacy stats format
        stats = data.get("stats", {})
        files_scanned = len(scanned_files) or stats.get("total", {}).get("files", 0)

        # Rules count from skipped_rules or stats
        rules_run = len(data.get("skipped_rules", [])) + len(findings)

        # Time calculation
        total_time = time_data.get("total_time", 0) if isinstance(time_data, dict) else 0
        scan_time_ms = (
            int(total_time * 1000)
            if total_time
            else int(stats.get("total", {}).get("time", {}).get("total_ms", 0))
        )

        errors_list = []
        for err in data.get("errors", []):
            if isinstance(err, dict):
                errors_list.append(str(err.get("message", err)))
            else:
                errors_list.append(str(err))

        return SastResult(
            findings=findings,
            files_scanned=files_scanned,
            rules_run=rules_run,
            scan_time_ms=scan_time_ms,
            errors=errors_list[:10],
            target_path=target_path,
        )

    def _to_finding(self, sf: SastFinding, target_path: str) -> Finding:
        """Convert SastFinding to Erebos Finding."""
        severity = _SEVERITY_MAP.get(sf.severity, Severity.MEDIUM)

        return Finding(
            tool="semgrep",
            severity=severity,
            title=f"[SAST] {sf.rule_id}",
            description=sf.message,
            target=target_path,
            cwe=sf.cwe,
            phase_found=Phase.VULN_SCAN,
        )
