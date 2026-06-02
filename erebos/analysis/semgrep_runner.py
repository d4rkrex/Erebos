"""Semgrep SAST runner with security controls.

VT-Spec R9: Run Semgrep with security rulesets.
VT-Spec EXEC-01: Only official rulesets unless --trust-rules explicitly set.
"""

from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from erebos.core.finding import Finding, FindingEvidence, Phase, Severity

logger = logging.getLogger(__name__)

# Semgrep severity mapping
_SEVERITY_MAP: Dict[str, Severity] = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}


class SastFinding(BaseModel):
    """Normalized SAST finding from Semgrep."""

    check_id: str
    severity: Severity
    message: str
    file: str  # relative path (INJ-03)
    line: int
    end_line: int = 0
    code_snippet: str = ""
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class SemgrepRunner:
    """Run Semgrep with security rulesets.

    VT-Spec EXEC-01: Only official semgrep rulesets (p/security-audit,
    p/owasp-top-ten, p/cwe-top-25). User custom rules require explicit
    --trust-rules flag.
    """

    OFFICIAL_RULESETS = [
        "p/security-audit",
        "p/owasp-top-ten",
        "p/cwe-top-25",
    ]

    def __init__(self, trust_custom_rules: bool = False):
        # VT-Spec EXEC-01: custom rules gated behind trust flag
        self._trust_custom = trust_custom_rules

    def run(
        self,
        source_path: Path,
        custom_rules: Optional[Path] = None,
        timeout: int = 300,
    ) -> List[SastFinding]:
        """Run Semgrep and normalize output.

        VT-Spec EXEC-01: Only official rulesets unless trust_custom_rules=True.
        If custom_rules provided without trust flag, log warning and skip.
        """
        rules = list(self.OFFICIAL_RULESETS)

        if custom_rules is not None:
            if not self._trust_custom:
                # VT-Spec EXEC-01: Reject custom rules without trust flag
                logger.warning(
                    "EXEC-01: Custom rules at %s rejected — "
                    "--trust-rules not set. Only official rulesets will be used.",
                    custom_rules,
                )
            else:
                # Validate custom rules path exists
                if custom_rules.exists():
                    rules.append(str(custom_rules))
                    logger.info(
                        "EXEC-01: Custom rules at %s accepted (trust_custom_rules=True)",
                        custom_rules,
                    )
                else:
                    logger.warning("Custom rules path does not exist: %s", custom_rules)

        cmd = self._build_command(source_path, rules)
        return self._execute_and_parse(cmd, source_path, timeout)

    def _build_command(self, source_path: Path, rules: List[str]) -> List[str]:
        """Build semgrep command.

        Always uses: --json --quiet --no-git-ignore
        """
        cmd = ["semgrep", "scan"]
        for rule in rules:
            cmd.extend(["--config", rule])
        cmd.extend(["--json", "--quiet", str(source_path)])
        return cmd

    def _execute_and_parse(
        self, cmd: List[str], source_path: Path, timeout: int
    ) -> List[SastFinding]:
        """Execute semgrep and parse JSON output."""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=str(source_path.parent),
            )
        except FileNotFoundError:
            logger.error("Semgrep not found. Install with: pip install semgrep")
            return []
        except subprocess.TimeoutExpired:
            logger.error("Semgrep timed out after %d seconds", timeout)
            return []

        # Semgrep exits with 1 if findings exist, 0 if clean
        if result.returncode not in (0, 1):
            logger.warning("Semgrep exited with code %d: %s", result.returncode, result.stderr[:500])
            return []

        return self._parse_output(result.stdout, source_path)

    def _parse_output(self, output: str, source_path: Path) -> List[SastFinding]:
        """Parse Semgrep JSON output into SastFinding objects."""
        if not output.strip():
            return []

        try:
            data = json.loads(output)
        except json.JSONDecodeError as e:
            logger.warning("Failed to parse Semgrep JSON: %s", e)
            return []

        findings: List[SastFinding] = []
        for result in data.get("results", []):
            finding = self._normalize_result(result, source_path)
            if finding:
                findings.append(finding)

        logger.info("Semgrep found %d findings", len(findings))
        return findings

    def _normalize_result(
        self, result: Dict[str, Any], source_path: Path
    ) -> Optional[SastFinding]:
        """Normalize a single Semgrep result."""
        try:
            check_id = result.get("check_id", "unknown")
            extra = result.get("extra", {})
            severity_str = extra.get("severity", "WARNING")
            severity = _SEVERITY_MAP.get(severity_str, Severity.MEDIUM)

            # VT-Spec INJ-03: Use relative paths
            abs_path = result.get("path", "")
            try:
                rel_path = str(Path(abs_path).relative_to(source_path))
            except (ValueError, TypeError):
                rel_path = abs_path

            metadata = extra.get("metadata", {})
            cwe_list = metadata.get("cwe", [])
            cwe = cwe_list[0] if cwe_list else None
            owasp_list = metadata.get("owasp", [])
            owasp = owasp_list[0] if owasp_list else None

            return SastFinding(
                check_id=check_id,
                severity=severity,
                message=extra.get("message", "")[:500],
                file=rel_path,
                line=result.get("start", {}).get("line", 0),
                end_line=result.get("end", {}).get("line", 0),
                code_snippet=extra.get("lines", "")[:200],
                cwe=cwe,
                owasp=owasp,
                metadata=metadata,
            )
        except Exception as e:
            logger.warning("Failed to normalize Semgrep result: %s", e)
            return None

    def to_findings(self, sast_findings: List[SastFinding]) -> List[Finding]:
        """Convert SastFinding to core Finding model for FactGraph integration."""
        findings: List[Finding] = []
        for sf in sast_findings:
            finding = Finding(
                tool="semgrep",
                severity=sf.severity,
                title=sf.check_id,
                description=sf.message,
                cwe=sf.cwe,
                evidence=FindingEvidence(
                    url=f"file://{sf.file}#L{sf.line}",
                    output=sf.code_snippet,
                ),
                phase_found=Phase.VULN_SCAN,
            )
            findings.append(finding)
        return findings
