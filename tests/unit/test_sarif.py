"""Tests for SARIF generation from SAST findings."""

import json

from erebos.core.finding import Finding, Phase, Severity
from erebos.core.sast.sarif import SarifGenerator
from erebos.core.sast.scanner import SastFinding, SastResult
from erebos.core.validation import ValidationResult
from erebos.core.validation.stages import StageVerdict


def test_generate_sarif_with_validation(tmp_path):
    """SARIF output includes results, rules, and validation metadata."""
    finding = SastFinding(
        rule_id="python-sql-string-formatting",
        severity="ERROR",
        message="SQL built via string interpolation instead of parameters",
        file_path="app/views.py",
        line_start=22,
        line_end=22,
        col_start=5,
        col_end=30,
        code_snippet='cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
        cwe="CWE-89: SQL Injection",
    )
    sast_result = SastResult(
        findings=[finding],
        files_scanned=1,
        rules_run=3,
        scan_time_ms=42,
        target_path="app",
    )
    vt_finding = Finding(
        tool="semgrep",
        severity=Severity.HIGH,
        title="[SAST] python-sql-string-formatting",
        description=finding.message,
        target="app",
        cwe="CWE-89",
        phase_found=Phase.VULN_SCAN,
    )
    validation = ValidationResult(
        finding=vt_finding,
        final_verdict=StageVerdict.PASS,
        confidence=0.91,
        exploitation_status="potential",
    )

    generator = SarifGenerator()
    document = generator.generate(sast_result, [validation])
    output_path = tmp_path / "result.sarif"
    generator.to_file(output_path)

    result = document["runs"][0]["results"][0]
    rule = document["runs"][0]["tool"]["driver"]["rules"][0]

    assert document["version"] == "2.1.0"
    assert result["ruleId"] == finding.rule_id
    assert result["level"] == "error"
    assert result["properties"]["erebosValidation"]["verdict"] == "pass"
    assert rule["relationships"][0]["target"]["id"] == "CWE-89"
    assert json.loads(output_path.read_text())["runs"][0]["results"][0]["ruleId"] == finding.rule_id


def test_to_json_requires_generate_first():
    """Generator should require a document before serialization."""
    generator = SarifGenerator()

    try:
        generator.to_json()
    except ValueError as exc:
        assert "No SARIF document generated yet" in str(exc)
    else:
        raise AssertionError("Expected ValueError before generate()")
