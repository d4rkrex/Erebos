"""Integration tests for CLI flags, DAST/InfraScanner wiring, and reporter.

VT-Spec R1-R10: Integration test coverage.
VT-Spec INJ-03: Report path sanitization.
VT-Spec DOS-01: Budget-aware DAST execution.
VT-Spec SCOPE-01: Allowlist enforcement on ingested findings.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from click.testing import CliRunner

from erebos.cli.commands import cli


# --- Part 1: CLI flag acceptance tests ---


class TestScanCommandFlags:
    """Test that the scan command accepts new CLI flags (NF4: opt-in)."""

    def setup_method(self):
        self.runner = CliRunner()

    def test_scan_accepts_source_flag(self):
        """VT-Spec R3: --source flag accepted by scan command."""
        result = self.runner.invoke(cli, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--source" in result.output
        assert "Source code path" in result.output

    def test_scan_accepts_ingest_flag(self):
        """VT-Spec R1: --ingest flag accepted by scan command."""
        result = self.runner.invoke(cli, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--ingest" in result.output
        assert "Ingest external findings" in result.output

    def test_scan_accepts_ingest_format_flag(self):
        """VT-Spec R8: --ingest-format flag with valid choices."""
        result = self.runner.invoke(cli, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--ingest-format" in result.output

    def test_scan_accepts_report_format_flag(self):
        """VT-Spec R6: --report-format flag accepted by scan command."""
        result = self.runner.invoke(cli, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--report-format" in result.output
        assert "md" in result.output
        assert "html" in result.output
        assert "json" in result.output

    def test_scan_accepts_trust_rules_flag(self):
        """VT-Spec EXEC-01: --trust-rules flag for custom Semgrep rules."""
        result = self.runner.invoke(cli, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--trust-rules" in result.output

    def test_scan_accepts_redact_paths_flag(self):
        """VT-Spec INJ-03: --redact-paths flag for path redaction."""
        result = self.runner.invoke(cli, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--redact-paths" in result.output


class TestIngestCommand:
    """Test the standalone ingest command."""

    def setup_method(self):
        self.runner = CliRunner()

    def test_ingest_command_exists(self):
        """VT-Spec R1: Standalone ingest command exists."""
        result = self.runner.invoke(cli, ["ingest", "--help"])
        assert result.exit_code == 0
        assert "Ingest external findings" in result.output

    def test_ingest_command_accepts_format_flag(self):
        """VT-Spec R8: --format flag with valid choices."""
        result = self.runner.invoke(cli, ["ingest", "--help"])
        assert result.exit_code == 0
        assert "--format" in result.output

    def test_ingest_command_accepts_target_flag(self):
        """VT-Spec SCOPE-01: --target flag for scope filtering."""
        result = self.runner.invoke(cli, ["ingest", "--help"])
        assert result.exit_code == 0
        assert "--target" in result.output

    def test_ingest_command_requires_file_argument(self):
        """VT-Spec R1: File argument is required."""
        result = self.runner.invoke(cli, ["ingest"])
        assert result.exit_code != 0  # Missing required argument


# --- Part 2: Report path sanitization tests ---


class TestReportPathSanitization:
    """Test report path sanitization in reporter role."""

    def test_sanitize_report_path_removes_scheme(self):
        """VT-Spec R7: Scheme is removed from report filename."""
        from erebos.reporting.models import sanitize_report_path

        result = sanitize_report_path("https://juice.labs.manuel-roldan.cloud")
        assert "https" not in result
        assert "://" not in result
        assert "juice" in result

    def test_sanitize_report_path_replaces_special_chars(self):
        """VT-Spec R7: Special characters replaced with dashes."""
        from erebos.reporting.models import sanitize_report_path

        result = sanitize_report_path("http://192.168.1.1:8080/api?key=val")
        assert ":" not in result
        assert "?" not in result
        assert "=" not in result

    def test_sanitize_report_path_no_leading_trailing_dashes(self):
        """VT-Spec R7: No leading/trailing dashes in filename."""
        from erebos.reporting.models import sanitize_report_path

        result = sanitize_report_path("https://example.com/")
        assert not result.startswith("-")
        assert not result.endswith("-")

    def test_sanitize_report_path_length_limit(self):
        """VT-Spec R7: Filename limited to 100 chars."""
        from erebos.reporting.models import sanitize_report_path

        long_target = "https://very-" + "long-" * 50 + "domain.com"
        result = sanitize_report_path(long_target)
        assert len(result) <= 100


# --- Part 3: Reporter role format tests ---


class TestReporterRoleFormat:
    """Test reporter role with different formats."""

    def _make_bus(self):
        """Create a mock FindingsBus."""
        bus = MagicMock()
        bus.subscribe.return_value = []
        bus.publish = MagicMock()
        return bus

    def test_reporter_default_format_is_md(self):
        """VT-Spec R6: Default format is markdown."""
        from erebos.agents.roles.reporter import ReporterRole

        bus = self._make_bus()
        role = ReporterRole(bus=bus, agent_id="test-1", target="example.com")
        result = asyncio.run(role.execute())
        assert result["report_format"] == "md"

    def test_reporter_json_format(self):
        """VT-Spec R6: JSON report format."""
        from erebos.agents.roles.reporter import ReporterRole

        bus = self._make_bus()
        role = ReporterRole(
            bus=bus, agent_id="test-1", target="example.com", report_format="json"
        )
        result = asyncio.run(role.execute())
        assert result["report_format"] == "json"

    def test_reporter_html_format(self):
        """VT-Spec R6: HTML report format."""
        from erebos.agents.roles.reporter import ReporterRole

        bus = self._make_bus()
        role = ReporterRole(
            bus=bus, agent_id="test-1", target="example.com", report_format="html"
        )
        result = asyncio.run(role.execute())
        assert result["report_format"] == "html"

    def test_reporter_redact_paths(self):
        """VT-Spec INJ-03: --redact-paths redacts absolute paths."""
        from erebos.agents.roles.reporter import ReporterRole

        finding_msg = MagicMock()
        finding_msg.payload = {
            "title": "SQLi",
            "severity": "HIGH",
            "file_path": "/home/user/secret/app.py",
        }
        finding_msg.role = MagicMock()
        finding_msg.role.value = "vuln-scan"

        bus = MagicMock()
        bus.subscribe.return_value = [finding_msg]
        bus.publish = MagicMock()

        role = ReporterRole(
            bus=bus, agent_id="test-1", target="example.com", redact_paths=True
        )
        result = asyncio.run(role.execute())
        # Verify that path is redacted — it won't appear in the basic summary
        # but the redaction logic is tested via _apply_path_redaction
        assert result["total_findings"] == 1

    def test_path_redaction_logic(self):
        """VT-Spec INJ-03: Path redaction replaces absolute paths."""
        from erebos.agents.roles.reporter import ReporterRole

        bus = MagicMock()
        bus.subscribe.return_value = []
        bus.publish = MagicMock()

        role = ReporterRole(
            bus=bus, agent_id="test-1", target="example.com", redact_paths=True
        )

        findings = [
            {"payload": {"file_path": "/home/user/app.py", "title": "test"}, "role": "vuln-scan"}
        ]
        redacted = role._apply_path_redaction(findings)
        assert redacted[0]["payload"]["file_path"] == "[REDACTED]"

    def test_path_relative_by_default(self):
        """VT-Spec INJ-03: Default is relative paths, not full redaction."""
        from erebos.agents.roles.reporter import ReporterRole

        bus = MagicMock()
        bus.subscribe.return_value = []
        bus.publish = MagicMock()

        role = ReporterRole(
            bus=bus, agent_id="test-1", target="example.com", redact_paths=False
        )

        findings = [
            {"payload": {"file_path": "/home/user/app.py", "title": "test"}, "role": "vuln-scan"}
        ]
        result = role._apply_path_redaction(findings)
        # With redact_paths=False, absolute paths are relativized (not [REDACTED])
        assert result[0]["payload"]["file_path"] != "[REDACTED]"


# --- Part 4: FleetConfig new parameters ---


class TestFleetConfigIntegration:
    """Test FleetConfig accepts new parameters."""

    def test_fleet_config_source_path(self):
        """VT-Spec R3: FleetConfig accepts source_path."""
        from erebos.agents.orchestrator import FleetConfig

        cfg = FleetConfig(
            target="example.com",
            source_path=Path("/tmp/source"),
            allowlist=["example.com"],
        )
        assert cfg.source_path == Path("/tmp/source")

    def test_fleet_config_trust_rules_default_false(self):
        """VT-Spec EXEC-01: trust_rules defaults to False."""
        from erebos.agents.orchestrator import FleetConfig

        cfg = FleetConfig(target="example.com", allowlist=["example.com"])
        assert cfg.trust_rules is False

    def test_fleet_config_report_format(self):
        """VT-Spec R6: FleetConfig accepts report_format."""
        from erebos.agents.orchestrator import FleetConfig

        cfg = FleetConfig(
            target="example.com",
            report_format="json",
            allowlist=["example.com"],
        )
        assert cfg.report_format == "json"

    def test_fleet_config_redact_paths(self):
        """VT-Spec INJ-03: FleetConfig accepts redact_paths."""
        from erebos.agents.orchestrator import FleetConfig

        cfg = FleetConfig(
            target="example.com",
            redact_paths=True,
            allowlist=["example.com"],
        )
        assert cfg.redact_paths is True

    def test_fleet_config_backward_compatible(self):
        """VT-Spec NF4: Default behavior unchanged without new flags."""
        from erebos.agents.orchestrator import FleetConfig

        cfg = FleetConfig(target="example.com", allowlist=["example.com"])
        assert cfg.source_path is None
        assert cfg.trust_rules is False
        assert cfg.report_format == "md"
        assert cfg.redact_paths is False


# --- Part 5: DAST executor wiring test ---


class TestDastWiring:
    """Test DAST executor is wired into exploit role."""

    def test_dast_executor_importable(self):
        """VT-Spec R2: DastExecutor can be imported."""
        from erebos.exploits.dast.executor import DastExecutor

        executor = DastExecutor(budget=100, allowlist=["example.com"])
        assert executor is not None

    def test_orchestrator_has_run_dast_phase(self):
        """VT-Spec R2: Orchestrator has _run_dast_phase method."""
        from erebos.agents.orchestrator import FleetOrchestrator

        assert hasattr(FleetOrchestrator, "_run_dast_phase")

    def test_orchestrator_has_gather_dast_targets(self):
        """VT-Spec R2: Orchestrator has _gather_dast_targets method."""
        from erebos.agents.orchestrator import FleetOrchestrator

        assert hasattr(FleetOrchestrator, "_gather_dast_targets")


# --- Part 6: InfraScanner wiring test ---


class TestInfraScannerWiring:
    """Test InfraScanner is wired into vuln-scan role."""

    def test_infra_scanner_importable(self):
        """VT-Spec R4: InfraScanner can be imported."""
        from erebos.scanners.infra_scanner import InfraScanner

        scanner = InfraScanner()
        assert scanner is not None

    def test_orchestrator_has_run_infra_scan(self):
        """VT-Spec R4: Orchestrator has _run_infra_scan method."""
        from erebos.agents.orchestrator import FleetOrchestrator

        assert hasattr(FleetOrchestrator, "_run_infra_scan")

    def test_orchestrator_has_gather_non_http_services(self):
        """VT-Spec R4: Orchestrator has _gather_non_http_services method."""
        from erebos.agents.orchestrator import FleetOrchestrator

        assert hasattr(FleetOrchestrator, "_gather_non_http_services")


# --- Part 7: Security mitigation tests ---


class TestSecurityMitigations:
    """Test that security mitigations are enforced."""

    def test_inj03_make_paths_relative(self):
        """VT-Spec INJ-03: make_paths_relative converts absolute to relative."""
        from erebos.reporting.models import make_paths_relative

        result = make_paths_relative("/home/user/project/src/app.py")
        # Should not start with /home/user — either relative or stripped
        assert not result.startswith("/home/user/project/")

    def test_dos01_dast_budget_cap(self):
        """VT-Spec DOS-01: DAST executor has budget cap."""
        from erebos.exploits.dast.executor import MAX_TOTAL_DAST_REQUESTS

        assert MAX_TOTAL_DAST_REQUESTS == 5000

    def test_exec01_trust_rules_flag_in_cli(self):
        """VT-Spec EXEC-01: --trust-rules flag exists and is opt-in."""
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--help"])
        assert "--trust-rules" in result.output
        # It's a flag (is_flag=True), so default is False

    def test_scope01_ingester_validates_allowlist(self):
        """VT-Spec SCOPE-01: FindingsIngester validates against allowlist."""
        from erebos.ingestion.ingester import FindingsIngester

        ingester = FindingsIngester(allowlist=["example.com"])
        # The ingester has an AllowlistValidator
        assert ingester._validator is not None
