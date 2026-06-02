"""Unit tests for TUI models."""

import pytest

from erebos.tui.models import (
    ScanDisplay,
    TUIState,
    FindingDisplay,
    SeverityFilter,
    PhaseFilter,
    ToolStatus,
)


class TestScanDisplay:
    """Tests for ScanDisplay model."""

    def test_create_scan_display(self):
        """Test creating a ScanDisplay."""
        scan = ScanDisplay(
            scan_id="abc12345",
            target="example.com",
            phase="recon",
            profile="standard",
            started_at="2024-01-01T00:00:00",
            findings_count=5,
        )

        assert scan.scan_id == "abc12345"
        assert scan.target == "example.com"
        assert scan.phase == "recon"
        assert scan.profile == "standard"
        assert scan.findings_count == 5

    def test_phase_emoji(self):
        """Test phase emoji mapping."""
        scan = ScanDisplay(
            scan_id="test",
            target="example.com",
            phase="recon",
            profile="standard",
            started_at="2024-01-01T00:00:00",
        )
        assert scan.phase_emoji == "🔍"

        scan_complete = ScanDisplay(
            scan_id="test",
            target="example.com",
            phase="complete",
            profile="standard",
            started_at="2024-01-01T00:00:00",
        )
        assert scan_complete.phase_emoji == "✅"


class TestTUIState:
    """Tests for TUIState model."""

    def test_create_tui_state(self):
        """Test creating TUIState."""
        state = TUIState()
        assert state.scans == []
        assert state.selected_scan_id is None
        assert state.refresh_interval == 2
        assert state.auto_refresh is True

    def test_get_selected_scan_empty(self):
        """Test get_selected_scan when no scan selected."""
        state = TUIState()
        assert state.get_selected_scan() is None

    def test_get_selected_scan_found(self):
        """Test get_selected_scan finds the correct scan."""
        scan = ScanDisplay(
            scan_id="test123",
            target="example.com",
            phase="recon",
            profile="standard",
            started_at="2024-01-01T00:00:00",
        )
        state = TUIState(scans=[scan], selected_scan_id="test123")
        assert state.get_selected_scan() == scan

    def test_get_selected_scan_not_found(self):
        """Test get_selected_scan returns None when scan not found."""
        scan = ScanDisplay(
            scan_id="test123",
            target="example.com",
            phase="recon",
            profile="standard",
            started_at="2024-01-01T00:00:00",
        )
        state = TUIState(scans=[scan], selected_scan_id="wrong-id")
        assert state.get_selected_scan() is None

    def test_filtered_findings_severity(self):
        """Test filtering findings by severity."""
        findings = [
            FindingDisplay(
                id="1",
                tool="nmap",
                severity="HIGH",
                title="Test",
                description="",
                phase_found="recon",
                timestamp="2024-01-01T00:00:00",
            ),
            FindingDisplay(
                id="2",
                tool="nmap",
                severity="INFO",
                title="Test 2",
                description="",
                phase_found="recon",
                timestamp="2024-01-01T00:00:00",
            ),
        ]
        state = TUIState()
        filtered = state.filtered_findings(findings)
        assert len(filtered) == 2  # No filter set, returns all

        state.severity_filter = SeverityFilter.HIGH
        filtered = state.filtered_findings(findings)
        assert len(filtered) == 1
        assert filtered[0].severity == "HIGH"

    def test_filtered_findings_phase(self):
        """Test filtering findings by phase."""
        findings = [
            FindingDisplay(
                id="1",
                tool="nmap",
                severity="HIGH",
                title="Test",
                description="",
                phase_found="recon",
                timestamp="2024-01-01T00:00:00",
            ),
            FindingDisplay(
                id="2",
                tool="nuclei",
                severity="CRITICAL",
                title="Test 2",
                description="",
                phase_found="vuln-scan",
                timestamp="2024-01-01T00:00:00",
            ),
        ]
        state = TUIState()
        state.phase_filter = PhaseFilter.RECON
        filtered = state.filtered_findings(findings)
        assert len(filtered) == 1
        assert filtered[0].phase_found == "recon"


class TestSeverityFilter:
    """Tests for SeverityFilter enum."""

    def test_severity_values(self):
        """Test SeverityFilter has all expected values."""
        assert SeverityFilter.ALL.value == "all"
        assert SeverityFilter.CRITICAL.value == "CRITICAL"
        assert SeverityFilter.HIGH.value == "HIGH"
        assert SeverityFilter.MEDIUM.value == "MEDIUM"
        assert SeverityFilter.LOW.value == "LOW"
        assert SeverityFilter.INFO.value == "INFO"


class TestPhaseFilter:
    """Tests for PhaseFilter enum."""

    def test_phase_values(self):
        """Test PhaseFilter has all expected values."""
        assert PhaseFilter.ALL.value == "all"
        assert PhaseFilter.RECON.value == "recon"
        assert PhaseFilter.DISCOVERY.value == "discovery"
        assert PhaseFilter.VULN_SCAN.value == "vuln-scan"
        assert PhaseFilter.REPORTING.value == "reporting"


class TestToolStatus:
    """Tests for ToolStatus enum."""

    def test_tool_status_values(self):
        """Test ToolStatus has all expected values."""
        assert ToolStatus.PENDING.value == "pending"
        assert ToolStatus.RUNNING.value == "running"
        assert ToolStatus.COMPLETE.value == "complete"
        assert ToolStatus.FAILED.value == "failed"
        assert ToolStatus.SKIPPED.value == "skipped"


class TestFindingDisplay:
    """Tests for FindingDisplay model."""

    def test_create_finding_display(self):
        """Test creating a FindingDisplay."""
        finding = FindingDisplay(
            id="test-id",
            tool="nmap",
            severity="HIGH",
            title="Open Port",
            description="Port 80 is open",
            url="192.168.1.1:80",
            phase_found="recon",
            timestamp="2024-01-01T00:00:00",
            cve="CVE-2024-0001",
            cwe="CWE-89",
        )

        assert finding.id == "test-id"
        assert finding.tool == "nmap"
        assert finding.severity == "HIGH"
        assert finding.url == "192.168.1.1:80"
        assert finding.cve == "CVE-2024-0001"

    def test_finding_display_defaults(self):
        """Test FindingDisplay optional fields default to None."""
        finding = FindingDisplay(
            id="test-id",
            tool="nmap",
            severity="INFO",
            title="Test",
            description="Test description",
            phase_found="recon",
            timestamp="2024-01-01T00:00:00",
        )

        assert finding.url is None
        assert finding.cve is None
        assert finding.cwe is None
