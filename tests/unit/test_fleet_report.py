"""Tests for fleet report generation."""

from __future__ import annotations

from erebos.agents.correlation import CorrelatedFinding
from erebos.reporting.fleet_report import FleetReportBuilder


class TestFleetReportBuilder:
    """REQ-01: FleetReportBuilder generates structured reports."""

    def _make_builder(self) -> FleetReportBuilder:
        return FleetReportBuilder(
            target="example.com",
            fleet_id="test-fleet-abc123",
            duration_ms=15000.0,
            agents_completed=5,
            agents_failed=0,
        )

    def _sample_findings(self) -> list:
        return [
            CorrelatedFinding(
                title="SQL Injection Auth Bypass",
                severity="CRITICAL",
                signal_count=3,
                priority_score=95,
                cve="CVE-2023-1234",
                cwe="CWE-89",
            ),
            CorrelatedFinding(
                title="Reflected XSS on /search",
                severity="HIGH",
                signal_count=2,
                priority_score=70,
                cwe="CWE-79",
            ),
            CorrelatedFinding(
                title="Open port 8080",
                severity="LOW",
                signal_count=1,
                priority_score=10,
            ),
        ]

    def test_executive_summary_severity_counts(self):
        """AC-01.1: Executive summary has correct severity counts."""
        builder = self._make_builder()
        findings = self._sample_findings()
        report = builder.build(findings)

        assert "**Critical**: 1" in report
        assert "**High**: 1" in report
        assert "**Low**: 1" in report
        assert "CRITICAL" in report  # Overall risk

    def test_findings_sorted_by_priority(self):
        """AC-01.2: Findings sorted by priority_score."""
        builder = self._make_builder()
        findings = self._sample_findings()
        report = builder.build(findings)

        # SQL injection (score 95) should appear before XSS (70)
        sqli_pos = report.find("SQL Injection")
        xss_pos = report.find("Reflected XSS")
        low_pos = report.find("Open port 8080")

        assert sqli_pos < xss_pos < low_pos

    def test_findings_include_cve_cwe(self):
        """AC-01.3: Findings include CVE/CWE."""
        builder = self._make_builder()
        findings = self._sample_findings()
        report = builder.build(findings)

        assert "CVE-2023-1234" in report
        assert "CWE-89" in report
        assert "CWE-79" in report

    def test_correlation_badge(self):
        """AC-01.4: Multi-signal findings show correlation badge."""
        builder = self._make_builder()
        findings = self._sample_findings()
        report = builder.build(findings)

        # Multi-signal findings should have correlation indicator
        assert "🔗" in report
        assert "3 independent" in report or "×3" in report

    def test_report_header_warning(self):
        """ID-01: Report has confidential warning header."""
        builder = self._make_builder()
        report = builder.build(self._sample_findings())

        assert "CONFIDENTIAL" in report
        assert "sensitive information" in report

    def test_empty_findings_minimal_report(self):
        """AC-03.4: Empty findings produces minimal valid report."""
        builder = self._make_builder()
        report = builder.build([])

        assert "# 🔒 Penetration Test Report" in report
        assert "**Unique correlated findings**: 0" in report
        assert "No critical or high severity findings" in report

    def test_cap_at_max_findings(self):
        """AC-01: Report caps at MAX_REPORT_FINDINGS."""
        builder = self._make_builder()
        # Create 300 findings
        findings = [
            CorrelatedFinding(
                title=f"Finding {i}",
                severity="LOW",
                signal_count=1,
                priority_score=5,
            )
            for i in range(300)
        ]
        report = builder.build(findings)

        # Should mention omitted findings
        assert "omitted" in report.lower()

    def test_save_report_permissions(self, tmp_path):
        """ID-01: Saved report has 600 permissions."""
        import os

        content = "# Test Report"
        filepath = FleetReportBuilder.save_report(
            content, str(tmp_path), "test-report.md"
        )

        assert filepath.exists()
        assert filepath.read_text() == content
        # Check permissions (600 = owner read/write only)
        mode = os.stat(filepath).st_mode & 0o777
        assert mode == 0o600

    def test_duration_in_header(self):
        """AC-01.1: Duration shown in header."""
        builder = self._make_builder()
        report = builder.build(self._sample_findings())

        assert "15.0s" in report

    def test_remediation_section(self):
        """Remediation priorities section for critical/high."""
        builder = self._make_builder()
        findings = self._sample_findings()
        report = builder.build(findings)

        assert "Remediation Priorities" in report
        assert "Immediate Action" in report
        assert "SQL Injection" in report
