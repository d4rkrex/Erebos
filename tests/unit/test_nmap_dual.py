"""Unit tests for dual nmap strategy and merge logic."""

from unittest.mock import MagicMock, Mock
import pytest

from erebos.core.finding import Finding, FindingEvidence, Severity, Phase
from erebos.core.phase_agent import ReconAgent


class TestNmapMergeLogic:
    """Tests for nmap result merging and dual strategy."""

    @pytest.fixture
    def agent(self):
        """Create a ReconAgent instance for testing."""
        transport = Mock()
        parsers = {}
        on_progress = Mock()
        on_finding = Mock()
        finding_store = Mock()
        scan_id = "test-scan"

        return ReconAgent(
            transport=transport,
            parsers=parsers,
            on_progress=on_progress,
            on_finding=on_finding,
            finding_store=finding_store,
            scan_id=scan_id,
        )

    def test_get_port_key_http_url(self, agent):
        """Test port key extraction from HTTP URL."""
        finding = Finding(
            title="HTTP Service",
            description="Test",
            severity=Severity.INFO,
            tool="nmap",
            phase_found=Phase.RECON,
            evidence=FindingEvidence(url="http://192.168.1.1:8080"),
        )

        key = agent._get_port_key(finding)
        assert key == ("192.168.1.1", 8080, "http")

    def test_get_port_key_https_url(self, agent):
        """Test port key extraction from HTTPS URL."""
        finding = Finding(
            title="HTTPS Service",
            description="Test",
            severity=Severity.INFO,
            tool="nmap",
            phase_found=Phase.RECON,
            evidence=FindingEvidence(url="https://example.com:443"),
        )

        key = agent._get_port_key(finding)
        assert key == ("example.com", 443, "https")

    def test_get_port_key_host_port_format(self, agent):
        """Test port key extraction from host:port format."""
        finding = Finding(
            title="SSH Service",
            description="Test",
            severity=Severity.INFO,
            tool="nmap",
            phase_found=Phase.RECON,
            evidence=FindingEvidence(url="192.168.1.1:22/tcp"),
        )

        key = agent._get_port_key(finding)
        assert key == ("192.168.1.1", 22, "tcp")

    def test_get_port_key_no_url(self, agent):
        """Test port key returns None for findings without URL."""
        finding = Finding(
            title="General Finding",
            description="Test",
            severity=Severity.INFO,
            tool="nmap",
            phase_found=Phase.RECON,
            evidence=FindingEvidence(),
        )

        key = agent._get_port_key(finding)
        assert key is None

    def test_merge_nmap_results_overlapping_ports(self, agent):
        """Test merge prefers full scan data for overlapping ports."""
        # Fast scan found port 80
        fast_findings = [
            Finding(
                title="HTTP - Fast Scan",
                description="Basic detection",
                severity=Severity.INFO,
                tool="nmap",
                phase_found=Phase.RECON,
                evidence=FindingEvidence(url="http://192.168.1.1:80"),
            )
        ]

        # Full scan found port 80 with more details
        full_findings = [
            Finding(
                title="HTTP - Apache 2.4.49",
                description="Detailed service version",
                severity=Severity.INFO,
                tool="nmap",
                phase_found=Phase.RECON,
                evidence=FindingEvidence(
                    url="http://192.168.1.1:80",
                    http_banner="Apache/2.4.49 (Unix)",
                ),
            )
        ]

        merged = agent._merge_nmap_results(fast_findings, full_findings)

        # Should have 1 finding (overlapping port)
        assert len(merged) == 1
        # Should prefer full scan data (Apache version)
        assert "Apache 2.4.49" in merged[0].title
        assert merged[0].evidence.http_banner == "Apache/2.4.49 (Unix)"

    def test_merge_nmap_results_unique_ports(self, agent):
        """Test merge includes unique ports from both scans."""
        # Fast scan found ports 22, 80
        fast_findings = [
            Finding(
                title="SSH",
                description="SSH service",
                severity=Severity.INFO,
                tool="nmap",
                phase_found=Phase.RECON,
                evidence=FindingEvidence(url="192.168.1.1:22/tcp"),
            ),
            Finding(
                title="HTTP",
                description="HTTP service",
                severity=Severity.INFO,
                tool="nmap",
                phase_found=Phase.RECON,
                evidence=FindingEvidence(url="http://192.168.1.1:80"),
            ),
        ]

        # Full scan found ports 80, 443, 8080
        full_findings = [
            Finding(
                title="HTTP",
                description="HTTP service",
                severity=Severity.INFO,
                tool="nmap",
                phase_found=Phase.RECON,
                evidence=FindingEvidence(url="http://192.168.1.1:80"),
            ),
            Finding(
                title="HTTPS",
                description="HTTPS service",
                severity=Severity.INFO,
                tool="nmap",
                phase_found=Phase.RECON,
                evidence=FindingEvidence(url="https://192.168.1.1:443"),
            ),
            Finding(
                title="HTTP Alt",
                description="HTTP alt service",
                severity=Severity.INFO,
                tool="nmap",
                phase_found=Phase.RECON,
                evidence=FindingEvidence(url="http://192.168.1.1:8080"),
            ),
        ]

        merged = agent._merge_nmap_results(fast_findings, full_findings)

        # Should have 4 unique ports: 22 (fast only), 80 (both), 443 (full only), 8080 (full only)
        assert len(merged) == 4

        # Extract ports from merged results
        ports = set()
        for finding in merged:
            key = agent._get_port_key(finding)
            if key:
                ports.add(key[1])  # port number

        assert ports == {22, 80, 443, 8080}

    def test_merge_nmap_results_empty_fast(self, agent):
        """Test merge with empty fast scan results."""
        fast_findings = []
        full_findings = [
            Finding(
                title="HTTP",
                description="HTTP service",
                severity=Severity.INFO,
                tool="nmap",
                phase_found=Phase.RECON,
                evidence=FindingEvidence(url="http://192.168.1.1:80"),
            )
        ]

        merged = agent._merge_nmap_results(fast_findings, full_findings)
        assert len(merged) == 1
        assert merged[0].title == "HTTP"

    def test_merge_nmap_results_empty_full(self, agent):
        """Test merge with empty full scan results (fallback to fast)."""
        fast_findings = [
            Finding(
                title="SSH",
                description="SSH service",
                severity=Severity.INFO,
                tool="nmap",
                phase_found=Phase.RECON,
                evidence=FindingEvidence(url="192.168.1.1:22/tcp"),
            )
        ]
        full_findings = []

        merged = agent._merge_nmap_results(fast_findings, full_findings)
        assert len(merged) == 1
        assert merged[0].title == "SSH"

    def test_merge_nmap_results_both_empty(self, agent):
        """Test merge with both scans empty."""
        merged = agent._merge_nmap_results([], [])
        assert len(merged) == 0

    def test_merge_prefers_full_scan_service_details(self, agent):
        """Test that merge prefers full scan service version details."""
        # Fast scan: basic detection
        fast_findings = [
            Finding(
                title="HTTP",
                description="HTTP service detected",
                severity=Severity.INFO,
                tool="nmap",
                phase_found=Phase.RECON,
                evidence=FindingEvidence(url="http://192.168.1.1:80"),
            )
        ]

        # Full scan: detailed version info
        full_findings = [
            Finding(
                title="HTTP - nginx 1.21.0",
                description="nginx/1.21.0 with vulnerable version",
                severity=Severity.MEDIUM,
                tool="nmap",
                phase_found=Phase.RECON,
                evidence=FindingEvidence(
                    url="http://192.168.1.1:80",
                    http_banner="nginx/1.21.0",
                ),
                cvss=5.3,
                cves=["CVE-2021-23017"],
            )
        ]

        merged = agent._merge_nmap_results(fast_findings, full_findings)

        assert len(merged) == 1
        # Verify full scan data is used
        assert "nginx 1.21.0" in merged[0].title
        assert merged[0].severity == Severity.MEDIUM
        assert merged[0].cvss == 5.3
        assert len(merged[0].cves) == 1
        assert merged[0].evidence.http_banner == "nginx/1.21.0"
